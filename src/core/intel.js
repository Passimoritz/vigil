'use strict';

// Threat-Intel, Risiko und Angriffspfade.
//
//  Threat-Intel-Cache: CISA KEV (aktiv ausgenutzte Luecken) + FIRST EPSS (Ausnutzungs-
//  wahrscheinlichkeit) werden einmal taeglich lokal gespeichert. Scans schlagen nur lokal
//  nach – sie warten nie auf externe APIs und scheitern nicht an Rate-Limits.
//
//  Kontext-Risiko (0–100): CVSS*10 bzw. Schweregrad, +15 (min. 95) bei KEV, +10 bei EPSS > 0.5,
//  x0.75 wenn nicht aus dem Internet erreichbar, x0.4 in Test-/Dev-Code.
//
//  Angriffspfade: Kombinationen offener Befunde werden zu einem TOXIC_COMBINATION-Befund.

const fs = require('fs');
const zlib = require('zlib');
const { normalizeFinding } = require('./schema');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';
const DAY = 24 * 60 * 60 * 1000;
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

function emptyIntel() { return { updatedAt: null, kev: new Set(), epss: new Map() }; }

function loadIntel(file) {
  try {
    const d = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { updatedAt: d.updatedAt || null, kev: new Set(d.kev || []), epss: new Map(Object.entries(d.epss || {})) };
  } catch { return emptyIntel(); }
}

const needsSync = (intel) => !intel.updatedAt || Date.now() - new Date(intel.updatedAt).getTime() > DAY;

// Laedt beide Feeds und schreibt den Cache. Fehler eines Feeds behalten den alten Stand.
async function syncIntel(file, { fetchImpl = fetch } = {}) {
  const prev = loadIntel(file);
  const out = { updatedAt: new Date().toISOString(), kev: [...prev.kev], epss: Object.fromEntries(prev.epss) };
  const notes = [];
  try {
    const r = await fetchImpl(KEV_URL, { signal: AbortSignal.timeout(30000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    out.kev = (j.vulnerabilities || []).map((v) => String(v.cveID || '').toUpperCase()).filter(Boolean);
    notes.push(`CISA KEV: ${out.kev.length} Einträge`);
  } catch (e) { notes.push('CISA KEV nicht aktualisiert: ' + e.message); }
  try {
    const r = await fetchImpl(EPSS_URL, { signal: AbortSignal.timeout(60000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const csv = zlib.gunzipSync(Buffer.from(await r.arrayBuffer())).toString('utf8');
    const epss = {};
    for (const line of csv.split('\n')) {
      const [cve, score, pct] = line.split(',');
      // Nur nennenswerte Werte speichern – haelt den Cache klein (sehr niedrige EPSS aendern nichts).
      if (/^CVE-/.test(cve) && Number(score) >= 0.005) epss[cve] = [Number(score), Number(pct)];
    }
    out.epss = epss;
    notes.push(`EPSS: ${Object.keys(epss).length} relevante CVEs`);
  } catch (e) { notes.push('EPSS nicht aktualisiert: ' + e.message); }
  fs.writeFileSync(file, JSON.stringify(out));
  return { ok: true, notes, updatedAt: out.updatedAt };
}

function cvesOf(f) {
  return [...new Set(`${f.ruleId || ''} ${f.title || ''} ${f.impact || ''}`.match(CVE_RE) || [])].map((c) => c.toUpperCase());
}

// Ergaenzt epssScore/epssPercentile/inCisaKev aus dem lokalen Cache.
function applyIntel(findings, intel) {
  if (!intel) return findings;
  return findings.map((f) => {
    const ids = cvesOf(f);
    if (!ids.length) return f;
    let best = null;
    for (const id of ids) { const e = intel.epss.get(id); if (e && (!best || e[0] > best[0])) best = e; }
    return { ...f, cves: ids, inCisaKev: ids.some((id) => intel.kev.has(id)), ...(best ? { epssScore: best[0], epssPercentile: best[1] } : {}) };
  });
}

// --- Kontext-Risiko --------------------------------------------------------
const SEV_BASE = { critical: 95, high: 80, medium: 55, low: 25, info: 5 };
function contextualRisk(f, { internetExposed = true } = {}) {
  let s = f.cvss != null ? f.cvss * 10 : SEV_BASE[f.severity] ?? 40;
  if (f.inCisaKev) s = Math.max(95, s + 15);
  if (f.epssScore > 0.5) s += 10;
  const exposed = internetExposed || (f.context || []).includes('internet-exposed') || (f.context || []).includes('request-handler');
  if (!exposed) s *= 0.75;
  if (f.devOnly) s *= 0.4;
  return Math.round(Math.max(0, Math.min(100, s)) * 10) / 10;
}

// --- Angriffswege -------------------------------------------------------------
// Mehrere einzelne Schwaechen, die zusammen einen kompletten Angriff ergeben. Jeder Teil
// beschreibt in Alltagssprache, WAS konkret gefunden wurde, und WIE man ihn behebt (`fix`,
// `effort` 1 = sehr leicht). Ein Weg gilt nur als "bestaetigt", wenn eine echte Luecke als
// Einstieg gefunden wurde – sonst ist er "moeglich" und wird schwaecher gewichtet.
const key = (f) => `${f.ruleId}@${f.location}`;
const rid = (re) => (f) => re.test(String(f.ruleId || ''));
const hostOfLoc = (loc) => { try { return new URL(String(loc).split(/\s/)[0]).hostname; } catch { return ''; } };
// Name aus dem Titel („Cookie „session“ ist …“), sonst aus der Regel-ID
const cookieName = (f) => (String(f.title || '').match(/„([^“]+)“/) || [])[1] || String(f.ruleId || '').replace(/^cookie-missing-[a-z]+-/, '') || 'Cookie';
// Nur Cookies, die nach Anmeldung/Sitzung aussehen – Tracking- und Consent-Cookies zaehlen nicht.
const SESSION_COOKIE = /sess|sid\b|^sid|auth|token|jwt|login|logon|remember|^user|account|connect\.sid|phpsessid|jsessionid|asp\.net/i;
const isSessionCookie = (f) => /^cookie-missing-httponly/.test(f.ruleId || '') && SESSION_COOKIE.test(cookieName(f));

const CHAINS = [
  {
    ruleId: 'toxic-container-escape', score: 100, possibleScore: 85, severity: 'critical', possibleSeverity: 'high',
    title: 'Angriffsweg: Vom Container auf den ganzen Server',
    entry: 'Angreifer aus dem Internet', goal: 'Ganzer Server übernommen',
    parts: [
      { test: rid(/^container-root-user$|^dockerfile-root-user$/), stage: 'Im Container Administrator', why: 'Wer im Container landet, hat dort sofort alle Rechte.', what: () => 'Der Container läuft mit Administratorrechten (root).', fix: 'Den Container mit einem normalen Benutzer starten (USER im Dockerfile bzw. user: in docker-compose).', effort: 1 },
      { test: rid(/^container-(docker-sock|privileged|cap-sys-admin)$/), stage: 'Vom Container auf den Server', why: 'Über diese Sonderrechte kommt man aus dem Container heraus auf den Server.', what: () => 'Der Container hat Sonderrechte auf den Server: Er darf Docker steuern (Docker-Socket) oder läuft „privileged“.', fix: 'Docker-Socket nicht in den Container einbinden und privileged/SYS_ADMIN entfernen.', effort: 2 },
      { test: (f) => f.category === 'SSRF' || /ssrf/i.test(f.ruleId || '') || (f.category === 'Dependencies' && ['critical', 'high'].includes(f.severity)),
        confirm: (f) => f.category === 'SSRF' || /ssrf/i.test(f.ruleId || ''),
        stage: 'Einstieg in die Anwendung', why: 'Über diese Lücke kommt ein Angreifer überhaupt erst in die Anwendung hinein.', order: 0,
        what: (items) => `Es gibt einen möglichen Einstieg von außen: ${items.map((x) => `„${x.title}“`).slice(0, 2).join(', ')}.`, fix: 'Die gefundene Lücke in der Anwendung bzw. das verwundbare Paket beheben.', effort: 3 },
    ],
    story: 'Wer über die Lücke in die Anwendung kommt, ist im Container sofort Administrator. Mit den Sonderrechten des Containers kann er von dort aus Docker steuern – und damit den ganzen Server samt allen anderen Anwendungen übernehmen.',
  },
  {
    ruleId: 'toxic-sourcemap-api', score: 98, severity: 'critical',
    title: 'Angriffsweg: Offener Quellcode verrät Zugänge',
    entry: 'Beliebiger Besucher', goal: 'Interne Zugänge benutzt',
    parts: [
      { test: rid(/^web-sourcemap-exposed$/), stage: 'Quellcode mitlesen', why: 'Der Quellcode verrät Adressen, Schnittstellen und manchmal Schlüssel.', what: () => 'Der ursprüngliche Quellcode der Webseite ist öffentlich abrufbar (SourceMap-Dateien).', fix: 'SourceMaps nicht mit ausliefern (im Build abschalten oder *.map auf dem Server sperren).', effort: 1 },
      { test: (f) => /^api-(bola|unauthenticated)/.test(f.ruleId || '') || (f.category === 'Secrets' && f.severity !== 'info'),
        stage: 'Ungeschützten Zugang nutzen', why: 'Was im Code steht, lässt sich direkt ausprobieren, weil der Zugang nicht abgesichert ist.',
        what: (items) => `Darin bzw. dahinter liegt ein Zugang, der nicht geschützt ist: ${items.map((x) => `„${x.title}“`).slice(0, 2).join(', ')}.`, fix: 'Den Zugang absichern: Schlüssel widerrufen und neu erzeugen bzw. die API-Route mit Rechteprüfung versehen.', effort: 2 },
    ],
    story: 'Aus dem offenen Quellcode liest ein Angreifer in Minuten alle internen Adressen und Schlüssel heraus – und benutzt den ungeschützten Zugang direkt.',
  },
  {
    ruleId: 'toxic-session-hijack', score: 92, possibleScore: 55, severity: 'high', possibleSeverity: 'medium',
    title: 'Angriffsweg: Anmeldungen von Besuchern könnten übernommen werden',
    entry: 'Eingeschleuster Code (z. B. über ein Eingabefeld oder ein manipuliertes Fremdskript)', goal: 'Konto des Besuchers übernommen',
    parts: [
      { test: (f) => /^(missing-csp-header|unsafe-csp-directive|csp-wildcard-script-src)$/.test(f.ruleId || '') || f.category === 'XSS',
        confirm: (f) => f.category === 'XSS',
        stage: 'Fremder Code läuft in der Seite', why: 'Ohne Content-Security-Policy hält der Browser eingeschleusten Code nicht auf – er läuft mit denselben Rechten wie die Seite selbst.',
        what: (items) => (items.some((x) => x.category === 'XSS')
          ? `Über eine gefundene Lücke lässt sich fremder Code in die Seite einschleusen: „${items.find((x) => x.category === 'XSS').title}“.`
          : 'Die Seite legt nicht fest, welche Skripte darauf laufen dürfen (keine wirksame Content-Security-Policy). Eingeschleuster Code würde also nicht blockiert.'),
        fix: 'Eine Content-Security-Policy setzen, die nur eigene Skripte erlaubt – zuerst im Beobachtungsmodus testen.', effort: 2 },
      { test: (f) => /^dom-token-in-storage$/.test(f.ruleId || '') || isSessionCookie(f),
        stage: 'Anmeldung auslesen', why: 'Der laufende Code kann das Anmelde-Cookie bzw. -Token lesen und an den Angreifer schicken.',
        what: (items) => {
          const c = items.filter(isSessionCookie).map(cookieName);
          return c.length
            ? `Das Anmelde-Cookie ${c.slice(0, 2).map((n) => `„${n}“`).join(' und ')} kann von Skripten auf der Seite gelesen werden (Schutz „HttpOnly“ fehlt).`
            : 'Das Anmelde-Token liegt im Browser-Speicher, den jedes Skript auf der Seite lesen kann.';
        },
        fix: 'Beim Anmelde-Cookie das Attribut HttpOnly setzen bzw. das Token aus dem Browser-Speicher in ein HttpOnly-Cookie verlegen – meist eine Zeile Konfiguration.', effort: 1 },
    ],
    story: 'Schafft es ein Angreifer, eigenen Code in die Seite zu bringen (z. B. über ein Eingabefeld oder ein manipuliertes Fremdskript), kann dieser Code die Anmeldung eines Besuchers auslesen. Der Angreifer ist dann als dieser Besucher eingeloggt – ohne dessen Passwort zu kennen.',
    possibleNote: 'Eine konkrete Einschleuse-Lücke wurde bisher nicht gefunden. Der Weg ist also möglich, aber nicht bewiesen.',
  },
  {
    ruleId: 'toxic-db-breach', score: 99, severity: 'critical',
    title: 'Angriffsweg: Datenbank direkt aus dem Internet erreichbar',
    entry: 'Automatischer Scanner im Internet', goal: 'Daten ausgelesen, verschlüsselt oder gelöscht',
    parts: [
      { test: (f) => /^container-db-port-public$/.test(f.ruleId || '') || (f.source === 'nmap' && /PostgreSQL|MySQL|Redis|MongoDB|Elasticsearch/i.test(f.title || '')),
        stage: 'Datenbank lauscht nach außen', why: 'Die Datenbank wartet auf Verbindungen aus jedem Netz.', what: () => 'Die Datenbank nimmt Verbindungen von allen Netzwerken an, nicht nur vom eigenen Server.', fix: 'Die Datenbank nur an 127.0.0.1 bzw. ein internes Netz binden.', effort: 1 },
      { test: rid(/^host-firewall-inactive$/), stage: 'Keine Firewall dazwischen', why: 'Nichts blockt die Verbindung ab, bevor sie die Datenbank erreicht.', what: () => 'Auf dem Server ist keine Firewall aktiv, die solche Verbindungen abblockt.', fix: 'Firewall einschalten und nur SSH, HTTP und HTTPS freigeben.', effort: 1 },
    ],
    story: 'Automatische Scanner durchsuchen das Internet ständig nach offenen Datenbanken. Ein solcher Server wird meist innerhalb von Stunden gefunden und dann ausgelesen, verschlüsselt oder gelöscht.',
  },
];

function correlate(findings) {
  const open = findings.filter((f) => !f.suppressed && f.status !== 'RESOLVED' && !/^toxic-/.test(f.ruleId || ''));
  const out = [];
  for (const ch of CHAINS) {
    const matched = ch.parts.map((p) => ({ p, items: open.filter(p.test) }));
    if (matched.some((m) => !m.items.length)) continue;
    // Bestaetigt nur, wenn jeder Teil mit "confirm" auch eine echte Luecke enthaelt.
    const confirmed = matched.every((m) => !m.p.confirm || m.items.some(m.p.confirm));
    const linked = matched.flatMap((m) => m.items.slice(0, 2));
    const hosts = [...new Set(linked.map((x) => hostOfLoc(x.location)).filter(Boolean))];
    const where = hosts.length === 1 ? ` auf ${hosts[0]}` : '';
    const n = matched.length === 2 ? 'Zwei' : matched.length === 3 ? 'Drei' : String(matched.length);
    const steps = [...matched].sort((a, b) => a.p.effort - b.p.effort)
      .map((m, i) => `${i === 0 ? 'Am schnellsten: ' : ''}${m.p.fix} (Befund: „${m.items[0].title}“)`);
    const f = normalizeFinding({
      ruleId: ch.ruleId,
      severity: confirmed ? ch.severity : (ch.possibleSeverity || ch.severity),
      category: 'Other',
      title: confirmed ? ch.title : ch.title.replace(/^Angriffsweg:/, 'Möglicher Angriffsweg:'),
      location: [...new Set(linked.map((x) => x.location))].slice(0, 3).join(' · ').slice(0, 290) || 'mehrere Stellen',
      description: `${n} Schwächen${where} hängen zusammen:\n${matched.map((m, i) => `${i + 1}. ${m.p.what(m.items)}`).join('\n')}`,
      impact: ch.story + (confirmed || !ch.possibleNote ? '' : ` ${ch.possibleNote}`),
      explanation: 'Einzeln wirken diese Schwächen oft harmlos. Zusammen ergeben sie einen vollständigen Weg für einen Angriff. Schon eine einzige Behebung unterbricht ihn – fang mit der einfachsten an.',
      steps,
      confidence: confirmed ? 'high' : 'medium', sourceModule: 'attack-path-correlator', linkedKeys: linked.map(key),
    }, 'correlator');
    // Ablauf fuer die Grafik: Einstieg -> Schritte (in Angriffsreihenfolge) -> Ziel; je Schritt die Befunde und die Unterbrechung
    const minEffort = Math.min(...matched.map((m) => m.p.effort));
    f.chain = {
      entry: ch.entry || '', goal: ch.goal || '', confirmed,
      steps: [...matched].sort((a, b) => (a.p.order ?? 1) - (b.p.order ?? 1)).map((m) => ({
        stage: m.p.stage || '', why: m.p.why || '', what: m.p.what(m.items), fix: m.p.fix, effort: m.p.effort, easiest: m.p.effort === minEffort,
        proven: !m.p.confirm || m.items.some(m.p.confirm), keys: m.items.slice(0, 2).map(key),
      })),
    };
    f.contextualRiskScore = confirmed ? ch.score : (ch.possibleScore || ch.score);
    f.category = 'AttackPath'; // eigene Kategorie nur fuer Angriffswege (nicht Teil der KI-Kategorien)
    f.toxic = true;
    out.push(f);
  }
  return out;
}

module.exports = { loadIntel, syncIntel, needsSync, applyIntel, contextualRisk, correlate, cvesOf, findingKey: key, CHAINS, emptyIntel };
