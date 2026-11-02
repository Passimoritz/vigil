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

// --- Angriffspfade -----------------------------------------------------------
const key = (f) => `${f.ruleId}@${f.location}`;
const rid = (re) => (f) => re.test(String(f.ruleId || ''));
const CHAINS = [
  {
    ruleId: 'toxic-container-escape', score: 100, severity: 'critical',
    title: 'Angriffspfad: Container-Ausbruch bis zur Host-Übernahme',
    parts: [
      ['Container läuft als root', rid(/^container-root-user$|^dockerfile-root-user$/)],
      ['Docker-Socket, privileged oder SYS_ADMIN', rid(/^container-(docker-sock|privileged|cap-sys-admin)$/)],
      ['Ausnutzbare Web-/API-Lücke oder SSRF', (f) => f.category === 'SSRF' || /ssrf/i.test(f.ruleId || '') || (f.category === 'Dependencies' && ['critical', 'high'].includes(f.severity))],
    ],
    story: 'Eine Lücke in der Anwendung bringt den Angreifer in den Container. Dort ist er root und erreicht über Socket bzw. Sonderrechte den Docker-Daemon – damit gehört ihm der ganze Server.',
  },
  {
    ruleId: 'toxic-sourcemap-api', score: 98, severity: 'critical',
    title: 'Angriffspfad: Quellcode-Leak führt zu interner API',
    parts: [
      ['Öffentliche SourceMap', rid(/^web-sourcemap-exposed$/)],
      ['Ungeschützte API-Route oder Client-Secret', (f) => /^api-(bola|unauthenticated)/.test(f.ruleId || '') || (f.category === 'Secrets' && f.severity !== 'info')],
    ],
    story: 'Aus der SourceMap liest der Angreifer den Original-Quellcode mit allen API-Pfaden und Schlüsseln – und nutzt die ungeschützte Route bzw. das Secret direkt.',
  },
  {
    ruleId: 'toxic-session-hijack', score: 92, severity: 'high',
    title: 'Angriffspfad: Sitzungsübernahme über XSS',
    parts: [
      ['Fehlende/unsichere CSP oder XSS-Senke', (f) => /^(missing-csp-header|unsafe-csp-directive|csp-wildcard-script-src)$/.test(f.ruleId || '') || f.category === 'XSS'],
      ['Token im localStorage oder Cookie ohne HttpOnly', rid(/^dom-token-in-storage$|^cookie-missing-httponly/)],
    ],
    story: 'Ohne wirksame CSP läuft eingeschleustes Skript ungehindert – und liest das Sitzungs-Token direkt aus dem Browser-Speicher bzw. dem nicht geschützten Cookie.',
  },
  {
    ruleId: 'toxic-db-breach', score: 99, severity: 'critical',
    title: 'Angriffspfad: Datenbank direkt aus dem Internet erreichbar',
    parts: [
      ['Datenbank-Port auf allen Schnittstellen', (f) => /^container-db-port-public$/.test(f.ruleId || '') || (f.source === 'nmap' && /PostgreSQL|MySQL|Redis|MongoDB|Elasticsearch/i.test(f.title || ''))],
      ['Keine aktive Host-Firewall', rid(/^host-firewall-inactive$/)],
    ],
    story: 'Die Datenbank lauscht öffentlich und keine Firewall hält Anfragen auf – automatisierte Scanner finden solche Server innerhalb von Stunden.',
  },
];

function correlate(findings) {
  const open = findings.filter((f) => !f.suppressed && f.status !== 'RESOLVED' && !/^toxic-/.test(f.ruleId || ''));
  const out = [];
  for (const ch of CHAINS) {
    const matched = ch.parts.map(([label, test]) => ({ label, items: open.filter(test) }));
    if (matched.some((m) => !m.items.length)) continue;
    const linked = matched.flatMap((m) => m.items.slice(0, 2));
    const f = normalizeFinding({
      ruleId: ch.ruleId, severity: ch.severity, category: 'Other', title: ch.title,
      location: [...new Set(linked.map((x) => x.location))].slice(0, 3).join(' · ').slice(0, 290) || 'mehrere Stellen',
      description: `${ch.story}\n\nKette: ${matched.map((m) => `${m.label} (${m.items.length}×)`).join(' → ')}`,
      remediation: 'Ein Glied der Kette brechen genügt – am besten das am einfachsten zu behebende.',
      confidence: 'high', sourceModule: 'attack-path-correlator', linkedKeys: linked.map(key),
    }, 'correlator');
    f.contextualRiskScore = ch.score;
    f.toxic = true;
    out.push(f);
  }
  return out;
}

module.exports = { loadIntel, syncIntel, needsSync, applyIntel, contextualRisk, correlate, cvesOf, findingKey: key, CHAINS, emptyIntel };
