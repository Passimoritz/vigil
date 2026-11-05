'use strict';

// Netz-Pruefungen rund um eine Webseite – ausschliesslich lesend:
//
//  mail-extended   MTA-STS (DNS + Richtliniendatei), TLS-RPT, BIMI
//  dns-dnssec      DNSSEC ueber eine DNS-over-HTTPS-Abfrage (dns.google)
//  domain-expiry   Ablauf der Domain ueber RDAP (rdap.org), Warnung bei 30/14/3 Tagen
//  tls-deep        Zertifikatskette, Zwischenzertifikate, OCSP-Stapling, HTTP/3 (alt-svc)
//  web-subdomains  Subdomains aus CT-Logs (crt.sh) und DNS; geprueft wird nur, was freigegeben ist
//  internetdb      Shodan InternetDB: offene Ports / bekannte CVEs laut Shodan, ohne selbst zu scannen
//  typo-domains    Tippfehler-/Verwechslungs-Domains, nur per DNS (kein Kontakt zu diesen Servern)
//
// Fremde Dienste werden nur ueber extFetch angesprochen – und nur die Hosts in OUTBOUND_HOSTS.

const tls = require('tls');
const net = require('net');
const { normalizeFinding } = require('../schema');
const { isInternalHost, isAllowlisted } = require('../scope');

const UA = 'Vigil-Audit/0.2 (+authorized,passive)';
const TIMEOUT = 12000;
const DAY = 86400000;

// Erlaubte ausgehende Hosts fuer Abfragen bei Dritten (nie das Ziel selbst).
const OUTBOUND_HOSTS = ['crt.sh', 'internetdb.shodan.io', 'rdap.org', 'dns.google'];

const W = (m, o) => normalizeFinding({ confidence: 'high', ...o, sourceModule: m }, m);

function extFetch(ctx, url, { signal } = {}) {
  const host = new URL(url).hostname;
  if (!OUTBOUND_HOSTS.includes(host)) return Promise.reject(new Error(`Ausgehende Verbindung zu ${host} ist nicht erlaubt.`));
  const t = AbortSignal.timeout(TIMEOUT);
  return (ctx.fetch || fetch)(url, { headers: { 'User-Agent': UA, Accept: 'application/json, application/rdap+json' }, redirect: 'follow', signal: signal ? AbortSignal.any([t, signal]) : t });
}

// DNS-Helfer: "gibt es nicht" ist ein Ergebnis, alles andere ein Fehler (dann gilt die Pruefung als nicht gelaufen).
const NX = new Set(['ENOTFOUND', 'ENODATA', 'ENONAME', 'NXDOMAIN', 'ESERVFAIL_NX']);
async function dnsTry(fn) {
  try { return { ok: true, value: await fn() }; } catch (e) { return NX.has(e.code) ? { ok: true, value: [] } : { ok: false, error: e.code || e.message }; }
}
const resolver = (ctx) => ctx.dns || require('dns').promises;
async function txt(ctx, name) { const r = await dnsTry(() => resolver(ctx).resolveTxt(name)); return r.ok ? r.value.map((x) => (Array.isArray(x) ? x.join('') : String(x))) : []; }

// Wenige parallele DNS-Abfragen, damit kein Resolver geflutet wird.
async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

const daysUntil = (d) => Math.floor((new Date(d).getTime() - Date.now()) / DAY);
const fmtDate = (d) => new Date(d).toISOString().slice(0, 10);
// 30/14/3 Tage: mittel / hoch / kritisch
const expirySeverity = (days) => (days < 3 ? 'critical' : days < 14 ? 'high' : days < 30 ? 'medium' : null);

// --- Mail: MTA-STS, TLS-RPT, BIMI -----------------------------------------------------------
function parseStsPolicy(text) {
  const p = { mx: [] };
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/^\s*([a-z_]+)\s*:\s*(.+?)\s*$/i);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === 'mx') p.mx.push(m[2].toLowerCase()); else p[k] = m[2];
  }
  return p;
}
const mxMatches = (pattern, host) => (pattern.startsWith('*.') ? host.endsWith(pattern.slice(1)) && host.split('.').length === pattern.split('.').length : host === pattern);

// opts.httpGet(url) -> { ok, status, body } (gedrosselt, vom Aufrufer); opts.allowFetch(host) -> bool
async function mailExtended(domain, ctx = {}, { httpGet, allowFetch = () => false } = {}) {
  const M = 'mail-extended';
  const out = [], notes = [];
  const loc = `DNS ${domain}`;
  const mxr = await dnsTry(() => resolver(ctx).resolveMx(domain));
  if (!mxr.ok) return { findings: out, notes: [`Mail-Prüfung für ${domain}: DNS-Abfrage fehlgeschlagen (${mxr.error}).`], ran: false };
  const mx = mxr.value.map((r) => String(r.exchange || '').toLowerCase().replace(/\.$/, '')).filter(Boolean);
  if (!mx.length) return { findings: out, notes: [`Mail-Prüfung: ${domain} empfängt keine Mails (kein MX-Eintrag) – MTA-STS, TLS-RPT und BIMI übersprungen.`], ran: true };

  // MTA-STS
  const sts = (await txt(ctx, '_mta-sts.' + domain)).find((t) => /^v=STSv1/i.test(t));
  if (!sts) out.push(W(M, { ruleId: 'mail-mtasts-missing', severity: 'low', category: 'Transport', title: 'Mails an die Domain können unverschlüsselt umgeleitet werden (MTA-STS fehlt)', location: `DNS _mta-sts.${domain}`, description: 'Die Domain empfängt Mails, verlangt von sendenden Servern aber keine verschlüsselte Zustellung (kein MTA-STS).', impact: 'Ein Angreifer auf dem Übertragungsweg kann die Verschlüsselung zwischen Mailservern unterdrücken und eingehende Mails mitlesen.', remediation: 'MTA-STS einrichten: TXT-Eintrag _mta-sts mit "v=STSv1; id=…" und die Datei https://mta-sts.<domain>/.well-known/mta-sts.txt mit "mode: enforce".', snippets: { dns: `_mta-sts.${domain}.  TXT  "v=STSv1; id=20260101000000Z"\n_smtp._tls.${domain}.  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@${domain}"`, policy: `# https://mta-sts.${domain}/.well-known/mta-sts.txt\nversion: STSv1\nmode: enforce\n${mx.map((h) => 'mx: ' + h).join('\n')}\nmax_age: 604800` } }));
  else {
    const host = 'mta-sts.' + domain;
    if (httpGet && allowFetch(host)) {
      const r = await httpGet(`https://${host}/.well-known/mta-sts.txt`);
      const p = r && r.ok && r.status === 200 ? parseStsPolicy(r.body) : null;
      if (!p || !/^STSv1$/i.test(p.version || '')) out.push(W(M, { ruleId: 'mail-mtasts-policy-invalid', severity: 'medium', category: 'Transport', title: 'MTA-STS ist angekündigt, die Richtliniendatei fehlt aber oder ist ungültig', location: `https://${host}/.well-known/mta-sts.txt`, evidence: r && r.ok ? `HTTP ${r.status}` : String((r && r.error) || 'nicht erreichbar'), description: 'Im DNS steht ein MTA-STS-Eintrag, aber unter https://mta-sts.<domain>/.well-known/mta-sts.txt liegt keine gültige Richtlinie.', impact: 'Sendende Mailserver können die Richtlinie nicht laden – der Schutz greift nicht, und manche Server stellen sogar gar nicht mehr zu.', remediation: 'Die Datei mit "version: STSv1", "mode", allen "mx"-Einträgen und "max_age" über HTTPS mit gültigem Zertifikat bereitstellen.' }));
      else {
        const mode = String(p.mode || '').toLowerCase();
        if (mode === 'testing') out.push(W(M, { ruleId: 'mail-mtasts-testing', severity: 'info', category: 'Transport', title: 'MTA-STS läuft nur im Testmodus', location: `https://${host}/.well-known/mta-sts.txt`, evidence: 'mode: testing', description: 'Die Richtlinie meldet Probleme nur, erzwingt die Verschlüsselung aber noch nicht.', remediation: 'Nach einer Beobachtungsphase (TLS-RPT-Berichte) auf "mode: enforce" umstellen.' }));
        else if (mode !== 'enforce') out.push(W(M, { ruleId: 'mail-mtasts-mode-none', severity: 'low', category: 'Transport', title: 'MTA-STS ist abgeschaltet (mode: none)', location: `https://${host}/.well-known/mta-sts.txt`, evidence: `mode: ${p.mode || '–'}`, description: 'Die Richtlinie ist vorhanden, verlangt aber keine Verschlüsselung.', remediation: 'Auf "mode: enforce" umstellen.' }));
        const unmatched = mx.filter((h) => !p.mx.some((pat) => mxMatches(pat, h)));
        if (unmatched.length) out.push(W(M, { ruleId: 'mail-mtasts-mx-mismatch', severity: 'medium', category: 'Transport', title: `MTA-STS-Richtlinie passt nicht zu den Mailservern (${unmatched.join(', ')})`, location: `https://${host}/.well-known/mta-sts.txt`, evidence: `MX: ${mx.join(', ')} · Richtlinie: ${p.mx.join(', ') || '–'}`, description: 'Mindestens ein Mailserver aus dem MX-Eintrag steht nicht in der MTA-STS-Richtlinie.', impact: 'Bei "mode: enforce" verweigern sendende Server die Zustellung an diesen Mailserver – Mails gehen verloren.', remediation: 'Alle MX-Hosts als "mx:"-Zeilen in die Richtlinie aufnehmen und die id im TXT-Eintrag erhöhen.' }));
      }
    } else notes.push(`MTA-STS-Richtlinie von ${host} nicht geladen: Host ist nicht freigegeben.`);
  }
  // TLS-RPT
  if (!(await txt(ctx, '_smtp._tls.' + domain)).some((t) => /^v=TLSRPTv1/i.test(t))) out.push(W(M, { ruleId: 'mail-tlsrpt-missing', severity: 'info', category: 'Transport', title: 'Keine Berichte über Verschlüsselungsprobleme beim Mailempfang (TLS-RPT fehlt)', location: `DNS _smtp._tls.${domain}`, description: 'Sendende Mailserver können dir nicht melden, wenn die verschlüsselte Zustellung scheitert.', remediation: `TXT-Eintrag anlegen: _smtp._tls.${domain} "v=TLSRPTv1; rua=mailto:tls-reports@${domain}".` }));
  // BIMI (setzt eine strenge DMARC-Regel voraus)
  const dmarc = (await txt(ctx, '_dmarc.' + domain)).find((t) => /^v=DMARC1/i.test(t)) || '';
  const enforced = /\bp=(quarantine|reject)\b/i.test(dmarc);
  const bimi = (await txt(ctx, 'default._bimi.' + domain)).find((t) => /^v=BIMI1/i.test(t));
  if (!bimi && enforced) out.push(W(M, { ruleId: 'mail-bimi-missing', severity: 'info', category: 'Config', title: 'Kein BIMI-Eintrag (Markenlogo im Posteingang)', location: `DNS default._bimi.${domain}`, description: 'DMARC ist streng genug für BIMI, es ist aber kein Logo hinterlegt. Postfächer wie Gmail zeigen dann kein geprüftes Logo neben deinen Mails.', remediation: `TXT-Eintrag default._bimi.${domain} "v=BIMI1; l=https://${domain}/logo.svg" anlegen (SVG Tiny PS).` }));
  if (bimi && !enforced) out.push(W(M, { ruleId: 'mail-bimi-without-dmarc', severity: 'info', category: 'Config', title: 'BIMI ist eingetragen, wirkt aber ohne strenge DMARC-Regel nicht', location: `DNS default._bimi.${domain}`, evidence: bimi, description: 'BIMI-Logos werden nur angezeigt, wenn DMARC auf p=quarantine oder p=reject steht.', remediation: 'DMARC auf p=quarantine oder p=reject verschärfen.' }));
  return { findings: out, notes, ran: true };
}

// --- DNSSEC (DNS-over-HTTPS) -------------------------------------------------------------
async function dnssec(domain, ctx = {}, { signal } = {}) {
  const M = 'dns-dnssec';
  const q = async (type) => { const r = await extFetch(ctx, `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`, { signal }); if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); };
  try {
    const ds = await q('DS');
    const hasDs = (ds.Answer || []).some((a) => a.type === 43);
    if (!hasDs) return { ran: true, findings: [W(M, { ruleId: 'dns-dnssec-missing', severity: 'low', category: 'Config', title: 'DNS-Antworten der Domain sind nicht signiert (kein DNSSEC)', location: `DNS ${domain}`, description: 'Für die Domain ist kein DNSSEC eingerichtet (kein DS-Eintrag in der übergeordneten Zone).', impact: 'Gefälschte DNS-Antworten (z. B. durch Cache-Poisoning) lassen sich von Resolvern nicht erkennen – Besucher und Mails können umgeleitet werden.', remediation: 'DNSSEC beim DNS-Anbieter aktivieren und den DS-Eintrag beim Registrar hinterlegen (bei vielen Anbietern ein Klick).' })] };
    const soa = await q('SOA');
    if (soa.Status === 2) return { ran: true, findings: [W(M, { ruleId: 'dns-dnssec-broken', severity: 'high', category: 'Config', title: 'DNSSEC ist fehlerhaft – prüfende Resolver erreichen die Domain nicht', location: `DNS ${domain}`, evidence: 'DS vorhanden, SOA-Abfrage: SERVFAIL', description: 'Es gibt einen DS-Eintrag, die Signaturen der Zone lassen sich aber nicht prüfen. Validierende Resolver liefern dann gar keine Antwort.', impact: 'Für viele Nutzer (z. B. mit Google- oder Cloudflare-DNS) ist die Domain samt Mail nicht erreichbar.', remediation: 'Schlüssel und DS-Eintrag beim DNS-Anbieter und Registrar abgleichen (z. B. mit dnsviz.net).' })] };
    return { ran: true, findings: [] };
  } catch (e) { return { ran: false, findings: [], notes: [`DNSSEC-Prüfung für ${domain} fehlgeschlagen: ${e.message}`] }; }
}

// --- Ablauf der Domain (RDAP) ---------------------------------------------------------------
async function domainExpiry(domain, ctx = {}, { signal } = {}) {
  const M = 'domain-expiry';
  try {
    const r = await extFetch(ctx, `https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal });
    if (r.status === 404) return { ran: true, findings: [], notes: [`Domain-Ablauf: ${domain} ist bei RDAP nicht verzeichnet.`] };
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    const ev = (j.events || []).find((e) => /expiration/i.test(e.eventAction || ''));
    if (!ev || !ev.eventDate) return { ran: true, findings: [], notes: [`Domain-Ablauf: Die Registrierungsstelle von ${domain} veröffentlicht kein Ablaufdatum.`] };
    const days = daysUntil(ev.eventDate);
    const sev = days < 0 ? 'critical' : expirySeverity(days);
    if (!sev) return { ran: true, findings: [] };
    return { ran: true, findings: [W(M, { ruleId: days < 0 ? 'domain-expired' : 'domain-expiring', severity: sev, category: 'Config', title: days < 0 ? `Domain ${domain} ist abgelaufen` : `Domain ${domain} läuft in ${days} ${days === 1 ? 'Tag' : 'Tagen'} ab`, location: `DNS ${domain}`, evidence: `RDAP expiration: ${ev.eventDate}`, description: `Laut Registrierungsdaten (RDAP) ist die Domain bis ${fmtDate(ev.eventDate)} registriert.`, impact: 'Läuft die Domain ab, sind Webseite und Mail weg – und jeder kann die Domain neu registrieren und Mails an deine Adressen empfangen.', remediation: 'Domain beim Registrar verlängern und die automatische Verlängerung einschalten.' })] };
  } catch (e) { return { ran: false, findings: [], notes: [`Domain-Ablauf für ${domain} nicht abrufbar: ${e.message}`] }; }
}

// --- TLS im Detail ---------------------------------------------------------------------------------
function tlsProbe(host, { port = 443, timeout = 10000 } = {}) {
  return new Promise((resolve) => {
    let ocsp = null;
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const s = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, requestOCSP: true, timeout }, () => {
      try {
        const leaf = s.getPeerCertificate(true);
        const chain = [];
        const seen = new Set();
        for (let c = leaf; c && c.raw && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
          seen.add(c.fingerprint256);
          const ia = c.infoAccess || {};
          chain.push({ subject: (c.subject && c.subject.CN) || '', issuer: (c.issuer && c.issuer.CN) || '', validTo: c.valid_to, selfIssued: !!(c.subject && c.issuer && JSON.stringify(c.subject) === JSON.stringify(c.issuer)), ocspUrl: (ia['OCSP - URI'] || [])[0] || '' });
        }
        const err = s.authorizationError;
        finish({ ok: true, authorized: s.authorized, authError: err ? String(err.code || err) : '', protocol: s.getProtocol(), chain, ocspStapled: !!(ocsp && ocsp.length) });
      } catch (e) { finish({ ok: false, error: e.message }); }
      s.end();
    });
    s.on('OCSPResponse', (r) => { ocsp = r; });
    s.on('error', (e) => finish({ ok: false, error: e.message }));
    s.on('timeout', () => { s.destroy(); finish({ ok: false, error: 'TLS-Timeout' }); });
  });
}

const CHAIN_ERRORS = /UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT|unable to verify the first certificate|unable to get local issuer/i;
// info: Ergebnis von tlsProbe; altSvc: Header der Startseite
function tlsDeepFindings(origin, info, altSvc) {
  const M = 'tls-deep';
  const out = [];
  if (!info || !info.ok) return out;
  if (!info.authorized && CHAIN_ERRORS.test(info.authError)) out.push(W(M, { ruleId: 'tls-chain-incomplete', severity: 'medium', category: 'Transport', title: 'Zertifikatskette unvollständig (Zwischenzertifikat fehlt)', location: origin, evidence: info.authError, description: 'Der Server schickt nur sein eigenes Zertifikat, nicht aber das Zwischenzertifikat der Zertifizierungsstelle.', impact: 'Desktop-Browser gleichen das oft aus, viele Apps, Mail-Programme, Android-Geräte und Schnittstellen brechen die Verbindung aber mit einem Zertifikatsfehler ab.', remediation: 'Am Webserver die vollständige Kette ausliefern (z. B. fullchain.pem statt cert.pem).' }));
  for (const c of (info.chain || []).slice(1)) {
    if (c.selfIssued || !c.validTo) continue; // Wurzelzertifikate liegen beim Browser, nicht beim Server
    const days = daysUntil(c.validTo);
    if (days < 0) out.push(W(M, { ruleId: 'tls-intermediate-expired', severity: 'high', category: 'Transport', title: `Zwischenzertifikat abgelaufen (${c.subject || c.issuer})`, location: origin, evidence: `valid_to: ${c.validTo}`, description: `Ein Zwischenzertifikat in der ausgelieferten Kette war nur bis ${fmtDate(c.validTo)} gültig.`, impact: 'Je nach Gerät schlägt die Prüfung des Zertifikats fehl und die Seite wird blockiert.', remediation: 'Aktuelle Zertifikatskette der Zertifizierungsstelle einspielen.' }));
    else if (days < 30) out.push(W(M, { ruleId: 'tls-intermediate-expiring', severity: expirySeverity(days), category: 'Transport', title: `Zwischenzertifikat läuft in ${days} Tagen ab (${c.subject || c.issuer})`, location: origin, evidence: `valid_to: ${c.validTo}`, description: `Ein Zwischenzertifikat in der ausgelieferten Kette ist nur bis ${fmtDate(c.validTo)} gültig.`, impact: 'Danach scheitert die Zertifikatsprüfung auf manchen Geräten, obwohl das eigene Zertifikat noch gilt.', remediation: 'Aktuelle Zertifikatskette der Zertifizierungsstelle einspielen.' }));
  }
  const leaf = (info.chain || [])[0];
  if (leaf && leaf.ocspUrl && !info.ocspStapled) out.push(W(M, { ruleId: 'tls-no-ocsp-stapling', severity: 'info', category: 'Transport', title: 'OCSP-Stapling ist nicht aktiv', location: origin, description: 'Das Zertifikat nennt einen OCSP-Dienst, der Server liefert die Sperrauskunft aber nicht selbst mit aus.', impact: 'Gering: Browser fragen die Zertifizierungsstelle selbst – das kostet Ladezeit und verrät ihr, wer die Seite besucht.', remediation: 'OCSP-Stapling einschalten (nginx: "ssl_stapling on; ssl_stapling_verify on;").' }));
  if (!/\bh3\b|h3-\d+/i.test(String(altSvc || ''))) out.push(W(M, { ruleId: 'http3-not-advertised', severity: 'info', category: 'Transport', title: 'HTTP/3 wird nicht angeboten', location: origin, description: 'Der Server kündigt kein HTTP/3 an (kein "h3" im Alt-Svc-Header).', impact: 'Kein Sicherheitsproblem: HTTP/3 lädt vor allem in Mobilnetzen schneller.', remediation: 'HTTP/3 (QUIC) am Webserver oder CDN aktivieren, falls verfügbar.' }));
  return out;
}

// Ablauf eines Zertifikats (fuer bekannte Subdomains)
function certExpiryFinding(host, info) {
  const leaf = info && info.ok && (info.chain || [])[0];
  if (!leaf || !leaf.validTo) return [];
  const days = daysUntil(leaf.validTo);
  const loc = `https://${host}/`;
  if (days < 0) return [W('web-subdomains', { ruleId: 'tls-cert-expired', severity: 'high', category: 'Transport', title: `Sicherheitszertifikat von ${host} ist abgelaufen`, location: loc, evidence: `valid_to: ${leaf.validTo}`, description: `Das HTTPS-Zertifikat von ${host} war nur bis ${fmtDate(leaf.validTo)} gültig.`, remediation: 'Zertifikat erneuern und die Erneuerung automatisieren.' })];
  const sev = expirySeverity(days);
  if (!sev) return [];
  return [W('web-subdomains', { ruleId: 'tls-cert-expiring', severity: sev, category: 'Transport', title: `Sicherheitszertifikat von ${host} läuft in ${days} ${days === 1 ? 'Tag' : 'Tagen'} ab`, location: loc, evidence: `valid_to: ${leaf.validTo}`, description: `Das HTTPS-Zertifikat von ${host} ist nur bis ${fmtDate(leaf.validTo)} gültig.`, remediation: 'Zertifikat jetzt erneuern und die Erneuerung automatisieren (z. B. Let’s Encrypt).' })];
}

// --- Subdomains --------------------------------------------------------------------------------
const COMMON_SUBS = ['www', 'mail', 'webmail', 'smtp', 'api', 'app', 'dev', 'test', 'staging', 'stage', 'beta', 'admin', 'portal', 'shop', 'blog', 'cdn', 'vpn', 'remote', 'git', 'gitlab', 'jenkins', 'ci', 'intranet', 'cloud', 'status', 'docs', 'm'];
async function exists(ctx, name) {
  const d = resolver(ctx);
  for (const fn of [() => d.resolve4(name), () => d.resolve6(name), () => d.resolveCname(name)]) {
    const r = await dnsTry(fn);
    if (r.ok && r.value.length) return true;
  }
  return false;
}

// opts: { host, deep, allowlist, crtsh(domain) -> [names], probe(host) -> tlsProbe-Ergebnis }
async function subdomains(domain, ctx = {}, { host, deep = false, allowlist = [], crtsh, probe = tlsProbe, signal } = {}) {
  const M = 'web-subdomains';
  const out = [], notes = [];
  const fromCt = deep && crtsh ? await crtsh(domain, signal).catch(() => []) : [];
  const fromDns = (await pool(COMMON_SUBS.map((s) => `${s}.${domain}`), 5, async (n) => ((await exists(ctx, n)) ? n : null))).filter(Boolean);
  const all = [...new Set([...fromCt, ...fromDns])].filter((n) => n !== host && n !== domain).slice(0, 60);
  if (!all.length) return { findings: out, notes: [`Subdomains: für ${domain} keine weiteren gefunden.`], ran: true };
  const covered = all.filter((n) => isAllowlisted(n, allowlist));
  const suggest = all.filter((n) => !covered.includes(n));
  for (const n of covered.slice(0, 10)) {
    if (signal && signal.aborted) break;
    const info = await probe(n);
    if (!info || !info.ok) continue;
    out.push(...certExpiryFinding(n, info));
    if (!info.authorized && info.authError) out.push(W(M, { ruleId: 'subdomain-cert-untrusted', severity: 'medium', category: 'Transport', title: `Zertifikat von ${n} wird nicht anerkannt`, location: `https://${n}/`, evidence: info.authError, description: `Browser vertrauen dem HTTPS-Zertifikat der Subdomain ${n} nicht (Fehler: ${info.authError}).`, remediation: 'Gültiges Zertifikat mit passendem Namen und vollständiger Kette einrichten.' }));
  }
  if (covered.length) notes.push(`Subdomains: ${covered.length} freigegebene geprüft (Zertifikat), ${suggest.length} weitere nur aufgelistet.`);
  if (suggest.length) out.push(W(M, { ruleId: 'subdomains-not-allowed', severity: 'info', category: 'Config', confidence: 'medium', title: `${suggest.length} weitere Subdomains gefunden, die nicht freigegeben sind`, location: `DNS ${domain}`, evidence: suggest.slice(0, 20).join(', '), description: `Aus Zertifikats-Logs und DNS sind diese Subdomains bekannt: ${suggest.slice(0, 20).join(', ')}${suggest.length > 20 ? ' …' : ''}. Vigil prüft sie nur, wenn sie freigegeben sind.`, impact: 'Vergessene Test- oder Altsysteme sind oft schlechter gepflegt als die Hauptseite.', remediation: 'Eigene Subdomains unter Einstellungen › Freigegebene Ziele eintragen (z. B. die Domain selbst), damit Vigil sie mitprüft; nicht mehr genutzte Einträge im DNS löschen.' }));
  return { findings: out, notes, ran: true };
}

// --- Shodan InternetDB -----------------------------------------------------------------------------
const RISKY_PORTS = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'MSSQL', 2375: 'Docker-API', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5601: 'Kibana', 5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };
async function internetDb(host, ctx = {}, { signal } = {}) {
  const M = 'internetdb';
  const out = [];
  const ips = net.isIPv4(host) ? [host] : await (async () => { const r = await dnsTry(() => resolver(ctx).resolve4(host)); return r.ok ? r.value : null; })();
  if (!ips) return { ran: false, findings: out, notes: [`Shodan InternetDB: IP-Adresse von ${host} nicht ermittelbar.`] };
  let ok = 0;
  for (const ip of ips.filter((x) => !isInternalHost(x)).slice(0, 3)) {
    try {
      const r = await extFetch(ctx, `https://internetdb.shodan.io/${ip}`, { signal });
      if (r.status === 404) { ok++; continue; }
      if (!r.ok) continue;
      const j = await r.json();
      ok++;
      const loc = `https://${host}/ IP ${ip}`;
      const ports = (j.ports || []).map(Number).filter(Boolean).sort((a, b) => a - b);
      if (ports.length) out.push(W(M, { ruleId: 'internetdb-ports', severity: 'info', category: 'Config', confidence: 'medium', title: `Laut Shodan von außen erreichbare Ports auf ${ip}: ${ports.join(', ')}`, location: loc, evidence: `Shodan InternetDB: ports ${ports.join(', ')}`, description: 'Shodan durchsucht regelmäßig das ganze Internet. Diese Ports waren dabei auf der IP-Adresse deiner Seite offen. Vigil hat dafür selbst nicht gescannt.', remediation: 'Prüfen, ob jeder dieser Dienste wirklich öffentlich erreichbar sein muss; alles andere per Firewall sperren.' }));
      for (const p of ports.filter((x) => RISKY_PORTS[x])) out.push(W(M, { ruleId: `internetdb-risky-port-${p}`, severity: 'medium', category: 'Config', confidence: 'medium', title: `${RISKY_PORTS[p]} laut Shodan öffentlich erreichbar (Port ${p} auf ${ip})`, location: loc, evidence: `Shodan InternetDB: port ${p}`, description: `Auf ${ip} ist laut Shodan ein ${RISKY_PORTS[p]}-Dienst aus dem Internet erreichbar. Solche Dienste gehören normalerweise nicht ins offene Netz.`, impact: 'Datenbanken, Fernwartung und Dateifreigaben sind ein beliebtes Ziel für automatisierte Angriffe und Passwort-Raten.', remediation: 'Port per Firewall sperren oder nur über VPN bzw. bestimmte IP-Adressen erlauben.' }));
      const vulns = (j.vulns || []).filter((v) => /^CVE-\d{4}-\d+$/i.test(v));
      if (vulns.length) out.push(W(M, { ruleId: 'internetdb-known-vulns', severity: 'medium', category: 'Dependencies', confidence: 'low', title: `Shodan ordnet ${ip} ${vulns.length} bekannte Schwachstelle(n) zu`, location: loc, evidence: vulns.slice(0, 15).join(', '), description: 'Shodan leitet aus den erkannten Software-Versionen bekannte Schwachstellen ab. Das ist eine Schätzung anhand der Versionsangaben – Rückportierungen von Sicherheitsupdates erkennt Shodan nicht.', impact: 'Stimmt die Zuordnung, sind diese Lücken öffentlich bekannt und werden gezielt gesucht.', remediation: 'Die genannten CVEs mit der tatsächlich installierten Software abgleichen und betroffene Dienste aktualisieren.' }));
    } catch (e) { if (signal && signal.aborted) break; }
  }
  return { ran: ok > 0 || !ips.length, findings: out, notes: [] };
}

// --- Tippfehler-Domains --------------------------------------------------------------------------------
const KEYS = { q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'rzg', z: 'tuh', u: 'zij', i: 'uok', o: 'ipl', p: 'o', a: 'qsy', s: 'adw', d: 'sfe', f: 'dgr', g: 'fht', h: 'gjz', j: 'hku', k: 'jli', l: 'ko', y: 'ax', x: 'yc', c: 'xv', v: 'cb', b: 'vn', n: 'bm', m: 'n' };
const GLYPHS = [['o', '0'], ['0', 'o'], ['l', '1'], ['1', 'l'], ['i', 'l'], ['l', 'i'], ['m', 'rn'], ['rn', 'm'], ['w', 'vv'], ['e', '3']];
const TLDS = ['com', 'de', 'net', 'org', 'eu', 'info', 'co', 'io'];
function typoVariants(domain, max = 60) {
  const dot = domain.indexOf('.');
  if (dot < 1) return [];
  const name = domain.slice(0, dot), tld = domain.slice(dot + 1);
  const out = new Set();
  const add = (n, t = tld) => { if (n && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(n) && `${n}.${t}` !== domain) out.add(`${n}.${t}`); };
  for (const t of TLDS) if (t !== tld) add(name, t);
  for (let k = 0; k < name.length; k++) add(name.slice(0, k) + name.slice(k + 1));
  for (let k = 0; k < name.length - 1; k++) add(name.slice(0, k) + name[k + 1] + name[k] + name.slice(k + 2));
  for (const [a, b] of GLYPHS) { let i = name.indexOf(a); while (i >= 0) { add(name.slice(0, i) + b + name.slice(i + a.length)); i = name.indexOf(a, i + 1); } }
  for (let k = 0; k < name.length; k++) add(name.slice(0, k + 1) + name[k] + name.slice(k + 1));
  for (let k = 0; k < name.length; k++) for (const c of KEYS[name[k]] || '') add(name.slice(0, k) + c + name.slice(k + 1));
  add('www' + name);
  for (let k = 1; k < name.length; k++) add(name.slice(0, k) + '-' + name.slice(k));
  return [...out].slice(0, max);
}

async function typoDomains(domain, ctx = {}, { signal, max = 60 } = {}) {
  const M = 'typo-domains';
  const d = resolver(ctx);
  const own = await dnsTry(() => d.resolveNs(domain));
  if (!own.ok) return { ran: false, findings: [], notes: [`Tippfehler-Domains: DNS nicht erreichbar (${own.error}).`] };
  const ownNs = new Set(own.value.map((x) => String(x).toLowerCase()));
  let errors = 0;
  const variants = typoVariants(domain, max);
  const found = (await pool(variants, 5, async (v) => {
    if (signal && signal.aborted) return null;
    const ns = await dnsTry(() => d.resolveNs(v));
    if (!ns.ok) { errors++; return null; }
    if (!ns.value.length) return null;
    const mine = ns.value.some((x) => ownNs.has(String(x).toLowerCase()));
    const mx = await dnsTry(() => d.resolveMx(v));
    return { v, mine, mx: mx.ok && mx.value.length > 0 };
  })).filter(Boolean);
  if (errors > variants.length / 2) return { ran: false, findings: [], notes: ['Tippfehler-Domains: zu viele DNS-Fehler – Prüfung unvollständig.'] };
  const foreign = found.filter((x) => !x.mine);
  const out = [];
  if (foreign.length) out.push(W(M, { ruleId: 'typo-domains-registered', severity: 'info', category: 'Config', confidence: 'medium', title: `${foreign.length} ähnlich geschriebene Domains sind registriert`, location: `DNS ${domain}`, evidence: foreign.slice(0, 25).map((x) => x.v).join(', '), description: `Diese Schreibvarianten von ${domain} existieren und gehören nicht zu deinen Nameservern: ${foreign.slice(0, 25).map((x) => x.v).join(', ')}. Vigil hat nur im DNS nachgesehen und keinen dieser Server kontaktiert.`, impact: 'Betrüger nutzen solche Domains für Phishing-Mails und gefälschte Seiten, die wie deine aussehen.', remediation: 'Wichtige Schreibvarianten selbst registrieren und weiterleiten; verdächtige Domains beobachten und bei Missbrauch beim Registrar melden.' }));
  for (const x of foreign.filter((y) => y.mx).slice(0, 5)) out.push(W(M, { ruleId: 'typo-domain-mail', severity: 'medium', category: 'Config', confidence: 'medium', title: `Ähnliche Domain kann Mails empfangen: ${x.v}`, location: `DNS ${x.v}`, evidence: `${x.v}: MX vorhanden`, description: `Die Domain ${x.v} sieht ${domain} zum Verwechseln ähnlich und hat einen Mailserver eingetragen.`, impact: 'Vertippt sich jemand beim Schreiben an dich, landet die Mail dort. Betrüger können damit außerdem täuschend echte Mails verschicken.', remediation: 'Prüfen, wem die Domain gehört; bei Missbrauch beim Registrar melden und die eigene Schreibvariante sichern.' }));
  return { ran: true, findings: out, notes: [`Tippfehler-Domains: ${variants.length} Varianten im DNS nachgeschlagen, ${found.length} existieren (${found.length - foreign.length} davon bei deinen Nameservern).`] };
}

module.exports = { OUTBOUND_HOSTS, extFetch, mailExtended, parseStsPolicy, dnssec, domainExpiry, tlsProbe, tlsDeepFindings, certExpiryFinding, subdomains, internetDb, typoVariants, typoDomains, expirySeverity };
