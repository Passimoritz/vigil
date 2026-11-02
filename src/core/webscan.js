'use strict';

// Zerstoerungsfreie, autorisierte Pruefung eines Web-Ziels.
// Nur nicht-invasive Checks: TLS, Sicherheits-Header, Cookies, CORS, HTTP-Methoden,
// versehentlich offengelegte Pfade (nur GET, kleine feste Liste). KEINE Angriffe,
// kein Fuzzing, kein Portscan, kein Brute-Force, keine Last-/DoS-Tests.

const tls = require('tls');
const { normalizeFinding } = require('./schema');
const { throttle, limiter } = require('./ratelimit');

// Hoechstens 2 Anfragen gleichzeitig, mindestens 400 ms Abstand je Host.
const WEB_LIMIT = limiter(2);
const WEB_GAP_MS = 400;

const TIMEOUT = 12000;
const MAX_BODY = 200 * 1024;

// Pfade, die versehentlich oeffentlich sein koennten (reiner GET, nicht-invasiv).
const SENSITIVE_PATHS = [
  { p: '/.git/HEAD', sig: /^ref:\s/m, sev: 'high', what: 'Offengelegtes Git-Repository' },
  { p: '/.git/config', sig: /\[core\]/, sev: 'high', what: 'Offengelegte Git-Konfiguration' },
  { p: '/.env', sig: /[A-Z0-9_]+\s*=/, sev: 'critical', what: 'Offengelegte .env-Datei (Zugangsdaten!)' },
  { p: '/.env.production', sig: /[A-Z0-9_]+\s*=/, sev: 'critical', what: 'Offengelegte .env.production' },
  { p: '/.aws/credentials', sig: /aws_access_key_id/i, sev: 'critical', what: 'Offengelegte AWS-Zugangsdaten' },
  { p: '/.htpasswd', sig: /:\$(?:apr1|1|2y|6)\$|:\{SHA\}/, sev: 'high', what: 'Offengelegte .htpasswd (Passwort-Hashes)' },
  { p: '/wp-config.php.bak', sig: /DB_PASSWORD|define\s*\(/, sev: 'critical', what: 'Offengelegte wp-config-Sicherung' },
  { p: '/.svn/entries', sig: /svn:|^\d+$/m, sev: 'medium', what: 'Offengelegtes SVN-Verzeichnis' },
  { p: '/backup.sql', sig: /INSERT INTO|CREATE TABLE/i, sev: 'high', what: 'Offengelegter SQL-Datenbank-Dump' },
  { p: '/server-status', sig: /Apache Server Status|Scoreboard/, sev: 'medium', what: 'Apache server-status offen' },
  { p: '/actuator/env', sig: /"propertySources"|activeProfiles/, sev: 'high', what: 'Spring-Actuator /env offen (Konfig-Leak)' },
  { p: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version/, sev: 'medium', what: 'phpinfo() offen (Umgebungs-Leak)' },
];

async function get(url, method = 'GET', extSignal) {
  return WEB_LIMIT(async () => {
    try { await throttle('web:' + new URL(url).host, WEB_GAP_MS); } catch { /* ungueltige URL -> fetch meldet den Fehler */ }
    return rawGet(url, method, extSignal);
  });
}
// Adaptiver Backoff: 3x 429/503/403 in Folge je Host -> Abbruch statt Selbst-Aussperrung.
const strikes = new Map();
class ThrottledError extends Error { constructor(h) { super(`Ziel ${h} drosselt Anfragen – Prüfung abgebrochen, damit deine IP nicht gesperrt wird.`); this.throttled = true; } }
function noteStatus(url, status) {
  let h; try { h = new URL(url).host; } catch { return; }
  if (status === 429 || status === 503 || status === 403) { const n = (strikes.get(h) || 0) + 1; strikes.set(h, n); if (n >= 3) { strikes.set(h, 0); throw new ThrottledError(h); } }
  else strikes.set(h, 0);
}
async function rawGet(url, method, extSignal) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  const signal = extSignal ? AbortSignal.any([ctrl.signal, extSignal]) : ctrl.signal;
  try {
    const res = await fetch(url, { method, redirect: 'follow', signal, headers: { 'User-Agent': 'Vigil-Audit/0.2 (+authorized,passive)' } });
    noteStatus(url, res.status);
    let body = '';
    if (method === 'GET') {
      body = (await res.text()).slice(0, MAX_BODY);
    }
    return { ok: true, status: res.status, headers: res.headers, body, finalUrl: res.url };
  } catch (e) { if (e.throttled) throw e; return { ok: false, error: e.message }; }
  finally { clearTimeout(t); }
}

function checkTls(host) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: TIMEOUT, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const result = { ok: true, cert, protocol, cipher: socket.getCipher(), authorized: socket.authorized, authError: socket.authorizationError };
      socket.end();
      resolve(result);
    });
    socket.on('error', (e) => resolve({ ok: false, error: e.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'TLS-Timeout' }); });
  });
}

function hostOf(url) { try { return new URL(url).hostname; } catch { return null; } }
function isHttps(url) { return /^https:/i.test(url); }

async function scanWeb(rawTarget, authorized, onProgress = () => {}, signal) {
  const findings = [];
  const notes = [];
  if (!authorized) return { findings, notes: [`Web-Pruefung "${rawTarget}" uebersprungen: keine Berechtigung bestaetigt.`] };

  let url = /^https?:\/\//i.test(rawTarget) ? rawTarget : 'https://' + rawTarget;
  onProgress({ phase: 'webscan', message: `Server-Pruefung: ${url}` });

  let res = await get(url, 'GET', signal);
  if (!res.ok && url.startsWith('https://')) { url = 'http://' + rawTarget.replace(/^https?:\/\//i, ''); res = await get(url, 'GET', signal); }
  if (!res.ok) return { findings, notes: [`Server nicht erreichbar: ${rawTarget} (${res.error})`] };

  const h = res.headers;
  const get1 = (k) => h.get(k);
  const https = isHttps(res.finalUrl || url);
  const host = hostOf(res.finalUrl || url);
  const add = (o) => findings.push(normalizeFinding({ ...o, location: o.location || (res.finalUrl || url) }, 'webscan'));

  // --- Transport / HTTPS ---
  if (!https) add({ ruleId: 'no-https', title: 'Kein HTTPS', severity: 'high', category: 'Transport', description: 'Das Ziel antwortet nur ueber unverschluesseltes HTTP.', reachability: 'Jeder im Netzpfad (WLAN, Provider) kann Verkehr mitlesen/veraendern.', impact: 'Abgriff von Sitzungen und Zugangsdaten, Manipulation der Inhalte.', remediation: 'HTTPS mit gueltigem Zertifikat einrichten und HTTP auf HTTPS umleiten.', confidence: 'high' });

  // --- TLS-Zertifikat ---
  if (https && host) {
    onProgress({ phase: 'webscan', message: 'Pruefe TLS-Zertifikat …' });
    const t = await checkTls(host);
    if (t.ok) {
      if (t.cert && t.cert.valid_to) {
        const days = Math.floor((new Date(t.cert.valid_to) - Date.now()) / 86400000);
        const ev = `valid_to: ${t.cert.valid_to}`;
        if (days < 0) add({ ruleId: 'tls-cert-expired', evidence: ev, title: 'TLS-Zertifikat abgelaufen', severity: 'high', category: 'Transport', description: `Gueltig bis ${t.cert.valid_to}.`, impact: 'Browser warnen Nutzer; Vertrauen/Erreichbarkeit leidet.', remediation: 'Zertifikat erneuern und Erneuerung automatisieren.', confidence: 'high' });
        else if (days < 14) add({ ruleId: 'tls-cert-expiring', evidence: ev, title: `TLS-Zertifikat laeuft in ${days} Tag(en) ab`, severity: 'high', category: 'Transport', description: `Gueltig bis ${t.cert.valid_to}.`, impact: 'Nach Ablauf blockieren Browser die Seite.', remediation: 'Zertifikat jetzt erneuern und Erneuerung automatisieren (z. B. ACME/Let\'s Encrypt).', confidence: 'high' });
        else if (days < 30) add({ ruleId: 'tls-cert-expiring', evidence: ev, title: `TLS-Zertifikat laeuft in ${days} Tagen ab`, severity: 'medium', category: 'Transport', description: `Gueltig bis ${t.cert.valid_to}.`, remediation: 'Erneuerung einplanen/automatisieren.', confidence: 'high' });
      }
      if (t.protocol && /^(SSLv\d|TLSv1(\.0|\.1)?)$/.test(t.protocol)) add({ ruleId: 'tls-legacy-protocol', evidence: `protocol: ${t.protocol}`, title: `Veraltetes TLS-Protokoll (${t.protocol})`, severity: 'medium', category: 'Transport', description: 'Der Server handelt eine Version unter TLS 1.2 aus.', remediation: 'Nur TLS 1.2 und 1.3 zulassen.', confidence: 'high' });
      if (t.cipher && /RC4|3DES|DES-CBC|NULL|EXPORT|anon|MD5/i.test(t.cipher.name || '')) add({ ruleId: 'tls-weak-cipher', evidence: `cipher: ${t.cipher.name}`, title: `Schwache TLS-Chiffre ausgehandelt (${t.cipher.name})`, severity: 'medium', category: 'Transport', description: 'Der Server bevorzugt eine veraltete Chiffre.', remediation: 'Moderne Chiffren-Liste konfigurieren.', confidence: 'high' });
      if (!t.authorized && t.authError) add({ ruleId: 'tls-cert-untrusted', evidence: String(t.authError), title: 'TLS-Zertifikat nicht vertrauenswuerdig', severity: 'medium', category: 'Transport', description: `Validierungsfehler: ${t.authError}.`, remediation: 'Gueltige, vollstaendige Zertifikatskette mit passendem Hostnamen bereitstellen.', confidence: 'high' });
    }
  }

  // --- Sicherheits-Header ---
  const csp = get1('content-security-policy') || '';
  if (https && !get1('strict-transport-security')) add({ ruleId: 'missing-hsts-header', title: 'HSTS-Header fehlt', severity: 'medium', category: 'Transport', description: 'Strict-Transport-Security fehlt.', reachability: 'Erster Aufruf kann auf HTTP umgebogen werden (SSL-Stripping).', remediation: 'Header setzen: "Strict-Transport-Security: max-age=31536000; includeSubDomains".', confidence: 'high' });
  if (!csp) add({ ruleId: 'missing-csp-header', title: 'Content-Security-Policy fehlt', severity: 'medium', category: 'Config', description: 'Keine CSP gesetzt.', reachability: 'Betrifft alle Besucher.', remediation: 'Eine CSP setzen, um XSS/Daten-Injektion zu erschweren.', confidence: 'high' });
  else {
    const unsafe = ['unsafe-inline', 'unsafe-eval'].filter((d) => csp.toLowerCase().includes(`'${d}'`));
    const scriptSrc = (csp.match(/script-src([^;]*)/i) || csp.match(/default-src([^;]*)/i) || [])[1] || '';
    if (/(^|\s)\*(\s|$)|(^|\s)(https?:|data:)(\s|$)/i.test(scriptSrc)) add({ ruleId: 'csp-wildcard-script-src', evidence: 'script-src' + scriptSrc.slice(0, 200), title: 'CSP erlaubt Skripte von überall (Wildcard in script-src)', severity: 'medium', category: 'XSS', description: 'Mit * bzw. https: als Skriptquelle hilft die CSP kaum gegen XSS.', remediation: 'Skriptquellen konkret benennen.', confidence: 'high' });
    if (unsafe.length) add({ ruleId: 'unsafe-csp-directive', evidence: csp.slice(0, 300), title: `Content-Security-Policy erlaubt ${unsafe.map((d) => `'${d}'`).join(' und ')}`, severity: 'medium', category: 'XSS', description: 'Die CSP hebelt ihren eigenen XSS-Schutz teilweise aus.', remediation: 'Inline-Skripte durch Nonces/Hashes ersetzen und auf eval verzichten; danach die unsicheren Direktiven entfernen.', confidence: 'high' });
  }
  if ((get1('x-content-type-options') || '').toLowerCase() !== 'nosniff') add({ ruleId: 'missing-x-content-type-options', title: 'X-Content-Type-Options fehlt/falsch', severity: 'low', category: 'Config', description: 'Header sollte "nosniff" sein.', remediation: 'Header setzen: "X-Content-Type-Options: nosniff".', confidence: 'high' });
  if (!get1('x-frame-options') && !/frame-ancestors/i.test(csp)) add({ ruleId: 'missing-clickjacking-protection', title: 'Clickjacking-Schutz fehlt', severity: 'low', category: 'Config', description: 'Weder X-Frame-Options noch CSP frame-ancestors gesetzt.', remediation: '"X-Frame-Options: DENY" oder CSP "frame-ancestors none" setzen.', confidence: 'high' });
  if (!get1('referrer-policy')) add({ ruleId: 'missing-referrer-policy', title: 'Referrer-Policy fehlt', severity: 'low', category: 'Config', description: 'Kein Referrer-Policy-Header.', remediation: 'z. B. "Referrer-Policy: strict-origin-when-cross-origin".', confidence: 'high' });
  if (https && !get1('cross-origin-opener-policy')) add({ ruleId: 'missing-coop', title: 'Cross-Origin-Opener-Policy fehlt', severity: 'info', category: 'Config', description: 'Fremde Pop-ups behalten Zugriff auf window.opener.', remediation: 'Cross-Origin-Opener-Policy: same-origin setzen.', confidence: 'high' });
  if (!get1('permissions-policy')) add({ ruleId: 'missing-permissions-policy', title: 'Permissions-Policy fehlt', severity: 'info', category: 'Config', description: 'Browser-Funktionen (Kamera, Mikrofon, Standort …) sind nicht eingeschraenkt.', remediation: 'z. B. "Permissions-Policy: camera=(), microphone=(), geolocation=()".', confidence: 'high' });

  // --- Cookies ---
  const cookies = h.getSetCookie ? h.getSetCookie() : (get1('set-cookie') ? [get1('set-cookie')] : []);
  for (const c of cookies) {
    const name = (c.split('=')[0] || 'Cookie').trim();
    const low = c.toLowerCase();
    if (https && !/;\s*secure/.test(low)) add({ ruleId: 'cookie-missing-secure-' + name.toLowerCase(), evidence: c.split(';').slice(1).join(';').trim().slice(0, 160), title: `Cookie ohne Secure-Flag: ${name}`, severity: 'medium', category: 'Config', description: 'Cookie kann ueber unverschluesselte Verbindungen uebertragen werden.', remediation: 'Secure-Flag setzen.', confidence: 'high' });
    if (!/;\s*httponly/.test(low)) add({ ruleId: 'cookie-missing-httponly-' + name.toLowerCase(), title: `Cookie ohne HttpOnly: ${name}`, severity: 'low', category: 'Config', description: 'Cookie ist per JavaScript lesbar (bei XSS stehlbar).', remediation: 'HttpOnly-Flag setzen, sofern nicht per JS benoetigt.', confidence: 'medium' });
    if (!/;\s*samesite/.test(low)) add({ ruleId: 'cookie-missing-samesite-' + name.toLowerCase(), title: `Cookie ohne SameSite: ${name}`, severity: 'low', category: 'Config', description: 'Erleichtert CSRF.', remediation: 'SameSite=Lax oder Strict setzen.', confidence: 'medium' });
  }

  // --- CORS ---
  if (get1('access-control-allow-origin') === '*') {
    const creds = (get1('access-control-allow-credentials') || '').toLowerCase() === 'true';
    add({ ruleId: 'cors-wildcard', title: 'Offene CORS-Richtlinie (Access-Control-Allow-Origin: *)', severity: creds ? 'high' : 'medium', category: 'AccessControl', description: creds ? 'Wildcard-Origin zusammen mit Credentials erlaubt.' : 'Jede Herkunft darf Antworten lesen.', remediation: 'Erlaubte Origins auf eine feste Liste beschraenken; Wildcard nie mit Credentials.', confidence: 'high' });
  }

  // --- Server-Banner / Info-Leak ---
  // Exakte Version (z. B. nginx/1.18.0, PHP/8.1.2) = LOW; nur der Produktname = INFO.
  const VERSIONED = /[A-Za-z][\w.-]*\/\d+(?:\.\d+)+/;
  for (const [hdr, label] of [['server', 'Server'], ['x-powered-by', 'X-Powered-By']]) {
    const val = get1(hdr);
    if (!val) continue;
    if (VERSIONED.test(val)) add({ ruleId: `version-disclosure-${hdr}`, evidence: `${label}: ${val}`, title: `Software-Version im ${label}-Header: ${val}`, severity: 'low', category: 'Config', description: 'Exakte Versionsangaben erleichtern die Suche nach passenden, bekannten Schwachstellen.', remediation: `Version im "${label}"-Header verbergen bzw. den Header entfernen.`, confidence: 'high' });
    else if (hdr === 'x-powered-by') add({ ruleId: 'tech-disclosure-x-powered-by', evidence: `${label}: ${val}`, title: `Technologie offengelegt (X-Powered-By: ${val})`, severity: 'info', category: 'Config', description: 'Unnoetige Information ueber die eingesetzte Technik.', remediation: '"X-Powered-By" entfernen.', confidence: 'high' });
  }

  // --- Inhalts-Checks aus der Antwort ---
  const body = res.body || '';
  if (https && /(?:src|href|action)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/i.test(body)) add({ ruleId: 'mixed-content', title: 'Gemischte Inhalte (HTTP auf HTTPS-Seite)', severity: 'low', category: 'Transport', description: 'Die HTTPS-Seite bindet Ressourcen ueber unverschluesseltes HTTP ein.', remediation: 'Alle eingebundenen Ressourcen ueber HTTPS laden.', confidence: 'medium' });
  if (/<title>\s*Index of \/|<h1>\s*Index of \//i.test(body)) add({ ruleId: 'directory-listing', title: 'Verzeichnisauflistung aktiv', severity: 'low', category: 'Config', description: 'Der Server listet Verzeichnisinhalte offen auf.', remediation: 'Directory-Listing am Webserver abschalten (z. B. "Options -Indexes").', confidence: 'high' });

  // --- Gefaehrliche HTTP-Methoden ---
  const opt = await get(url, 'OPTIONS', signal);
  if (opt.ok) {
    const allow = (opt.headers.get('allow') || '').toUpperCase();
    if (allow.includes('TRACE')) add({ ruleId: 'http-trace', title: 'HTTP TRACE aktiviert', severity: 'medium', category: 'Config', description: 'TRACE kann Cross-Site-Tracing (XST) ermoeglichen.', remediation: 'TRACE serverseitig deaktivieren.', confidence: 'medium' });
    const bad = ['PUT', 'DELETE', 'CONNECT'].filter((m) => allow.includes(m));
    if (bad.length) add({ ruleId: 'http-write-methods', title: `Schreibende HTTP-Methoden erlaubt: ${bad.join(', ')}`, severity: 'low', category: 'Config', description: 'Methoden wie PUT/DELETE koennten ungewollt Aenderungen zulassen.', remediation: 'Nicht benoetigte Methoden sperren.', confidence: 'low' });
  }

  // --- Offengelegte Pfade (nur GET, feste kleine Liste) ---
  onProgress({ phase: 'webscan', message: 'Pruefe auf offengelegte Pfade …' });
  let origin;
  try { origin = new URL(res.finalUrl || url).origin; } catch { origin = null; }
  if (origin) {
    for (const sp of SENSITIVE_PATHS) {
      if (signal && signal.aborted) break;
      const u = origin + sp.p;
      const r = await get(u, 'GET', signal);
      if (!r.ok) continue;
      if (r.status === 200 && sp.sig.test(r.body || '')) {
        add({ ruleId: 'exposed-' + sp.p.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase(), title: sp.what, severity: sp.sev, category: (sp.sev === 'critical' ? 'Secrets' : 'Config'), location: u, description: `Unter ${sp.p} ist Inhalt oeffentlich erreichbar, der nicht nach aussen gehoeren sollte.`, reachability: 'Direkt per Browser/HTTP abrufbar, ohne Anmeldung.', impact: sp.sev === 'critical' ? 'Moeglicher Abfluss von Zugangsdaten/Secrets.' : 'Informations-/Quellcode-Leak, erleichtert weitere Angriffe.', remediation: `Zugriff auf ${sp.p} am Webserver sperren bzw. die Datei aus dem Web-Root entfernen.`, confidence: 'high' });
      }
    }
  }

  notes.push(`Server-Pruefung abgeschlossen: ${res.finalUrl || url} (${findings.length} Befund[e]).`);
  return { findings, notes };
}

module.exports = { scanWeb };
