'use strict';

// Zerstoerungsfreie, autorisierte Pruefung eines Web-Ziels.
// Nur nicht-invasive Checks: TLS, Sicherheits-Header, Cookies, CORS, HTTP-Methoden,
// versehentlich offengelegte Pfade (nur GET, kleine feste Liste). KEINE Angriffe,
// kein Fuzzing, kein Portscan, kein Brute-Force, keine Last-/DoS-Tests.

const tls = require('tls');
const { normalizeFinding } = require('./schema');

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
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  const signal = extSignal ? AbortSignal.any([ctrl.signal, extSignal]) : ctrl.signal;
  try {
    const res = await fetch(url, { method, redirect: 'follow', signal, headers: { 'User-Agent': 'Vigil-Audit/0.1 (+authorized,passive)' } });
    let body = '';
    if (method === 'GET') {
      body = (await res.text()).slice(0, MAX_BODY);
    }
    return { ok: true, status: res.status, headers: res.headers, body, finalUrl: res.url };
  } catch (e) { return { ok: false, error: e.message }; }
  finally { clearTimeout(t); }
}

function checkTls(host) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port: 443, servername: host, timeout: TIMEOUT, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const result = { ok: true, cert, protocol, authorized: socket.authorized, authError: socket.authorizationError };
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
  if (!https) add({ title: 'Kein HTTPS', severity: 'high', category: 'Transport', description: 'Das Ziel antwortet nur ueber unverschluesseltes HTTP.', reachability: 'Jeder im Netzpfad (WLAN, Provider) kann Verkehr mitlesen/veraendern.', impact: 'Abgriff von Sitzungen und Zugangsdaten, Manipulation der Inhalte.', remediation: 'HTTPS mit gueltigem Zertifikat einrichten und HTTP auf HTTPS umleiten.', confidence: 'high' });

  // --- TLS-Zertifikat ---
  if (https && host) {
    onProgress({ phase: 'webscan', message: 'Pruefe TLS-Zertifikat …' });
    const t = await checkTls(host);
    if (t.ok) {
      if (t.cert && t.cert.valid_to) {
        const days = Math.round((new Date(t.cert.valid_to) - Date.now()) / 86400000);
        if (days < 0) add({ title: 'TLS-Zertifikat abgelaufen', severity: 'high', category: 'Transport', description: `Gueltig bis ${t.cert.valid_to}.`, impact: 'Browser warnen Nutzer; Vertrauen/Erreichbarkeit leidet.', remediation: 'Zertifikat erneuern und Erneuerung automatisieren.', confidence: 'high' });
        else if (days < 21) add({ title: `TLS-Zertifikat laeuft bald ab (${days} Tage)`, severity: 'low', category: 'Transport', description: `Gueltig bis ${t.cert.valid_to}.`, remediation: 'Erneuerung einplanen/automatisieren.', confidence: 'high' });
      }
      if (t.protocol && /TLSv1(\.0|\.1)?$/.test(t.protocol)) add({ title: `Veraltetes TLS-Protokoll (${t.protocol})`, severity: 'medium', category: 'Transport', description: 'Der Server erlaubt eine alte, unsichere TLS-Version.', remediation: 'Nur TLS 1.2 und 1.3 zulassen.', confidence: 'medium' });
      if (!t.authorized && t.authError) add({ title: 'TLS-Zertifikat nicht vertrauenswuerdig', severity: 'medium', category: 'Transport', description: `Validierungsfehler: ${t.authError}.`, remediation: 'Gueltige, vollstaendige Zertifikatskette mit passendem Hostnamen bereitstellen.', confidence: 'high' });
    }
  }

  // --- Sicherheits-Header ---
  if (https && !get1('strict-transport-security')) add({ title: 'HSTS-Header fehlt', severity: 'medium', category: 'Transport', description: 'Strict-Transport-Security fehlt.', reachability: 'Erster Aufruf kann auf HTTP umgebogen werden (SSL-Stripping).', remediation: 'Header setzen: "Strict-Transport-Security: max-age=31536000; includeSubDomains".', confidence: 'high' });
  if (!get1('content-security-policy')) add({ title: 'Content-Security-Policy fehlt', severity: 'medium', category: 'Config', description: 'Keine CSP gesetzt.', reachability: 'Betrifft alle Besucher.', remediation: 'Eine CSP setzen, um XSS/Daten-Injektion zu erschweren.', confidence: 'high' });
  if ((get1('x-content-type-options') || '').toLowerCase() !== 'nosniff') add({ title: 'X-Content-Type-Options fehlt/falsch', severity: 'low', category: 'Config', description: 'Header sollte "nosniff" sein.', remediation: 'Header setzen: "X-Content-Type-Options: nosniff".', confidence: 'high' });
  if (!get1('x-frame-options') && !/frame-ancestors/i.test(get1('content-security-policy') || '')) add({ title: 'Clickjacking-Schutz fehlt', severity: 'low', category: 'Config', description: 'Weder X-Frame-Options noch CSP frame-ancestors gesetzt.', remediation: '"X-Frame-Options: DENY" oder CSP "frame-ancestors none" setzen.', confidence: 'high' });
  if (!get1('referrer-policy')) add({ title: 'Referrer-Policy fehlt', severity: 'low', category: 'Config', description: 'Kein Referrer-Policy-Header.', remediation: 'z. B. "Referrer-Policy: strict-origin-when-cross-origin".', confidence: 'high' });

  // --- Cookies ---
  const cookies = h.getSetCookie ? h.getSetCookie() : (get1('set-cookie') ? [get1('set-cookie')] : []);
  for (const c of cookies) {
    const name = (c.split('=')[0] || 'Cookie').trim();
    const low = c.toLowerCase();
    if (https && !/;\s*secure/.test(low)) add({ title: `Cookie ohne Secure-Flag: ${name}`, severity: 'medium', category: 'Config', description: 'Cookie kann ueber unverschluesselte Verbindungen uebertragen werden.', remediation: 'Secure-Flag setzen.', confidence: 'high' });
    if (!/;\s*httponly/.test(low)) add({ title: `Cookie ohne HttpOnly: ${name}`, severity: 'low', category: 'Config', description: 'Cookie ist per JavaScript lesbar (bei XSS stehlbar).', remediation: 'HttpOnly-Flag setzen, sofern nicht per JS benoetigt.', confidence: 'medium' });
    if (!/;\s*samesite/.test(low)) add({ title: `Cookie ohne SameSite: ${name}`, severity: 'low', category: 'Config', description: 'Erleichtert CSRF.', remediation: 'SameSite=Lax oder Strict setzen.', confidence: 'medium' });
  }

  // --- CORS ---
  if (get1('access-control-allow-origin') === '*') {
    const creds = (get1('access-control-allow-credentials') || '').toLowerCase() === 'true';
    add({ title: 'Offene CORS-Richtlinie (Access-Control-Allow-Origin: *)', severity: creds ? 'high' : 'medium', category: 'AccessControl', description: creds ? 'Wildcard-Origin zusammen mit Credentials erlaubt.' : 'Jede Herkunft darf Antworten lesen.', remediation: 'Erlaubte Origins auf eine feste Liste beschraenken; Wildcard nie mit Credentials.', confidence: 'high' });
  }

  // --- Server-Banner / Info-Leak ---
  const server = get1('server');
  if (server && /\d/.test(server)) add({ title: `Software-Version im Server-Header: ${server}`, severity: 'low', category: 'Config', description: 'Versionsangaben erleichtern die Suche nach passenden Exploits.', remediation: 'Version im "Server"-Header verbergen.', confidence: 'medium' });
  if (get1('x-powered-by')) add({ title: `Technologie offengelegt (X-Powered-By: ${get1('x-powered-by')})`, severity: 'low', category: 'Config', description: 'Unnoetige Information ueber die eingesetzte Technik.', remediation: '"X-Powered-By" entfernen.', confidence: 'high' });

  // --- Inhalts-Checks aus der Antwort ---
  const body = res.body || '';
  if (https && /(?:src|href|action)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/i.test(body)) add({ title: 'Gemischte Inhalte (HTTP auf HTTPS-Seite)', severity: 'low', category: 'Transport', description: 'Die HTTPS-Seite bindet Ressourcen ueber unverschluesseltes HTTP ein.', remediation: 'Alle eingebundenen Ressourcen ueber HTTPS laden.', confidence: 'medium' });
  if (/<title>\s*Index of \/|<h1>\s*Index of \//i.test(body)) add({ title: 'Verzeichnisauflistung aktiv', severity: 'low', category: 'Config', description: 'Der Server listet Verzeichnisinhalte offen auf.', remediation: 'Directory-Listing am Webserver abschalten (z. B. "Options -Indexes").', confidence: 'high' });

  // --- Gefaehrliche HTTP-Methoden ---
  const opt = await get(url, 'OPTIONS', signal);
  if (opt.ok) {
    const allow = (opt.headers.get('allow') || '').toUpperCase();
    if (allow.includes('TRACE')) add({ title: 'HTTP TRACE aktiviert', severity: 'medium', category: 'Config', description: 'TRACE kann Cross-Site-Tracing (XST) ermoeglichen.', remediation: 'TRACE serverseitig deaktivieren.', confidence: 'medium' });
    const bad = ['PUT', 'DELETE', 'CONNECT'].filter((m) => allow.includes(m));
    if (bad.length) add({ title: `Schreibende HTTP-Methoden erlaubt: ${bad.join(', ')}`, severity: 'low', category: 'Config', description: 'Methoden wie PUT/DELETE koennten ungewollt Aenderungen zulassen.', remediation: 'Nicht benoetigte Methoden sperren.', confidence: 'low' });
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
        add({ title: sp.what, severity: sp.sev, category: (sp.sev === 'critical' ? 'Secrets' : 'Config'), location: u, description: `Unter ${sp.p} ist Inhalt oeffentlich erreichbar, der nicht nach aussen gehoeren sollte.`, reachability: 'Direkt per Browser/HTTP abrufbar, ohne Anmeldung.', impact: sp.sev === 'critical' ? 'Moeglicher Abfluss von Zugangsdaten/Secrets.' : 'Informations-/Quellcode-Leak, erleichtert weitere Angriffe.', remediation: `Zugriff auf ${sp.p} am Webserver sperren bzw. die Datei aus dem Web-Root entfernen.`, confidence: 'high' });
      }
    }
  }

  notes.push(`Server-Pruefung abgeschlossen: ${res.finalUrl || url} (${findings.length} Befund[e]).`);
  return { findings, notes };
}

module.exports = { scanWeb };
