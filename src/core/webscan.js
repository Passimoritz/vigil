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
  onProgress({ phase: 'webscan', message: `Server-Prüfung: ${url}` });

  let res = await get(url, 'GET', signal);
  if (!res.ok && url.startsWith('https://')) { url = 'http://' + rawTarget.replace(/^https?:\/\//i, ''); res = await get(url, 'GET', signal); }
  if (!res.ok) return { findings, notes: [`Server nicht erreichbar: ${rawTarget} (${res.error})`] };

  const h = res.headers;
  const get1 = (k) => h.get(k);
  const https = isHttps(res.finalUrl || url);
  const host = hostOf(res.finalUrl || url);
  const add = (o) => findings.push(normalizeFinding({ ...o, location: o.location || (res.finalUrl || url) }, 'webscan'));

  // --- Transport / HTTPS ---
  // Texte bewusst in Alltagssprache: description = was gefunden wurde, impact = was passieren kann.
  if (!https) add({ ruleId: 'no-https', title: 'Seite ist nicht verschlüsselt (kein HTTPS)', severity: 'high', category: 'Transport', description: 'Die Seite ist nur über unverschlüsseltes HTTP erreichbar.', impact: 'Jeder auf dem Weg der Daten – etwa im selben WLAN oder beim Provider – kann mitlesen und Inhalte verändern, auch Passwörter und Anmeldungen.', remediation: 'HTTPS mit gültigem Zertifikat einrichten und HTTP dauerhaft auf HTTPS umleiten.', confidence: 'high' });

  // --- TLS-Zertifikat ---
  if (https && host) {
    onProgress({ phase: 'webscan', message: 'Prüfe TLS-Zertifikat …' });
    const t = await checkTls(host);
    if (t.ok) {
      if (t.cert && t.cert.valid_to) {
        const days = Math.floor((new Date(t.cert.valid_to) - Date.now()) / 86400000);
        const ev = `valid_to: ${t.cert.valid_to}`;
        const until = new Date(t.cert.valid_to).toLocaleDateString('de-DE');
        if (days < 0) add({ ruleId: 'tls-cert-expired', evidence: ev, title: 'Sicherheitszertifikat ist abgelaufen', severity: 'high', category: 'Transport', description: `Das HTTPS-Zertifikat der Seite war nur bis ${until} gültig.`, impact: 'Browser zeigen Besuchern eine große Warnung und blockieren die Seite. Viele klicken die Warnung weg – genau darauf setzen Betrüger.', remediation: 'Zertifikat erneuern und die Erneuerung automatisieren.', confidence: 'high' });
        else if (days < 14) add({ ruleId: 'tls-cert-expiring', evidence: ev, title: `Sicherheitszertifikat läuft in ${days} ${days === 1 ? 'Tag' : 'Tagen'} ab`, severity: 'high', category: 'Transport', description: `Das HTTPS-Zertifikat ist nur noch bis ${until} gültig.`, impact: 'Danach blockieren Browser die Seite mit einer Warnung.', remediation: 'Zertifikat jetzt erneuern und die Erneuerung automatisieren (z. B. Let’s Encrypt).', confidence: 'high' });
        else if (days < 30) add({ ruleId: 'tls-cert-expiring', evidence: ev, title: `Sicherheitszertifikat läuft in ${days} Tagen ab`, severity: 'medium', category: 'Transport', description: `Das HTTPS-Zertifikat ist nur noch bis ${until} gültig.`, impact: 'Wird es nicht rechtzeitig erneuert, blockieren Browser die Seite.', remediation: 'Erneuerung einplanen oder automatisieren.', confidence: 'high' });
      }
      if (t.protocol && /^(SSLv\d|TLSv1(\.0|\.1)?)$/.test(t.protocol)) add({ ruleId: 'tls-legacy-protocol', evidence: `protocol: ${t.protocol}`, title: `Veraltete Verschlüsselung (${t.protocol})`, severity: 'medium', category: 'Transport', description: `Der Server verschlüsselt mit ${t.protocol}. Dieses Verfahren gilt seit Jahren als unsicher.`, impact: 'Die Verbindung lässt sich mit bekannten Angriffen leichter knacken oder abschwächen.', remediation: 'Nur TLS 1.2 und 1.3 zulassen.', confidence: 'high' });
      if (t.cipher && /RC4|3DES|DES-CBC|NULL|EXPORT|anon|MD5/i.test(t.cipher.name || '')) add({ ruleId: 'tls-weak-cipher', evidence: `cipher: ${t.cipher.name}`, title: `Schwaches Verschlüsselungsverfahren (${t.cipher.name})`, severity: 'medium', category: 'Transport', description: `Der Server wählt das veraltete Verfahren ${t.cipher.name}, obwohl moderne möglich wären.`, impact: 'Mitgeschnittene Verbindungen lassen sich unter Umständen entschlüsseln.', remediation: 'Eine moderne Liste von Verschlüsselungsverfahren einstellen.', confidence: 'high' });
      if (!t.authorized && t.authError) add({ ruleId: 'tls-cert-untrusted', evidence: String(t.authError), title: 'Sicherheitszertifikat wird nicht anerkannt', severity: 'medium', category: 'Transport', description: `Browser vertrauen dem Zertifikat nicht (Fehler: ${t.authError}).`, impact: 'Besucher sehen eine Warnung und können eine echte Seite nicht von einer gefälschten unterscheiden.', remediation: 'Gültige, vollständige Zertifikatskette mit passendem Namen bereitstellen.', confidence: 'high' });
    }
  }

  // --- Sicherheits-Header ---
  const csp = get1('content-security-policy') || '';
  if (https && !get1('strict-transport-security')) add({ ruleId: 'missing-hsts-header', title: 'Browser werden nicht auf HTTPS festgelegt (HSTS fehlt)', severity: 'medium', category: 'Transport', description: 'Die Seite sagt dem Browser nicht, dass sie ausschließlich verschlüsselt geöffnet werden soll.', impact: 'Beim ersten Aufruf, z. B. in einem öffentlichen WLAN, kann ein Angreifer die Verbindung auf unverschlüsselt umlenken und mitlesen.', remediation: 'Header setzen: "Strict-Transport-Security: max-age=31536000; includeSubDomains".', confidence: 'high' });
  if (!csp) add({ ruleId: 'missing-csp-header', title: 'Kein Schutz gegen eingeschleuste Skripte (Content-Security-Policy fehlt)', severity: 'medium', category: 'Config', description: 'Die Seite legt nicht fest, von wo Skripte geladen werden dürfen. Der Browser führt deshalb jedes Skript aus, das in die Seite gelangt.', impact: 'Gelingt es einem Angreifer, Code in die Seite zu bringen, läuft dieser ungehindert und kann Eingaben, Anmeldungen oder Daten der Besucher abgreifen.', remediation: 'Eine Content-Security-Policy setzen, die nur eigene Skripte erlaubt.', confidence: 'high' });
  else {
    const unsafe = ['unsafe-inline', 'unsafe-eval'].filter((d) => csp.toLowerCase().includes(`'${d}'`));
    const scriptSrc = (csp.match(/script-src([^;]*)/i) || csp.match(/default-src([^;]*)/i) || [])[1] || '';
    if (/(^|\s)\*(\s|$)|(^|\s)(https?:|data:)(\s|$)/i.test(scriptSrc)) add({ ruleId: 'csp-wildcard-script-src', evidence: 'script-src' + scriptSrc.slice(0, 200), title: 'Skript-Schutz erlaubt Skripte von jeder Adresse', severity: 'medium', category: 'Config', description: 'Die Content-Security-Policy ist zwar gesetzt, erlaubt aber Skripte von beliebigen Servern. Sie schützt dadurch kaum.', impact: 'Eingeschleuster Code kann sich einfach von einem fremden Server nachladen.', remediation: 'Die erlaubten Skriptquellen konkret benennen statt „*“ oder „https:“.', confidence: 'high' });
    if (unsafe.length) add({ ruleId: 'unsafe-csp-directive', evidence: csp.slice(0, 300), title: 'Skript-Schutz ist teilweise ausgehebelt', severity: 'medium', category: 'Config', description: `Die Content-Security-Policy erlaubt ${unsafe.map((d) => `'${d}'`).join(' und ')}. Damit dürfen auch Skripte direkt im HTML bzw. dynamisch erzeugter Code laufen.`, impact: 'Genau so arbeitet eingeschleuster Code – der Schutz greift deshalb an der wichtigsten Stelle nicht.', remediation: 'Inline-Skripte in Dateien auslagern oder per Nonce/Hash freigeben und auf eval verzichten; danach die unsicheren Angaben entfernen.', confidence: 'high' });
  }
  if ((get1('x-content-type-options') || '').toLowerCase() !== 'nosniff') add({ ruleId: 'missing-x-content-type-options', title: 'Browser darf Dateitypen selbst erraten', severity: 'low', category: 'Config', description: 'Der Header „X-Content-Type-Options: nosniff“ fehlt.', impact: 'Eine hochgeladene oder fremde Datei kann vom Browser fälschlich als Skript ausgeführt werden.', remediation: 'Header setzen: "X-Content-Type-Options: nosniff".', confidence: 'high' });
  if (!get1('x-frame-options') && !/frame-ancestors/i.test(csp)) add({ ruleId: 'missing-clickjacking-protection', title: 'Seite kann unsichtbar in fremde Seiten eingebettet werden', severity: 'low', category: 'Config', description: 'Nichts verbietet anderen Webseiten, diese Seite in einem Rahmen anzuzeigen.', impact: 'Betrüger können die Seite unsichtbar über ihre eigene legen und Besucher zu Klicks verleiten, die sie nicht wollen (Clickjacking).', remediation: '"X-Frame-Options: DENY" oder in der Content-Security-Policy "frame-ancestors \'none\'" setzen.', confidence: 'high' });
  if (!get1('referrer-policy')) add({ ruleId: 'missing-referrer-policy', title: 'Volle Adresse wird an fremde Seiten weitergegeben', severity: 'low', category: 'Config', description: 'Es ist nicht festgelegt, wie viel der Browser beim Klick auf externe Links über die Herkunft verrät.', impact: 'Externe Seiten sehen die komplette Adresse – samt eventuell darin enthaltener Kennungen oder Suchbegriffe.', remediation: 'z. B. "Referrer-Policy: strict-origin-when-cross-origin" setzen.', confidence: 'high' });
  if (https && !get1('cross-origin-opener-policy')) add({ ruleId: 'missing-coop', title: 'Fenster ist nicht von fremden Pop-ups getrennt', severity: 'info', category: 'Config', description: 'Ein von hier geöffnetes fremdes Fenster kann weiterhin auf dieses Fenster zugreifen.', impact: 'Gering: Fremde Seiten könnten die Seite im Hintergrund umleiten, etwa auf eine gefälschte Anmeldeseite.', remediation: '"Cross-Origin-Opener-Policy: same-origin" setzen.', confidence: 'high' });
  if (!get1('permissions-policy')) add({ ruleId: 'missing-permissions-policy', title: 'Browser-Funktionen sind nicht eingeschränkt', severity: 'info', category: 'Config', description: 'Es ist nicht festgelegt, ob eingebundene Inhalte Kamera, Mikrofon oder Standort anfragen dürfen.', impact: 'Gering: Fremde eingebundene Inhalte könnten solche Rechte beim Besucher anfragen.', remediation: 'z. B. "Permissions-Policy: camera=(), microphone=(), geolocation=()" setzen.', confidence: 'high' });

  // --- Cookies ---
  const cookies = h.getSetCookie ? h.getSetCookie() : (get1('set-cookie') ? [get1('set-cookie')] : []);
  for (const c of cookies) {
    const name = (c.split('=')[0] || 'Cookie').trim();
    const low = c.toLowerCase();
    if (https && !/;\s*secure/.test(low)) add({ ruleId: 'cookie-missing-secure-' + name.toLowerCase(), evidence: c.split(';').slice(1).join(';').trim().slice(0, 160), title: `Cookie „${name}“ wird auch unverschlüsselt gesendet`, severity: 'medium', category: 'Config', description: `Dem Cookie „${name}“ fehlt das Attribut „Secure“. Der Browser schickt es deshalb auch über unverschlüsselte Verbindungen.`, impact: 'Im selben WLAN kann jemand das Cookie mitlesen. Ist es ein Anmelde-Cookie, kann er sich damit als der Besucher ausgeben.', remediation: 'Beim Setzen des Cookies das Attribut "Secure" ergänzen.', confidence: 'high' });
    if (!/;\s*httponly/.test(low)) add({ ruleId: 'cookie-missing-httponly-' + name.toLowerCase(), title: `Cookie „${name}“ ist für Skripte lesbar`, severity: 'low', category: 'Config', description: `Dem Cookie „${name}“ fehlt das Attribut „HttpOnly“. Jedes Skript auf der Seite kann es auslesen.`, impact: 'Gelangt fremder Code in die Seite, kann er das Cookie stehlen. Kritisch ist das nur bei Anmelde- oder Sitzungs-Cookies.', remediation: 'Beim Setzen des Cookies das Attribut "HttpOnly" ergänzen – sofern die Seite es nicht selbst per JavaScript braucht.', confidence: 'medium' });
    if (!/;\s*samesite/.test(low)) add({ ruleId: 'cookie-missing-samesite-' + name.toLowerCase(), title: `Cookie „${name}“ wird auch von fremden Seiten mitgeschickt`, severity: 'low', category: 'Config', description: `Dem Cookie „${name}“ fehlt das Attribut „SameSite“.`, impact: 'Eine fremde Seite kann im Hintergrund Anfragen an diese Seite auslösen, bei denen das Cookie mitgeschickt wird – etwa um im Namen eines angemeldeten Besuchers etwas zu ändern (CSRF).', remediation: 'Beim Setzen des Cookies "SameSite=Lax" oder "SameSite=Strict" ergänzen.', confidence: 'medium' });
  }

  // --- CORS ---
  if (get1('access-control-allow-origin') === '*') {
    const creds = (get1('access-control-allow-credentials') || '').toLowerCase() === 'true';
    add({ ruleId: 'cors-wildcard', title: 'Jede fremde Webseite darf Antworten dieses Servers lesen', severity: creds ? 'high' : 'medium', category: 'AccessControl', description: creds ? 'Der Server erlaubt jeder Webseite, Antworten zu lesen – auch mit den Anmeldedaten der Besucher (CORS: „*“ zusammen mit Credentials).' : 'Der Server erlaubt jeder Webseite, seine Antworten zu lesen (CORS: „*“).', impact: creds ? 'Eine präparierte Seite kann im Namen eingeloggter Besucher deren Daten abrufen.' : 'Unkritisch bei öffentlichen Daten; problematisch, wenn hier interne oder persönliche Daten ausgeliefert werden.', remediation: 'Erlaubte Herkunftsadressen als feste Liste pflegen; „*“ nie zusammen mit Anmeldedaten.', confidence: 'high' });
  }

  // --- Server-Banner / Info-Leak ---
  // Exakte Version (z. B. nginx/1.18.0, PHP/8.1.2) = LOW; nur der Produktname = INFO.
  const VERSIONED = /[A-Za-z][\w.-]*\/\d+(?:\.\d+)+/;
  for (const [hdr, label] of [['server', 'Server'], ['x-powered-by', 'X-Powered-By']]) {
    const val = get1(hdr);
    if (!val) continue;
    if (VERSIONED.test(val)) add({ ruleId: `version-disclosure-${hdr}`, evidence: `${label}: ${val}`, title: `Server verrät seine Software-Version (${val})`, severity: 'low', category: 'Config', description: `Der Server nennt in jeder Antwort die genaue Software und Version: „${val}“.`, impact: 'Angreifer sehen sofort, welche bekannten Lücken zu genau dieser Version passen, und können gezielt danach suchen.', remediation: `Die Versionsangabe im "${label}"-Header abschalten – und die Software aktuell halten.`, confidence: 'high' });
    else if (hdr === 'x-powered-by') add({ ruleId: 'tech-disclosure-x-powered-by', evidence: `${label}: ${val}`, title: `Server verrät die eingesetzte Technik (${val})`, severity: 'info', category: 'Config', description: `Der Server nennt in jeder Antwort die eingesetzte Technik: „${val}“.`, impact: 'Gering: erleichtert Angreifern nur die Vorbereitung.', remediation: 'Den Header "X-Powered-By" entfernen.', confidence: 'high' });
  }

  // --- Inhalts-Checks aus der Antwort ---
  const body = res.body || '';
  if (https && /(?:src|href|action)\s*=\s*["']http:\/\/(?!localhost|127\.0\.0\.1)/i.test(body)) add({ ruleId: 'mixed-content', title: 'Verschlüsselte Seite lädt Teile unverschlüsselt nach', severity: 'low', category: 'Transport', description: 'Die Seite selbst ist verschlüsselt, bindet aber Bilder, Skripte oder Formulare über unverschlüsseltes „http://“ ein.', impact: 'Diese Teile können unterwegs ausgetauscht werden – bei Skripten oder Formularen auch mit schädlichem Inhalt.', remediation: 'Alle eingebundenen Inhalte über "https://" laden.', confidence: 'medium' });
  if (/<title>\s*Index of \/|<h1>\s*Index of \//i.test(body)) add({ ruleId: 'directory-listing', title: 'Server zeigt Dateilisten von Ordnern an', severity: 'low', category: 'Config', description: 'Ruft man einen Ordner ohne Startseite auf, zeigt der Server alle darin liegenden Dateien an.', impact: 'Fremde finden so Dateien, die nicht für sie gedacht sind, etwa Sicherungen oder Konfigurationen.', remediation: 'Die Ordner-Auflistung am Webserver abschalten (z. B. "Options -Indexes" oder "autoindex off").', confidence: 'high' });

  // --- Gefaehrliche HTTP-Methoden ---
  const opt = await get(url, 'OPTIONS', signal);
  if (opt.ok) {
    const allow = (opt.headers.get('allow') || '').toUpperCase();
    if (allow.includes('TRACE')) add({ ruleId: 'http-trace', title: 'Server spiegelt Anfragen zurück (HTTP TRACE)', severity: 'medium', category: 'Config', description: 'Der Server beantwortet die Testfunktion TRACE, die eine Anfrage samt Kopfzeilen unverändert zurückschickt.', impact: 'In Verbindung mit anderen Lücken können darüber geschützte Cookies ausgelesen werden.', remediation: 'TRACE am Webserver abschalten.', confidence: 'medium' });
    const bad = ['PUT', 'DELETE', 'CONNECT'].filter((m) => allow.includes(m));
    if (bad.length) add({ ruleId: 'http-write-methods', title: `Server meldet ändernde Befehle als erlaubt (${bad.join(', ')})`, severity: 'low', category: 'Config', description: `Der Server gibt an, Befehle zum Hochladen oder Löschen (${bad.join(', ')}) zu akzeptieren.`, impact: 'Sind diese wirklich ohne Anmeldung nutzbar, könnten Fremde Dateien ablegen oder löschen. Oft ist es nur eine zu großzügige Angabe.', remediation: 'Nicht benötigte Befehle am Webserver sperren.', confidence: 'low' });
  }

  // --- Offengelegte Pfade (nur GET, feste kleine Liste) ---
  onProgress({ phase: 'webscan', message: 'Prüfe auf offengelegte Pfade …' });
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

  notes.push(`Server-Prüfung abgeschlossen: ${res.finalUrl || url} (${findings.length} Befund[e]).`);
  return { findings, notes };
}

module.exports = { scanWeb };
