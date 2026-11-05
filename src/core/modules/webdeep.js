'use strict';

// Tiefe Web-Pruefung eigener Seiten – zerstoerungsfrei:
//
//  web-crawl        geht Unterseiten derselben Domain durch (Links, Formulare, Parameter) und
//                   prueft Formulare: Passwort ueber HTTP, fehlender CSRF-Schutz, Passwort in der URL
//  web-probe        nur fuer nachgewiesene/interne Domains, nur GET: harmlose Testwerte in gefundene
//                   Parameter (XSS-Reflexion, SQL-Fehlermeldungen, offene Weiterleitung, Pfad-Ausbruch)
//  web-login        nur fuer nachgewiesene/interne Domains, mit einem TESTKONTO aus den Einstellungen:
//                   Anmeldung ueber HTTPS, neue Sitzung nach Login (Session Fixation), Cookie-Schutz,
//                   verraet die Anmeldung existierende Konten, beendet Abmelden die Sitzung,
//                   danach Durchgang durch den angemeldeten Bereich (inkl. Proben)
//
// Bewusst NICHT: Passwoerter durchprobieren, Formulare abschicken (ausser dem Test-Login),
// POST/PUT/DELETE an die Anwendung, Last. Alles gedrosselt ueber den WafGuard.

const { normalizeFinding } = require('../schema');
const { WafGuard, request } = require('./web');

const W = (module, o) => normalizeFinding({ confidence: 'high', ...o, sourceModule: module }, module);
const MAX_PAGES = 40;
const MAX_PROBE_PARAMS = 25;

// --- kleine Helfer --------------------------------------------------------------
function cookiesFrom(res) {
  const raw = (res.headers && typeof res.headers.getSetCookie === 'function') ? res.headers.getSetCookie() : [];
  return raw.map((c) => { const [nv, ...attrs] = c.split(';'); const i = nv.indexOf('='); return { name: nv.slice(0, i).trim(), value: nv.slice(i + 1).trim(), raw: c, attrs: attrs.map((a) => a.trim().toLowerCase()) }; }).filter((c) => c.name);
}
class Jar {
  constructor() { this.c = new Map(); }
  take(res) { for (const k of cookiesFrom(res)) { if (/max-age=0|expires=thu, 01 jan 1970/i.test(k.raw) || k.value === '') this.c.delete(k.name); else this.c.set(k.name, k); } return this; }
  header() { return [...this.c.values()].map((k) => `${k.name}=${k.value}`).join('; '); }
  clone() { const j = new Jar(); for (const [n, v] of this.c) j.c.set(n, { ...v }); return j; }
}
const attr = (tag, name) => { const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')); return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null; };
const decode = (s) => String(s || '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'");

function parseForms(html, pageUrl) {
  const forms = [];
  const re = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi; let m;
  while ((m = re.exec(html)) && forms.length < 30) {
    const action = decode(attr(m[1], 'action') || '');
    let url; try { url = new URL(action || pageUrl, pageUrl).href; } catch { continue; }
    const inputs = [...m[2].matchAll(/<(input|select|textarea)\b([^>]*)>/gi)].map((x) => ({ tag: x[1].toLowerCase(), name: attr(x[2], 'name') || '', type: (attr(x[2], 'type') || 'text').toLowerCase(), value: decode(attr(x[2], 'value') || '') }));
    forms.push({ page: pageUrl, action: url, method: (attr(m[1], 'method') || 'get').toLowerCase(), inputs });
  }
  return forms;
}
const CSRF_NAME = /csrf|xsrf|_token|authenticity|nonce|__requestverificationtoken|anti.?forgery/i;

function sameSite(u, base) { try { return new URL(u).host === new URL(base).host; } catch { return false; } }
function links(html, pageUrl) {
  const out = new Set();
  for (const m of String(html || '').matchAll(/\b(?:href|src|action)\s*=\s*["']([^"'#]+)/gi)) {
    try { const u = new URL(decode(m[1]), pageUrl); if (/^https?:$/.test(u.protocol)) { u.hash = ''; out.add(u.href); } } catch { /* ungueltig */ }
  }
  return [...out];
}
const isPageLike = (u) => !/\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|map|woff2?|ttf|eot|pdf|zip|gz|mp4|mp3|webm|avi|docx?|xlsx?|pptx?)(\?|$)/i.test(u);
const isLogout = (u) => /log-?out|sign-?out|abmelden|logoff/i.test(u);

// --- Durchgang ------------------------------------------------------------------------
async function crawl(start, guard, { jar, signal, max = MAX_PAGES } = {}) {
  const queue = [start];
  const seen = new Set();
  const pages = [];
  while (queue.length && pages.length < max) {
    if (signal && signal.aborted) break;
    const url = queue.shift();
    const key = url.replace(/\?.*$/, (q) => '?' + [...new URLSearchParams(q.slice(1)).keys()].sort().join('&'));
    if (seen.has(key) || isLogout(url)) continue;
    seen.add(key);
    const r = await request(guard, url, { headers: jar && jar.c.size ? { Cookie: jar.header() } : {}, signal });
    if (!r.ok) continue;
    if (jar) jar.take(r);
    if (r.status >= 300 && r.status < 400 && r.headers.get('location')) {
      try { const to = new URL(r.headers.get('location'), url).href; if (sameSite(to, start)) queue.push(to); } catch { /* egal */ }
      continue;
    }
    if (!/html/i.test(r.headers.get('content-type') || '')) continue;
    const page = { url, status: r.status, html: r.body, headers: r.headers, forms: parseForms(r.body, url) };
    pages.push(page);
    for (const l of links(r.body, url)) if (sameSite(l, start) && isPageLike(l)) queue.push(l);
  }
  return pages;
}

// Formular-Pruefungen (passiv, auf jeder gefundenen Seite)
function formFindings(pages, { loggedIn = false } = {}) {
  const out = [];
  const seen = new Set();
  const M = 'web-crawl';
  for (const p of pages) for (const f of p.forms) {
    const pw = f.inputs.some((i) => i.type === 'password');
    const once = (k) => { const s = `${k}|${f.action.replace(/\?.*/, '')}`; if (seen.has(s)) return false; seen.add(s); return true; };
    if (pw && (/^http:/i.test(f.action) || /^http:/i.test(p.url)) && once('pw-http')) out.push(W(M, { ruleId: 'form-password-http', severity: 'critical', category: 'Transport', title: 'Passwort wird unverschlüsselt übertragen', description: `Das Anmeldeformular auf ${p.url} sendet an ${f.action} – ohne HTTPS. Jeder im selben Netz (z. B. öffentliches WLAN) kann das Passwort mitlesen.`, remediation: 'Seite und Formularziel ausschließlich über HTTPS ausliefern und HTTP auf HTTPS umleiten.', location: p.url }));
    if (pw && f.method === 'get' && once('pw-get')) out.push(W(M, { ruleId: 'form-password-get', severity: 'high', category: 'Auth', title: 'Passwort landet in der Adresszeile', description: `Das Formular auf ${p.url} sendet das Passwort per GET. Es steht damit in der URL, im Browserverlauf und in Server-Logs.`, remediation: 'method="post" verwenden.', location: p.url }));
    if (f.method === 'post' && (loggedIn || pw) && !f.inputs.some((i) => i.type === 'hidden' && CSRF_NAME.test(i.name)) && once('csrf')) {
      out.push(W(M, { ruleId: 'form-no-csrf', severity: loggedIn ? 'medium' : 'low', category: 'AccessControl', confidence: 'medium', title: `Formular ohne erkennbaren CSRF-Schutz${loggedIn ? ' im angemeldeten Bereich' : ''}`, description: `Das Formular auf ${p.url} (Ziel ${f.action}) enthält kein verstecktes Schutz-Token. Eine fremde Webseite könnte angemeldete Besucher unbemerkt dieses Formular abschicken lassen.`, impact: 'Aktionen im Namen des Opfers, z. B. E-Mail oder Passwort ändern.', remediation: 'CSRF-Token in jedes Formular einbauen (die meisten Frameworks haben das eingebaut) und Sitzungs-Cookies mit SameSite=Lax oder Strict setzen.', location: p.url }));
    }
  }
  return out;
}

// --- Proben in Parametern (nur GET, harmlose Werte) -----------------------------------------
const SQL_ERR = /SQL syntax|mysql_fetch|mysqli?_|ORA-\d{5}|PostgreSQL.*ERROR|pg_query|SQLite3?::|SQLSTATE\[|Unclosed quotation mark|quoted string not properly terminated|ODBC .*Driver|Microsoft OLE DB|syntax error at or near|You have an error in your SQL/i;
const REDIRECT_PARAM = /^(next|url|redirect|redirect_?uri|redirect_?url|return|return_?to|returnurl|continue|dest|destination|goto|target|r|u)$/i;
const FILE_PARAM = /^(file|path|page|template|include|doc|document|folder|dir|view|load|download)$/i;

function paramTargets(pages) {
  const out = [];
  const seen = new Set();
  for (const p of pages) {
    const getForms = p.forms.filter((f) => f.method === 'get').map((f) => { const u = new URL(f.action); for (const i of f.inputs) if (i.name && !['submit', 'button', 'password'].includes(i.type)) u.searchParams.set(i.name, i.value || 'test'); return u.href; });
    for (const c of [p.url, ...links(p.html, p.url), ...getForms]) {
      let u; try { u = new URL(c); } catch { continue; }
      if (!sameSite(u.href, p.url) || isLogout(u.href)) continue;
      for (const k of u.searchParams.keys()) {
        const id = `${u.origin}${u.pathname}?${k}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push({ url: u.href, param: k });
        if (out.length >= MAX_PROBE_PARAMS) return out;
      }
    }
  }
  return out;
}

async function probe(guard, targets, { jar, signal } = {}) {
  const M = 'web-probe';
  const out = [];
  const H = () => (jar && jar.c.size ? { Cookie: jar.header() } : {});
  const withParam = (url, k, v) => { const u = new URL(url); u.searchParams.set(k, v); return u.href; };
  for (const t of targets) {
    if (signal && signal.aborted) break;
    const loc = `${t.url.replace(/\?.*$/, '')} (Parameter „${t.param}“)`;
    const base = await request(guard, t.url, { headers: H(), signal });
    if (!base.ok) continue;
    // 1. Reflexion: wird ein Testwert mit Sonderzeichen unveraendert in die Seite geschrieben?
    const mark = `vgl${Math.random().toString(36).slice(2, 8)}`;
    const r1 = await request(guard, withParam(t.url, t.param, `${mark}"'<b>${mark}`), { headers: H(), signal });
    if (r1.ok && /html/i.test(r1.headers.get('content-type') || '') && r1.body.includes(`<b>${mark}`)) out.push(W(M, { ruleId: 'probe-xss-reflected', severity: 'high', category: 'XSS', title: `Eingabe wird ungefiltert in die Seite geschrieben (XSS) – „${t.param}“`, description: `Vigil hat einen harmlosen Testwert mit HTML-Zeichen in „${t.param}“ gesendet. Er kam unverändert in der Seite zurück. Damit lässt sich über einen präparierten Link Skriptcode im Browser von Besuchern ausführen.`, impact: 'Sitzungen übernehmen, Eingaben mitlesen, die Seite im Namen des Opfers bedienen.', remediation: 'Alle Ausgaben kontextgerecht maskieren (Template-Engine mit Auto-Escape) und eine Content-Security-Policy setzen.', location: loc, evidence: `Antwort enthält <b>${mark}` }));
    // 2. SQL: erzeugt ein einzelnes Anfuehrungszeichen eine Datenbank-Fehlermeldung?
    if (!SQL_ERR.test(base.body)) {
      const orig = new URL(t.url).searchParams.get(t.param) || '1';
      const r2 = await request(guard, withParam(t.url, t.param, `${orig}'"`), { headers: H(), signal });
      if (r2.ok && SQL_ERR.test(r2.body)) out.push(W(M, { ruleId: 'probe-sql-error', severity: 'critical', category: 'Injection', title: `Datenbank-Fehler durch ein Anführungszeichen – „${t.param}“ (SQL-Injection)`, description: `Ein angehängtes Anführungszeichen in „${t.param}“ löst eine Datenbank-Fehlermeldung aus („${(r2.body.match(SQL_ERR) || [''])[0]}“). Der Wert wird also direkt in den SQL-Befehl eingesetzt.`, impact: 'Über diesen Parameter lässt sich die Datenbank sehr wahrscheinlich auslesen oder verändern.', remediation: 'Prepared Statements bzw. Platzhalter verwenden und Fehlermeldungen nicht an Besucher ausgeben.', location: loc }));
    }
    // 3. Offene Weiterleitung
    if (REDIRECT_PARAM.test(t.param)) {
      const r3 = await request(guard, withParam(t.url, t.param, 'https://vigil-redirect-test.invalid/'), { headers: H(), signal, readBody: false });
      const to = r3.ok ? r3.headers.get('location') || '' : '';
      if (r3.ok && r3.status >= 300 && r3.status < 400 && /^(https?:)?\/\/vigil-redirect-test\.invalid/i.test(to)) out.push(W(M, { ruleId: 'probe-open-redirect', severity: 'medium', category: 'Config', title: `Offene Weiterleitung über „${t.param}“`, description: `Die Seite leitet auf jede beliebige Adresse weiter, die in „${t.param}“ steht. Phishing-Links sehen dadurch aus, als kämen sie von deiner Domain.`, remediation: 'Nur relative Pfade oder Ziele aus einer festen Liste erlauben.', location: loc }));
    }
    // 4. Pfad-Ausbruch: liefert ein ../-Pfad bekannte Systemdateien?
    if (FILE_PARAM.test(t.param)) {
      for (const v of ['../../../../../../etc/passwd', '..\\..\\..\\..\\..\\..\\windows\\win.ini']) {
        const r4 = await request(guard, withParam(t.url, t.param, v), { headers: H(), signal });
        if (r4.ok && (/root:[x*]?:0:0:/.test(r4.body) || /\[fonts\][\s\S]{0,200}\[extensions\]/i.test(r4.body))) { out.push(W(M, { ruleId: 'probe-path-traversal', severity: 'critical', category: 'PathTraversal', title: `Systemdateien über „${t.param}“ lesbar (Path Traversal)`, description: `Mit ../ in „${t.param}“ liefert der Server eine Systemdatei (${v.includes('passwd') ? '/etc/passwd' : 'win.ini'}). Damit lassen sich auch Konfigurationsdateien mit Passwörtern lesen.`, remediation: 'Nur Dateinamen aus einer festen Liste erlauben bzw. den Pfad normalisieren und prüfen, dass er im erlaubten Ordner bleibt.', location: loc })); break; }
      }
    }
  }
  return out;
}

// --- Login mit Testkonto ------------------------------------------------------------------
const norm = (s) => String(s || '').replace(/<input[^>]*type=["']?hidden[^>]*>/gi, '').replace(/[0-9a-f]{16,}/gi, '').replace(/\d+/g, '').replace(/\s+/g, ' ');
const looksLoggedOut = (html) => /type=["']?password/i.test(html || '');

function buildLoginBody(form, user, pass, { userField, passField } = {}) {
  const p = new URLSearchParams();
  const pw = form.inputs.find((i) => i.type === 'password' && (!passField || i.name === passField));
  const us = (userField ? form.inputs.find((i) => i.name === userField) : null)
    || form.inputs.find((i) => ['email', 'text'].includes(i.type) && /user|mail|login|name|konto|account|benutzer/i.test(i.name))
    || form.inputs.find((i) => ['email', 'text'].includes(i.type) && i.name);
  for (const i of form.inputs) if (i.name && i.type === 'hidden') p.set(i.name, i.value);
  if (us) p.set(us.name, user);
  if (pw) p.set(pw.name, pass);
  return { body: p.toString(), userName: us && us.name, passName: pw && pw.name };
}

// Testkonto und Cookies gehen nie an einen anderen Host als die freigegebene Anmeldeseite:
// Formularziel und jede Weiterleitung muessen auf demselben Host bleiben, sonst wird abgebrochen.
async function postForm(guard, url, body, jar, signal, home = url) {
  if (!sameSite(url, home)) return { ok: false, offsite: true, error: `Formular sendet an fremden Host (${new URL(url).host})`, finalUrl: url };
  let r = await request(guard, url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(jar.c.size ? { Cookie: jar.header() } : {}) }, body, signal });
  if (r.ok) jar.take(r);
  let final = url;
  for (let i = 0; i < 4 && r.ok && r.status >= 300 && r.status < 400 && r.headers.get('location'); i++) {
    const next = new URL(r.headers.get('location'), final).href;
    if (!sameSite(next, home)) return { ...r, offsite: true, finalUrl: next };
    final = next;
    r = await request(guard, final, { headers: jar.c.size ? { Cookie: jar.header() } : {}, signal });
    if (r.ok) jar.take(r);
  }
  return { ...r, finalUrl: final };
}

async function loginAudit(cfg, guard, { signal, onProgress = () => {} } = {}) {
  const M = 'web-login';
  const out = [], notes = [];
  const jar = new Jar();
  const page = await request(guard, cfg.loginUrl, { signal });
  if (!page.ok) return { findings: out, notes: [`Login-Prüfung: Anmeldeseite nicht erreichbar (${page.error}).`] };
  jar.take(page);
  const form = parseForms(page.body, cfg.loginUrl).find((f) => f.inputs.some((i) => i.type === 'password'));
  if (!form) return { findings: out, notes: ['Login-Prüfung: kein Anmeldeformular mit Passwortfeld gefunden. Anmeldungen per JavaScript/API (z. B. Single-Page-Apps) prüft Vigil noch nicht automatisch.'] };
  if (/^http:/i.test(cfg.loginUrl) || /^http:/i.test(form.action)) out.push(W(M, { ruleId: 'form-password-http', severity: 'critical', category: 'Transport', title: 'Anmeldung ohne HTTPS', description: 'Anmeldeseite oder Formularziel nutzen HTTP. Passwörter lassen sich unterwegs mitlesen.', remediation: 'Ausschließlich HTTPS verwenden.', location: cfg.loginUrl }));
  const before = jar.clone();
  onProgress({ phase: 'webscan', message: 'Login-Prüfung: Anmeldung mit dem Testkonto …' });
  const { body, userName, passName } = buildLoginBody(form, cfg.username, cfg.password, cfg);
  if (!userName || !passName) return { findings: out, notes: ['Login-Prüfung: Benutzer- oder Passwortfeld nicht eindeutig erkannt – Feldnamen in den Einstellungen angeben.'] };
  const res = await postForm(guard, form.action, body, jar, signal, cfg.loginUrl);
  if (res.offsite) return { findings: out, notes: [`Login-Prüfung abgebrochen: Die Anmeldung führt zu einem anderen Host (${new URL(res.finalUrl).host}). Vigil schickt das Testkonto nur an die freigegebene Domain.`] };
  const changed = [...jar.c.values()].filter((k) => !before.c.has(k.name) || before.c.get(k.name).value !== k.value);
  const ok = res.ok && res.status < 400 && !looksLoggedOut(res.body) && (changed.length > 0 || res.finalUrl !== form.action);
  if (!ok) return { findings: out, notes: [`Login-Prüfung: Anmeldung mit dem Testkonto hat nicht geklappt (Status ${res.status || res.error}). Zugangsdaten und Anmelde-Adresse prüfen.`] };
  notes.push(`Login-Prüfung: Anmeldung mit dem Testkonto erfolgreich (${new URL(res.finalUrl).pathname}).`);
  // Sitzungs-Cookie: das beim Login vergebene Cookie (bevorzugt mit Sitzungs-Namen)
  const sessionName = (changed.find((k) => /sess|sid|auth|token|login|jwt|identity/i.test(k.name)) || changed[0] || {}).name
    || [...before.c.keys()].find((n) => /sess|sid|auth/i.test(n));
  const session = sessionName ? jar.c.get(sessionName) : null;
  if (session) {
    const old = before.c.get(session.name);
    if (old && old.value === session.value) out.push(W(M, { ruleId: 'login-session-fixation', severity: 'high', category: 'Auth', title: 'Sitzung wird beim Anmelden nicht erneuert (Session Fixation)', description: `Das Sitzungs-Cookie „${session.name}“ hat vor und nach dem Login denselben Wert. Wer einem Opfer vorher eine Sitzungskennung unterschiebt, ist nach dessen Anmeldung mit angemeldet.`, remediation: 'Nach erfolgreichem Login immer eine neue Sitzungskennung vergeben (z. B. session.regenerate()).', location: cfg.loginUrl }));
    const a = session.attrs.join(';');
    const miss = [!/httponly/.test(a) && 'HttpOnly', !/secure/.test(a) && 'Secure', !/samesite=(lax|strict)/.test(a) && 'SameSite'].filter(Boolean);
    if (miss.length) out.push(W(M, { ruleId: 'login-session-cookie-flags', severity: miss.includes('HttpOnly') || miss.includes('Secure') ? 'high' : 'medium', category: 'Auth', title: `Anmelde-Cookie „${session.name}“ ohne ${miss.join(', ')}`, description: `Nach dem Login setzt die Seite „${session.name}“ ohne ${miss.join(', ')}. ${miss.includes('HttpOnly') ? 'Skripte können es lesen (gefährlich bei XSS). ' : ''}${miss.includes('Secure') ? 'Es kann unverschlüsselt übertragen werden. ' : ''}${miss.includes('SameSite') ? 'Fremde Seiten können es bei Anfragen mitschicken lassen (CSRF).' : ''}`.trim(), remediation: `Set-Cookie: ${session.name}=…; HttpOnly; Secure; SameSite=Lax`, location: cfg.loginUrl }));
  }
  // Verraet die Anmeldung, ob ein Konto existiert? (2 Fehlversuche, kein Durchprobieren)
  onProgress({ phase: 'webscan', message: 'Login-Prüfung: Antworten bei falschen Daten …' });
  const tryWrong = async (user) => { const j = new Jar(); const p = await request(guard, cfg.loginUrl, { signal }); if (!p.ok) return null; j.take(p); const f = parseForms(p.body, cfg.loginUrl).find((x) => x.inputs.some((i) => i.type === 'password')) || form; return postForm(guard, f.action, buildLoginBody(f, user, `vigil-falsch-${Date.now()}`, cfg).body, j, signal, cfg.loginUrl); };
  const a1 = await tryWrong(cfg.username);
  const a2 = await tryWrong(`vigil-gibt-es-nicht-${Math.random().toString(36).slice(2, 8)}@example.invalid`);
  if (a1 && a2 && a1.ok && a2.ok && !a1.offsite && !a2.offsite) {
    const t1 = norm(a1.body), t2 = norm(a2.body);
    const diff = a1.status !== a2.status || new URL(a1.finalUrl).pathname !== new URL(a2.finalUrl).pathname || Math.abs(t1.length - t2.length) > Math.max(30, t1.length * 0.03);
    if (diff) out.push(W(M, { ruleId: 'login-user-enumeration', severity: 'medium', category: 'Auth', confidence: 'medium', title: 'Anmeldung verrät, ob ein Konto existiert', description: 'Bei falschem Passwort für ein existierendes Konto antwortet die Seite anders als bei einem nicht existierenden Konto (andere Meldung, Weiterleitung oder Länge). So lassen sich gültige Benutzernamen bzw. E-Mail-Adressen sammeln.', impact: 'Erleichtert gezieltes Passwort-Raten und Phishing.', remediation: 'Immer dieselbe Meldung ausgeben, z. B. „E-Mail oder Passwort falsch“, und gleich schnell antworten.', location: cfg.loginUrl }));
  }
  notes.push('Login-Prüfung: Sperre nach vielen Fehlversuchen wird bewusst nicht getestet (kein Durchprobieren von Passwörtern).');
  // Angemeldeter Bereich: durchgehen, Formulare pruefen, Parameter proben
  onProgress({ phase: 'webscan', message: 'Login-Prüfung: angemeldeter Bereich …' });
  const authPages = await crawl(res.finalUrl, guard, { jar, signal, max: 30 });
  out.push(...formFindings(authPages, { loggedIn: true }));
  out.push(...(await probe(guard, paramTargets(authPages), { jar, signal })));
  // Abmelden: ist die alte Sitzung danach wirklich ungueltig?
  const protectedPage = authPages.find((p) => p.status === 200 && !looksLoggedOut(p.html) && p.url !== cfg.loginUrl);
  const logoutUrl = authPages.flatMap((p) => links(p.html, p.url)).find((l) => sameSite(l, res.finalUrl) && isLogout(l));
  if (protectedPage && logoutUrl) {
    const oldCookies = jar.header();
    await request(guard, logoutUrl, { headers: { Cookie: oldCookies }, signal, readBody: false });
    const again = await request(guard, protectedPage.url, { headers: { Cookie: oldCookies }, signal });
    if (again.ok && again.status === 200 && !looksLoggedOut(again.body) && norm(again.body).length > 0.8 * norm(protectedPage.html).length) out.push(W(M, { ruleId: 'login-logout-not-invalidated', severity: 'medium', category: 'Auth', title: 'Abmelden beendet die Sitzung nicht', description: `Nach dem Abmelden ist ${protectedPage.url} mit dem alten Sitzungs-Cookie weiter erreichbar. Ein gestohlenes Cookie bleibt so gültig, auch wenn sich das Opfer abmeldet.`, remediation: 'Beim Abmelden die Sitzung auf dem Server löschen, nicht nur das Cookie im Browser.', location: logoutUrl }));
    notes.push('Login-Prüfung: Abmelden geprüft.');
  } else notes.push('Login-Prüfung: kein Abmelde-Link gefunden – Sitzungsende nicht geprüft.');
  return { findings: out, notes, ran: true, pages: authPages.length };
}

// --- Einstieg -----------------------------------------------------------------------------
// opts: { deep (verifiziert/intern), login: {loginUrl, username, password, userField?, passField?} | null }
async function runDeepWeb(targetUrl, { deep = false, login = null, rps = 4, signal, onProgress = () => {} } = {}) {
  const guard = new WafGuard(rps);
  const findings = [], notes = [], ran = [];
  const scripts = new Set(); // eingebundene Skripte (fuer den Abgleich verwundbarer Bibliotheken)
  let cmsHints = []; // CMS-Kern/Plugins mit Version aus dem HTML (Abgleich in supplychain.js)
  const url = /^https?:\/\//i.test(targetUrl) ? targetUrl : 'https://' + targetUrl;
  let crawled = []; // gefundene Seiten fuer die Zusatzpruefungen (websuite.js), nur im Speicher
  try {
    onProgress({ phase: 'webscan', message: `Unterseiten und Formulare: ${new URL(url).host} …` });
    const pages = await crawl(url, guard, { signal, max: deep ? MAX_PAGES : 12 });
    crawled = pages;
    findings.push(...formFindings(pages));
    try { cmsHints = require('./cms').cmsFromHtml(pages); } catch { /* nur Zusatzinfo */ }
    for (const p of pages) for (const m of String(p.html).matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)/gi)) { try { scripts.add(new URL(m[1], p.url).href); } catch { /* egal */ } }
    if (pages.length) ran.push('web-crawl'); else notes.push('Webseite nicht erreichbar – Durchgang übersprungen, bestehende Befunde bleiben offen.');
    notes.push(`Webseite durchgegangen: ${pages.length} Seite(n), ${pages.reduce((n, p) => n + p.forms.length, 0)} Formular(e).`);
    if (deep) {
      const targets = paramTargets(pages);
      onProgress({ phase: 'webscan', message: `Schwachstellen-Proben: ${targets.length} Parameter …` });
      findings.push(...(await probe(guard, targets, { signal })));
      if (pages.length) ran.push('web-probe');
      notes.push(`Schwachstellen-Proben: ${targets.length} Parameter mit harmlosen Testwerten geprüft (nur GET).`);
      if (login && login.loginUrl && login.username && login.password) {
        const l = await loginAudit(login, guard, { signal, onProgress });
        findings.push(...l.findings); notes.push(...l.notes);
        if (l.ran) ran.push('web-login');
      }
    } else notes.push('Schwachstellen-Proben und Login-Prüfung nur für nachgewiesene eigene Domains (Übersicht › Verifizieren).');
  } catch (e) {
    if (e.throttled) return { findings, notes: [...notes, e.message], ran, throttled: true, scripts: [...scripts], cmsHints, pages: crawled };
    notes.push('Tiefe Web-Prüfung: ' + e.message);
  }
  return { findings, notes, ran, throttled: false, scripts: [...scripts], cmsHints, pages: crawled };
}

module.exports = { runDeepWeb, crawl, parseForms, formFindings, paramTargets, probe, loginAudit, Jar, buildLoginBody, links, attr, sameSite, isLogout };
