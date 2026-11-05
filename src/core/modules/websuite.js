'use strict';

// Zusatzpruefungen fuer Webseiten (laeuft nach Server-Check, Durchgang und Browser-Pruefung).
// Alles lesend und gedrosselt: nur GET/HEAD an das freigegebene Ziel, DNS-Abfragen und wenige
// Auskunftsdienste (webnet.OUTBOUND_HOSTS). Keine Formulare, keine Anmeldung, keine Last.
//
//  web-sectxt   /.well-known/security.txt (RFC 9116): vorhanden, Contact, gueltiges Expires
//  web-links    defekte Links derselben Seite (nur Links aus bereits geladenen Seiten)
//  js-secrets   Zugangsdaten und interne Adressen in ausgelieferten JavaScript-Dateien
//  api-live     OpenAPI-Beschreibung: jeder GET-Endpunkt einmal ohne Anmeldung (nur verifiziert)
//  … sowie die Auswertungen aus webpage.js und webnet.js

const crypto = require('crypto');
const { normalizeFinding, redactSecret } = require('../schema');
const { WafGuard, request, registrableDomain, crtShSubdomains } = require('./web');
const { links: pageLinks, sameSite, isLogout } = require('./webdeep');
const { SECRET_RULES } = require('../prescan');
const { isInternalHost, isAllowlisted } = require('../scope');
const page = require('./webpage');
const netc = require('./webnet');

const W = (m, o) => normalizeFinding({ confidence: 'high', ...o, sourceModule: m }, m);
const MAX_JS = 3 * 1024 * 1024;
const UA = 'Vigil-Audit/0.2 (+authorized,passive)';
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
const isIp = (h) => /^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':');

// Ganze Datei laden (fuer Hashes und Bundles), gedrosselt ueber den WafGuard.
async function fetchFull(guard, url, { signal, max = MAX_JS } = {}) {
  const host = new URL(url).host;
  await guard.before(host);
  const t = AbortSignal.timeout(15000);
  try {
    const res = await fetch(url, { headers: { 'User-Agent': UA }, redirect: 'follow', signal: signal ? AbortSignal.any([t, signal]) : t });
    guard.after(host, res.status);
    if (!res.ok) return { ok: false, status: res.status };
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.length > max ? { ok: false, status: res.status, tooBig: true } : { ok: true, status: res.status, buf, type: res.headers.get('content-type') || '' };
  } catch (e) { if (e.throttled) throw e; return { ok: false, error: e.message }; }
}

// Weiterleitungen nur innerhalb desselben Hosts (bzw. www-Variante) folgen.
async function follow(guard, url, opts = {}) {
  let cur = url;
  const t0 = Date.now();
  for (let i = 0; i < 5; i++) {
    const r = await request(guard, cur, opts);
    if (!r.ok) return { ...r, url: cur };
    const loc = r.status >= 300 && r.status < 400 && r.headers.get('location');
    if (!loc) return { ...r, url: cur, ms: Date.now() - t0 };
    const next = new URL(loc, cur).href;
    if (hostOf(next).replace(/^www\./, '') !== hostOf(url).replace(/^www\./, '')) return { ...r, url: cur, offsite: next };
    cur = next;
  }
  return { ok: false, error: 'zu viele Weiterleitungen', url: cur };
}

// --- security.txt (RFC 9116) -----------------------------------------------------------------------
function parseSecurityTxt(text) {
  const out = { contact: [], expires: null };
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z-]+)\s*:\s*(.+?)\s*$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === 'contact') out.contact.push(m[2]);
    if (k === 'expires') out.expires = m[2];
  }
  return out;
}
function securityTxtFindings(origin, r) {
  const M = 'web-sectxt';
  const loc = origin + '/.well-known/security.txt';
  const text = r && r.ok && r.status === 200 && !/<html|<!doctype/i.test(r.body || '') ? r.body : null;
  if (!text || !/^\s*(contact|expires)\s*:/im.test(text)) return [W(M, { ruleId: 'sectxt-missing', severity: 'info', category: 'Config', title: 'Keine security.txt – Sicherheitsforscher finden keinen Ansprechpartner', location: loc, description: 'Unter /.well-known/security.txt liegt keine Datei nach RFC 9116.', impact: 'Wer eine Lücke findet, weiß nicht, wem er sie melden soll – Meldungen gehen verloren oder landen öffentlich.', remediation: 'Eine security.txt mit Contact und Expires anlegen.', snippets: { 'security.txt': `Contact: mailto:security@${hostOf(origin).replace(/^www\./, '')}\nExpires: ${new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10)}T00:00:00Z\nPreferred-Languages: de, en\nCanonical: ${loc}` } })];
  const p = parseSecurityTxt(text);
  const out = [];
  if (!p.contact.length) out.push(W(M, { ruleId: 'sectxt-no-contact', severity: 'low', category: 'Config', title: 'security.txt ohne Contact-Angabe', location: loc, description: 'Die security.txt nennt keinen Kontakt. Contact ist nach RFC 9116 Pflicht.', remediation: 'Eine Zeile "Contact: mailto:…" oder "Contact: https://…" ergänzen.' }));
  const exp = p.expires ? new Date(p.expires) : null;
  if (!exp || Number.isNaN(exp.getTime())) out.push(W(M, { ruleId: 'sectxt-no-expires', severity: 'low', category: 'Config', title: 'security.txt ohne gültiges Ablaufdatum (Expires)', location: loc, evidence: p.expires ? `Expires: ${p.expires}` : '', description: 'Expires ist nach RFC 9116 Pflicht, damit veraltete Kontaktdaten erkennbar sind.', remediation: 'Eine Zeile "Expires: 2027-01-01T00:00:00Z" (höchstens ein Jahr in der Zukunft) ergänzen.' }));
  else if (exp.getTime() < Date.now()) out.push(W(M, { ruleId: 'sectxt-expired', severity: 'low', category: 'Config', title: 'security.txt ist abgelaufen', location: loc, evidence: `Expires: ${p.expires}`, description: `Die security.txt galt nur bis ${exp.toISOString().slice(0, 10)}. Melder müssen davon ausgehen, dass die Kontaktdaten veraltet sind.`, remediation: 'Kontaktdaten prüfen und das Expires-Datum erneuern (am besten jährlich automatisch).' }));
  return out;
}

// --- Zugangsdaten in ausgelieferten JavaScript-Dateien ------------------------------------------------------------
const SKIP_RULES = new Set(['Stripe Publishable Key (live)']); // absichtlich oeffentlich
const LOW_RULES = new Set(['Google API Key', 'JWT']); // im Frontend oft gewollt (Maps-Key, anonyme Tokens)
const INTERNAL_URL = /\b(?:https?|wss?):\/\/((?:localhost|127\.0\.0\.1)(?::\d+)(?:\/[^\s"'`)\\]*)?|(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:internal|local|lan|corp|intranet)(?::\d+)?|[a-z0-9-]+\.(?:dev|staging|stage|test|int)\.[a-z0-9-]+\.[a-z]{2,}(?::\d+)?)/gi;
function scanBundle(url, text, feedRules) {
  const M = 'js-secrets';
  const out = [];
  for (const rule of SECRET_RULES) {
    if (SKIP_RULES.has(rule.name)) continue;
    rule.re.lastIndex = 0;
    const m = rule.re.exec(text);
    if (!m) continue;
    const low = LOW_RULES.has(rule.name);
    const generic = /Generisch/.test(rule.name);
    out.push(W(M, { ruleId: 'jsbundle-secret-' + rule.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''), severity: low ? 'low' : generic ? 'medium' : rule.sev, category: 'Secrets', confidence: generic || low ? 'low' : 'medium', title: `Zugangsdaten im ausgelieferten JavaScript: ${rule.name}`, location: url, evidence: redactSecret(m[0]), description: `Die Datei wird an jeden Besucher ausgeliefert und enthält einen Wert im Format „${rule.name}“.${low ? ' Manche Schlüssel dieser Art sind für das Frontend gedacht – dann müssen sie beim Anbieter auf deine Domain beschränkt sein.' : ''}`, impact: 'Jeder kann die Datei im Browser öffnen und den Wert herauskopieren.', remediation: 'Geheime Schlüssel nie ins Frontend bauen: Schlüssel beim Anbieter sperren und neu erzeugen, Aufrufe über das eigene Backend leiten. Öffentliche Schlüssel beim Anbieter auf die eigene Domain einschränken.' }));
  }
  if (feedRules && feedRules.length) {
    const { scanSecretsWithFeed } = require('../feedscan');
    const seen = new Set(out.map((f) => f.evidence));
    for (const f of scanSecretsWithFeed([{ label: url, content: text.replace(/;/g, ';\n') }], feedRules).slice(0, 5)) {
      const ev = (f.description.match(/\(([^()]*REDACTED[^()]*)\)/) || [])[1] || '';
      if (ev && seen.has(ev)) continue;
      out.push(W(M, { ...f, ruleId: 'jsbundle-' + f.ruleId, title: f.title.replace(/^Zugangsdaten im Code:/, 'Zugangsdaten im ausgelieferten JavaScript:'), location: url, evidence: ev || undefined }));
    }
  }
  const internal = [...new Set([...text.matchAll(INTERNAL_URL)].map((m) => m[0].replace(/[\\]+$/, '')))].slice(0, 8);
  if (internal.length) out.push(W(M, { ruleId: 'jsbundle-internal-urls', severity: 'low', category: 'Config', confidence: 'low', title: `Interne Adressen im ausgelieferten JavaScript (${internal.length})`, location: url, evidence: internal.join(', ').slice(0, 400), description: `Die Datei verrät Adressen aus dem internen Netz oder von Test-Systemen: ${internal.slice(0, 5).join(', ')}.`, impact: 'Angreifer lernen so die interne Struktur kennen und finden oft schlechter geschützte Test- oder Admin-Systeme.', remediation: 'Adressen über Umgebungsvariablen je Umgebung setzen und Test-/Entwicklungswerte aus dem Produktions-Build entfernen.' }));
  return out;
}

// --- Defekte Links ---------------------------------------------------------------------------------------------
async function brokenLinks(base, pages, guard, { signal, max = 30 } = {}) {
  const ref = new Map();
  for (const p of pages) for (const l of pageLinks(p.html, p.url)) if (sameSite(l, base) && !ref.has(l)) ref.set(l, p.url);
  const crawled = new Map(pages.map((p) => [p.url, p.status]));
  const broken = [];
  for (const p of pages) if (p.status >= 400 && ![401, 403, 429].includes(p.status)) broken.push({ url: p.url, status: p.status, from: ref.get(p.url) || '' });
  let checked = 0;
  for (const [l, from] of ref) {
    if (checked >= max || (signal && signal.aborted)) break;
    if (crawled.has(l) || isLogout(l) || /[?&](logout|delete|remove|unsubscribe)=/i.test(l)) continue;
    checked++;
    let r = await request(guard, l, { method: 'HEAD', readBody: false, signal });
    if (r.ok && (r.status === 405 || r.status === 501)) r = await request(guard, l, { signal });
    if (r.ok && r.status >= 400 && ![401, 403, 429].includes(r.status)) broken.push({ url: l, status: r.status, from });
  }
  const out = [];
  if (broken.length) out.push(W('web-links', { ruleId: 'web-broken-links', severity: 'low', category: 'Other', title: `${broken.length} defekte Link(s) auf der eigenen Seite`, location: base, evidence: broken.slice(0, 10).map((b) => `${b.url} → HTTP ${b.status}${b.from ? ` ← ${b.from}` : ''}`).join(' · ').slice(0, 480), description: `Diese Adressen der eigenen Seite antworten mit einem Fehler: ${broken.slice(0, 5).map((b) => `${b.url} (HTTP ${b.status})`).join(', ')}.`, impact: 'Besucher landen im Leeren, und Suchmaschinen werten defekte Links ab.', remediation: 'Links korrigieren, entfernen oder die Zielseiten per Weiterleitung (301) auf den neuen Ort lenken.' }));
  return { findings: out, checked: checked + pages.length };
}

// --- OpenAPI: jeden GET-Endpunkt einmal ohne Anmeldung --------------------------------------------------------------
const SPEC_PATHS = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api/openapi.json', '/api-docs', '/swagger/v1/swagger.json'];
const SIDE_EFFECT = /logout|log-out|signout|delete|remove|reset|unsubscribe|send|trigger|cancel|revoke|purge|destroy|run|execute|approve/i;
const needsAuth = (sec) => Array.isArray(sec) && sec.some((s) => s && Object.keys(s).length);
async function apiLive(origin, guard, { specs = [], signal } = {}) {
  const M = 'api-live';
  const notes = [];
  let spec = null, specUrl = '';
  for (const s of specs) if (s && typeof s === 'object' && s.paths) { spec = s; specUrl = 'Einstellungen'; break; }
  for (const p of spec ? [] : SPEC_PATHS) {
    if (signal && signal.aborted) break;
    const r = await request(guard, origin + p, { signal, headers: { Accept: 'application/json' } });
    if (!r.ok || r.status !== 200) continue;
    try { const j = JSON.parse(r.body); if (j && j.paths && (j.openapi || j.swagger)) { spec = j; specUrl = origin + p; break; } } catch { /* kein JSON */ }
  }
  if (!spec) return { findings: [], notes: ['API-Prüfung: keine OpenAPI-Beschreibung gefunden (nur JSON wird gelesen).'], ran: true };
  let base = origin;
  try {
    const srv = spec.servers && spec.servers[0] && spec.servers[0].url ? new URL(spec.servers[0].url, origin) : new URL(spec.basePath || '/', origin);
    if (srv.host !== new URL(origin).host) return { findings: [], notes: [`API-Prüfung: Die API liegt auf ${srv.host} – nicht das geprüfte Ziel, deshalb übersprungen.`], ran: false };
    base = srv.origin + srv.pathname.replace(/\/+$/, '');
  } catch { /* Standard: origin */ }
  const global = spec.security;
  const ops = Object.entries(spec.paths).filter(([p, o]) => o && o.get && !/[{}:]/.test(p) && !SIDE_EFFECT.test(p)).slice(0, 25);
  const leaks = [], open = [];
  for (const [p, o] of ops) {
    if (signal && signal.aborted) break;
    const r = await request(guard, base + p, { signal, headers: { Accept: 'application/json' } });
    if (!r.ok || r.status !== 200) continue;
    const body = String(r.body || '').trim();
    if (body.length < 3 || /^(\[\]|\{\})$/.test(body) || /text\/html/i.test(r.headers.get('content-type') || '')) continue;
    const auth = o.get.security !== undefined ? needsAuth(o.get.security) : needsAuth(global);
    (auth ? leaks : open).push({ p, size: body.length });
  }
  const out = [];
  for (const l of leaks.slice(0, 10)) out.push(W(M, { ruleId: 'api-live-unauth-data', severity: 'high', category: 'AccessControl', title: `API-Endpunkt liefert Daten ohne Anmeldung: GET ${l.p}`, location: base + l.p, evidence: `HTTP 200 ohne Anmeldung, ${l.size} Zeichen`, description: 'Laut API-Beschreibung braucht dieser Endpunkt eine Anmeldung. Ein Abruf ohne Token oder Cookie liefert trotzdem Daten.', impact: 'Jeder im Internet kann diese Daten abrufen.', remediation: 'Die Anmeldung serverseitig für jeden Endpunkt erzwingen (Middleware/Guard), nicht nur in der Dokumentation.' }));
  if (open.length) out.push(W(M, { ruleId: 'api-live-public-data', severity: 'info', category: 'AccessControl', confidence: 'medium', title: `${open.length} öffentliche API-Endpunkt(e) liefern Daten ohne Anmeldung`, location: base, evidence: open.slice(0, 12).map((x) => 'GET ' + x.p).join(', '), description: `Diese Endpunkte sind laut Beschreibung öffentlich und liefern ohne Anmeldung Daten: ${open.slice(0, 8).map((x) => x.p).join(', ')}.`, remediation: 'Prüfen, ob alle diese Daten wirklich öffentlich sein sollen.' }));
  notes.push(`API-Prüfung: ${ops.length} GET-Endpunkt(e) aus ${specUrl} einmal ohne Anmeldung abgerufen.`);
  return { findings: out, notes, ran: true };
}

// --- Einstieg --------------------------------------------------------------------------------------------------------------
// opts: { deep, pages, scripts, observed (Browser-Daten), allowlist, previous (letzter Stand), feeds, openApi, rps, signal, onProgress, ctx }
async function runWebSuite(targetUrl, opts = {}) {
  const { deep = false, pages = [], scripts = [], observed = null, allowlist = [], previous = null, feeds = null, openApi = null, rps = 4, signal, onProgress = () => {}, ctx = {} } = opts;
  const guard = new WafGuard(rps);
  const extGuard = new WafGuard(rps); // fremde Skript-Server getrennt drosseln
  const findings = [], notes = [], ran = [];
  const url = /^https?:\/\//i.test(targetUrl) ? targetUrl : 'https://' + targetUrl;
  const host = hostOf(url);
  const internal = isInternalHost(host);
  const domain = isIp(host) || internal ? null : registrableDomain(host);
  const aborted = () => !!(signal && signal.aborted);
  const step = async (id, label, fn) => {
    if (aborted()) return;
    onProgress({ phase: 'webscan', message: `${label}: ${host} …` });
    try {
      const r = await fn();
      if (!r) return;
      findings.push(...(r.findings || []));
      notes.push(...(r.notes || []));
      if (r.ran !== false) ran.push(id);
    } catch (e) {
      if (e.throttled) throw e;
      notes.push(`${label}: ${e.message}`);
    }
  };
  let watch = null;
  try {
    // Startseite (eigene Anfrage: Header, Antwortzeit)
    const home = await follow(guard, url, { signal });
    if (!home.ok) return { findings, notes: [`Zusatzprüfungen: ${url} nicht erreichbar (${home.error || home.status}).`], ran, throttled: false, watch: null };
    const origin = new URL(home.url).origin;
    const https = origin.startsWith('https:');
    const homeHtml = /html/i.test(home.headers.get('content-type') || '') ? home.body : '';
    const allPages = pages.length ? pages : (homeHtml ? [{ url: home.url, status: home.status, html: homeHtml, headers: home.headers, forms: [] }] : []);
    const res = page.pageResources(allPages);
    const scriptTags = [...res.resources.filter((r) => r.kind === 'script').map((r) => ({ src: r.url, integrity: r.integrity || '' })), ...((observed && observed.scripts) || []), ...scripts.map((s) => ({ src: s, integrity: '' }))];
    const scriptList = [...new Map(scriptTags.filter((s) => s.src).map((s) => [s.src, s])).values()];
    // Wenn dasselbe Skript einmal mit integrity vorkommt, zaehlt das
    for (const s of scriptTags) if (s.integrity && scriptList.find((x) => x.src === s.src)) scriptList.find((x) => x.src === s.src).integrity = s.integrity;

    await step('web-sectxt', 'security.txt', async () => {
      let r = await request(guard, origin + '/.well-known/security.txt', { signal });
      if (!(r.ok && r.status === 200)) r = await request(guard, origin + '/security.txt', { signal });
      return { findings: securityTxtFindings(origin, r) };
    });
    await step('web-seo', 'Suchmaschinen-Grundlagen', async () => {
      const robots = await request(guard, origin + '/robots.txt', { signal });
      const sitemap = await request(guard, origin + '/sitemap.xml', { signal, headers: { Accept: 'application/xml' } });
      return { findings: page.seoFindings(home.url, homeHtml, { robots: robots.ok ? robots : { status: 0 }, sitemap: sitemap.ok ? sitemap : { status: 0 } }) };
    });
    if (homeHtml && page.isGermanSite(home.url, homeHtml)) await step('web-legal', 'Impressum und Datenschutz', async () => {
      const l = page.legalLinks(allPages);
      const status = {};
      for (const k of ['imprint', 'privacy']) {
        if (!l[k] || !sameSite(l[k], origin)) continue;
        const known = allPages.find((p) => p.url === l[k]);
        if (known) { status[k] = known.status; continue; }
        const r = await follow(guard, l[k], { signal, readBody: false });
        if (r.ok) status[k] = r.status;
      }
      return { findings: page.legalFindings(home.url, l, status) };
    });
    await step('web-observatory', 'Header-Bewertung', async () => {
      let redirectsToHttps = null;
      if (https) {
        const r = await request(guard, `http://${new URL(origin).host}/`, { signal, readBody: false });
        if (r.ok) redirectsToHttps = r.status >= 300 && r.status < 400 && /^https:/i.test(r.headers.get('location') || '');
      }
      return { findings: page.observatory(home.url, home.headers, { https, redirectsToHttps, scripts: scriptList, origin }) };
    });
    if (https) await step('tls-deep', 'TLS im Detail', async () => {
      const info = await (ctx.tlsProbe || netc.tlsProbe)(host);
      if (!info.ok) return { ran: false, notes: [`TLS-Detailprüfung: ${info.error}`] };
      return { findings: netc.tlsDeepFindings(origin, info, home.headers.get('alt-svc')), notes: ['TLS-Detailprüfung: sichere Neuverhandlung (Renegotiation) lässt sich mit Node nicht zuverlässig erkennen und wird nicht bewertet.'] };
    });
    if (domain) {
      await step('domain-expiry', 'Domain-Ablauf (RDAP)', () => netc.domainExpiry(domain, ctx, { signal }));
      await step('mail-extended', 'Mail-Sicherheit (MTA-STS, TLS-RPT, BIMI)', () => netc.mailExtended(domain, ctx, { httpGet: (u) => request(guard, u, { signal }), allowFetch: (h) => isAllowlisted(h, allowlist) }));
      await step('dns-dnssec', 'DNSSEC', () => netc.dnssec(domain, ctx, { signal }));
      await step('web-subdomains', 'Subdomains', () => netc.subdomains(domain, ctx, { host, deep, allowlist, crtsh: ctx.crtsh || crtShSubdomains, probe: ctx.tlsProbe || netc.tlsProbe, signal }));
      await step('typo-domains', 'Tippfehler-Domains', () => netc.typoDomains(domain, ctx, { signal }));
    }
    if (!internal) await step('internetdb', 'Shodan InternetDB', () => netc.internetDb(host, ctx, { signal }));

    // Skripte: eigene Bundles nach Zugangsdaten durchsuchen, fremde fuer SRI-Hashes einmal laden
    const fetched = new Map(), hashes = new Map();
    await step('js-secrets', 'JavaScript-Dateien', async () => {
      const own = scriptList.filter((s) => sameSite(s.src, origin)).slice(0, deep ? 15 : 8);
      const out = [];
      for (const s of own) {
        if (aborted()) break;
        const r = await fetchFull(guard, s.src, { signal });
        if (!r.ok) continue;
        hashes.set(s.src, crypto.createHash('sha256').update(r.buf).digest('hex'));
        out.push(...scanBundle(s.src, r.buf.toString('utf8'), feeds && feeds.secretRules));
      }
      return { findings: out, notes: [`JavaScript-Dateien: ${own.length} eigene Datei(en) auf Zugangsdaten und interne Adressen geprüft.`] };
    });
    await step('web-sri', 'Integritäts-Hashes', async () => {
      const ext = scriptList.filter((s) => !sameSite(s.src, origin) && /^https?:/i.test(s.src)).slice(0, 10);
      for (const s of ext) {
        if (aborted()) break;
        try { const r = await fetchFull(extGuard, s.src, { signal, max: 2 * 1024 * 1024 }); if (r.ok) { fetched.set(s.src, r.buf); hashes.set(s.src, crypto.createHash('sha256').update(r.buf).digest('hex')); } } catch (e) { if (!e.throttled) throw e; }
      }
      return { findings: page.sriSnippet(origin, scriptList, fetched) };
    });
    await step('web-csp-suggest', 'CSP-Vorschlag', async () => ({ findings: page.cspSuggestion(origin, home.headers.get('content-security-policy'), { ...res, requests: (observed && observed.requests) || [] }) }));
    await step('web-privacy', 'Datenschutz beim ersten Aufruf', async () => {
      if (observed) return { findings: page.privacyFindings(origin, { requests: observed.requests || [], cookies: observed.cookies || [], observed: true }) };
      // Ohne Browser: nur, was direkt (nicht per Consent-Tool blockiert) im HTML steht
      const direct = res.resources.filter((r) => !/text\/plain/.test(r.type || ''));
      return { findings: page.privacyFindings(origin, { requests: direct, observed: false }), notes: ['Datenschutz-Prüfung ohne Browser: nur direkt im HTML eingebundene Dienste und Cookies ausgewertet.'] };
    });
    await step('web-a11y', 'Barrierefreiheit', async () => ({ findings: page.a11yFindings(home.url, observed && observed.a11y ? observed.a11y : page.a11yFromHtml(homeHtml)) }));
    if (observed && observed.perf) await step('web-speed', 'Ladezeit', async () => ({ findings: page.speedFindings(home.url, observed.perf) }));
    if (allPages.length) await step('web-links', 'Defekte Links', async () => {
      const r = await brokenLinks(origin + '/', allPages, guard, { signal, max: deep ? 40 : 15 });
      return { findings: r.findings, notes: [`Links: ${r.checked} Adresse(n) der eigenen Seite geprüft.`] };
    });
    if (deep) await step('api-live', 'API-Endpunkte', () => apiLive(origin, guard, { specs: openApi ? [].concat(openApi) : [], signal }));

    // Aenderungen gegenueber dem letzten Lauf
    watch = { at: new Date().toISOString(), origin, scripts: scriptList.slice(0, 100).map((s) => ({ url: s.src, ...(hashes.has(s.src) ? { sha256: hashes.get(s.src) } : {}) })), forms: res.forms.slice(0, 100).map((f) => ({ page: f.page, action: f.action })) };
    const changes = page.changeWatch(watch, previous);
    findings.push(...changes);
    notes.push(previous ? `Änderungs-Wächter: ${changes.length} Änderung(en) seit dem letzten Lauf.` : 'Änderungs-Wächter: erster Lauf – Skripte und Formularziele als Vergleichsstand gespeichert.');
  } catch (e) {
    if (e.throttled) return { findings, notes: [...notes, e.message], ran, throttled: true, watch: null };
    notes.push('Zusatzprüfungen: ' + e.message);
  }
  return { findings, notes, ran, throttled: false, watch };
}

module.exports = { runWebSuite, securityTxtFindings, parseSecurityTxt, scanBundle, brokenLinks, apiLive, fetchFull };
