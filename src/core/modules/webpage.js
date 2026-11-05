'use strict';

// Auswertung bereits geladener Seiten – ohne eigene Netzanfragen:
//
//  web-csp-suggest  Content-Security-Policy-Vorschlag aus den beobachteten Quellen (kopierfertig)
//  web-sri          fertige integrity-Attribute (sha384) fuer externe Skripte
//  web-privacy      Tracking, Schriften, Videos und Cookies, die vor einer Einwilligung laden
//  web-a11y         Barrierefreiheit: Sprache, Alternativtexte, Feldbeschriftungen, Kontrast
//  web-speed        Seitengewicht, Anfragen, Antwortzeit, LCP/CLS aus dem unsichtbaren Browser
//  web-observatory  Header-Bewertung nach den Kriterien des Mozilla Observatory (Note als Info)
//  web-seo          Titel, Beschreibung, robots.txt, sitemap.xml
//  web-legal        Impressum und Datenschutzerklaerung verlinkt (deutschsprachige Seiten)
//  web-change-watch Skripte und Formularziele im Vergleich zum vorigen Lauf
//
// DOM_COLLECT_SCRIPT laeuft im unsichtbaren Browser (electron/domaudit.js) und liefert die
// Rohdaten fuer Barrierefreiheit, Ladezeit und Skripte.

const crypto = require('crypto');
const { normalizeFinding } = require('../schema');

const W = (m, o) => normalizeFinding({ confidence: 'high', ...o, sourceModule: m }, m);
const attr = (tag, name) => { const m = String(tag).match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')); return m ? (m[2] ?? m[3] ?? m[4] ?? '').replace(/&amp;/g, '&') : null; };
const originOf = (u) => { try { const x = new URL(u); return x.protocol === 'ws:' || x.protocol === 'wss:' ? `${x.protocol}//${x.host}` : x.origin; } catch { return null; } };
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };
const abs = (u, base) => { try { return new URL(u, base).href; } catch { return null; } };
const sha = (alg, buf) => crypto.createHash(alg).update(buf).digest('base64');
const uniq = (a) => [...new Set(a.filter(Boolean))];
const list = (a, n = 12) => a.slice(0, n).join(', ') + (a.length > n ? ' …' : '');

// --- Ressourcen aus dem HTML ------------------------------------------------------------------
// -> { resources: [{url, kind, integrity, type, page}], inlineScripts, inlineStyles, forms: [{page, action}] }
function pageResources(pages) {
  const resources = [], forms = [];
  let inlineScripts = 0, inlineStyles = 0;
  for (const p of pages || []) {
    const html = String(p.html || '');
    const push = (u, kind, extra = {}) => { const a = u && abs(u.trim(), p.url); if (a && /^(https?|wss?):/i.test(a)) resources.push({ url: a, kind, page: p.url, ...extra }); };
    for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      const type = (attr(m[1], 'type') || '').toLowerCase();
      const src = attr(m[1], 'src');
      if (src) push(src, 'script', { integrity: attr(m[1], 'integrity') || '', type });
      else if (m[2].trim() && !/json|template|text\/plain|x-tmpl/.test(type)) inlineScripts++;
    }
    for (const m of html.matchAll(/<link\b([^>]*)>/gi)) {
      const rel = (attr(m[1], 'rel') || '').toLowerCase(), as = (attr(m[1], 'as') || '').toLowerCase(), href = attr(m[1], 'href');
      if (/stylesheet/.test(rel)) push(href, 'style', { integrity: attr(m[1], 'integrity') || '' });
      else if (/preload|modulepreload/.test(rel)) push(href, as === 'font' ? 'font' : as === 'style' ? 'style' : as === 'image' ? 'img' : 'script');
      else if (/icon/.test(rel)) push(href, 'img');
    }
    for (const m of html.matchAll(/<img\b([^>]*)>/gi)) push(attr(m[1], 'src'), 'img');
    for (const m of html.matchAll(/<iframe\b([^>]*)>/gi)) push(attr(m[1], 'src'), 'frame');
    for (const m of html.matchAll(/<(?:video|audio|source)\b([^>]*)>/gi)) push(attr(m[1], 'src'), 'media');
    for (const m of html.matchAll(/<form\b([^>]*)>/gi)) { const a = abs(attr(m[1], 'action') || p.url, p.url); if (a) forms.push({ page: p.url, action: a }); }
    inlineStyles += (html.match(/<style\b/gi) || []).length + (html.match(/\sstyle\s*=\s*["'][^"']/gi) || []).length;
  }
  return { resources, inlineScripts, inlineStyles, forms };
}

// Beobachtete Browser-Anfragen (Electron resourceType) -> Art
const KIND_OF_TYPE = { script: 'script', stylesheet: 'style', image: 'img', font: 'font', xhr: 'connect', fetch: 'connect', webSocket: 'connect', ping: 'connect', subFrame: 'frame', media: 'media' };

// --- CSP-Vorschlag ----------------------------------------------------------------------------------
function weakCsp(csp) { const c = String(csp || '').toLowerCase(); const s = (c.match(/script-src([^;]*)/) || c.match(/default-src([^;]*)/) || [])[1] || ''; return !c || /'unsafe-inline'|'unsafe-eval'/.test(s) || /(^|\s)(\*|https?:|data:)(\s|$)/.test(s); }

function buildCsp(origin, { resources = [], requests = [], inlineScripts = 0, inlineStyles = 0, forms = [] } = {}) {
  const https = /^https:/.test(origin);
  const dirs = { 'default-src': new Set(["'self'"]), 'script-src': new Set(["'self'"]), 'style-src': new Set(["'self'"]), 'img-src': new Set(["'self'", 'data:']), 'font-src': new Set(["'self'"]), 'connect-src': new Set(["'self'"]), 'frame-src': new Set(), 'media-src': new Set(), 'object-src': new Set(["'none'"]), 'base-uri': new Set(["'self'"]), 'form-action': new Set(["'self'"]), 'frame-ancestors': new Set(["'self'"]) };
  const dirOf = { script: 'script-src', style: 'style-src', img: 'img-src', font: 'font-src', connect: 'connect-src', frame: 'frame-src', media: 'media-src' };
  const all = [...resources, ...requests.map((r) => ({ url: r.url, kind: KIND_OF_TYPE[r.type] }))];
  for (const r of all) {
    const d = dirOf[r.kind];
    const o = originOf(r.url);
    if (!d || !o || o === origin) continue;
    dirs[d].add(o);
    if (o === 'https://fonts.googleapis.com') dirs['font-src'].add('https://fonts.gstatic.com');
  }
  for (const f of forms) { const o = originOf(f.action); if (o && o !== origin) dirs['form-action'].add(o); }
  if (inlineStyles) dirs['style-src'].add("'unsafe-inline'");
  const policy = Object.entries(dirs).filter(([, v]) => v.size).map(([k, v]) => `${k} ${[...v].join(' ')}`).join('; ') + (https ? '; upgrade-insecure-requests' : '');
  return { policy, inlineScripts, external: uniq(all.map((r) => originOf(r.url)).filter((o) => o && o !== origin)) };
}

function cspSuggestion(origin, currentCsp, data) {
  if (!weakCsp(currentCsp)) return [];
  const { policy, inlineScripts, external } = buildCsp(origin, data);
  const note = inlineScripts ? `Die Seite enthält ${inlineScripts} Inline-Skript(e). Diese laufen mit der Richtlinie nicht mehr – auslagern oder per Nonce/Hash freigeben.` : 'Inline-Skripte wurden nicht gefunden.';
  return [W('web-csp-suggest', {
    ruleId: 'csp-suggestion', severity: 'info', category: 'Config', confidence: 'medium',
    title: 'Vorschlag für eine Content-Security-Policy aus den beobachteten Quellen', location: origin,
    evidence: external.length ? `Fremde Quellen: ${list(external)}` : 'Nur eigene Quellen',
    description: `Vigil hat aus den tatsächlich geladenen Skripten, Styles, Bildern, Schriften und Verbindungen eine passende Richtlinie zusammengestellt. ${note}`,
    remediation: 'Zuerst als "Content-Security-Policy-Report-Only" setzen und einige Tage beobachten, dann als "Content-Security-Policy" scharf schalten.',
    patch: `Content-Security-Policy-Report-Only: ${policy}\n\nContent-Security-Policy: ${policy}`,
    snippets: { nginx: `add_header Content-Security-Policy "${policy}" always;`, apache: `Header always set Content-Security-Policy "${policy}"`, express: `app.use((req, res, next) => { res.setHeader('Content-Security-Policy', ${JSON.stringify(policy)}); next(); });` },
  })];
}

// --- SRI ------------------------------------------------------------------------------------------------
const VERSIONED = /@\d|\/v?\d+\.\d+|[.-]\d+\.\d+(\.\d+)?[.-]|[a-f0-9]{8,}|[?&]v(er)?=\d/i;
// scripts: [{src, integrity}], fetched: Map(src -> Buffer|null)
function sriSnippet(origin, scripts, fetched) {
  const ext = [];
  const seen = new Set();
  for (const s of scripts || []) {
    if (!s.src || seen.has(s.src) || originOf(s.src) === origin || /^sha(256|384|512)-/.test(s.integrity || '')) continue;
    seen.add(s.src);
    ext.push(s.src);
  }
  if (!ext.length) return [];
  const lines = [], dynamic = [];
  for (const src of ext) {
    const buf = fetched && fetched.get(src);
    if (!buf) continue;
    if (!VERSIONED.test(new URL(src).pathname + new URL(src).search)) { dynamic.push(hostOf(src)); continue; }
    lines.push(`<script src="${src}"\n        integrity="sha384-${sha('sha384', buf)}"\n        crossorigin="anonymous"></script>`);
  }
  if (!lines.length && !dynamic.length) return [];
  return [W('web-sri', {
    ruleId: 'sri-snippet', severity: 'info', category: 'Dependencies',
    title: lines.length ? `Fertige Integritäts-Hashes für ${lines.length} externe(s) Skript(e)` : 'Externe Skripte ohne feste Version – keine Integritäts-Hashes möglich', location: origin,
    evidence: list(ext.map(hostOf)),
    description: `Vigil hat die externen Skripte einmal geladen und daraus SHA-384-Prüfsummen berechnet. Mit dem integrity-Attribut führt der Browser ein Skript nur aus, wenn es genau diesem Stand entspricht.${dynamic.length ? ` Nicht berücksichtigt (Adresse ohne feste Version, der Inhalt ändert sich): ${list(uniq(dynamic))}.` : ''}`,
    remediation: 'Die Script-Tags durch die Fassungen mit integrity ersetzen. Bei jedem Versionswechsel des Skripts den Hash neu erzeugen; Skripte ohne feste Version besser selbst hosten.',
    ...(lines.length ? { patch: lines.join('\n') } : {}),
  })];
}

// --- Datenschutz: was laedt vor der Einwilligung? ------------------------------------------------------------------
const THIRD = [
  [/(^|\.)(google-analytics\.com|analytics\.google\.com|googletagmanager\.com)$/, 'Google Analytics / Tag Manager', 'analytics'],
  [/(^|\.)(doubleclick\.net|googlesyndication\.com|googleadservices\.com)$/, 'Google Ads', 'analytics'],
  [/(^|\.)(facebook\.net|facebook\.com)$/, 'Meta Pixel', 'analytics'],
  [/(^|\.)(hotjar\.com|hotjar\.io)$/, 'Hotjar', 'analytics'],
  [/(^|\.)clarity\.ms$/, 'Microsoft Clarity', 'analytics'],
  [/^bat\.bing\.com$/, 'Microsoft Ads', 'analytics'],
  [/(^|\.)(licdn\.com|ads\.linkedin\.com|px\.ads\.linkedin\.com)$/, 'LinkedIn Insight', 'analytics'],
  [/(^|\.)(analytics\.tiktok\.com|tiktok\.com)$/, 'TikTok Pixel', 'analytics'],
  [/(^|\.)(segment\.com|segment\.io|mixpanel\.com|amplitude\.com|heapanalytics\.com)$/, 'Analyse-Dienst', 'analytics'],
  [/(^|\.)(fonts\.googleapis\.com|fonts\.gstatic\.com)$/, 'Google Fonts', 'fonts'],
  [/(^|\.)(use\.typekit\.net|p\.typekit\.net)$/, 'Adobe Fonts', 'fonts'],
  [/(^|\.)(youtube\.com|youtube-nocookie\.com|ytimg\.com|googlevideo\.com)$/, 'YouTube', 'video'],
  [/(^|\.)(vimeo\.com|vimeocdn\.com)$/, 'Vimeo', 'video'],
  [/(^|\.)(maps\.googleapis\.com|maps\.gstatic\.com)$/, 'Google Maps', 'video'],
];
const TRACKING_COOKIE = /^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|_clck|_clsk|_uet|_pin_|_tt_|_ttp|IDE|NID|MUID|li_|bcookie|lidc|__utm)/;
const classify = (host) => (THIRD.find(([re]) => re.test(host)) || null);

// requests: [{url, type?}] (Browser) oder statische Ressourcen; cookies: [{name, domain}]; observed: Browser-Daten?
function privacyFindings(origin, { requests = [], cookies = [], observed = false } = {}) {
  const M = 'web-privacy';
  const out = [];
  const own = hostOf(origin).replace(/^www\./, '');
  const third = requests.map((r) => hostOf(r.url)).filter((h) => h && h !== own && !h.endsWith('.' + own) && h.replace(/^www\./, '') !== own);
  const by = { analytics: new Set(), fonts: new Set(), video: new Set() }, other = new Set();
  for (const h of third) { const c = classify(h); if (c) by[c[2]].add(c[1]); else other.add(h); }
  const when = observed ? 'Beim ersten Aufruf – ohne dass eine Einwilligung gegeben wurde – lädt die Seite' : 'Die Seite bindet direkt im HTML ein, also vermutlich schon vor einer Einwilligung:';
  const conf = observed ? 'high' : 'medium';
  if (by.analytics.size) out.push(W(M, { ruleId: 'privacy-tracking-before-consent', severity: 'medium', category: 'Other', confidence: conf, title: `Tracking lädt vor der Einwilligung: ${[...by.analytics].join(', ')}`, location: origin, evidence: list(uniq(third.filter((h) => (classify(h) || [])[2] === 'analytics'))), description: `${when} ${[...by.analytics].join(', ')}.`, impact: 'Nach DSGVO und TTDSG dürfen Analyse- und Werbedienste erst nach einer aktiven Einwilligung laden. Das ist ein häufiger Abmahn- und Bußgeldgrund.', remediation: 'Die Dienste erst nach der Einwilligung laden (Consent-Tool mit Vorab-Blockierung, z. B. type="text/plain" bis zur Zustimmung) oder auf einwilligungsfreie Statistik ohne Cookies umsteigen.' }));
  if (by.fonts.size) out.push(W(M, { ruleId: 'privacy-external-fonts', severity: 'low', category: 'Other', confidence: conf, title: `Schriften werden von einem fremden Server geladen: ${[...by.fonts].join(', ')}`, location: origin, evidence: list(uniq(third.filter((h) => (classify(h) || [])[2] === 'fonts'))), description: 'Beim Laden der Schriften geht die IP-Adresse jedes Besuchers an den Anbieter.', impact: 'Deutsche Gerichte haben das ohne Einwilligung als Datenschutzverstoß gewertet (LG München, Google Fonts).', remediation: 'Die Schriftdateien selbst hosten und aus dem eigenen Server ausliefern.' }));
  if (by.video.size) out.push(W(M, { ruleId: 'privacy-embeds-before-consent', severity: 'low', category: 'Other', confidence: conf, title: `Eingebettete Inhalte laden ohne Einwilligung: ${[...by.video].join(', ')}`, location: origin, evidence: list(uniq(third.filter((h) => (classify(h) || [])[2] === 'video'))), description: 'Videos oder Karten von Drittanbietern werden sofort geladen und übertragen dabei Daten der Besucher an den Anbieter.', remediation: 'Eine Zwei-Klick-Lösung verwenden: erst ein Vorschaubild zeigen und den Inhalt nach Klick bzw. Einwilligung nachladen.' }));
  const restHosts = [...other];
  if (restHosts.length) out.push(W(M, { ruleId: 'privacy-third-party-hosts', severity: 'info', category: 'Other', confidence: conf, title: `${restHosts.length} weitere fremde Server werden beim ersten Aufruf kontaktiert`, location: origin, evidence: list(restHosts, 20), description: `Neben der eigenen Domain lädt die Seite Inhalte von: ${list(restHosts, 20)}.`, remediation: 'Prüfen, ob jeder dieser Dienste nötig ist und in der Datenschutzerklärung steht; wo möglich selbst hosten.' }));
  const track = cookies.filter((c) => TRACKING_COOKIE.test(c.name || '') || (c.domain && !String(c.domain).replace(/^\./, '').endsWith(own)));
  if (track.length) out.push(W(M, { ruleId: 'privacy-cookies-before-consent', severity: 'medium', category: 'Other', title: `Cookies vor der Einwilligung gesetzt: ${list(uniq(track.map((c) => c.name)), 8)}`, location: origin, evidence: list(track.map((c) => `${c.name} (${c.domain || own})`), 10), description: 'Direkt beim ersten Aufruf setzen die Seite oder eingebundene Dienste Tracking- bzw. Drittanbieter-Cookies.', impact: 'Nicht notwendige Cookies brauchen vorher eine Einwilligung (§ 25 TTDSG, DSGVO).', remediation: 'Diese Cookies erst nach der Einwilligung setzen lassen.' }));
  return out;
}

// --- Barrierefreiheit -------------------------------------------------------------------------------------
// Statische Grundlage aus dem HTML (ohne Browser): Sprache, Alternativtexte, Feldbeschriftungen
function a11yFromHtml(html) {
  const s = String(html || '');
  const lang = attr((s.match(/<html\b([^>]*)>/i) || [])[1] || '', 'lang') || '';
  const imgs = [...s.matchAll(/<img\b([^>]*)>/gi)].map((m) => m[1]);
  const noAlt = imgs.filter((t) => attr(t, 'alt') == null && !/role\s*=\s*["']?(presentation|none)|aria-hidden\s*=\s*["']?true/i.test(t));
  const labelled = new Set([...s.matchAll(/<label\b([^>]*)>/gi)].map((m) => attr(m[1], 'for')).filter(Boolean));
  const wrapped = [...s.matchAll(/<label\b[^>]*>([\s\S]*?)<\/label>/gi)].map((m) => m[1]).join(' ');
  const fields = [...s.matchAll(/<(input|select|textarea)\b([^>]*)>/gi)].filter((m) => !/^(hidden|submit|button|reset|image)$/i.test(attr(m[2], 'type') || ''));
  const unlabeled = fields.filter((m) => { const id = attr(m[2], 'id'); return !(id && labelled.has(id)) && attr(m[2], 'aria-label') == null && attr(m[2], 'aria-labelledby') == null && attr(m[2], 'title') == null && !wrapped.includes(m[0]); });
  return { lang, imgNoAlt: noAlt.length, imgNoAltEx: noAlt.slice(0, 5).map((t) => attr(t, 'src') || '?'), unlabeled: unlabeled.length, unlabeledEx: unlabeled.slice(0, 5).map((m) => attr(m[2], 'name') || attr(m[2], 'id') || m[1]), contrast: null, contrastEx: [] };
}

function a11yFindings(url, a) {
  const M = 'web-a11y';
  const out = [];
  if (!a) return out;
  if (!a.lang) out.push(W(M, { ruleId: 'a11y-lang-missing', severity: 'low', category: 'Other', title: 'Sprache der Seite ist nicht angegeben (lang-Attribut fehlt)', location: url, description: 'Im <html>-Tag fehlt das lang-Attribut.', impact: 'Screenreader lesen den Text dann womöglich mit falscher Aussprache vor; auch Übersetzungsfunktionen raten nur (WCAG 3.1.1).', remediation: 'Sprache angeben, z. B. <html lang="de">.' }));
  if (a.imgNoAlt) out.push(W(M, { ruleId: 'a11y-img-alt-missing', severity: 'low', category: 'Other', title: `${a.imgNoAlt} Bild(er) ohne Alternativtext`, location: url, evidence: list(a.imgNoAltEx || [], 5), description: 'Bilder ohne alt-Attribut sind für blinde Besucher nicht erfassbar; Screenreader lesen stattdessen oft den Dateinamen vor (WCAG 1.1.1).', remediation: 'Jedem Bild ein passendes alt-Attribut geben; rein dekorative Bilder mit alt="" kennzeichnen.' }));
  if (a.unlabeled) out.push(W(M, { ruleId: 'a11y-form-label-missing', severity: 'low', category: 'Other', title: `${a.unlabeled} Formularfeld(er) ohne Beschriftung`, location: url, evidence: list(a.unlabeledEx || [], 5), description: 'Diese Eingabefelder haben kein zugeordnetes <label>, kein aria-label und keinen title. Screenreader können nicht ansagen, was einzutragen ist (WCAG 1.3.1, 4.1.2).', remediation: 'Zu jedem Feld ein <label for="…"> anlegen oder aria-label setzen; ein Platzhalter allein reicht nicht.' }));
  if (a.contrast) out.push(W(M, { ruleId: 'a11y-contrast-low', severity: a.contrast >= 5 ? 'low' : 'info', category: 'Other', confidence: 'medium', title: `${a.contrast} Textstelle(n) mit zu wenig Kontrast`, location: url, evidence: list((a.contrastEx || []).map((c) => `„${c.text}“ ${c.ratio}:1`), 5), description: 'Der Kontrast zwischen Text- und Hintergrundfarbe liegt unter dem Mindestwert von 4,5:1 (große Schrift 3:1). Gemessen im unsichtbaren Browser (WCAG 1.4.3).', impact: 'Menschen mit Sehschwäche, ältere Besucher und alle bei Sonnenlicht können den Text schlecht lesen.', remediation: 'Text dunkler bzw. Hintergrund heller wählen; Werte z. B. mit dem WebAIM Contrast Checker prüfen.' }));
  return out;
}

// --- Ladezeit ------------------------------------------------------------------------------------------------
function speedFindings(url, p) {
  if (!p) return [];
  const kb = Math.round((p.bytes || 0) / 1024);
  const slow = [];
  if (p.ttfb > 1800) slow.push('Der Server antwortet langsam (über 1,8 Sekunden bis zum ersten Byte).');
  if (p.lcp > 4000) slow.push('Das größte Element erscheint erst nach mehr als 4 Sekunden.');
  if (p.cls > 0.25) slow.push('Der Inhalt verschiebt sich beim Laden stark.');
  if (kb > 5120) slow.push('Die Seite ist sehr schwer (über 5 MB).');
  if (p.requests > 150) slow.push('Die Seite stellt sehr viele Anfragen (über 150).');
  const v = (x) => (x == null ? '–' : String(Math.round(x)));
  return [W('web-speed', {
    ruleId: 'web-speed', severity: slow.length ? 'low' : 'info', category: 'Other', confidence: 'medium',
    title: `Ladeverhalten: ${kb} KB, ${p.requests || 0} Anfragen, Antwortzeit ${v(p.ttfb)} ms`, location: url,
    evidence: `TTFB ${v(p.ttfb)} ms · DOM ${v(p.dcl)} ms · LCP ${v(p.lcp)} ms · CLS ${p.cls == null ? '–' : Number(p.cls).toFixed(2)}`,
    description: [`Gemessen beim ersten Aufruf im unsichtbaren Browser: Antwortzeit des Servers ${v(p.ttfb)} ms, Seite aufgebaut nach ${v(p.dcl)} ms, größtes Element sichtbar nach ${v(p.lcp)} ms.`, ...slow].join(' '),
    impact: slow.length ? 'Langsame Seiten verlieren Besucher und werden von Suchmaschinen schlechter eingestuft.' : '',
    remediation: slow.length ? 'Bilder verkleinern (WebP/AVIF, passende Größe), Skripte reduzieren oder verzögert laden, Caching und Komprimierung aktivieren, Bildern feste Maße geben.' : 'Kein Handlungsbedarf.',
  })];
}

// --- Mozilla-Observatory-Bewertung ----------------------------------------------------------------------------
const GRADES = [[100, 'A+'], [90, 'A'], [85, 'A-'], [80, 'B+'], [70, 'B'], [65, 'B-'], [60, 'C+'], [50, 'C'], [45, 'C-'], [40, 'D+'], [30, 'D'], [25, 'D-'], [-Infinity, 'F']];
// h: Headers (get), opts: { https, redirectsToHttps (true/false/null), scripts: [{src, integrity}], origin }
function observatory(url, h, { https, redirectsToHttps = null, scripts = [], origin } = {}) {
  const get = (k) => (h && typeof h.get === 'function' ? h.get(k) : (h || {})[k]) || '';
  const items = [];
  let score = 100, bonus = 0;
  const minus = (n, text) => { score -= n; items.push(`${text} (-${n})`); };
  const csp = get('content-security-policy').toLowerCase();
  const sSrc = (csp.match(/script-src([^;]*)/) || csp.match(/default-src([^;]*)/) || [])[1] || '';
  if (!csp) minus(25, 'Content-Security-Policy fehlt');
  else if (/'unsafe-inline'/.test(sSrc) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(sSrc)) minus(20, 'Content-Security-Policy erlaubt Inline-Skripte');
  else if (/'unsafe-eval'/.test(sSrc)) minus(10, 'Content-Security-Policy erlaubt eval');
  else if (/(^|\s)(\*|https?:)(\s|$)/.test(sSrc)) minus(20, 'Content-Security-Policy erlaubt Skripte von überall');
  else bonus += 5;
  const raw = h && typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  if (raw.length) {
    if (https && raw.some((c) => !/;\s*secure/i.test(c))) minus(20, 'Cookies ohne Secure');
    else if (raw.some((c) => /sess|sid|auth|token/i.test(c.split('=')[0]) && !/;\s*httponly/i.test(c))) minus(10, 'Sitzungs-Cookie ohne HttpOnly');
    else if (raw.every((c) => /;\s*samesite/i.test(c))) bonus += 5;
  }
  if (!https) minus(20, 'Kein HTTPS');
  else if (redirectsToHttps === false) minus(20, 'HTTP leitet nicht auf HTTPS um');
  const hsts = get('strict-transport-security').toLowerCase();
  if (https) {
    if (!hsts) minus(20, 'HSTS fehlt');
    else if (Number((hsts.match(/max-age=(\d+)/) || [])[1] || 0) < 15552000) minus(10, 'HSTS kürzer als 6 Monate');
    else if (/preload/.test(hsts)) bonus += 5;
  }
  const ext = (scripts || []).filter((s) => originOf(s.src) && originOf(s.src) !== origin);
  if (ext.some((s) => /^http:/i.test(s.src))) minus(50, 'Externe Skripte über HTTP');
  else if (ext.some((s) => !/^sha(256|384|512)-/.test(s.integrity || ''))) minus(5, 'Externe Skripte ohne Integritätsprüfung');
  else if (ext.length) bonus += 5;
  if (get('x-content-type-options').toLowerCase() !== 'nosniff') minus(5, 'X-Content-Type-Options fehlt');
  if (/frame-ancestors/.test(csp)) bonus += 5;
  else if (!get('x-frame-options')) minus(20, 'Schutz vor Einbetten (X-Frame-Options) fehlt');
  const rp = get('referrer-policy').toLowerCase();
  if (/unsafe-url|no-referrer-when-downgrade/.test(rp)) minus(5, 'Referrer-Policy gibt volle Adressen weiter');
  else if (rp) bonus += 5;
  if (score >= 90) score += bonus; // Bonuspunkte zaehlen nur ab 90 Punkten (wie beim Observatory)
  score = Math.max(0, score);
  const grade = GRADES.find(([min]) => score >= min)[1];
  return [W('web-observatory', {
    ruleId: 'observatory-grade', severity: 'info', category: 'Config',
    title: `Header-Bewertung nach Mozilla Observatory: Note ${grade} (${score} Punkte)`, location: url,
    evidence: `${score}/100`,
    description: items.length ? 'Vigil hat die Antwort-Header nach den Kriterien des Mozilla Observatory bewertet. Die Abzüge stehen in der Liste der Schritte.' : 'Vigil hat die Antwort-Header nach den Kriterien des Mozilla Observatory bewertet. Es gibt keine Abzüge.',
    ...(items.length ? { steps: items } : {}),
    remediation: items.length ? 'Die einzelnen Header-Befunde dieser Prüfung beheben – jede behobene Stelle hebt die Note.' : 'Kein Handlungsbedarf.',
  })];
}

// --- SEO --------------------------------------------------------------------------------------------------------
// robots/sitemap: { status, body } oder null (nicht abgefragt)
function seoFindings(url, html, { robots = null, sitemap = null } = {}) {
  const M = 'web-seo';
  const out = [];
  const s = String(html || '');
  const title = ((s.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '').trim();
  const desc = [...s.matchAll(/<meta\b([^>]*)>/gi)].map((m) => m[1]).find((t) => /name\s*=\s*["']?description/i.test(t));
  if (!title) out.push(W(M, { ruleId: 'seo-title-missing', severity: 'info', category: 'Other', title: 'Startseite hat keinen Titel', location: url, description: 'Im HTML fehlt ein <title>. Suchmaschinen und Browser-Tabs zeigen dann nur die Adresse.', remediation: 'Einen aussagekräftigen <title> mit 30–60 Zeichen setzen.' }));
  else if (title.length > 65) out.push(W(M, { ruleId: 'seo-title-long', severity: 'info', category: 'Other', title: `Seitentitel ist sehr lang (${title.length} Zeichen)`, location: url, evidence: title.slice(0, 120), description: 'Suchmaschinen kürzen Titel ab etwa 60 Zeichen.', remediation: 'Den Titel auf das Wichtigste kürzen.' }));
  if (!desc || !(attr(desc, 'content') || '').trim()) out.push(W(M, { ruleId: 'seo-description-missing', severity: 'info', category: 'Other', title: 'Keine Meta-Beschreibung', location: url, description: 'Es gibt kein <meta name="description">. Suchmaschinen wählen dann selbst einen Textausschnitt für das Suchergebnis.', remediation: 'Eine Beschreibung mit 120–160 Zeichen setzen.' }));
  if (robots) {
    const okRobots = robots.status === 200 && !/<html/i.test(robots.body || '');
    if (!okRobots) out.push(W(M, { ruleId: 'seo-robots-missing', severity: 'info', category: 'Other', title: 'Keine robots.txt', location: new URL('/robots.txt', url).href, evidence: `HTTP ${robots.status || '–'}`, description: 'Unter /robots.txt liegt keine Datei. Suchmaschinen crawlen dann alles und finden die Sitemap nicht automatisch.', remediation: 'Eine robots.txt mit Verweis auf die Sitemap anlegen.', snippets: { robots: `User-agent: *\nAllow: /\nSitemap: ${new URL('/sitemap.xml', url).href}` } }));
    else {
      const groups = String(robots.body).split(/(?=^\s*user-agent\s*:)/im);
      if (groups.some((g) => /^\s*user-agent\s*:\s*\*\s*$/im.test(g) && /^\s*disallow\s*:\s*\/\s*$/im.test(g))) out.push(W(M, { ruleId: 'seo-robots-disallow-all', severity: 'low', category: 'Other', title: 'robots.txt sperrt alle Suchmaschinen aus', location: new URL('/robots.txt', url).href, evidence: 'User-agent: * / Disallow: /', description: 'Die robots.txt verbietet allen Suchmaschinen die ganze Seite – oft ein Überbleibsel aus der Entwicklung.', remediation: 'Wenn die Seite gefunden werden soll: "Disallow: /" entfernen.' }));
    }
    const declared = okRobots && /^\s*sitemap\s*:/im.test(robots.body || '');
    if (sitemap && !(sitemap.status === 200 && /<(urlset|sitemapindex)\b/i.test(sitemap.body || '')) && !declared) out.push(W(M, { ruleId: 'seo-sitemap-missing', severity: 'info', category: 'Other', title: 'Keine sitemap.xml', location: new URL('/sitemap.xml', url).href, evidence: `HTTP ${sitemap.status || '–'}`, description: 'Es gibt weder /sitemap.xml noch einen Sitemap-Verweis in der robots.txt. Suchmaschinen finden neue Unterseiten dann langsamer.', remediation: 'Eine sitemap.xml erzeugen (die meisten CMS können das) und in der robots.txt verlinken.' }));
  }
  return out;
}

// --- Impressum / Datenschutz -----------------------------------------------------------------------------------
function isGermanSite(url, html) {
  const lang = (attr((String(html || '').match(/<html\b([^>]*)>/i) || [])[1] || '', 'lang') || '').toLowerCase();
  return /^de\b/.test(lang) || /\.(de|at|ch)$/.test(hostOf(url));
}
// -> { imprint: url|null, privacy: url|null }
function legalLinks(pages) {
  let imprint = null, privacy = null;
  for (const p of pages || []) {
    for (const m of String(p.html || '').matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
      const href = attr(m[1], 'href');
      const text = `${href || ''} ${m[2].replace(/<[^>]+>/g, ' ')}`;
      const u = href && abs(href, p.url);
      if (!u) continue;
      if (!imprint && /impressum|imprint|legal-notice|anbieterkennzeichnung/i.test(text)) imprint = u;
      if (!privacy && /datenschutz|privacy|dsgvo|gdpr/i.test(text)) privacy = u;
    }
    if (imprint && privacy) break;
  }
  return { imprint, privacy };
}
// status: { imprint: http-status|null, privacy: ... } (nur fuer gefundene, eigene Links)
function legalFindings(url, links, status = {}) {
  const M = 'web-legal';
  const out = [];
  if (!links.imprint) out.push(W(M, { ruleId: 'legal-imprint-missing', severity: 'low', category: 'Other', confidence: 'medium', title: 'Kein Impressum verlinkt', location: url, description: 'Auf den geprüften Seiten ist kein Link zu einem Impressum zu finden.', impact: 'Geschäftsmäßige Webseiten in Deutschland brauchen ein leicht erreichbares Impressum (§ 5 DDG); Fehlen wird häufig abgemahnt.', remediation: 'Ein Impressum anlegen und von jeder Seite aus verlinken (meist im Footer).' }));
  if (!links.privacy) out.push(W(M, { ruleId: 'legal-privacy-missing', severity: 'low', category: 'Other', confidence: 'medium', title: 'Keine Datenschutzerklärung verlinkt', location: url, description: 'Auf den geprüften Seiten ist kein Link zu einer Datenschutzerklärung zu finden.', impact: 'Wer personenbezogene Daten verarbeitet – und sei es nur über Server-Logs –, muss darüber informieren (Art. 13 DSGVO).', remediation: 'Eine Datenschutzerklärung anlegen und von jeder Seite aus verlinken.' }));
  for (const [k, label] of [['imprint', 'Impressum'], ['privacy', 'Datenschutzerklärung']]) {
    const s = status[k];
    if (links[k] && s && s >= 400) out.push(W(M, { ruleId: `legal-${k}-broken`, severity: 'low', category: 'Other', title: `Link zu ${label} führt ins Leere (HTTP ${s})`, location: links[k], description: `Der Link zu ${label} ist vorhanden, die Seite dahinter antwortet aber mit Status ${s}.`, remediation: 'Den Link korrigieren bzw. die Seite wiederherstellen.' }));
  }
  return out;
}

// --- Aenderungen seit dem letzten Lauf ---------------------------------------------------------------------------
// current/previous: { at, origin, scripts: [{url, sha256?}], forms: [{page, action}] }
function changeWatch(current, previous) {
  const M = 'web-change-watch';
  const out = [];
  if (!previous || !Array.isArray(previous.scripts)) return out;
  const origin = current.origin;
  const prevScripts = new Map(previous.scripts.map((s) => [s.url, s]));
  const prevHosts = new Set(previous.scripts.map((s) => hostOf(s.url)));
  const since = previous.at ? ` (vorheriger Lauf: ${String(previous.at).slice(0, 10)})` : '';
  for (const s of current.scripts) {
    if (originOf(s.url) === origin) continue;
    const before = prevScripts.get(s.url);
    if (!before) {
      if (out.filter((f) => f.ruleId === 'watch-new-third-party-script').length >= 5) continue;
      out.push(W(M, { ruleId: 'watch-new-third-party-script', severity: prevHosts.has(hostOf(s.url)) ? 'low' : 'medium', category: 'Dependencies', title: `Neues externes Skript seit dem letzten Lauf: ${hostOf(s.url)}`, location: s.url.slice(0, 280), description: `Dieses Skript eines fremden Servers war beim letzten Lauf noch nicht eingebunden${since}.`, impact: 'Unerwartete neue Skripte sind ein typisches Zeichen für eine manipulierte Seite (z. B. Kreditkarten-Skimmer) oder ein ungeprüft eingebautes Tracking.', remediation: 'Prüfen, ob die Einbindung gewollt ist. Falls nicht: Seite und Server auf Manipulation untersuchen, Zugänge ändern.' }));
    } else if (before.sha256 && s.sha256 && before.sha256 !== s.sha256 && VERSIONED.test(s.url)) {
      out.push(W(M, { ruleId: 'watch-third-party-script-changed', severity: 'medium', category: 'Dependencies', title: `Externes Skript hat sich seit dem letzten Lauf verändert: ${hostOf(s.url)}`, location: s.url.slice(0, 280), evidence: `sha256 vorher ${before.sha256.slice(0, 12)}… jetzt ${s.sha256.slice(0, 12)}…`, description: `Das Skript hat dieselbe, versionierte Adresse wie beim letzten Lauf, aber einen anderen Inhalt${since}.`, impact: 'Ändert sich eine feste Version unbemerkt, kann der Anbieter oder sein Server kompromittiert sein (Lieferketten-Angriff).', remediation: 'Den Inhalt prüfen und das Skript mit einem integrity-Hash festschreiben oder selbst hosten.' }));
    }
  }
  const prevActions = new Set((previous.forms || []).map((f) => hostOf(f.action)));
  const ownHost = hostOf(origin);
  for (const f of current.forms || []) {
    const h = hostOf(f.action);
    if (!h || h === ownHost || prevActions.has(h)) continue;
    prevActions.add(h);
    out.push(W(M, { ruleId: 'watch-form-target-changed', severity: 'high', category: 'Config', title: `Formular sendet jetzt an einen anderen Server: ${h}`, location: f.page, evidence: `action: ${f.action.slice(0, 200)}`, description: `Ein Formular auf ${f.page} schickt seine Eingaben an ${h}. Beim letzten Lauf hat kein Formular dorthin gesendet${since}.`, impact: 'Ein umgebogenes Formularziel leitet Anmeldedaten oder Zahlungsdaten an Fremde weiter.', remediation: 'Prüfen, ob die Änderung gewollt ist. Falls nicht: Seite wiederherstellen und Zugänge zum Server bzw. CMS ändern.' }));
  }
  return out;
}

// --- Skript fuer den unsichtbaren Browser (Barrierefreiheit, Ladezeit, Skripte) ---------------------------------------
const DOM_COLLECT_SCRIPT = `(() => new Promise((done) => {
  const out = { lang: document.documentElement.getAttribute('lang') || '' };
  const vis = (el) => { const r = el.getClientRects(); const cs = getComputedStyle(el); return r.length && cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0.1; };
  const imgs = [...document.images].filter((i) => !i.hasAttribute('alt') && !/^(presentation|none)$/.test(i.getAttribute('role') || '') && i.getAttribute('aria-hidden') !== 'true' && vis(i));
  out.imgNoAlt = imgs.length; out.imgNoAltEx = imgs.slice(0, 5).map((i) => (i.currentSrc || i.src || '?').slice(0, 120));
  const fields = [...document.querySelectorAll('input, select, textarea')].filter((el) => !/^(hidden|submit|button|reset|image)$/i.test(el.type || '') && vis(el));
  const un = fields.filter((el) => !(el.labels && el.labels.length) && !el.getAttribute('aria-label') && !el.getAttribute('aria-labelledby') && !el.title);
  out.unlabeled = un.length; out.unlabeledEx = un.slice(0, 5).map((el) => el.name || el.id || el.type);
  const parse = (c) => { const m = String(c).match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(/[\\s,\\/]+/).filter(Boolean).map(Number); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const bg = (el) => { for (let e = el; e; e = e.parentElement) { const cs = getComputedStyle(e); if (cs.backgroundImage && cs.backgroundImage !== 'none') return null; const c = parse(cs.backgroundColor); if (c && c.a > 0.9) return c; } return { r: 255, g: 255, b: 255, a: 1 }; };
  const bad = []; let n = 0;
  const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT);
  const seen = new Set();
  while (walker.nextNode() && n < 400) {
    const t = walker.currentNode; const el = t.parentElement;
    if (!el || seen.has(el) || !t.nodeValue.trim() || /^(SCRIPT|STYLE|NOSCRIPT)$/.test(el.tagName) || !vis(el)) continue;
    seen.add(el); n++;
    const cs = getComputedStyle(el); const fg = parse(cs.color); const b = bg(el);
    if (!fg || !b || fg.a < 0.5) continue;
    const L1 = lum(fg), L2 = lum(b); const ratio = (Math.max(L1, L2) + 0.05) / (Math.min(L1, L2) + 0.05);
    const size = parseFloat(cs.fontSize) || 16; const large = size >= 24 || (size >= 18.66 && Number(cs.fontWeight) >= 700);
    if (ratio < (large ? 3 : 4.5)) bad.push({ text: t.nodeValue.trim().slice(0, 40), ratio: Math.round(ratio * 100) / 100 });
  }
  out.contrast = bad.length; out.contrastEx = bad.slice(0, 5);
  out.scripts = [...document.querySelectorAll('script[src]')].map((s) => ({ src: s.src, integrity: s.integrity || '' }));
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const res = performance.getEntriesByType('resource');
  out.perf = { ttfb: nav.responseStart ? nav.responseStart - (nav.requestStart || 0) : null, dcl: nav.domContentLoadedEventEnd || null, load: nav.loadEventEnd || null, requests: res.length + 1, bytes: (nav.transferSize || 0) + res.reduce((s, r) => s + (r.transferSize || r.encodedBodySize || 0), 0), lcp: null, cls: 0 };
  try {
    new PerformanceObserver((l) => { const e = l.getEntries(); if (e.length) out.perf.lcp = e[e.length - 1].startTime; }).observe({ type: 'largest-contentful-paint', buffered: true });
    new PerformanceObserver((l) => { for (const e of l.getEntries()) if (!e.hadRecentInput) out.perf.cls += e.value; }).observe({ type: 'layout-shift', buffered: true });
  } catch (e) {}
  setTimeout(() => done(out), 300);
}))()`;

module.exports = { pageResources, buildCsp, weakCsp, cspSuggestion, sriSnippet, privacyFindings, a11yFromHtml, a11yFindings, speedFindings, observatory, seoFindings, isGermanSite, legalLinks, legalFindings, changeWatch, DOM_COLLECT_SCRIPT, VERSIONED, originOf };
