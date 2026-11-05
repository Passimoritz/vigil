'use strict';

// Tagesaktuelle Erkennung ohne App-Update: Vigil laedt oeffentliche Erkennungsdaten selbst nach.
//
//  live bei jedem Lauf   OSV.dev (Schwachstellen aller Paket-Oekosysteme), Defender-Signaturen (Windows)
//  taeglich (intel.js)   CISA KEV (aktiv ausgenutzt), FIRST EPSS (Ausnutzungs-Wahrscheinlichkeit)
//  taeglich (hier)       gitleaks-Regeln (Zugangsdaten-Formate vieler Dienste),
//                        retire.js-Datenbank (verwundbare JavaScript-Bibliotheken),
//                        Phishing-/Schadsoftware-Adressen (OpenPhish, URLhaus), BSI CERT-Bund-Hinweise,
//                        YARA- und Semgrep-Regeln (nur wenn das Werkzeug installiert ist),
//                        nuclei-Vorlagen (aktualisiert nuclei selbst, wenn installiert)
//  optional              OSV-Komplettabzug fuer den Offline-Betrieb (osvoffline.js)
//
// Sicherheit: nur feste HTTPS-Quellen, Groessengrenze, Pruefung von Form und Mindestumfang, die
// letzte gute Fassung bleibt bei jedem Fehler erhalten. Feeds sind reine DATEN – es wird nie Code
// aus dem Netz ausgefuehrt; Regex-Muster werden begrenzt, einzeln kompiliert und nur zeilenweise
// auf hoechstens 2000 Zeichen lange Zeilen angewendet.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { verifyDownload } = require('./verify');

const MAX_AGE_MS = 20 * 60 * 60 * 1000; // spaetestens nach 20 Stunden neu laden

// --- gitleaks.toml (TOML-Teilmenge: [[rules]] mit id, description, regex, keywords, entropy) -------
function parseTomlString(v) {
  v = v.trim();
  if (v.startsWith("'''")) return v.slice(3, v.lastIndexOf("'''"));
  if (v.startsWith('"""')) return v.slice(3, v.lastIndexOf('"""'));
  if (v.startsWith("'")) return v.slice(1, v.lastIndexOf("'"));
  if (v.startsWith('"')) { try { return JSON.parse(v.slice(0, v.lastIndexOf('"') + 1)); } catch { return v.slice(1, v.lastIndexOf('"')); } }
  return v.replace(/\s+#.*$/, '');
}
function parseGitleaksToml(text) {
  const rules = [];
  const blocks = String(text).replace(/\r\n/g, '\n').split(/^\[\[rules\]\]\s*$/m).slice(1);
  for (const b of blocks) {
    // nur der Kopf der Regel, ohne Unterabschnitte wie [[rules.allowlists]]
    const body = b.split(/^\[/m)[0];
    const get = (k) => {
      const line = body.split('\n').findIndex((l) => new RegExp(`^${k}\\s*=`).test(l));
      if (line < 0) return null;
      const rest = body.split('\n').slice(line).join('\n').replace(new RegExp(`^${k}\\s*=\\s*`), '');
      if (rest.startsWith("'''")) return rest.slice(3, rest.indexOf("'''", 3));
      return parseTomlString(rest.split('\n')[0]);
    };
    const id = get('id'), regex = get('regex');
    if (!id || !regex) continue;
    const kw = body.match(/^keywords\s*=\s*\[([\s\S]*?)\]/m);
    const keywords = kw ? [...kw[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1].toLowerCase()) : [];
    const ent = get('entropy');
    rules.push({ id, description: get('description') || id, regex, keywords, entropy: ent ? Number(ent) : null });
  }
  return rules;
}

// Go-RE2 -> JavaScript. Was nicht sicher uebersetzbar ist, wird verworfen (null).
function goRegexToJs(src) {
  if (!src || src.length > 2000) return null;
  let flags = 'g';
  let s = src;
  if (s.includes('(?i)')) { flags += 'i'; s = s.split('(?i)').join(''); }
  s = s.replace(/\(\?[msU-]+\)/g, '').split('(?P<').join('(?<').split('\\z').join('$').split('\\A').join('^');
  const posix = { '[:alnum:]': 'a-zA-Z0-9', '[:alpha:]': 'a-zA-Z', '[:digit:]': '0-9', '[:space:]': '\\s', '[:xdigit:]': '0-9a-fA-F', '[:upper:]': 'A-Z', '[:lower:]': 'a-z', '[:word:]': '\\w' };
  for (const [k, v] of Object.entries(posix)) s = s.split(k).join(v);
  if (s.includes('\\p{') || s.includes('\\Q') || /\(\?[^:=!<]/.test(s)) return null;
  try { return new RegExp(s, flags); } catch { return null; }
}
const shannon = (str) => { const m = new Map(); for (const ch of str) m.set(ch, (m.get(ch) || 0) + 1); let h = 0; for (const n of m.values()) { const p = n / str.length; h -= p * Math.log2(p); } return h; };

function compileSecretRules(rules) {
  return (rules || []).map((r) => ({ ...r, re: goRegexToJs(r.regex) })).filter((r) => r.re);
}

// --- retire.js-Datenbank ----------------------------------------------------------------------
const VER = '[0-9][0-9a-z._\\-]*';
function compileRetire(repo) {
  const libs = [];
  for (const [name, lib] of Object.entries(repo || {})) {
    if (!lib || !Array.isArray(lib.vulnerabilities) || !lib.extractors) continue;
    const ex = (k) => (lib.extractors[k] || []).map((p) => { try { return new RegExp(String(p).split('§§version§§').join(`(${VER})`).slice(0, 1000)); } catch { return null; } }).filter(Boolean);
    libs.push({ name, vulns: lib.vulnerabilities.filter((v) => v && (v.below || v.atOrAbove)).slice(0, 200), filename: ex('filename'), uri: ex('uri'), filecontent: ex('filecontent') });
  }
  return libs;
}

// --- Verwaltung ---------------------------------------------------------------------------------
const FEEDS = [
  {
    id: 'gitleaks-rules', label: 'Zugangsdaten-Formate (gitleaks-Regeln)',
    urls: ['https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml'],
    maxBytes: 3 * 1024 * 1024,
    parse: (text) => { const rules = parseGitleaksToml(text); if (rules.length < 50) throw new Error(`nur ${rules.length} Regeln – Format unerwartet`); return rules; },
    count: (d) => d.length,
  },
  {
    id: 'retirejs', label: 'Verwundbare JavaScript-Bibliotheken (retire.js)',
    urls: ['https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json', 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json'],
    maxBytes: 8 * 1024 * 1024,
    parse: (text) => { const j = JSON.parse(text); const n = Object.values(j).filter((l) => l && Array.isArray(l.vulnerabilities)).length; if (n < 20) throw new Error(`nur ${n} Bibliotheken – Format unerwartet`); return j; },
    count: (d) => Object.keys(d).length,
  },
  // Phishing- und Schadsoftware-Adressen: fuer Links in Dokumenten/Mails und die eigene Domain
  {
    id: 'openphish', label: 'Phishing-Adressen (OpenPhish Community)', unit: 'Adressen',
    urls: ['https://openphish.com/feed.txt'],
    maxBytes: 8 * 1024 * 1024,
    parse: (text) => parseUrlList(text, 20, 150000),
    count: (d) => d.length,
  },
  {
    id: 'urlhaus', label: 'Schadsoftware-Adressen (URLhaus, abuse.ch)', unit: 'Adressen',
    urls: ['https://urlhaus.abuse.ch/downloads/text_online/'],
    maxBytes: 24 * 1024 * 1024,
    parse: (text) => parseUrlList(text, 20, 250000),
    count: (d) => d.length,
  },
  // Sicherheitshinweise des BSI (CERT-Bund WID) – werden mit den Paketen der gespeicherten SBOMs abgeglichen
  {
    id: 'certbund', label: 'Sicherheitshinweise (BSI CERT-Bund)', unit: 'Meldungen',
    urls: ['https://wid.cert-bund.de/content/public/securityAdvisory/rss'],
    maxBytes: 6 * 1024 * 1024,
    parse: (text) => { const items = parseRss(text); if (items.length < 3) throw new Error(`nur ${items.length} Meldungen – Format unerwartet`); return items; },
    count: (d) => d.length,
  },
  // Support-Enden von Datenbanken, Betriebssystemen und Bibliotheken (endoflife.date)
  {
    id: 'endoflife', label: 'Support-Enden (endoflife.date)', unit: 'Produkte',
    urls: [require('./eol').FEED_URL],
    maxBytes: 16 * 1024 * 1024,
    parse: (text) => require('./eol').parseFull(text),
    count: (d) => Object.keys(d).length,
  },
  // Nur wenn das jeweilige Werkzeug installiert ist
  {
    id: 'yara-rules', label: 'YARA-Regeln (signature-base)', unit: 'Regeln', when: (ctx) => !!(ctx.tools && ctx.tools.yara), sidecar: 'yar',
    urls: ['https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_webshells.yar', 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_mimikatz.yar'],
    maxBytes: 4 * 1024 * 1024,
    parse: (text) => { if (/^\s*include\s+"/m.test(text)) throw new Error('Regeln mit include werden nicht geladen'); const n = countYaraRules(text); if (n < 3) throw new Error(`nur ${n} Regeln – Format unerwartet`); return text; },
    count: (d) => countYaraRules(d),
  },
  {
    id: 'semgrep-rules', label: 'Semgrep-Regeln (Registry p/default)', unit: 'Regeln', when: (ctx) => !!(ctx.tools && ctx.tools.semgrep), sidecar: 'yml',
    urls: ['https://semgrep.dev/c/p/default'],
    maxBytes: 12 * 1024 * 1024,
    parse: (text) => { if (!/^rules:/m.test(text)) throw new Error('kein Semgrep-Regelsatz'); const n = (text.match(/^\s*-\s+id:/gm) || []).length; if (n < 20) throw new Error(`nur ${n} Regeln – Format unerwartet`); return text; },
    count: (d) => (d.match(/^\s*-\s+id:/gm) || []).length,
  },
  // nuclei aktualisiert seine Vorlagen selbst (nuclei -update-templates); Vigil stoesst das nur an
  { id: 'nuclei-templates', label: 'nuclei-Vorlagen (vom Werkzeug selbst aktualisiert)', unit: 'Vorlagen', tool: true, when: (ctx) => !!(ctx.updaters && ctx.updaters['nuclei-templates']) },
];

function parseUrlList(text, min, cap) {
  const urls = String(text).split(/\r?\n/).map((l) => l.trim()).filter((l) => /^https?:\/\/\S+$/i.test(l) && l.length < 2000).slice(0, cap);
  if (urls.length < min) throw new Error(`nur ${urls.length} Adressen – Format unerwartet`);
  return urls;
}
function parseRss(text) {
  const items = [];
  const dec = (s) => String(s || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  for (const m of String(text).matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi)) {
    const get = (k) => dec((m[1].match(new RegExp(`<${k}\\b[^>]*>([\\s\\S]*?)<\\/${k}>`, 'i')) || [])[1]);
    const title = get('title').slice(0, 300), link = get('link').slice(0, 500);
    if (title) items.push({ title, link: /^https:\/\//.test(link) ? link : '', date: get('pubDate'), summary: get('description').slice(0, 600) });
    if (items.length >= 1000) break;
  }
  return items;
}
const countYaraRules = (t) => (String(t).match(/^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_]\w*/gm) || []).length;

const file = (dir, id) => path.join(dir, `${id}.json`);
const sidecarFile = (dir, f) => path.join(dir, `${f.id}.${f.sidecar}`);
const dataHash = (data) => crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
// Integritaet im Cache: die gespeicherte Fassung traegt einen Hash ihrer Daten. Passt er nicht
// (Datei veraendert oder beschaedigt), wird sie nicht verwendet und beim naechsten Lauf neu geladen.
function loadFeed(dir, id) {
  let d;
  try { d = JSON.parse(fs.readFileSync(file(dir, id), 'utf8')); } catch { return null; }
  if (d && d.dataSha256 && dataHash(d.data) !== d.dataSha256) return null;
  return d;
}
const ALLOWED = ['https://endoflife.date/', 'https://raw.githubusercontent.com/', 'https://www.cisa.gov/', 'https://epss.cyentia.com/', 'https://openphish.com/', 'https://urlhaus.abuse.ch/', 'https://wid.cert-bund.de/', 'https://semgrep.dev/', 'https://crt.sh/', 'https://api.osv.dev/', 'https://osv-vulnerabilities.storage.googleapis.com/'];
// Ist eine Quelle aktiv? (z. B. YARA-Regeln nur, wenn yara installiert ist)
const isActive = (f, ctx) => !f.when || !!f.when(ctx || {});

// Optionale Festlegung je Feed in <feeds>/pins.json (z. B. fuer Firmen, die nur freigegebene
// Fassungen zulassen): { "<feed-id>": { "sha256": ["<hex>", …], "minisign": { "publicKey": "…", "sigUrl": "https://…" } } }
function loadPins(dir) { try { const p = JSON.parse(fs.readFileSync(path.join(dir, 'pins.json'), 'utf8')); return p && typeof p === 'object' ? p : {}; } catch { return {}; } }

async function fetchLimited(url, maxBytes, fetchImpl, { binary = false, raw = false, timeoutMs = 60000 } = {}) {
  if (!ALLOWED.some((p) => url.startsWith(p))) throw new Error('Quelle nicht erlaubt');
  const r = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs), headers: { 'User-Agent': 'Vigil-Feeds/1' }, redirect: 'error' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > maxBytes) throw new Error('zu groß');
  return binary || raw ? buf : buf.toString('utf8');
}

// Download pruefen, bevor er verwendet wird: SHA-256-Festlegung und/oder minisign-Signatur.
async function verifyFeed(buf, spec, fetchImpl) {
  if (!spec || (!spec.sha256 && !spec.minisign)) return { pinned: false, signed: false };
  let minisign = null;
  if (spec.minisign && spec.minisign.publicKey && spec.minisign.sigUrl) minisign = { publicKey: spec.minisign.publicKey, signature: await fetchLimited(spec.minisign.sigUrl, 64 * 1024, fetchImpl) };
  const r = verifyDownload(buf, { sha256: spec.sha256, minisign });
  return { pinned: r.pinned, signed: r.signed };
}

function writeRec(dir, f, rec) {
  fs.writeFileSync(file(dir, f.id) + '.tmp', JSON.stringify(rec));
  fs.renameSync(file(dir, f.id) + '.tmp', file(dir, f.id));
  // Regeldateien fuer externe Werkzeuge (yara, semgrep) zusaetzlich als Datei ablegen
  if (f.sidecar && typeof rec.data === 'string') { fs.writeFileSync(sidecarFile(dir, f) + '.tmp', rec.data); fs.renameSync(sidecarFile(dir, f) + '.tmp', sidecarFile(dir, f)); }
}

// Laedt alle faelligen Feeds; bei Fehlern bleibt die letzte gute Fassung.
// ctx: { tools: { yara, semgrep }, updaters: { 'nuclei-templates': async () => ({ count }) } }
async function syncFeeds(dir, { force = false, fetchImpl = fetch, now = Date.now(), ctx = {} } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const results = [];
  const pins = loadPins(dir);
  for (const f of FEEDS) {
    if (!isActive(f, ctx)) { results.push({ id: f.id, skipped: true, inactive: true }); continue; }
    const old = loadFeed(dir, f.id);
    if (!force && old && now - Date.parse(old.fetchedAt) < (f.maxAgeMs || MAX_AGE_MS)) { results.push({ id: f.id, skipped: true }); continue; }
    let lastErr = null;
    if (f.tool) {
      try {
        const r = await ctx.updaters[f.id]();
        if (!r || r.ok === false) throw new Error((r && r.error) || 'Aktualisierung fehlgeschlagen');
        writeRec(dir, f, { id: f.id, fetchedAt: new Date(now).toISOString(), count: r.count || null, changed: true, data: null });
        results.push({ id: f.id, ok: true, count: r.count || null });
      } catch (e) { lastErr = e.message; }
    } else {
      for (const url of f.urls) {
        try {
          const buf = await fetchLimited(url, f.maxBytes, fetchImpl, { raw: true });
          const v = await verifyFeed(buf, pins[f.id] || f.verify, fetchImpl); // wirft bei Abweichung
          const text = buf.toString('utf8');
          const data = f.parse(text);
          const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
          const rec = { id: f.id, url, fetchedAt: new Date(now).toISOString(), sha256, dataSha256: dataHash(data), pinned: v.pinned, signed: v.signed, count: f.count(data), changed: !old || old.sha256 !== sha256, data };
          writeRec(dir, f, rec);
          results.push({ id: f.id, ok: true, count: rec.count, changed: rec.changed });
          lastErr = null;
          break;
        } catch (e) { lastErr = e.message; }
      }
    }
    if (lastErr) {
      if (old) { old.lastError = lastErr; old.lastErrorAt = new Date(now).toISOString(); try { fs.writeFileSync(file(dir, f.id), JSON.stringify(old)); } catch { /* egal */ } }
      results.push({ id: f.id, ok: false, error: lastErr });
    }
  }
  return results;
}

// Kompilierte Fassung fuer die Pruefung (einmal je Laden)
function loadCompiled(dir) {
  const g = loadFeed(dir, 'gitleaks-rules');
  const r = loadFeed(dir, 'retirejs');
  const lists = ['openphish', 'urlhaus'].map((id) => { const d = loadFeed(dir, id); return d && Array.isArray(d.data) ? { source: id === 'openphish' ? 'OpenPhish' : 'URLhaus', urls: d.data } : null; }).filter(Boolean);
  const cb = loadFeed(dir, 'certbund');
  const eol = loadFeed(dir, 'endoflife');
  const side = (id, ext) => { const p = path.join(dir, `${id}.${ext}`); return fs.existsSync(p) ? p : null; };
  return {
    secretRules: g ? compileSecretRules(g.data) : [], retire: r ? compileRetire(r.data) : [],
    phishLists: lists, phish: require('./linkcheck').buildPhishIndex(lists),
    advisories: cb && Array.isArray(cb.data) ? cb.data : [],
    eol: eol && eol.data && typeof eol.data === 'object' ? eol.data : null,
    yaraFile: side('yara-rules', 'yar'), semgrepFile: side('semgrep-rules', 'yml'),
    at: { gitleaks: g && g.fetchedAt, retire: r && r.fetchedAt },
  };
}
function feedStatus(dir, ctx) {
  return FEEDS.map((f) => { const d = loadFeed(dir, f.id); return { id: f.id, label: f.label, unit: f.unit || (f.id === 'retirejs' ? 'Bibliotheken' : 'Regeln'), inactive: ctx ? !isActive(f, ctx) : false, fetchedAt: d && d.fetchedAt, count: d && d.count, lastError: d && d.lastError, lastErrorAt: d && d.lastErrorAt }; });
}
const needsFeedSync = (dir, now = Date.now(), ctx) => FEEDS.some((f) => { if (ctx && !isActive(f, ctx)) return false; if (!ctx && f.when) return false; const d = loadFeed(dir, f.id); return !d || now - Date.parse(d.fetchedAt) >= (f.maxAgeMs || MAX_AGE_MS); });

module.exports = { syncFeeds, loadCompiled, feedStatus, needsFeedSync, loadFeed, verifyFeed, parseGitleaksToml, goRegexToJs, compileSecretRules, compileRetire, shannon, FEEDS, fetchLimited, parseUrlList, parseRss, countYaraRules, ALLOWED, MAX_AGE_MS };
