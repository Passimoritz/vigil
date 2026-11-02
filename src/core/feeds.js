'use strict';

// Tagesaktuelle Erkennung ohne App-Update: Vigil laedt oeffentliche Erkennungsdaten selbst nach.
//
//  live bei jedem Lauf   OSV.dev (Schwachstellen aller Paket-Oekosysteme), Defender-Signaturen (Windows)
//  taeglich (intel.js)   CISA KEV (aktiv ausgenutzt), FIRST EPSS (Ausnutzungs-Wahrscheinlichkeit)
//  taeglich (hier)       gitleaks-Regeln (Zugangsdaten-Formate vieler Dienste),
//                        retire.js-Datenbank (verwundbare JavaScript-Bibliotheken)
//
// Sicherheit: nur feste HTTPS-Quellen, Groessengrenze, Pruefung von Form und Mindestumfang, die
// letzte gute Fassung bleibt bei jedem Fehler erhalten. Feeds sind reine DATEN – es wird nie Code
// aus dem Netz ausgefuehrt; Regex-Muster werden begrenzt, einzeln kompiliert und nur zeilenweise
// auf hoechstens 2000 Zeichen lange Zeilen angewendet.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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
];

const file = (dir, id) => path.join(dir, `${id}.json`);
function loadFeed(dir, id) { try { return JSON.parse(fs.readFileSync(file(dir, id), 'utf8')); } catch { return null; } }
const ALLOWED = ['https://raw.githubusercontent.com/', 'https://www.cisa.gov/', 'https://epss.cyentia.com/'];

async function fetchLimited(url, maxBytes, fetchImpl) {
  if (!ALLOWED.some((p) => url.startsWith(p))) throw new Error('Quelle nicht erlaubt');
  const r = await fetchImpl(url, { signal: AbortSignal.timeout(60000), headers: { 'User-Agent': 'Vigil-Feeds/1' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > maxBytes) throw new Error('zu groß');
  return buf.toString('utf8');
}

// Laedt alle faelligen Feeds; bei Fehlern bleibt die letzte gute Fassung.
async function syncFeeds(dir, { force = false, fetchImpl = fetch, now = Date.now() } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const results = [];
  for (const f of FEEDS) {
    const old = loadFeed(dir, f.id);
    if (!force && old && now - Date.parse(old.fetchedAt) < MAX_AGE_MS) { results.push({ id: f.id, skipped: true }); continue; }
    let lastErr = null;
    for (const url of f.urls) {
      try {
        const text = await fetchLimited(url, f.maxBytes, fetchImpl);
        const data = f.parse(text);
        const sha256 = crypto.createHash('sha256').update(text).digest('hex');
        const rec = { id: f.id, url, fetchedAt: new Date(now).toISOString(), sha256, count: f.count(data), changed: !old || old.sha256 !== sha256, data };
        fs.writeFileSync(file(dir, f.id) + '.tmp', JSON.stringify(rec));
        fs.renameSync(file(dir, f.id) + '.tmp', file(dir, f.id));
        results.push({ id: f.id, ok: true, count: rec.count, changed: rec.changed });
        lastErr = null;
        break;
      } catch (e) { lastErr = e.message; }
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
  return { secretRules: g ? compileSecretRules(g.data) : [], retire: r ? compileRetire(r.data) : [], at: { gitleaks: g && g.fetchedAt, retire: r && r.fetchedAt } };
}
function feedStatus(dir) {
  return FEEDS.map((f) => { const d = loadFeed(dir, f.id); return { id: f.id, label: f.label, fetchedAt: d && d.fetchedAt, count: d && d.count, lastError: d && d.lastError, lastErrorAt: d && d.lastErrorAt }; });
}
const needsFeedSync = (dir, now = Date.now()) => FEEDS.some((f) => { const d = loadFeed(dir, f.id); return !d || now - Date.parse(d.fetchedAt) >= MAX_AGE_MS; });

module.exports = { syncFeeds, loadCompiled, feedStatus, needsFeedSync, parseGitleaksToml, goRegexToJs, compileSecretRules, compileRetire, shannon, FEEDS };
