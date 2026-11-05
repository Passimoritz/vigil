'use strict';

// Ingest: nimmt Ziele (Dateien, Ordner, ZIP/JAR, EXE/Binaries, Links, IP/Host)
// und erzeugt daraus normalisierte "Units" (Beweis-/Pruefmaterial) fuer die Analyse.

const fs = require('fs');
const path = require('path');
const os = require('os');
const https = require('https');
const http = require('http');
const AdmZip = require('adm-zip');
const { makeMatcher, loadIgnore } = require('./ignore');
const { analyzeBinary } = require('./binaryaudit');

// --- Grenzen, damit nichts ausufert -------------------------------------
const MAX_TEXT_BYTES = 400 * 1024;      // groesste Textdatei, die voll gelesen wird
const MAX_STRINGS_BYTES = 200 * 1024;   // wieviel aus einem Binary als "strings" extrahiert wird
const MAX_FILES = 2500;                  // Dateianzahl pro Lauf
const MAX_TOTAL_BYTES = 40 * 1024 * 1024; // Gesamt-Textbudget
const MAX_HTTP_BYTES = 256 * 1024;       // wieviel von einem Link/Endpoint gelesen wird

const TEXT_EXT = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.json5',
  '.py', '.rb', '.php', '.java', '.kt', '.kts', '.go', '.rs', '.c', '.h',
  '.cpp', '.cc', '.hpp', '.cs', '.swift', '.m', '.mm', '.scala', '.clj',
  '.cxx', '.hh', '.hxx', '.dart', '.sc', '.ex', '.exs', '.lua', '.erb', '.rake', '.cshtml', '.razor',
  '.sh', '.bash', '.zsh', '.ps1', '.psm1', '.psd1', '.bat', '.cmd',
  '.ipynb', '.gql',
  '.html', '.htm', '.css', '.scss', '.vue', '.svelte',
  '.sql', '.graphql', '.proto',
  '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf', '.env', '.properties',
  '.xml', '.gradle', '.tf', '.dockerfile', '.md', '.txt', '.lock',
]);

const SKIP_DIR = new Set(['node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out', 'target', '.next', '.cache', 'vendor', '__pycache__', '.venv', 'venv']);

const BINARY_EXE_EXT = new Set(['.exe', '.dll', '.so', '.dylib', '.bin', '.msi', '.app']);
const ARCHIVE_EXT = new Set(['.zip', '.jar', '.war', '.ear', '.apk', '.aar', '.nupkg', '.ipa', '.xapk']);
const { decodeAxml, decodeBplist } = require('./modules/mobile');
const { analyzeDocument, DOC_EXT } = require('./docaudit');
const { analyzeModelFile, isModelExt } = require('./modelscan');

// Modelldatei lesen: ZIP-Modelle (PyTorch) bis 512 MB ganz, sonst nur der Anfang (dort steht der Pickle)
function readModel(full, size) {
  const HEAD = 32 * 1024 * 1024;
  if (size <= HEAD) return fs.readFileSync(full);
  const fd = fs.openSync(full, 'r');
  try {
    const magic = Buffer.alloc(4); fs.readSync(fd, magic, 0, 4, 0);
    if (magic.readUInt32BE(0) === 0x504b0304 && size <= 512 * 1024 * 1024) return fs.readFileSync(full);
    const buf = Buffer.alloc(HEAD); const n = fs.readSync(fd, buf, 0, HEAD, 0); return buf.subarray(0, n);
  } finally { fs.closeSync(fd); }
}

function extname(p) {
  const e = path.extname(p).toLowerCase();
  if (!e && path.basename(p).toLowerCase() === 'dockerfile') return '.dockerfile';
  return e;
}

function langFor(ext) {
  const map = {
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.tsx': 'typescript', '.jsx': 'javascript',
    '.py': 'python', '.rb': 'ruby', '.php': 'php', '.java': 'java',
    '.kt': 'kotlin', '.go': 'go', '.rs': 'rust', '.cs': 'csharp',
    '.c': 'c', '.cpp': 'cpp', '.h': 'c', '.sh': 'bash', '.ps1': 'powershell',
    '.sql': 'sql', '.html': 'html', '.yml': 'yaml', '.yaml': 'yaml',
    '.xml': 'xml', '.gradle': 'gradle',
    '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.hh': 'cpp', '.hxx': 'cpp',
    '.dart': 'dart', '.scala': 'scala', '.sc': 'scala', '.ex': 'elixir', '.exs': 'elixir', '.lua': 'lua',
    '.rake': 'ruby', '.erb': 'ruby', '.bash': 'bash', '.zsh': 'bash', '.psm1': 'powershell', '.psd1': 'powershell',
    '.kts': 'kotlin', '.swift': 'swift', '.ipynb': 'json', '.json': 'json', '.graphql': 'graphql', '.gql': 'graphql',
  };
  return map[ext] || 'text';
}

// Druckbare ASCII-/UTF-8-Strings aus einem Buffer ziehen (fuer EXE/DLL etc.).
function extractStrings(buf, minLen = 4) {
  const out = [];
  let cur = [];
  const limit = Math.min(buf.length, MAX_STRINGS_BYTES);
  for (let i = 0; i < limit; i++) {
    const c = buf[i];
    if (c >= 0x20 && c <= 0x7e) {
      cur.push(c);
    } else {
      if (cur.length >= minLen) out.push(Buffer.from(cur).toString('ascii'));
      cur = [];
    }
  }
  if (cur.length >= minLen) out.push(Buffer.from(cur).toString('ascii'));
  return out;
}

function looksBinary(buf) {
  const n = Math.min(buf.length, 4096);
  let nonText = 0;
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c === 0) return true;
    if (c < 0x09 || (c > 0x0d && c < 0x20)) nonText++;
  }
  return nonText / Math.max(1, n) > 0.3;
}

// --- Ergebnis-Sammler ---------------------------------------------------
class Collector {
  constructor() {
    this.units = [];
    this.totalBytes = 0;
    this.fileCount = 0;
    this.notes = [];
    this.findings = []; // z. B. aus der Binary-Analyse
  }
  atCapacity() {
    return this.fileCount >= MAX_FILES || this.totalBytes >= MAX_TOTAL_BYTES;
  }
  add(unit) {
    if (this.atCapacity()) return false;
    this.units.push(unit);
    this.fileCount++;
    this.totalBytes += Buffer.byteLength(unit.content || '', 'utf8');
    return true;
  }
}

function addTextBuffer(col, label, kind, buf, srcPath) {
  const ext = extname(srcPath || label);
  if (looksBinary(buf)) {
    if (BINARY_EXE_EXT.has(ext)) for (const bf of analyzeBinary(buf, srcPath || label)) col.findings.push(bf);
    const strings = extractStrings(buf);
    if (strings.length) {
      col.add({
        label, kind: 'binary-strings', language: 'text', path: srcPath || label,
        content: strings.join('\n'),
        meta: { note: 'Binaerdatei - nur extrahierte Zeichenketten, keine echte Dekompilierung.' },
      });
    }
    return;
  }
  let text = buf.toString('utf8');
  if (Buffer.byteLength(text, 'utf8') > MAX_TEXT_BYTES) {
    text = text.slice(0, MAX_TEXT_BYTES) + '\n\n/* ... [von Vigil gekuerzt] ... */';
  }
  col.add({ label, kind, language: langFor(ext), path: srcPath || label, content: text });
}

function walkDir(col, dir, root, matcher) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (e) { col.notes.push(`Ordner nicht lesbar: ${dir} (${e.code || e.message})`); return; }

  for (const ent of entries) {
    if (col.atCapacity()) { col.notes.push('Limit erreicht - weitere Dateien übersprungen.'); return; }
    const full = path.join(dir, ent.name);
    const rel = path.relative(root, full).replace(/\\/g, '/');
    if (ent.name === '.vigilignore') continue;                 // Steuerdatei selbst nicht pruefen
    if (matcher && matcher(rel, ent.name)) continue;           // per .vigilignore ausgeschlossen
    if (ent.isDirectory()) {
      if (SKIP_DIR.has(ent.name)) continue;
      walkDir(col, full, root, matcher);
    } else if (ent.isFile()) {
      ingestFile(col, full, root);
    }
  }
}

// root = absoluter Pfad des urspruenglich gewaehlten Ordners (oder null bei Einzeldatei).
function ingestFile(col, full, root) {
  const ext = extname(full);
  let stat;
  try { stat = fs.statSync(full); } catch { return; }
  // Lesbares Label: "ordnername/unterordner/datei.js" bzw. nur der Dateiname.
  const rel = root ? path.join(path.basename(root), path.relative(root, full)) : path.basename(full);

  if (ARCHIVE_EXT.has(ext)) {
    ingestArchive(col, full, rel);
    return;
  }
  // Dokumente mit moeglichem aktivem Inhalt (Makros, PDF-JavaScript, eingebettete Objekte)
  if (DOC_EXT.has(ext) && stat.size < 60 * 1024 * 1024) {
    try { for (const f of analyzeDocument(fs.readFileSync(full), rel.replace(/\\/g, '/'))) col.findings.push(f); } catch (e) { col.notes.push(`Dokument nicht lesbar: ${rel}`); }
    if (ext !== '.pdf' && ext !== '.rtf') return; // Office-Binaerformate liefern keinen sinnvollen Text
  }
  // KI-Modelldateien (Pickle): gefaehrliche Importe pruefen, ohne die Datei zu laden
  if (isModelExt(ext)) {
    try { for (const f of analyzeModelFile(readModel(full, stat.size), rel.replace(/\\/g, '/'))) col.findings.push(f); }
    catch (e) { col.notes.push(`Modelldatei nicht lesbar: ${rel}`); }
  }
  if (BINARY_EXE_EXT.has(ext)) {
    try {
      const buf = fs.readFileSync(full);
      for (const bf of analyzeBinary(buf, rel)) col.findings.push(bf);
      const strings = extractStrings(buf);
      col.add({
        label: rel, kind: 'binary-strings', language: 'text', path: full,
        content: strings.join('\n'),
        meta: { note: `Binary (${ext}). Nur extrahierte Strings; echte Binary-Analyse ist begrenzt.` },
      });
    } catch (e) { col.notes.push(`Binary nicht lesbar: ${full}`); }
    return;
  }
  // Textartig oder unbekannt: versuchen zu lesen, wenn nicht zu gross.
  if (stat.size > MAX_TEXT_BYTES * 3 && !TEXT_EXT.has(ext)) {
    col.notes.push(`Uebersprungen (zu gross/unbekannt): ${rel}`);
    return;
  }
  try {
    const buf = fs.readFileSync(full);
    addTextBuffer(col, rel, 'file', buf, full);
  } catch (e) { col.notes.push(`Datei nicht lesbar: ${full}`); }
}

function ingestArchive(col, archivePath, label) {
  let zip;
  try { zip = new AdmZip(archivePath); }
  catch (e) { col.notes.push(`Archiv nicht lesbar: ${archivePath} (${e.message})`); return; }
  const entries = zip.getEntries();
  col.notes.push(`Archiv geöffnet: ${label} (${entries.length} Einträge)`);
  for (const ent of entries) {
    if (col.atCapacity()) { col.notes.push('Limit erreicht - restliches Archiv übersprungen.'); break; }
    if (ent.isDirectory) continue;
    const name = ent.entryName;
    const ext = extname(name);
    if (ARCHIVE_EXT.has(ext)) {
      col.notes.push(`Verschachteltes Archiv nicht entpackt: ${name}`);
      continue;
    }
    let buf;
    try { buf = ent.getData(); } catch { continue; }
    if (buf.length > MAX_TEXT_BYTES * 3 && !TEXT_EXT.has(ext)) continue;
    // Handy-Apps: binaeres Manifest bzw. binaere Info.plist lesbar machen
    if (/(^|\/)AndroidManifest\.xml$/i.test(name) || /\.app\/Info\.plist$/i.test(name)) {
      const xml = /plist$/i.test(name) ? decodeBplist(buf) : decodeAxml(buf);
      if (xml) { col.add({ label: `${label}!/${name}`, kind: 'archive-entry', language: 'xml', path: name, content: xml, meta: { note: 'aus dem Binärformat der App zurückgewandelt' } }); continue; }
    }
    if (DOC_EXT.has(ext)) { for (const f of analyzeDocument(buf, `${label}!/${name}`)) col.findings.push(f); if (ext !== '.pdf' && ext !== '.rtf') continue; }
    if (isModelExt(ext)) { try { for (const f of analyzeModelFile(buf, `${label}!/${name}`)) col.findings.push(f); } catch { /* defekt */ } }
    addTextBuffer(col, `${label}!/${name}`, 'archive-entry', buf, name);
  }
}

// --- Netzwerkziele (nur passiv, nur mit Berechtigung) -------------------
function fetchUrl(url) {
  return new Promise((resolve) => {
    let mod, target;
    try { target = new URL(url); } catch { return resolve({ error: 'Ungueltige URL' }); }
    mod = target.protocol === 'http:' ? http : https;
    const req = mod.request(url, { method: 'GET', timeout: 12000, headers: { 'User-Agent': 'Vigil-Audit/0.1 (+passive)' } }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size <= MAX_HTTP_BYTES) chunks.push(c);
        if (size > MAX_HTTP_BYTES) res.destroy();
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('close', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ error: 'Timeout' }); });
    req.on('error', (e) => resolve({ error: e.message }));
    req.end();
  });
}

async function ingestEndpoint(col, rawTarget, authorized) {
  if (!authorized) {
    col.notes.push(`Netzwerkziel "${rawTarget}" übersprungen: keine Berechtigung bestätigt.`);
    return;
  }
  // IP oder Host ohne Schema -> als https behandeln, Fallback http.
  let url = rawTarget;
  if (!/^https?:\/\//i.test(rawTarget)) url = 'https://' + rawTarget;
  let res = await fetchUrl(url);
  if (res.error && url.startsWith('https://')) {
    res = await fetchUrl('http://' + rawTarget.replace(/^https?:\/\//i, ''));
    url = 'http://' + rawTarget.replace(/^https?:\/\//i, '');
  }
  if (res.error) { col.notes.push(`Endpoint nicht erreichbar: ${rawTarget} (${res.error})`); return; }

  const headerLines = Object.entries(res.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n');
  const body = (res.body || '').slice(0, MAX_HTTP_BYTES);
  col.add({
    label: url,
    kind: 'endpoint',
    language: 'http',
    path: url,
    content:
      `# Passiver Endpoint-Review (nur Antwort gelesen, keine aktiven Angriffe)\n` +
      `URL: ${url}\nStatus: ${res.status}\n\n## Response-Header\n${headerLines}\n\n## Body (Anfang)\n${body}`,
    meta: { note: 'Passiver Abruf der Serverantwort. Pruefe Sicherheits-Header, Cookies, Info-Leaks, veraltete Software-Banner.' },
  });
}

// --- Oeffentliche API ---------------------------------------------------
// targets: [{ type: 'path'|'url'|'endpoint'|'image', value, authorized? }]
async function ingestTargets(targets, onProgress = () => {}) {
  const col = new Collector();
  for (const t of targets) {
    if (col.atCapacity()) break;
    if (t.type === 'image' || t.type === 'system') continue; // Container-Images prueft trivy direkt (kein Quelltext zum Einlesen)
    onProgress({ phase: 'ingest', message: `Lese: ${t.value}` });
    try {
      if (t.type === 'url' || t.type === 'endpoint') {
        await ingestEndpoint(col, t.value, !!t.authorized);
      } else {
        // Pfad: Datei oder Ordner
        let stat;
        try { stat = fs.statSync(t.value); }
        catch { col.notes.push(`Pfad nicht gefunden: ${t.value}`); continue; }
        if (stat.isDirectory()) {
          const patterns = loadIgnore(t.value);
          if (patterns.length) col.notes.push(`.vigilignore: ${patterns.length} Muster aktiv in ${path.basename(t.value)}.`);
          walkDir(col, t.value, t.value, makeMatcher(patterns));
        } else ingestFile(col, t.value, null);
      }
    } catch (e) {
      col.notes.push(`Fehler bei ${t.value}: ${e.message}`);
    }
  }
  return { units: col.units, notes: col.notes, findings: col.findings, stats: { files: col.fileCount, bytes: col.totalBytes } };
}

module.exports = { ingestTargets, extractStrings, TEXT_EXT, tmpDir: os.tmpdir() };
