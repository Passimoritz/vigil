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
const archives = require('./archives');
const bundled = require('./bundled');
const { analyzeScript, SCRIPT_EXT } = require('./scriptobf');
const { analyzeLnk } = require('./lnk');
const { readMail, MAIL_EXT } = require('./mail');
const { extractDocUrls } = require('./linkcheck');
const MAX_DEPTH = 2; // Archiv im Archiv (bzw. Anhang in der Mail) – tiefer wird nicht entpackt
// Diese Eintraege werden auch gross gelesen (bis zur Archiv-Grenze), weil sie eigene Pruefungen haben
const BIG_OK = /\.(exe|dll|so|dylib|sys|ocx|scr|msi|bin|jar|war|ear|zip|7z|rar|tar|tgz|gz|iso|img|vhdx?|dmg|cab|eml|msg|pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|rtf)$/i;
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
    this.links = [];        // Links aus Dokumenten und Mails (fuer den Phishing-Abgleich)
    this.bundledDeps = [];  // in Programmen/JARs eingebaute Bibliotheken (fuer den CVE-Abgleich)
    this.pending = [];      // asynchrone Arbeit (Entpacken ueber 7-Zip)
  }
  addLinks(urls, label) { for (const url of urls || []) if (this.links.length < 5000) this.links.push({ url, label: String(label).replace(/\\/g, '/') }); }
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

// Programme: Packer/APIs, Schutzfunktionen (PE) und eingebaute Bibliotheken
function binaryChecks(col, buf, label) {
  for (const bf of analyzeBinary(buf, label)) col.findings.push(bf);
  for (const f of bundled.bundledFindings(bundled.detectBundled(buf), label)) col.findings.push(f);
}

function addTextBuffer(col, label, kind, buf, srcPath) {
  const ext = extname(srcPath || label);
  if (looksBinary(buf)) {
    if (BINARY_EXE_EXT.has(ext)) binaryChecks(col, buf, label);
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
  if (SCRIPT_EXT.has(ext)) for (const f of analyzeScript(text, label, ext)) col.findings.push(f);
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
  const label = rel.replace(/\\/g, '/');

  if (ARCHIVE_EXT.has(ext)) {
    ingestArchive(col, full, rel, 1);
    return;
  }
  // tar/gz/ISO (reines JS) bzw. 7z/RAR/MSI/DMG/VHD (ueber 7-Zip, falls installiert)
  const kind = archives.archiveKind(full);
  if (kind) {
    ingestArchiveAny(col, { file: full, name: full }, label, 1);
    if (ext !== '.msi') return; // MSI zusaetzlich als Programmdatei pruefen
  }
  // E-Mails und Verknuepfungen
  if (MAIL_EXT.has(ext) || ext === '.lnk') {
    if (stat.size > archives.LIMITS.maxEntryBytes) { col.notes.push(`Uebersprungen (zu gross): ${rel}`); return; }
    try { processEntry(col, label, full, fs.readFileSync(full), 0); } catch (e) { col.notes.push(`Datei nicht lesbar: ${rel}`); }
    return;
  }
  // Dokumente mit moeglichem aktivem Inhalt (Makros, PDF-JavaScript, eingebettete Objekte)
  if (DOC_EXT.has(ext) && stat.size < 60 * 1024 * 1024) {
    try { const buf = fs.readFileSync(full); for (const f of analyzeDocument(buf, label)) col.findings.push(f); col.addLinks(extractDocUrls(buf, ext), label); } catch (e) { col.notes.push(`Dokument nicht lesbar: ${rel}`); }
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
      binaryChecks(col, buf, rel);
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

// Ein Eintrag aus einem Archiv oder ein Mail-Anhang: dieselben Pruefungen wie fuer Dateien.
function processEntry(col, label, name, buf, depth) {
  const ext = extname(name);
  if (ARCHIVE_EXT.has(ext) || (archives.archiveKind(name) && depth > 0)) {
    if (depth >= MAX_DEPTH) { col.notes.push(`Verschachteltes Archiv nicht entpackt: ${name}`); return; }
    ingestArchiveAny(col, { buf, name }, label, depth + 1);
    return;
  }
  // Eingebaute Java-Bibliotheken (auch in umgepackten "fat jars")
  if (/(^|\/)META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/i.test(name)) {
    const d = bundled.parsePomProperties(buf.toString('utf8'));
    if (d && col.bundledDeps.length < 2000) col.bundledDeps.push({ ecosystem: 'Maven', name: d.maven, version: d.version, raw: `${d.maven}@${d.version} (eingebaut in ${String(label).split('!/')[0]})` });
    return;
  }
  // Handy-Apps: binaeres Manifest bzw. binaere Info.plist lesbar machen
  if (/(^|\/)AndroidManifest\.xml$/i.test(name) || /\.app\/Info\.plist$/i.test(name)) {
    const xml = /plist$/i.test(name) ? decodeBplist(buf) : decodeAxml(buf);
    if (xml) { col.add({ label, kind: 'archive-entry', language: 'xml', path: name, content: xml, meta: { note: 'aus dem Binärformat der App zurückgewandelt' } }); return; }
  }
  if (MAIL_EXT.has(ext)) { ingestMail(col, buf, label, depth); return; }
  if (ext === '.lnk') { for (const f of analyzeLnk(buf, label)) col.findings.push(f); return; }
  if (DOC_EXT.has(ext)) {
    for (const f of analyzeDocument(buf, label)) col.findings.push(f);
    col.addLinks(extractDocUrls(buf, ext), label);
    if (ext !== '.pdf' && ext !== '.rtf') return;
  }
  if (isModelExt(ext)) { try { for (const f of analyzeModelFile(buf, label)) col.findings.push(f); } catch { /* defekt */ } }
  if (depth >= 2 && ext === '.class') return; // Klassen in verschachtelten JARs: nur die Paketangaben zaehlen
  addTextBuffer(col, label, 'archive-entry', buf, name);
}

function ingestMail(col, buf, label, depth) {
  let r = null;
  try { r = readMail(buf, label); } catch { r = null; }
  if (!r) { col.notes.push(`E-Mail nicht lesbar: ${label}`); return; }
  for (const f of r.findings) col.findings.push(f);
  col.addLinks(r.urls, label);
  for (const a of r.attachments) {
    if (col.atCapacity()) break;
    const name = path.posix.basename(String(a.name || 'anhang').replace(/\\/g, '/')).slice(0, 200) || 'anhang';
    processEntry(col, `${label}!/${name}`, name, a.data, depth + 1);
  }
}

// Eintraege eines entpackten Archivs pruefen (gemeinsam fuer tar, ISO und 7-Zip)
function finishEntries(col, label, entries, unsafe, depth, kind, bomb = false) {
  col.notes.push(`Archiv geöffnet: ${label} (${entries.length} Einträge)`);
  for (const f of archives.archiveFindings({ label, unsafe, bomb, names: entries.map((e) => e.name), kind })) col.findings.push(f);
  for (const e of entries) {
    if (col.atCapacity()) { col.notes.push('Limit erreicht - restliches Archiv übersprungen.'); break; }
    if (!e.data) continue;
    if (e.data.length > MAX_TEXT_BYTES * 3 && !TEXT_EXT.has(extname(e.name)) && !BIG_OK.test(e.name)) continue;
    processEntry(col, `${label}!/${e.name}`, e.name, e.data, depth);
  }
}

// Alle Nicht-ZIP-Formate. src = { file } (Datei auf der Platte) oder { buf, name } (aus Archiv/Mail)
function ingestArchiveAny(col, src, label, depth) {
  const name = src.name || src.file;
  if (ARCHIVE_EXT.has(extname(name))) { ingestArchive(col, src.buf || src.file, label, depth); return; }
  const kind = archives.archiveKind(name);
  let size = src.buf ? src.buf.length : 0;
  if (src.file) { try { size = fs.statSync(src.file).size; } catch { return; } }
  if (kind === 'tar' || kind === 'tgz' || kind === 'gz') {
    if (size > archives.LIMITS.maxTotalBytes) { col.notes.push(`Archiv zu groß, übersprungen: ${label}`); return; }
    let buf = src.buf || fs.readFileSync(src.file);
    if (kind !== 'tar') {
      const g = archives.gunzipLimited(buf);
      if (g.error === 'bomb') { finishEntries(col, label, [], [], depth, kind, true); return; }
      if (g.error) { col.notes.push(`Archiv nicht lesbar: ${label} (${g.error})`); return; }
      buf = g.data;
    }
    if (kind === 'gz' && buf.subarray(257, 262).toString('latin1') !== 'ustar') {
      const inner = path.posix.basename(String(name).replace(/\\/g, '/')).replace(/\.gz$/i, '');
      processEntry(col, `${label}!/${inner}`, inner, buf, depth);
      return;
    }
    const t = archives.parseTar(buf);
    col.notes.push(...t.notes);
    finishEntries(col, label, t.entries, t.unsafe, depth, kind);
    return;
  }
  if (kind === 'iso') {
    let r = null;
    if (src.file) r = archives.isoFromFile(src.file);
    else {
      const b = src.buf;
      const p = archives.parseIso((off, len) => b.subarray(off, Math.min(b.length, off + len)), b.length);
      if (p) r = { ...p, entries: p.entries.map((e) => ({ name: e.name, size: e.size, data: e.read() })) };
    }
    if (r) { col.notes.push(...r.notes); finishEntries(col, label, r.entries, [], depth, 'iso'); return; }
    // reines UDF-Abbild: 7-Zip versuchen
  }
  queue7z(col, src, label, depth);
}

// 7-Zip laeuft asynchron; ingestTargets wartet am Ende darauf
function queue7z(col, src, label, depth) {
  col.pending.push(async () => {
    let file = src.file, tmp = null;
    try {
      if (!file) { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-arc-')); file = path.join(tmp, 'archiv' + extname(src.name || '.7z')); fs.writeFileSync(file, src.buf); }
      const r = await archives.sevenZipEntries(file);
      if (r.missing) { col.notes.push(`Inhalt von ${label} übersprungen: 7-Zip fehlt (optional).`); return; }
      col.notes.push(...(r.notes || []));
      // Nur gelistet (zu gross): Namen trotzdem fuer die Abbild-Pruefung nutzen
      if (r.names) { for (const f of archives.archiveFindings({ label, unsafe: r.unsafe || [], names: r.names, kind: '7z' })) col.findings.push(f); return; }
      finishEntries(col, label, r.entries || [], r.unsafe || [], depth, '7z', !!r.bomb);
    } catch (e) { col.notes.push(`Archiv nicht lesbar: ${label} (${e.message})`); }
    finally { if (tmp) try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* egal */ } }
  });
}

// ZIP/JAR/APK … (adm-zip). source = Pfad oder Buffer.
function ingestArchive(col, source, label, depth = 1) {
  let zip;
  try { zip = new AdmZip(source); }
  catch (e) { col.notes.push(`Archiv nicht lesbar: ${label} (${e.message})`); return; }
  const entries = zip.getEntries();
  const files = entries.filter((e) => !e.isDirectory);
  const unsafe = files.map((e) => e.entryName).filter((n) => archives.safeName(n).unsafe);
  // Zip-Bombe: entpackte Groesse laut Verzeichnis gegen die gepackte Groesse
  const unpacked = files.reduce((a, e) => a + (e.header.size || 0), 0);
  const packed = files.reduce((a, e) => a + (e.header.compressedSize || 0), 0) || 1;
  const bomb = unpacked > 100 * 1024 * 1024 && unpacked / packed > archives.LIMITS.maxRatio;
  col.notes.push(`Archiv geöffnet: ${label} (${entries.length} Einträge)`);
  for (const f of archives.archiveFindings({ label: String(label).replace(/\\/g, '/'), unsafe, bomb, names: [] })) col.findings.push(f);
  if (bomb) return;
  let total = 0;
  for (const ent of files.slice(0, archives.LIMITS.maxEntries)) {
    if (col.atCapacity()) { col.notes.push('Limit erreicht - restliches Archiv übersprungen.'); break; }
    const name = ent.entryName;
    const ext = extname(name);
    const size = ent.header.size || 0;
    // Groesse VOR dem Entpacken pruefen
    if (size > MAX_TEXT_BYTES * 3 && !TEXT_EXT.has(ext) && !BIG_OK.test(name) && !/pom\.properties$/i.test(name)) continue;
    if (size > archives.LIMITS.maxEntryBytes || total + size > archives.LIMITS.maxTotalBytes) continue;
    let buf;
    try { buf = ent.getData(); } catch { continue; }
    total += buf.length;
    processEntry(col, `${label}!/${name}`, name, buf, depth);
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
    // Entpacken ueber 7-Zip (asynchron; kann weitere Arbeit nachschieben)
    for (let guard = 0; col.pending.length && guard < 500; guard++) {
      onProgress({ phase: 'ingest', message: 'Entpacke Archive …' });
      try { await col.pending.shift()(); } catch (e) { col.notes.push(`Archiv: ${e.message}`); }
    }
  }
  return { units: col.units, notes: col.notes, findings: col.findings, links: col.links, bundledDeps: col.bundledDeps, stats: { files: col.fileCount, bytes: col.totalBytes } };
}

module.exports = { ingestTargets, extractStrings, TEXT_EXT, tmpDir: os.tmpdir() };
