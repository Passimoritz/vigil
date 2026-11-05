'use strict';

// Weitere Archiv- und Abbildformate entpacken – rein lesend, nichts wird ausgefuehrt:
//  tar / tar.gz / tgz / gz   reines JavaScript (zlib)
//  ISO 9660 (+ Joliet)       reines JavaScript, liest nur Verzeichnis und Dateiinhalte
//  7z, RAR, MSI, DMG, VHD,   ueber ein installiertes 7-Zip ("7z"), sonst still uebersprungen
//  IMG (und ISO als Fallback)
//
// Schutz wie beim ZIP-Einlesen (ingest.js): Obergrenzen fuer Eintraege, Groesse je Eintrag und
// Gesamtgroesse, Erkennung von Zip-Bomben (Kompressionsverhaeltnis) und Pfad-Ausbruch ("../",
// absolute Pfade, Laufwerksbuchstaben). 7-Zip entpackt nur in einen frischen Temp-Ordner, der
// danach geloescht wird; Verknuepfungen (Symlinks) werden dabei nicht verfolgt.

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { spawn } = require('child_process');
const { normalizeFinding } = require('./schema');

const LIMITS = {
  maxEntries: 5000,
  maxEntryBytes: 64 * 1024 * 1024,   // groesster einzelner Eintrag, der gelesen wird
  maxTotalBytes: 256 * 1024 * 1024,  // Summe aller entpackten Inhalte
  maxRatio: 200,                     // ab diesem Verhaeltnis entpackt/gepackt: Zip-Bombe
};

const TAR_EXT = ['.tar', '.tgz', '.tar.gz', '.gz'];
const SEVENZIP_EXT = new Set(['.7z', '.rar', '.msi', '.dmg', '.vhd', '.vhdx', '.img', '.cab', '.xz', '.bz2', '.tbz2', '.txz']);
const DISK_IMAGE_EXT = new Set(['.iso', '.img', '.vhd', '.vhdx', '.dmg']);
// In Abbildern verdaechtig: alles, was per Doppelklick startet
const RUNNABLE = /\.(exe|scr|com|pif|cpl|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|jar|dll)$/i;

function archiveKind(name) {
  const n = String(name).toLowerCase();
  if (n.endsWith('.tar.gz') || n.endsWith('.tgz')) return 'tgz';
  if (n.endsWith('.tar')) return 'tar';
  if (n.endsWith('.gz')) return 'gz';
  if (n.endsWith('.iso')) return 'iso';
  const ext = path.extname(n);
  if (SEVENZIP_EXT.has(ext)) return '7z';
  return null;
}

// Eintragsname pruefen: liefert den bereinigten Namen und ob er aus dem Ziel ausbrechen wuerde.
function safeName(name) {
  const n = String(name || '').replace(/\\/g, '/').replace(/\0.*$/, '');
  const unsafe = /^\/|^[a-zA-Z]:/.test(n) || n.split('/').some((p) => p === '..');
  const clean = n.split('/').filter((p) => p && p !== '.' && p !== '..').join('/').replace(/^[a-zA-Z]:/, '');
  return { name: clean, unsafe };
}

// --- tar ---------------------------------------------------------------------------------------
const octal = (b) => { const s = b.toString('latin1').replace(/\0.*$/, '').trim(); return s ? parseInt(s, 8) || 0 : 0; };
const cstr = (b) => b.toString('utf8').replace(/\0.*$/, '');

function parseTar(buf, limits = LIMITS) {
  const entries = [], unsafe = [], notes = [];
  let off = 0, total = 0, longName = null, paxPath = null;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((x) => x === 0)) break; // Ende-Markierung
    let name = cstr(h.subarray(0, 100));
    const size = octal(h.subarray(124, 136));
    const type = String.fromCharCode(h[156] || 48);
    const magic = h.subarray(257, 262).toString('latin1');
    if (magic === 'ustar') { const prefix = cstr(h.subarray(345, 500)); if (prefix) name = prefix + '/' + name; }
    const dataStart = off + 512;
    const data = buf.subarray(dataStart, Math.min(buf.length, dataStart + size));
    off = dataStart + Math.ceil(size / 512) * 512;
    if (type === 'L') { longName = cstr(data); continue; }
    if (type === 'x') { const m = data.toString('utf8').match(/\d+ path=([^\n]*)\n/); paxPath = m ? m[1] : null; continue; }
    if (type === 'g') continue;
    if (longName) { name = longName; longName = null; }
    if (paxPath) { name = paxPath; paxPath = null; }
    const s = safeName(name);
    if (s.unsafe) unsafe.push(name);
    if (type === '2' || type === '1') { const target = cstr(h.subarray(157, 257)); if (/^\/|^[a-zA-Z]:|(^|\/)\.\.(\/|$)/.test(target)) unsafe.push(`${name} -> ${target}`); continue; }
    if (type !== '0' && type !== '\0' && type !== '7') continue; // nur normale Dateien
    if (entries.length >= limits.maxEntries) { notes.push('Archiv: zu viele Einträge – Rest übersprungen.'); break; }
    if (size > limits.maxEntryBytes) { entries.push({ name: s.name, size, data: null, skipped: true }); continue; }
    if (total + size > limits.maxTotalBytes) { notes.push('Archiv: Gesamtgröße erreicht – Rest übersprungen.'); break; }
    total += size;
    entries.push({ name: s.name, size, data });
  }
  return { entries, unsafe, notes };
}

// gzip mit harter Obergrenze fuer die entpackte Groesse (Schutz vor gz-Bomben)
function gunzipLimited(buf, limits = LIMITS) {
  try { return { data: zlib.gunzipSync(buf, { maxOutputLength: limits.maxTotalBytes }) }; }
  catch (e) { return { error: /maxOutputLength|buffer|Cannot create a Buffer/i.test(String(e.message)) || e.code === 'ERR_BUFFER_TOO_LARGE' ? 'bomb' : e.message }; }
}

// --- ISO 9660 / Joliet ------------------------------------------------------------------------
// reader(offset, length) -> Buffer; size = Gesamtgroesse
function parseIso(reader, size, limits = LIMITS) {
  const SECTOR = 2048;
  let pvd = null, joliet = null;
  for (let s = 16; s < 32 && (s + 1) * SECTOR <= size; s++) {
    const d = reader(s * SECTOR, SECTOR);
    if (d.subarray(1, 6).toString('latin1') !== 'CD001') break;
    if (d[0] === 1 && !pvd) pvd = d;
    if (d[0] === 2 && /%\/[@CE]/.test(d.subarray(88, 91).toString('latin1'))) joliet = d;
    if (d[0] === 255) break;
  }
  if (!pvd) return null;
  const vd = joliet || pvd;
  const decodeName = (b) => {
    let s;
    if (joliet) { const c = Buffer.from(b.subarray(0, b.length & ~1)); c.swap16(); s = c.toString('utf16le'); } else s = b.toString('latin1');
    return s.replace(/;\d+$/, '').replace(/\.$/, '');
  };
  const entries = [], notes = [];
  const seen = new Set();
  let total = 0;
  const walk = (lba, len, prefix, depth) => {
    if (depth > 12 || seen.has(lba) || entries.length >= limits.maxEntries) return;
    seen.add(lba);
    const dir = reader(lba * SECTOR, Math.min(len, 4 * 1024 * 1024));
    let p = 0;
    while (p < dir.length) {
      const recLen = dir[p];
      if (!recLen) { p = (Math.floor(p / SECTOR) + 1) * SECTOR; continue; }
      const rec = dir.subarray(p, p + recLen);
      p += recLen;
      if (rec.length < 34) break;
      const extent = rec.readUInt32LE(2), dlen = rec.readUInt32LE(10), flags = rec[25], nlen = rec[32];
      const raw = rec.subarray(33, 33 + nlen);
      if (nlen === 1 && (raw[0] === 0 || raw[0] === 1)) continue; // . und ..
      const name = decodeName(raw);
      const full = prefix ? `${prefix}/${name}` : name;
      if (flags & 2) { walk(extent, dlen, full, depth + 1); continue; }
      if (entries.length >= limits.maxEntries) { notes.push('Abbild: zu viele Einträge – Rest übersprungen.'); return; }
      const off = extent * SECTOR;
      if (off + dlen > size) continue;
      entries.push({ name: full, size: dlen, read: () => (dlen > limits.maxEntryBytes || total + dlen > limits.maxTotalBytes ? null : (total += dlen, reader(off, dlen))) });
    }
  };
  const root = vd.subarray(156, 190);
  walk(root.readUInt32LE(2), root.readUInt32LE(10), '', 0);
  return { entries, notes, joliet: !!joliet };
}

function isoFromFile(file, limits = LIMITS) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
    const size = fs.fstatSync(fd).size;
    const reader = (off, len) => { const b = Buffer.alloc(Math.max(0, Math.min(len, size - off))); if (b.length) fs.readSync(fd, b, 0, b.length, off); return b; };
    const r = parseIso(reader, size, limits);
    if (!r) return null;
    // Inhalte sofort lesen, solange die Datei offen ist (begrenzt)
    return { ...r, entries: r.entries.map((e) => ({ name: e.name, size: e.size, data: e.read() })) };
  } catch { return null; } finally { if (fd != null) try { fs.closeSync(fd); } catch { /* egal */ } }
}

// --- 7-Zip (optional) --------------------------------------------------------------------------
function sevenZipPath() {
  const cands = [
    path.join(process.env.ProgramFiles || 'C:\\Program Files', '7-Zip', '7z.exe'),
    path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', '7-Zip', '7z.exe'),
  ];
  for (const c of cands) { try { if (fs.existsSync(c)) return c; } catch { /* weiter */ } }
  return '7z';
}
function run(cmd, args, timeoutMs = 120000) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { return resolve({ ok: false, missing: true }); }
    let out = '';
    const t = setTimeout(() => { try { child.kill(); } catch { /* egal */ } }, timeoutMs);
    child.stdout.on('data', (d) => { if (out.length < 8e6) out += d; });
    child.stderr.on('data', () => {});
    child.on('error', (e) => { clearTimeout(t); resolve({ ok: false, missing: e.code === 'ENOENT' }); });
    child.on('close', (code) => { clearTimeout(t); resolve({ ok: true, code, out }); });
  });
}
// Ausgabe von "7z l -slt": Bloecke mit "Path = …", "Size = …", "Folder = +"
function parse7zList(text) {
  const items = [];
  const body = String(text).split(/^-{5,}\s*$/m).slice(1).join('\n');
  for (const block of body.split(/\r?\n\r?\n/)) {
    const get = (k) => { const m = block.match(new RegExp(`^${k} = (.*)$`, 'm')); return m ? m[1].trim() : ''; };
    const p = get('Path');
    if (!p) continue;
    const isDir = get('Folder') === '+' || /D/.test(get('Attributes').split(' ')[0] || '');
    items.push({ name: p, size: Number(get('Size')) || 0, packed: Number(get('Packed Size')) || 0, dir: isDir });
  }
  return items;
}

async function sevenZipEntries(file, limits = LIMITS) {
  const exe = sevenZipPath();
  const list = await run(exe, ['l', '-slt', '-p-', '-sccUTF-8', '--', file]);
  if (!list.ok) return { missing: true };
  const items = parse7zList(list.out).filter((x) => !x.dir);
  const unsafe = items.filter((x) => safeName(x.name).unsafe).map((x) => x.name);
  const total = items.reduce((a, x) => a + x.size, 0);
  const notes = [];
  let packedSize = 0; try { packedSize = fs.statSync(file).size; } catch { /* egal */ }
  const bomb = total > 100 * 1024 * 1024 && packedSize && total / packedSize > limits.maxRatio;
  if (bomb || items.length > limits.maxEntries * 2) return { entries: [], unsafe, notes, bomb: true, listed: items.length, total };
  // Sehr grosse Abbilder (z. B. mehrere GB) nicht auf die Platte entpacken
  if (total > limits.maxTotalBytes * 4) return { entries: [], unsafe, notes: ['Archiv zu groß zum Entpacken (über 1 GB) – nur die Liste der Einträge geprüft.'], names: items.map((x) => x.name), listed: items.length, total };
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-7z-'));
  const entries = [];
  try {
    // Nur Dateien bis zur Groessengrenze; Pfad-Ausbrueche blockiert 7-Zip selbst (kein -snld/-spf)
    const x = await run(exe, ['x', '-y', '-bd', '-p-', `-o${tmp}`, '--', file], 300000);
    if (!x.ok) return { missing: !!x.missing, entries, unsafe, notes };
    const root = fs.realpathSync(tmp);
    let sum = 0;
    const walk = (dir, depth) => {
      if (depth > 16 || entries.length >= limits.maxEntries) return;
      let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of ents) {
        const full = path.join(dir, e.name);
        let st; try { st = fs.lstatSync(full); } catch { continue; }
        if (st.isSymbolicLink()) continue;
        if (st.isDirectory()) { walk(full, depth + 1); continue; }
        if (!st.isFile()) continue;
        let real; try { real = fs.realpathSync(full); } catch { continue; }
        if (!real.startsWith(root + path.sep)) continue; // ausserhalb des Temp-Ordners: ignorieren
        const rel = path.relative(root, real).replace(/\\/g, '/');
        if (st.size > limits.maxEntryBytes || sum + st.size > limits.maxTotalBytes) { entries.push({ name: rel, size: st.size, data: null, skipped: true }); continue; }
        sum += st.size;
        try { entries.push({ name: rel, size: st.size, data: fs.readFileSync(real) }); } catch { /* egal */ }
      }
    };
    walk(root, 0);
  } finally { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* egal */ } }
  return { entries, unsafe, notes, listed: items.length, total };
}

// --- Befunde -----------------------------------------------------------------------------------
const F = (o) => normalizeFinding({ category: 'Other', confidence: 'high', sourceModule: 'archive-audit', ...o }, 'archive-audit');

function archiveFindings({ label, unsafe = [], bomb = false, names = [], kind = '' }) {
  const out = [];
  if (unsafe.length) out.push(F({
    ruleId: 'archive-path-traversal', severity: 'high',
    title: `Archiv mit Pfad-Ausbruch: ${path.basename(label)}`,
    description: `Einträge wie „${String(unsafe[0]).slice(0, 120)}“ würden beim Entpacken außerhalb des Zielordners landen („Zip Slip“). Betroffen: ${unsafe.length} Eintrag/Einträge.`,
    impact: 'Ein schlecht geschütztes Entpackprogramm überschreibt damit beliebige Dateien, z. B. im Autostart.',
    remediation: 'Archiv nicht entpacken, wenn die Herkunft unklar ist. Eigene Entpack-Routinen müssen jeden Pfad auf „..“ und absolute Pfade prüfen.',
    location: label,
  }));
  if (bomb) out.push(F({
    ruleId: 'archive-bomb', severity: 'medium', confidence: 'medium',
    title: `Archiv entpackt sich auf ein Vielfaches: ${path.basename(label)}`,
    description: 'Das Archiv ist extrem stark komprimiert (Zip-Bombe). Vigil hat es deshalb nicht entpackt.',
    impact: 'Beim Entpacken kann die Festplatte volllaufen oder ein Virenscanner aussteigen.',
    remediation: 'Nicht entpacken; Herkunft prüfen.',
    location: label,
  }));
  if (DISK_IMAGE_EXT.has(path.extname(String(label)).toLowerCase()) || kind === 'iso') {
    const run = names.filter((n) => RUNNABLE.test(n));
    if (run.length) out.push(F({
      ruleId: 'image-contains-executable', severity: run.some((n) => /\.(lnk|hta|js|jse|vbs|vbe|wsf|scr|bat|cmd|ps1)$/i.test(n)) ? 'high' : 'medium', confidence: 'medium',
      title: `Abbild-Datei enthält startbare Dateien: ${path.basename(label)}`,
      description: `In diesem Laufwerks-Abbild (ISO/IMG/VHD) liegen Programme, Skripte oder Verknüpfungen: ${run.slice(0, 6).map((n) => path.basename(n)).join(', ')}${run.length > 6 ? ' …' : ''}. Angreifer verpacken Schadsoftware gern so, weil Windows für Dateien in eingebundenen Abbildern oft keine Herkunftswarnung („aus dem Internet“) zeigt.`,
      impact: 'Ein Doppelklick auf die Verknüpfung oder das Programm im eingebundenen Laufwerk startet den Inhalt ohne die übliche Sicherheitswarnung.',
      remediation: 'Abbild nicht per Doppelklick einbinden, wenn es per E-Mail oder Download kam. Eigene Software lieber als signierten Installer verteilen.',
      location: label,
    }));
  }
  return out;
}

module.exports = { LIMITS, TAR_EXT, SEVENZIP_EXT, DISK_IMAGE_EXT, archiveKind, safeName, parseTar, gunzipLimited, parseIso, isoFromFile, parse7zList, sevenZipEntries, archiveFindings, RUNNABLE };
