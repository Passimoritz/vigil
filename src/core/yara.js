'use strict';

// Optionale YARA-Pruefung: Ist das Werkzeug "yara" (bzw. yara64) installiert, prueft Vigil das
// Ziel mit den eigenen Regeln aus dem Regel-Ordner und den per Feed geladenen Regeln. YARA liest
// die Dateien nur – nichts wird ausgefuehrt. Fehlt yara oder gibt es keine Regeln: still ueberspringen.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { normalizeFinding } = require('./schema');

const CANDIDATES = [
  path.join(os.homedir(), 'Tools', 'yara', 'yara64.exe'),
  path.join(os.homedir(), 'Tools', 'yara', 'yara.exe'),
  path.join(process.env.ProgramFiles || 'C:\\Program Files', 'YARA', 'yara64.exe'),
  'yara64', 'yara',
];

function run(cmd, args, { signal, timeoutMs = 300000 } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); } catch { return resolve({ ok: false, missing: true }); }
    let out = '', err = '';
    const kill = () => { try { child.kill(); } catch { /* egal */ } };
    const t = setTimeout(kill, timeoutMs);
    if (signal) signal.addEventListener('abort', kill, { once: true });
    child.stdout.on('data', (d) => { if (out.length < 4e6) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 1e5) err += d; });
    child.on('error', (e) => { clearTimeout(t); resolve({ ok: false, missing: e.code === 'ENOENT', error: e.message }); });
    child.on('close', (code) => { clearTimeout(t); resolve({ ok: true, code, out, err }); });
  });
}

let cached;
async function findYara() {
  if (cached !== undefined) return cached;
  for (const c of CANDIDATES) {
    if (path.isAbsolute(c) && !fs.existsSync(c)) continue;
    const r = await run(c, ['--version'], { timeoutMs: 8000 });
    if (r.ok && r.code === 0 && /^\d+\.\d+/.test(r.out.trim())) return (cached = c);
  }
  return (cached = null);
}

function ruleFiles(dir, max = 100) {
  if (!dir) return [];
  try { return fs.readdirSync(dir).filter((f) => /\.(yar|yara)$/i.test(f)).slice(0, max).map((f) => path.join(dir, f)); } catch { return []; }
}

// "Regelname Pfad" je Zeile
function parseYaraOutput(text) {
  const hits = [];
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^([A-Za-z_][\w]*)\s+(.+)$/);
    if (m) hits.push({ rule: m[1], file: m[2].trim() });
  }
  return hits;
}

function yaraFindings(hits, rulesLabel) {
  const byFile = new Map();
  for (const h of hits) { if (!byFile.has(h.file)) byFile.set(h.file, new Set()); byFile.get(h.file).add(h.rule); }
  return [...byFile].slice(0, 200).map(([file, rules]) => normalizeFinding({
    ruleId: 'yara-match', severity: 'high', category: 'Other', confidence: 'medium',
    title: `YARA-Regel schlägt an: ${[...rules].slice(0, 3).join(', ')}`,
    description: `Die Datei „${path.basename(file)}“ passt zu den YARA-Regeln ${[...rules].slice(0, 8).join(', ')} (${rulesLabel}). YARA-Regeln beschreiben typische Merkmale bekannter Schadsoftware oder Angriffswerkzeuge.`,
    impact: 'Je nach Regel kann die Datei Schadsoftware, eine Webshell oder ein Hacker-Werkzeug sein.',
    remediation: 'Datei nicht ausführen. Regelbeschreibung prüfen und die Datei z. B. mit Microsoft Defender oder einem Online-Dienst gegenprüfen.',
    location: file.replace(/\\/g, '/'), sourceModule: 'yara',
  }, 'yara'));
}

// opts: { rulesDir, feedFile, signal, onProgress }
async function runYara(target, { rulesDir, feedFile, signal, onProgress = () => {} } = {}) {
  const files = [...ruleFiles(rulesDir), ...(feedFile && fs.existsSync(feedFile) ? [feedFile] : [])];
  if (!files.length) return { findings: [], notes: [], ran: false };
  const exe = await findYara();
  if (!exe) return { findings: [], notes: [], ran: false };
  onProgress({ phase: 'prescan', message: `YARA: ${files.length} Regeldatei(en) …` });
  const hits = [], notes = [];
  let ok = 0;
  // Jede Regeldatei einzeln: eine fehlerhafte Datei soll die anderen nicht blockieren.
  // Externe Variablen der Feed-Regeln (filename, filepath …) leer vorbelegen.
  for (const rf of files) {
    if (signal && signal.aborted) break;
    const r = await run(exe, ['-w', '-r', '-d', 'filename=', '-d', 'filepath=', '-d', 'extension=', '-d', 'filetype=', '-d', 'owner=', rf, target], { signal });
    if (!r.ok) continue;
    if (r.code !== 0 && !r.out) { notes.push(`YARA: Regeldatei ${path.basename(rf)} nicht lesbar (${(r.err || '').split('\n')[0].slice(0, 120)}).`); continue; }
    ok++;
    hits.push(...parseYaraOutput(r.out));
  }
  notes.push(`YARA: ${ok} Regeldatei(en) geprüft, ${hits.length} Treffer.`);
  return { findings: yaraFindings(hits, files.length > 1 ? `${files.length} Regeldateien` : path.basename(files[0])), notes, ran: ok > 0 };
}

module.exports = { runYara, findYara, parseYaraOutput, yaraFindings, ruleFiles, _reset: () => { cached = undefined; } };
