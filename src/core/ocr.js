'use strict';

// Optionale Texterkennung (OCR) fuer Bilder im Projekt: Screenshots mit sichtbaren Passwoertern,
// Schluesseln oder Tokens. Nutzt nur ein lokal installiertes tesseract (liest das Bild, aendert
// nichts). Ist tesseract nicht vorhanden, wird die Pruefung still uebersprungen.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { normalizeFinding, redactSecret } = require('./schema');
const { makeMatcher, loadIgnore } = require('./ignore');

const M = 'ocr-image-audit';
const IMG = /\.(png|jpe?g)$/i;
const SKIP_DIR = new Set(['node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'out', 'target', '.next', '.cache', 'vendor', '__pycache__', '.venv', 'venv']);
const MAX_IMAGES = 40;
const MAX_BYTES = 8 * 1024 * 1024;

function firstExisting(cands, fallback) {
  for (const c of cands) { try { if (c && fs.existsSync(c)) return c; } catch { /* ignore */ } }
  return fallback;
}
const TESSERACT = firstExisting([
  'C:\\Program Files\\Tesseract-OCR\\tesseract.exe',
  'C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe',
  path.join(os.homedir(), 'AppData', 'Local', 'Programs', 'Tesseract-OCR', 'tesseract.exe'),
  '/usr/bin/tesseract', '/usr/local/bin/tesseract', '/opt/homebrew/bin/tesseract',
], 'tesseract');

// tesseract <bild> stdout – liefert { ok, text } (ok=false, wenn das Programm fehlt)
function runTesseract(img, { signal, timeoutMs = 30000 } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(TESSERACT, [img, 'stdout', '--psm', '3'], { windowsHide: true }); }
    catch (e) { return resolve({ ok: false, missing: true, text: '' }); }
    let out = '';
    const kill = () => { try { child.kill(); } catch { /* egal */ } };
    const timer = setTimeout(kill, timeoutMs);
    if (signal) signal.addEventListener?.('abort', kill, { once: true });
    child.stdout.on('data', (d) => { if (out.length < 200000) out += d.toString(); });
    child.stderr.on('data', () => {});
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, missing: e.code === 'ENOENT', text: '' }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ ok: code === 0, text: out }); });
  });
}

function findImages(root, limit = MAX_IMAGES) {
  const out = [];
  let st; try { st = fs.statSync(root); } catch { return out; }
  if (st.isFile()) return IMG.test(root) && st.size <= MAX_BYTES ? [{ full: root, rel: path.basename(root) }] : [];
  const matcher = makeMatcher(loadIgnore(root));
  const walk = (dir) => {
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (out.length >= limit) return;
      const full = path.join(dir, e.name);
      const rel = path.relative(root, full).replace(/\\/g, '/');
      if (matcher && matcher(rel, e.name)) continue;
      if (e.isDirectory()) { if (!SKIP_DIR.has(e.name)) walk(full); continue; }
      if (!e.isFile() || !IMG.test(e.name)) continue;
      try { if (fs.statSync(full).size > MAX_BYTES) continue; } catch { continue; }
      out.push({ full, rel: path.join(path.basename(root), rel).replace(/\\/g, '/') });
    }
  };
  walk(root);
  return out;
}

// Sichtbare Zugangsdaten im erkannten Text
const LABELED = /\b(passwor[dt]|kennwort|pass(?:wd)?|pwd|pin|api[ _-]?key|secret|token|client[ _-]?secret|zugangscode)\b\s*[:=]\s*(\S{4,})/gi;
const PLACEHOLDER = /^(\*+|•+|x+|\.+|<[^>]*>|\[[^\]]*\]|your\w*|dein\w*|ihr\w*|example|beispiel|changeme|none|null|\?+)$/i;
let SECRET_RULES = null;
function secretsInText(text) {
  if (!SECRET_RULES) SECRET_RULES = require('./prescan').SECRET_RULES.filter((r) => !/Generisches|Klartext-HTTP|JWT|Basic-Auth|Twilio/.test(r.name));
  const hits = [];
  let m;
  LABELED.lastIndex = 0;
  const label = (k) => (/^(pass|pwd|kennwort)/i.test(k) ? 'Passwort' : /^api/i.test(k) ? 'API-Schlüssel' : /^zugang/i.test(k) ? 'Zugangscode' : /^pin$/i.test(k) ? 'PIN' : /secret/i.test(k) ? 'Secret' : 'Token');
  while ((m = LABELED.exec(text)) && hits.length < 5) if (!PLACEHOLDER.test(m[2])) hits.push({ kind: label(m[1]), value: m[2] });
  for (const r of SECRET_RULES) { r.re.lastIndex = 0; const x = r.re.exec(text); if (x) hits.push({ kind: r.name, value: x[0] }); }
  return hits;
}

// roots: Pfad-Ziele; opts.run ersetzt tesseract (Tests)
async function scanImages(roots, { signal, onProgress = () => {}, run = runTesseract } = {}) {
  const findings = [];
  const notes = [];
  const imgs = roots.flatMap((r) => findImages(r)).slice(0, MAX_IMAGES);
  if (!imgs.length) return { findings, notes, ran: false };
  onProgress({ phase: 'prescan', message: `Texterkennung in ${imgs.length} Bild(ern) …` });
  let ran = false;
  for (const img of imgs) {
    if (signal && signal.aborted) break;
    const r = await run(img.full, { signal });
    if (r.missing) return { findings: [], notes: [], ran: false }; // tesseract fehlt: still ueberspringen
    if (!r.ok) continue;
    ran = true;
    const hits = secretsInText(r.text || '');
    if (!hits.length) continue;
    findings.push(normalizeFinding({
      ruleId: 'ocr-visible-password', severity: 'high', category: 'Secrets', confidence: 'medium',
      title: `Zugangsdaten im Bild sichtbar: ${img.rel.split('/').pop()}`,
      description: `Die Texterkennung hat im Bild ${[...new Set(hits.map((h) => h.kind))].slice(0, 3).join(', ')} gefunden. Screenshots mit Passwörtern oder Schlüsseln landen leicht in Repositories, Tickets oder Dokumentationen und sind dort für alle lesbar.`,
      remediation: 'Den Zugang sperren bzw. das Passwort ändern, das Bild entfernen oder die Stelle schwärzen und auch aus der Git-Historie löschen.',
      location: img.rel,
      evidence: hits.slice(0, 3).map((h) => `${h.kind}: ${redactSecret(h.value)}`).join(', '),
      sourceModule: M,
    }, M));
  }
  return { findings, notes, ran };
}

module.exports = { scanImages, findImages, secretsInText, runTesseract, TESSERACT };
