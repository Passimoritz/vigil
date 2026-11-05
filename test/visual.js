'use strict';

// Visuelle Regression: startet die App mit leerem Datenordner, stellt einen festen Zustand her
// (test/visual-renderer.js), fotografiert die Hauptansichten (webContents.capturePage in
// electron/main.js) und vergleicht sie Pixel fuer Pixel mit test/visual/baseline/*.png.
//
//   npm run visual           Referenzbilder neu aufnehmen (nach gewollten Oberflaechen-Aenderungen)
//   npm run visual:check     nur vergleichen, Exit-Code 1 bei Abweichung
//   (npm run e2e vergleicht ebenfalls – dort nur als Hinweis, ausser VIGIL_VISUAL_STRICT=1)
//
// Toleranz: ein Pixel zaehlt als abweichend, wenn ein Farbkanal um mehr als 32 von 255 abweicht;
// eine Ansicht gilt als gleich, solange hoechstens 1,5 % der Pixel abweichen. Andere Bildgroesse
// (z. B. andere Bildschirm-Skalierung) wird uebersprungen statt als Fehler gewertet.

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const png = require('./visual/png');

const BASE = path.join(__dirname, 'visual', 'baseline');
const MAX_RATIO = 0.015;

function capture() {
  const electron = require('electron');
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-visual-'));
  const shots = path.join(data, 'shots');
  const out = path.join(data, 'result.json');
  return new Promise((resolve) => {
    const child = spawn(electron, [path.join(__dirname, '..')], {
      env: { ...process.env, VIGIL_E2E_SCRIPT: path.join(__dirname, 'visual-renderer.js'), VIGIL_E2E_OUT: out, VIGIL_E2E_DATA: path.join(data, 'userData'), VIGIL_VISUAL_DIR: shots },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    const timer = setTimeout(() => child.kill(), 90000);
    child.on('exit', () => { clearTimeout(timer); resolve({ data, shots }); });
  });
}

async function runVisual({ update = false, strict = false, log = console.log } = {}) {
  const { data, shots } = await capture();
  const files = fs.existsSync(shots) ? fs.readdirSync(shots).filter((f) => f.endsWith('.png')) : [];
  const results = [];
  if (!files.length) results.push({ name: 'Visuell: Aufnahmen', ok: false, info: 'keine Bildschirmfotos erzeugt' });
  if (update) {
    fs.mkdirSync(BASE, { recursive: true });
    for (const f of files) fs.copyFileSync(path.join(shots, f), path.join(BASE, f));
    log(`  Referenzbilder aktualisiert: ${files.join(', ')} -> test/visual/baseline/`);
  } else {
    for (const f of files) {
      const name = `Visuell: ${f.replace(/\.png$/, '')}`;
      const basePath = path.join(BASE, f);
      if (!fs.existsSync(basePath)) { results.push({ name, ok: true, info: 'kein Referenzbild (npm run visual)', skipped: true }); continue; }
      const a = png.decode(fs.readFileSync(basePath)), b = png.decode(fs.readFileSync(path.join(shots, f)));
      const c = png.compare(a, b);
      if (!c.sameSize) { results.push({ name, ok: true, skipped: true, info: `andere Größe (${b.width}×${b.height} statt ${a.width}×${a.height}) – übersprungen` }); continue; }
      const ok = c.ratio <= MAX_RATIO;
      let info = `${(c.ratio * 100).toFixed(2)} % abweichend`;
      if (!ok) {
        const diffDir = path.join(__dirname, 'visual', 'diff');
        fs.mkdirSync(diffDir, { recursive: true });
        fs.writeFileSync(path.join(diffDir, f), png.encode(c.diff));
        fs.copyFileSync(path.join(shots, f), path.join(diffDir, f.replace(/\.png$/, '.actual.png')));
        info += ` – Unterschiede in test/visual/diff/${f}`;
      }
      results.push({ name, ok: ok || !strict, info: ok ? info : (strict ? info : 'Hinweis: ' + info) });
    }
  }
  try { fs.rmSync(data, { recursive: true, force: true }); } catch { /* egal */ }
  return results;
}

module.exports = { runVisual };

if (require.main === module) {
  const update = process.argv.includes('--update');
  runVisual({ update, strict: true }).then((results) => {
    for (const x of results) console.log(`  ${x.ok ? 'ok  ' : 'FAIL'} ${x.name}${x.info ? ' – ' + x.info : ''}`);
    process.exit(results.some((x) => !x.ok) ? 1 : 0);
  });
}
