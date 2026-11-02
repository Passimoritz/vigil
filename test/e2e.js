'use strict';

// Automatische Oberflaechen-Tests: startet die echte App (Electron) mit leerem Datenordner,
// laesst test/e2e-renderer.js im Fenster alle wichtigen Klickwege durchspielen und gibt das
// Ergebnis aus. Aufruf: npm run e2e  (Exit-Code 0 = alles gruen)

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const electron = require('electron'); // Pfad zur Electron-Binary
const data = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-e2e-'));
const out = path.join(data, 'result.json');

const child = spawn(electron, [path.join(__dirname, '..')], {
  env: { ...process.env, VIGIL_E2E_SCRIPT: path.join(__dirname, 'e2e-renderer.js'), VIGIL_E2E_OUT: out, VIGIL_E2E_DATA: path.join(data, 'userData') },
  stdio: ['ignore', 'ignore', 'pipe'],
});
const timer = setTimeout(() => { console.error('Zeitüberschreitung (90 s)'); child.kill(); }, 90000);
child.on('exit', (code) => {
  clearTimeout(timer);
  let r = null;
  try { r = JSON.parse(fs.readFileSync(out, 'utf8')); } catch { /* kein Ergebnis */ }
  if (!r) { console.error('Kein Ergebnis von der App (Exit ' + code + ').'); process.exit(1); }
  for (const x of r.results) console.log(`  ${x.ok ? 'ok  ' : 'FAIL'} ${x.name}${x.info ? ' – ' + x.info : ''}`);
  const failed = r.results.filter((x) => !x.ok).length;
  console.log(`\n${r.results.length - failed} ok, ${failed} fehlgeschlagen`);
  try { fs.rmSync(data, { recursive: true, force: true }); } catch { /* egal */ }
  process.exit(failed ? 1 : 0);
});
