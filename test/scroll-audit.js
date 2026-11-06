'use strict';

// Prueft das Mausrad in der echten App: test/scroll-audit-renderer.js schickt echte Rad-Ereignisse in jede Ansicht.
// Aufruf: node test/scroll-audit.js  (Exit-Code 0 = alles scrollt)

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

function run() {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-scroll-'));
  const out = path.join(data, 'result.json');
  const electron = require('electron');
  return new Promise((resolve) => {
    const child = spawn(electron, [path.join(__dirname, '..')], { env: { ...process.env, VIGIL_E2E_SCRIPT: path.join(__dirname, 'scroll-audit-renderer.js'), VIGIL_E2E_OUT: out, VIGIL_E2E_DATA: path.join(data, 'userData') }, stdio: 'ignore' });
    const timer = setTimeout(() => child.kill(), 180000);
    child.on('exit', () => {
      clearTimeout(timer);
      let r = null;
      try { r = JSON.parse(fs.readFileSync(out, 'utf8')).results[0]; } catch { /* unten gemeldet */ }
      try { fs.rmSync(data, { recursive: true, force: true }); } catch { /* egal */ }
      resolve(r);
    });
  });
}

module.exports = { run };

if (require.main === module) {
  run().then((r) => {
    console.log(JSON.stringify(r, null, 1));
    process.exit(r && r.dead && !r.dead.length && r.focusOk && r.follows && r.stays ? 0 : 1);
  });
}
