'use strict';

// Prueft die Uebersetzungen in der echten App: test/i18n-audit-renderer.js geht alle Ansichten in beiden
// Sprachen durch; dazu kommen Beispiele fuer Meldungen, die nur in seltenen Faellen erscheinen.
// Aufruf: node test/i18n-audit.js  (Exit-Code 0 = nichts fehlt)

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');


function run() {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-i18n-'));
  const out = path.join(data, 'result.json');
  const script = path.join(data, 'renderer.js');
  fs.writeFileSync(script, fs.readFileSync(path.join(__dirname, 'i18n-audit-renderer.js'), 'utf8'));
  const electron = require('electron');
  return new Promise((resolve) => {
    const child = spawn(electron, [path.join(__dirname, '..')], { env: { ...process.env, VIGIL_E2E_SCRIPT: script, VIGIL_E2E_OUT: out, VIGIL_E2E_DATA: path.join(data, 'userData') }, stdio: ['ignore', 'ignore', 'ignore'] });
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
    if (!r || !r.german) { console.error('Kein Ergebnis von der App:', JSON.stringify(r)); process.exit(1); }
    const show = (title, list) => { console.log(`\n${title}: ${list.length}`); for (const x of list) console.log(typeof x === 'string' ? `  ${x}` : `  [${x.at}] ${x.text}`); };
    show('Deutsch in der englischen Ansicht', r.german);
    show('Englisch in der deutschen Ansicht', r.english);
    show('Meldungstexte ohne Übersetzung', r.stat);
    process.exit(r.german.length || r.english.length || r.stat.length ? 1 : 0);
  });
}
