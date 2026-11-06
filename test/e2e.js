'use strict';

// Automatische Oberflaechen-Tests: startet die echte App (Electron) mit leerem Datenordner,
// laesst test/e2e-renderer.js im Fenster alle wichtigen Klickwege durchspielen und gibt das
// Ergebnis aus. Danach: Selbstschutz (test/e2e-security-renderer.js: App-Sperre, Verschluesselung
// im Ruhezustand) und visuelle Regression (test/visual.js).
// Aufruf: npm run e2e  (Exit-Code 0 = alles gruen)

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const electron = require('electron'); // Pfad zur Electron-Binary

// Startet die App mit einem Skript im Fenster; liefert { results, userData, cleanup }
function runApp(script, label) {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-e2e-'));
  const out = path.join(data, 'result.json');
  const userData = path.join(data, 'userData');
  return new Promise((resolve) => {
    const child = spawn(electron, [path.join(__dirname, '..')], {
      env: { ...process.env, VIGIL_E2E_SCRIPT: path.join(__dirname, script), VIGIL_E2E_OUT: out, VIGIL_E2E_DATA: userData },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    const timer = setTimeout(() => { console.error(`Zeitüberschreitung (90 s): ${label}`); child.kill(); }, 90000);
    child.on('exit', (code) => {
      clearTimeout(timer);
      let r = null;
      try { r = JSON.parse(fs.readFileSync(out, 'utf8')); } catch { /* kein Ergebnis */ }
      resolve({
        results: r ? r.results : [{ name: label, ok: false, info: 'Kein Ergebnis von der App (Exit ' + code + ').' }],
        userData,
        cleanup: () => { try { fs.rmSync(data, { recursive: true, force: true }); } catch { /* egal */ } },
      });
    });
  });
}

(async () => {
  const all = [];
  const main = await runApp('e2e-renderer.js', 'Oberfläche');
  all.push(...main.results);
  main.cleanup();

  const sec = await runApp('e2e-security-renderer.js', 'Selbstschutz');
  all.push(...sec.results);
  // Verschluesselung im Ruhezustand: Schluessel angelegt, Befund-Speicher (falls vorhanden) verschluesselt
  try {
    const { isEncrypted } = require('../src/core/securefile');
    const storeFile = path.join(sec.userData, 'findings-store.json');
    const keyOk = fs.existsSync(path.join(sec.userData, 'data.key'));
    const storeOk = !fs.existsSync(storeFile) || isEncrypted(fs.readFileSync(storeFile));
    const cfg = JSON.parse(fs.readFileSync(path.join(sec.userData, 'config.json'), 'utf8'));
    all.push({ name: 'Sicherheit: Datenschlüssel angelegt, Befund-Speicher verschlüsselt', ok: keyOk && storeOk, info: keyOk ? (storeOk ? '' : 'Befund-Speicher im Klartext') : 'kein data.key (safeStorage nicht verfügbar?)' });
    all.push({ name: 'Sicherheit: kein Klartext-Passwort in config.json', ok: !JSON.stringify(cfg).includes('geheim-123') });
  } catch (e) { all.push({ name: 'Sicherheit: Dateien prüfen', ok: false, info: e.message }); }
  sec.cleanup();

  // Uebersetzungen: keine Texte der jeweils anderen Sprache in irgendeiner Ansicht
  try {
    const check = (name, ok, info = '') => all.push({ name, ok: !!ok, info });
    const sc = await require('./scroll-audit').run();
    check('Mausrad: scrollt überall', !!sc && Array.isArray(sc.dead) && sc.dead.length === 0, sc && sc.dead ? sc.dead.slice(0, 6).join(' | ') : JSON.stringify(sc));
    check('Mausrad: fokussiertes Auswahlfeld scrollt die Seite, Wert bleibt', !!sc && sc.focusOk);
    check('Protokoll: folgt unten, bleibt beim Hochscrollen stehen', !!sc && sc.follows && sc.stays);
    const ra = await require('./resume-audit').run();
    check('Pausieren: Stand liegt verschlüsselt auf der Platte', !!ra && ra.onDisk && ra.encrypted && ra.p1 && ra.p1.paused);
    check('Neustart: Lauf gilt als pausiert, Hinweis sichtbar', !!ra && ra.p2 && ra.p2.runBefore === 'PAUSED' && !!ra.p2.banner);
    check('Fortsetzen: Lauf wird fertig, gespeicherter Stand ist weg', !!ra && ra.p2 && ra.p2.status === 'COMPLETED' && ra.p2.after === null);
    check('Übersicht: Export in allen Formaten', !!ra && ra.p2 && Object.values(ra.p2.saved).every((x) => x === 'ok') && ra.jsonOk, ra && ra.p2 ? JSON.stringify(ra.p2.saved).slice(0, 200) : '');
    check('Übersicht: Export eines einzelnen Laufs', !!ra && ra.p2 && ra.p2.byRun === 'ok' && ra.p2.noRunErr);
    check('Greenbone je Prüfung: Schalter ändert die voraussichtliche Zeit', !!ra && ra.p3 && ra.p3.etaOn > 3600 && ra.p3.etaOff < 3600 && /^≈ 1[.,]\d (h|Std\.)$/.test(ra.p3.etaOnText) && /Min\.$|min$/.test(ra.p3.etaText), ra && ra.p3 ? `${ra.p3.etaOnText} / ${ra.p3.etaText}` : '');
    check('Greenbone je Prüfung: abgewählt startet es nicht, Einstellung bleibt an', !!ra && ra.p3 && ra.p3.shown && ra.p3.def && ra.p3.locked && ra.p3.finished && ra.p3.steps > 0 && !ra.p3.gbMsgs.length && ra.p3.reset && ra.p3.stillOn, ra ? JSON.stringify(ra.p3).slice(0, 240) : '');
    check('Übersicht: dieselben Formate wie im Reiter Ergebnis', !!ra && ra.p2 && ra.p2.same && ra.p2.open === 0);
    const a = await require('./i18n-audit').run();
    if (!a || !a.german) all.push({ name: 'Sprache: Prüflauf', ok: false, info: 'kein Ergebnis' });
    else {
      const fmt = (l) => l.slice(0, 8).map((x) => (typeof x === 'string' ? x : x.text).slice(0, 70)).join(' | ');
      all.push({ name: 'Sprache: nichts Deutsches in der englischen Ansicht', ok: !a.german.length, info: fmt(a.german) });
      all.push({ name: 'Sprache: nichts Englisches in der deutschen Ansicht', ok: !a.english.length, info: fmt(a.english) });
      all.push({ name: 'Sprache: seltene Meldungen übersetzt', ok: !a.stat.length, info: fmt(a.stat) });
    }
  } catch (e) { all.push({ name: 'Sprache: Prüflauf', ok: false, info: e.message }); }

  // Visuelle Regression (nur Hinweis, ausser VIGIL_VISUAL_STRICT=1)
  if (process.env.VIGIL_E2E_NO_VISUAL !== '1') {
    try { all.push(...await require('./visual').runVisual({ strict: process.env.VIGIL_VISUAL_STRICT === '1' })); }
    catch (e) { all.push({ name: 'Visuell', ok: process.env.VIGIL_VISUAL_STRICT !== '1', info: e.message }); }
  }

  for (const x of all) console.log(`  ${x.ok ? 'ok  ' : 'FAIL'} ${x.name}${x.info ? ' – ' + x.info : ''}`);
  const failed = all.filter((x) => !x.ok).length;
  console.log(`\n${all.length - failed} ok, ${failed} fehlgeschlagen`);
  process.exit(failed ? 1 : 0);
})();
