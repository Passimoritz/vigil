'use strict';

// Prueft in der echten App ueber einen echten Neustart hinweg: Pruefung pausieren, App beenden, neu starten, fortsetzen.
// Danach den Export aus der Uebersicht (gefilterte Befunde und einzelner Lauf).
// Aufruf: node test/resume-audit.js  (Exit-Code 0 = alles in Ordnung)

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const WAIT = `const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const $ = (id) => document.getElementById(id);
  for (let i = 0; i < 150 && !(window.state && state.config && $('runBtn')); i++) await wait(80);
  await wait(300);
  try { if ($('obSkip') && !$('onboard').hidden) $('obSkip').click(); } catch { /* keine Einfuehrung */ }`;

// Erster Start: pausieren, solange der Lauf noch nicht fertig ist. Danach endet die App mitten im Lauf.
const PHASE1 = `(async () => {
  ${WAIT}
  state.targets = [{ type: 'system', value: 'browserext' }];
  runAudit({ resumeId: null });
  let paused = false;
  for (let i = 0; i < 200 && !paused; i++) { const r = await window.vigil.pauseAudit(); paused = r.paused; await wait(5); }
  await wait(1200);
  return { ok: true, results: [{ name: 'p1', paused, title: $('progressTitle').textContent }] };
})();`;

// Zweiter Start: Hinweis sichtbar, per Klick fortsetzen, bis der Lauf fertig ist.
const PHASE2 = `(async () => {
  ${WAIT}
  await wait(300);
  const info = await window.vigil.pausedRunInfo();
  const stats = await window.vigil.dashboard({ limit: 5 });
  const runBefore = stats.stats.runs.find((r) => info && r.id === info.id);
  showView('scan');
  const banner = !$('pausedRun').hidden && $('pausedRunTitle').textContent;
  const msgs = [];
  const un = window.vigil.onProgress((p) => msgs.push(p.message));
  $('pausedRunGo').click();
  await wait(200);
  for (let i = 0; i < 600 && state.running; i++) await wait(100);
  un();
  const after = await window.vigil.pausedRunInfo();
  const s2 = await window.vigil.dashboard({ limit: 5000, status: '' });
  const run = s2.stats.runs.find((r) => info && r.id === info.id);
  // Export: gefilterte Befunde und einzelner Lauf, in allen wichtigen Formaten
  const saved = {};
  for (const fmt of ['json', 'md', 'html', 'csv', 'xlsx', 'sarif', 'execpdf', 'pdf', 'auditzip']) {
    const r = await window.vigil.saveReportFrom(fmt, { kind: 'findings', filter: { status: 'OPEN,IN_PROGRESS' } });
    saved[fmt] = r.ok ? 'ok' : r.error;
  }
  const byRun = run ? await window.vigil.saveReportFrom('json', { kind: 'run', runId: run.id }) : { ok: false, error: 'kein Lauf' };
  const noRun = await window.vigil.saveReportFrom('json', { kind: 'run', runId: 'gibt-es-nicht' });
  // Das Exportmenue der Uebersicht bietet dieselben Formate wie der Reiter Ergebnis
  showView('dash'); await wait(400);
  $('dashExportBtn').click(); await wait(300);
  const dashMenu = [...document.querySelectorAll('.export-menu [data-fmt]')].map((b) => b.dataset.fmt).sort();
  const resultMenu = [...$('exportMenu').querySelectorAll('[data-fmt]')].map((b) => b.dataset.fmt).sort();
  closeMenus();
  const open = document.querySelectorAll('.export-menu').length;
  return { ok: true, results: [{ name: 'p2', info, runBefore: runBefore && runBefore.status, banner, resumed: msgs.length, after, status: run && run.status, saved, byRun: byRun.ok ? 'ok' : byRun.error, noRunErr: !noRun.ok, same: dashMenu.join() === resultMenu.join() && dashMenu.length > 8, open }] };
})();`;

// Echte App, Greenbone eingerichtet und eingeschaltet: Fuer diesen Lauf abgewaehlt darf es nicht starten.
const PHASE3 = (url) => `(async () => {
  ${WAIT}
  showView('scan');
  state.targets = [{ type: 'url', value: ${JSON.stringify(url)}, authorized: true }];
  renderTargets();
  for (let i = 0; i < 50 && !(state.gb && state.gb.ready); i++) await wait(100);
  const shown = !$('gbRunRow').hidden, def = $('gbRunChk').checked;
  const etaOf = async (want) => { for (let i = 0; i < 100; i++) { const s = expectedSeconds(); if (s != null && want(s)) break; await wait(100); } return expectedSeconds(); };
  const etaOn = await etaOf((s) => s > 3600);
  const etaOnText = $('runEta').textContent;
  $('gbRunChk').click();
  const etaOff = await etaOf((s) => s < 3600);
  const etaText = $('runEta').textContent;
  const msgs = [];
  const un = window.vigil.onProgress((p) => msgs.push(String(p.message || '')));
  runAudit();
  await wait(200);
  const locked = $('gbRunChk').disabled;
  for (let i = 0; i < 1200 && state.running; i++) await wait(100);
  un();
  const cfg = await window.vigil.greenboneGet();
  return { ok: true, results: [{ name: 'p3', shown, def, etaOn, etaOnText, etaOff, etaText, locked, finished: !state.running, steps: msgs.length, gbMsgs: msgs.filter((m) => /greenbone/i.test(m)), reset: state.gbChoice === null && $('gbRunChk').checked, stillOn: cfg.enabled }] };
})();`;

function start(data, code, name) {
  const out = path.join(data, `${name}.json`);
  const script = path.join(data, `${name}.js`);
  fs.writeFileSync(script, code);
  const electron = require('electron');
  return new Promise((resolve) => {
    const child = spawn(electron, [path.join(__dirname, '..')], { env: { ...process.env, VIGIL_E2E_SCRIPT: script, VIGIL_E2E_OUT: out, VIGIL_E2E_DATA: path.join(data, 'userData'), VIGIL_E2E_SAVE_DIR: path.join(data, 'saved') }, stdio: 'ignore' });
    const timer = setTimeout(() => child.kill(), 150000);
    child.on('exit', () => {
      clearTimeout(timer);
      let r = null;
      try { r = JSON.parse(fs.readFileSync(out, 'utf8')).results[0]; } catch { /* unten gemeldet */ }
      resolve(r);
    });
  });
}

async function run() {
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-resume-'));
  fs.mkdirSync(path.join(data, 'saved'));
  const p1 = await start(data, PHASE1, 'p1');
  const file = path.join(data, 'userData', 'paused-run.json');
  const onDisk = fs.existsSync(file);
  const encrypted = onDisk ? !/browserext/.test(fs.readFileSync(file, 'utf8')) : false;
  const p2 = await start(data, PHASE2, 'p2');
  const files = fs.readdirSync(path.join(data, 'saved'));
  const jsonFile = files.find((f) => /\.json$/.test(f));
  let jsonOk = false;
  try { const j = JSON.parse(fs.readFileSync(path.join(data, 'saved', jsonFile), 'utf8')); jsonOk = Array.isArray(j.findings) || !!j.summary; } catch { /* bleibt false */ }
  try { fs.rmSync(data, { recursive: true, force: true }); } catch { /* egal */ }
  // Eigene Daten mit eingerichtetem Greenbone, Ziel ist ein kleiner Server auf diesem Rechner
  const data3 = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-gbrun-'));
  fs.mkdirSync(path.join(data3, 'userData'));
  fs.writeFileSync(path.join(data3, 'userData', 'config.json'), JSON.stringify({ greenbone: { enabled: true, asked: true, setup: { state: 'ready' } } }));
  const srv = require('http').createServer((_q, s) => { s.setHeader('Content-Type', 'text/html'); s.end('<!doctype html><title>t</title>'); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const p3 = await start(data3, PHASE3(`http://127.0.0.1:${srv.address().port}`), 'p3');
  srv.close();
  try { fs.rmSync(data3, { recursive: true, force: true }); } catch { /* egal */ }
  return { p1, onDisk, encrypted, p2, p3, files: files.length, jsonOk };
}

module.exports = { run };

if (require.main === module) {
  run().then((r) => { console.log(JSON.stringify(r, null, 1)); });
}
