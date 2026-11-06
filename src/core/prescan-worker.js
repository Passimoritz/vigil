'use strict';

// Statische Vorpruefung im eigenen Thread. Sie rechnet bei grossen Projekten viele Sekunden am Stueck. Im Hauptprozess
// wuerde das die ganze Oberflaeche einfrieren, auch das Mausrad, denn dessen Ereignisse laufen durch den Hauptprozess.

const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

if (!isMainThread && workerData && workerData.vigilPrescan) {
  const { prescan } = require('./prescan');
  const { runStaticModules } = require('./modules/static');
  const pre = prescan(workerData.units, workerData.opts);
  const mods = runStaticModules(workerData.units, (p) => parentPort.postMessage({ progress: p }));
  parentPort.postMessage({ result: { pre, mods } });
}

// Ergebnis wie direkt gerechnet. Klappt der Thread nicht (z. B. nicht uebertragbare Daten), rechnet der Hauptprozess.
function inline(units, opts, onProgress) {
  const { prescan } = require('./prescan');
  const { runStaticModules } = require('./modules/static');
  return { pre: prescan(units, opts), mods: runStaticModules(units, onProgress) };
}
function runPrescan(units, opts, onProgress = () => {}) {
  return new Promise((resolve) => {
    let worker; let settled = false;
    const fallback = () => { if (settled) return; settled = true; try { worker && worker.terminate(); } catch { /* egal */ } resolve(inline(units, opts, onProgress)); };
    try {
      worker = new Worker(path.join(__dirname, 'prescan-worker.js'), { workerData: { vigilPrescan: true, units, opts } });
    } catch { fallback(); return; }
    worker.on('message', (m) => {
      if (m.progress) { onProgress(m.progress); return; }
      if (m.result && !settled) { settled = true; worker.terminate(); resolve(m.result); }
    });
    worker.on('error', fallback);
    worker.on('exit', () => { if (!settled) fallback(); });
  });
}

module.exports = { runPrescan };
