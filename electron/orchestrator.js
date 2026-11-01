'use strict';

// Scan-Warteschlange (In-Process statt Redis/BullMQ): Scans laufen nacheinander,
// jeder Lauf wird mit Status QUEUED -> RUNNING -> COMPLETED/FAILED protokolliert und
// sein Ergebnis in den Befund-Speicher (Lebenszyklus) uebernommen.

const crypto = require('crypto');
const store = require('../src/core/store');

function createOrchestrator({ storeFile, runAudit, buildConfig }) {
  let db = store.load(storeFile);
  const queue = [];
  let current = null; // { job, ctrl }
  const persist = () => { try { store.save(storeFile, db); } catch (e) { console.warn('Befund-Speicher nicht gespeichert:', e.message); } };

  // job: { targets (scope-geprueft), providerId, origin: 'app'|'api', onProgress? }
  function enqueue(job) {
    const id = crypto.randomUUID();
    const run = store.addRun(db, {
      id, status: 'QUEUED', origin: job.origin || 'app', providerId: job.providerId || null,
      targets: job.targets.map((t) => ({ type: t.type, value: t.value })),
      targetIds: job.targets.map((t) => store.targetIdOf(t)),
      scannersUsed: [], createdAt: new Date().toISOString(), startedAt: null, finishedAt: null, summary: null, errorLog: null,
    });
    persist();
    let resolve;
    const done = new Promise((r) => { resolve = r; });
    queue.push({ ...job, id, resolve });
    pump();
    return { id, run, done };
  }

  async function pump() {
    if (current || !queue.length) return;
    const job = queue.shift();
    const ctrl = new AbortController();
    current = { job, ctrl };
    store.updateRun(db, job.id, { status: 'RUNNING', startedAt: new Date().toISOString() });
    persist();
    let outcome;
    try {
      const cfg = buildConfig(job.providerId);
      cfg.signal = ctrl.signal;
      const { result } = await runAudit(job.targets, cfg, (p) => { try { if (job.onProgress) job.onProgress(p); } catch { /* Fenster weg */ } });
      const scannersRun = (result.meta && result.meta.scannersRun) || [];
      // Abgebrochene Laeufe sind unvollstaendig: nichts automatisch schliessen.
      const applied = store.applyRun(db, { targets: job.targets, findings: result.findings, scannersRun: ctrl.signal.aborted ? [] : scannersRun });
      result.findings = applied.findings;
      result.lifecycle = { ...applied.counters, resolved: applied.resolved, runId: job.id };
      result.hasBaseline = applied.counters.updated + applied.counters.reopened > 0;
      result.suppressedCount = applied.findings.filter((f) => f.suppressed).length;
      store.updateRun(db, job.id, {
        status: ctrl.signal.aborted ? 'FAILED' : 'COMPLETED',
        finishedAt: new Date().toISOString(),
        scannersUsed: [...new Set(scannersRun.map((s) => s.source).concat(result.meta && result.meta.batches ? ['ai'] : []))],
        summary: { ...result.summary, ...applied.counters },
        errorLog: ctrl.signal.aborted ? 'Abgebrochen.' : null,
      });
      outcome = { ok: true, result, canceled: ctrl.signal.aborted, runId: job.id };
    } catch (e) {
      store.updateRun(db, job.id, { status: 'FAILED', finishedAt: new Date().toISOString(), errorLog: e.message });
      outcome = { ok: false, error: e.message, runId: job.id };
    } finally {
      persist();
      current = null;
    }
    job.resolve(outcome);
    pump();
  }

  return {
    enqueue,
    cancel() { if (current) { current.ctrl.abort(); return true; } return false; },
    getRun: (id) => db.runs.find((r) => r.id === id) || null,
    listFindings: (filter) => store.listFindings(db, filter),
    stats: () => store.stats(db),
    targets: () => store.stats(db).targets,
    setStatus(id, status, note) { const r = store.setStatus(db, id, status, note); if (r.ok) persist(); return r; },
    clear() { db = store.emptyStore(); persist(); },
  };
}

module.exports = { createOrchestrator };
