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
    const t0 = Date.now();
    try {
      const cfg = buildConfig(job.providerId);
      cfg.signal = ctrl.signal;
      // Domain-Nachweis aus dem Speicher mitgeben – entscheidet ueber tiefe Web-Pruefungen.
      const targets = job.targets.map((t) => { const rec = db.targets[store.targetIdOf(t)]; return { ...t, verified: !!(rec && rec.ownershipVerified) }; });
      // Aus Fehlalarmen lernen: bestaetigte Fehlalarme dieser Ziele gehen als Hinweis an die KI
      cfg.knownFalsePositives = store.falsePositivesFor(db, job.targets.map((t) => store.targetIdOf(t)));
      // Aenderungs-Waechter: Skripte/Formularziele des letzten Laufs zum Vergleich
      cfg.webWatch = store.webWatchFor(db, job.targets);
      const { result } = await runAudit(targets, cfg, (p) => { try { if (job.onProgress) job.onProgress(p); } catch { /* Fenster weg */ } });
      const scannersRun = (result.meta && result.meta.scannersRun) || [];
      // Abgebrochene oder gedrosselte Laeufe sind unvollstaendig: nichts automatisch schliessen.
      const complete = !ctrl.signal.aborted && !(result.meta && result.meta.throttled);
      const applied = store.applyRun(db, { targets: job.targets, findings: result.findings, scannersRun: complete ? scannersRun : [], sbom: result.meta && result.meta.sbom, webWatch: complete && result.meta ? result.meta.webWatch : null });
      result.findings = applied.findings;
      result.lifecycle = { ...applied.counters, resolved: applied.resolved, runId: job.id };
      result.hasBaseline = applied.counters.updated + applied.counters.reopened > 0;
      result.suppressedCount = applied.findings.filter((f) => f.suppressed).length;
      const partial = (result.errors || []).some((e) => /fehlgeschlagen|nicht ausgefuehrt|Fehler/i.test(e));
      const status = ctrl.signal.aborted ? 'FAILED' : result.meta && result.meta.throttled ? 'THROTTLED_ABORTED' : partial ? 'PARTIAL_FAILURE' : 'COMPLETED';
      const st = store.stats(db);
      store.updateRun(db, job.id, {
        status,
        finishedAt: new Date().toISOString(),
        durationMs: Date.now() - t0,
        scannersUsed: [...new Set(scannersRun.map((s) => s.source).concat(result.meta && result.meta.batches ? ['ai'] : []))],
        newFindingsCount: applied.counters.created,
        resolvedCount: applied.counters.resolved,
        totalOpenCount: st.targets.filter((t) => applied.targetIds.includes(t.id)).reduce((n, t) => n + t.open.total, 0),
        toxicChainsCount: applied.counters.toxic,
        summary: { ...result.summary, ...applied.counters },
        errorLog: ctrl.signal.aborted ? 'Abgebrochen.' : status === 'THROTTLED_ABORTED' ? 'Ziel hat Anfragen gedrosselt – Web-Prüfung abgebrochen.' : null,
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
    setBaseline(targetId) { const r = store.setBaseline(db, targetId); if (r.ok) persist(); return r; },
    searchSbom: (q) => store.searchSbom(db, q),
    getTarget: (id) => db.targets[id] || null,
    setTargetMeta(id, patch) { const r = store.setTargetMeta(db, id, patch); if (r.ok) persist(); return r; },
    deleteFindings(ids) { const r = store.deleteFindings(db, ids); if (r.deleted) persist(); return r; },
    deleteTarget(id) { const r = store.deleteTarget(db, id); if (r.ok) persist(); return r; },
    deleteRun(id) { const r = store.deleteRun(db, id); if (r.ok) persist(); return r; },
    purgeResolved(targetId) { const r = store.purgeResolved(db, targetId); if (r.deleted) persist(); return r; },
    clear() { db = store.emptyStore(); persist(); },
  };
}

module.exports = { createOrchestrator };
