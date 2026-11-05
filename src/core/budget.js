'use strict';

// Monatliches KI-Budget: lokale Ausgaben-Liste (ai-spend.json) mit Kosten je Lauf bzw. je
// Einzelaufruf (Rueckfrage, Patch, Erklaerung …). Nur Schaetzwerte aus cost.js – massgeblich
// bleibt die Abrechnung des Anbieters. Lokale Modelle kosten nichts und zaehlen nicht.

const fs = require('fs');
const path = require('path');

const MAX_ENTRIES = 5000;
const monthOf = (iso) => String(iso || new Date().toISOString()).slice(0, 7);

function load(file) {
  try { const d = JSON.parse(fs.readFileSync(file, 'utf8')); return { entries: Array.isArray(d.entries) ? d.entries : [] }; }
  catch { return { entries: [] }; }
}
function save(file, ledger) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file + '.tmp', JSON.stringify({ entries: ledger.entries.slice(-MAX_ENTRIES) }));
    fs.renameSync(file + '.tmp', file);
    return true;
  } catch { return false; }
}

// entry: { kind:'run'|'ask'|'patch'|'explain'|'summary'|'threat'|'upgrade', usd, provider, model, inputTokens, outputTokens, runId? }
function record(ledger, entry, now = new Date().toISOString()) {
  const usd = Math.max(0, Number(entry.usd) || 0);
  if (!usd && !entry.inputTokens && !entry.outputTokens) return ledger;
  ledger.entries.push({ at: now, kind: entry.kind || 'run', usd: Math.round(usd * 1e6) / 1e6, provider: entry.provider || '', model: entry.model || '', inputTokens: entry.inputTokens || 0, outputTokens: entry.outputTokens || 0, ...(entry.runId ? { runId: entry.runId } : {}) });
  if (ledger.entries.length > MAX_ENTRIES) ledger.entries.splice(0, ledger.entries.length - MAX_ENTRIES);
  return ledger;
}

function stats(ledger, budgetUsd = 0, now = new Date().toISOString()) {
  const month = monthOf(now);
  const byMonth = new Map();
  for (const e of ledger.entries) {
    const m = monthOf(e.at);
    const x = byMonth.get(m) || { month: m, usd: 0, runs: 0, calls: 0 };
    x.usd += e.usd || 0; if (e.kind === 'run') x.runs++; else x.calls++;
    byMonth.set(m, x);
  }
  const cur = byMonth.get(month) || { month, usd: 0, runs: 0, calls: 0 };
  const budget = Math.max(0, Number(budgetUsd) || 0);
  const recentRuns = ledger.entries.filter((e) => e.kind === 'run').slice(-10).reverse();
  return {
    month, budget, spent: round(cur.usd), runs: cur.runs, calls: cur.calls,
    remaining: budget ? round(Math.max(0, budget - cur.usd)) : null,
    exceeded: !!budget && cur.usd >= budget,
    percent: budget ? Math.min(999, Math.round((cur.usd / budget) * 100)) : null,
    months: [...byMonth.values()].sort((a, b) => b.month.localeCompare(a.month)).slice(0, 6).map((x) => ({ ...x, usd: round(x.usd) })),
    recentRuns: recentRuns.map((e) => ({ at: e.at, usd: round(e.usd), model: e.model, provider: e.provider })),
    avgRunUsd: cur.runs ? round(ledger.entries.filter((e) => e.kind === 'run' && monthOf(e.at) === month).reduce((a, e) => a + e.usd, 0) / cur.runs) : 0,
  };
}
const round = (n) => Math.round((Number(n) || 0) * 10000) / 10000;

// Vor einem Lauf/Aufruf: reicht das Budget? estimateUsd = geschaetzte Kosten des Vorhabens.
function check(ledger, budgetUsd, estimateUsd = 0, now) {
  const s = stats(ledger, budgetUsd, now);
  if (!s.budget) return { ok: true, ...s, wouldExceed: false };
  const wouldExceed = s.spent + Math.max(0, Number(estimateUsd) || 0) > s.budget;
  return { ok: !s.exceeded && !wouldExceed, ...s, wouldExceed };
}

module.exports = { load, save, record, stats, check, monthOf };
