'use strict';

// Dauerhafter Befund-Speicher mit Lebenszyklus (lokale JSON-Datei statt Datenbank).
//
//  Ziele    – jedes gepruefte Ziel (Pfad, Webadresse, Server, Container-Image)
//  Befunde  – je Fingerabdruck SHA-256(targetId:scanner:ruleId:location)
//  Laeufe   – Verlauf der Scans (QUEUED/RUNNING/COMPLETED/FAILED)
//
// Regeln bei jedem abgeschlossenen Lauf (applyRun):
//  - OPEN / IN_PROGRESS wiedergefunden      -> lastSeenAt + Evidence aktualisieren
//  - FALSE_POSITIVE / ACCEPTED_RISK wieder  -> nur lastSeenAt, Status bleibt
//  - RESOLVED wiedergefunden                -> zurueck auf OPEN (Regression)
//  - OPEN, aber in diesem Lauf nicht mehr gefunden (gleiches Ziel + Scanner lief) -> RESOLVED
// KI-Befunde werden nie automatisch geschlossen: die KI findet nicht deterministisch jedes Mal dasselbe.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { splitLoc } = require('./schema');
const { FINDING_STATUSES } = require('./validation');

const MAX_RUNS = 300;
const HIDDEN = new Set(['FALSE_POSITIVE', 'ACCEPTED_RISK']);
const ACTIVE = new Set(['OPEN', 'IN_PROGRESS']);
// Fuer den Fingerabdruck zaehlt die stabilste Quelle eines zusammengefuehrten Befunds.
const SOURCE_PRIORITY = ['prescan', 'osv', 'webscan', 'gitleaks', 'trufflehog', 'trivy', 'grype', 'osv-scanner', 'semgrep', 'bandit', 'checkov', 'retire', 'hadolint', 'nmap', 'nuclei', 'binary', 'ai'];

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function emptyStore() { return { version: 1, targets: {}, findings: {}, runs: [] }; }

function load(file) {
  try {
    const d = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { ...emptyStore(), ...d, targets: d.targets || {}, findings: d.findings || {}, runs: Array.isArray(d.runs) ? d.runs : [] };
  } catch { return emptyStore(); }
}
// Atomar schreiben (erst Temp-Datei, dann umbenennen) – kein halb geschriebener Speicher.
function save(file, store) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(store), 'utf8');
  fs.renameSync(tmp, file);
}

// --- Ziele ---------------------------------------------------------------
function normIdentifier(t) {
  const v = String(t.value || '').trim();
  if (t.type === 'path') return path.resolve(v).replace(/[\\/]+$/, '').toLowerCase();
  if (t.type === 'url') { try { const u = new URL(v); return `${u.protocol}//${u.host}${u.pathname.replace(/\/+$/, '')}`.toLowerCase(); } catch { return v.toLowerCase(); } }
  return v.toLowerCase();
}
function targetIdOf(t) { return sha256(`${t.type}:${normIdentifier(t)}`).slice(0, 16); }

function upsertTarget(store, t, now) {
  const id = targetIdOf(t);
  const prev = store.targets[id];
  store.targets[id] = {
    id,
    name: prev ? prev.name : (t.type === 'path' ? path.basename(String(t.value)) || String(t.value) : String(t.value)),
    type: t.type,
    identifier: String(t.value),
    verified: t.type === 'path' || t.type === 'image' || !!t.authorized || !!(prev && prev.verified),
    createdAt: prev ? prev.createdAt : now,
    updatedAt: now,
    lastScanAt: now,
  };
  return id;
}

// Welchem Ziel gehoert ein Befund? Bei einem Ziel eindeutig, sonst ueber den Ort.
function assignTarget(f, runTargets) {
  if (runTargets.length === 1) return runTargets[0].id;
  const loc = String(f.location || '').toLowerCase().replace(/\\/g, '/');
  let host = null;
  try { host = new URL(f.location).host.toLowerCase(); } catch { /* kein URL-Ort */ }
  for (const t of runTargets) {
    const ident = String(t.value).toLowerCase().replace(/\\/g, '/');
    if (t.type === 'url' && host) { try { if (new URL(t.value).host.toLowerCase() === host) return t.id; } catch { /* weiter */ } }
    if (t.type === 'endpoint' && (host === ident || loc.startsWith(ident))) return t.id;
    if (t.type === 'image' && loc.includes(ident)) return t.id;
    if (t.type === 'path') {
      if (loc.startsWith(ident)) return t.id;
      const base = ident.split('/').filter(Boolean).pop();
      if (base && (loc.startsWith(base + '/') || loc.startsWith(base + ':') || loc.includes('/' + base + '/'))) return t.id;
    }
  }
  return (runTargets.find((t) => t.type === 'path') || runTargets[0]).id;
}

function primarySource(f) {
  const srcs = f.sources && f.sources.length ? f.sources : [f.source];
  return [...srcs].sort((a, b) => rank(a) - rank(b))[0] || 'ai';
}
const rank = (s) => { const i = SOURCE_PRIORITY.indexOf(s); return i < 0 ? SOURCE_PRIORITY.length - 1 : i; };

function fingerprintOf(targetId, f) {
  const loc = splitLoc(f.location);
  const location = loc.line != null ? `${loc.file}:${loc.line}` : (loc.file || String(f.location || '').toLowerCase());
  return sha256(`${targetId}:${primarySource(f)}:${f.ruleId || ''}:${location}`);
}

// --- Lauf anwenden -----------------------------------------------------------
// run: { targets:[{type,value,authorized}], findings:[...], scannersRun:[{target:value, source}], now }
// Ergebnis: annotierte Befunde + Statistik dieses Laufs.
function applyRun(store, run) {
  const now = run.now || new Date().toISOString();
  const runTargets = run.targets.map((t) => ({ ...t, id: upsertTarget(store, t, now) }));
  const seen = new Set();
  const counters = { created: 0, reopened: 0, resolved: 0, updated: 0 };

  const annotated = run.findings.map((f) => {
    const targetId = assignTarget(f, runTargets);
    const fp = fingerprintOf(targetId, f);
    seen.add(fp);
    const prev = store.findings[fp];
    const snapshot = { ...f };
    delete snapshot.id; delete snapshot.status; delete snapshot.isNew; delete snapshot.suppressed; delete snapshot.regression;
    let status = 'OPEN', isNew = false, regression = false;
    if (!prev) { isNew = true; counters.created++; }
    else if (prev.status === 'RESOLVED') { regression = true; counters.reopened++; }
    else { status = prev.status; counters.updated++; }
    store.findings[fp] = {
      id: fp, fingerprint: fp, targetId,
      sourceScanner: primarySource(f), ruleId: f.ruleId || '', title: f.title, severity: f.severity,
      cvssScore: f.cvss ?? null, location: f.location, evidence: f.evidence || (prev && prev.evidence) || undefined,
      status,
      statusNote: prev && status === prev.status ? prev.statusNote : (regression ? 'Wieder aufgetaucht (Regression).' : undefined),
      firstSeenAt: prev ? prev.firstSeenAt : now,
      lastSeenAt: now,
      statusChangedAt: prev && prev.status === status ? prev.statusChangedAt : now,
      finding: snapshot,
    };
    return { ...f, id: fp, targetId, status, isNew, regression, suppressed: HIDDEN.has(status), firstSeenAt: store.findings[fp].firstSeenAt };
  });

  // Auto-Resolve: nur fuer Ziel+Scanner-Paare, die in diesem Lauf vollstaendig gelaufen sind.
  const ran = new Set();
  for (const s of run.scannersRun || []) {
    if (s.source === 'ai') continue;
    const t = runTargets.find((x) => x.value === s.target) || (runTargets.length === 1 ? runTargets[0] : null);
    if (t) ran.add(`${t.id}:${s.source}`);
  }
  const resolvedNow = [];
  for (const rec of Object.values(store.findings)) {
    if (rec.status !== 'OPEN' || seen.has(rec.id)) continue;
    if (!ran.has(`${rec.targetId}:${rec.sourceScanner}`)) continue;
    rec.status = 'RESOLVED'; rec.statusChangedAt = now; rec.statusNote = 'Automatisch behoben: im letzten vollständigen Lauf nicht mehr gefunden.';
    counters.resolved++;
    resolvedNow.push({ id: rec.id, title: rec.title, location: rec.location, severity: rec.severity });
  }
  return { findings: annotated, counters, resolved: resolvedNow, targetIds: runTargets.map((t) => t.id) };
}

// --- Status & Abfragen -----------------------------------------------------
function setStatus(store, id, status, note) {
  if (!FINDING_STATUSES.includes(status)) return { ok: false, error: 'Unbekannter Status.' };
  const rec = store.findings[id];
  if (!rec) return { ok: false, error: 'Befund nicht gefunden.' };
  if (rec.status !== status) { rec.status = status; rec.statusChangedAt = new Date().toISOString(); }
  rec.statusNote = note || undefined;
  return { ok: true, finding: rec };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
// filter: { status?, severity?, targetId?, q?, limit? }
function listFindings(store, filter = {}) {
  const q = String(filter.q || '').toLowerCase().trim();
  let list = Object.values(store.findings);
  if (filter.status) { const set = new Set(String(filter.status).split(',')); list = list.filter((f) => set.has(f.status)); }
  if (filter.severity) { const set = new Set(String(filter.severity).toLowerCase().split(',')); list = list.filter((f) => set.has(f.severity)); }
  if (filter.targetId) list = list.filter((f) => f.targetId === filter.targetId);
  if (q) list = list.filter((f) => `${f.title} ${f.location} ${f.ruleId}`.toLowerCase().includes(q));
  list.sort((a, b) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || String(b.lastSeenAt).localeCompare(String(a.lastSeenAt)));
  const limit = Math.max(1, Math.min(Number(filter.limit) || 500, 5000));
  return list.slice(0, limit).map((f) => ({ ...f, targetName: store.targets[f.targetId] ? store.targets[f.targetId].name : '?' }));
}

function stats(store) {
  const open = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byStatus = Object.fromEntries(FINDING_STATUSES.map((s) => [s, 0]));
  const perTarget = {};
  for (const f of Object.values(store.findings)) {
    byStatus[f.status] = (byStatus[f.status] || 0) + 1;
    if (ACTIVE.has(f.status)) {
      open[f.severity] = (open[f.severity] || 0) + 1;
      const p = perTarget[f.targetId] || (perTarget[f.targetId] = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 });
      p[f.severity]++; p.total++;
    }
  }
  const targets = Object.values(store.targets)
    .map((t) => ({ ...t, open: perTarget[t.id] || { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 } }))
    .sort((a, b) => String(b.lastScanAt).localeCompare(String(a.lastScanAt)));
  return { open, openTotal: Object.values(open).reduce((a, b) => a + b, 0), byStatus, targets, runs: store.runs.slice(0, 20) };
}

// --- Laeufe -------------------------------------------------------------------
function addRun(store, run) {
  store.runs.unshift(run);
  if (store.runs.length > MAX_RUNS) store.runs.length = MAX_RUNS;
  return run;
}
function updateRun(store, id, patch) {
  const r = store.runs.find((x) => x.id === id);
  if (r) Object.assign(r, patch);
  return r;
}

module.exports = { emptyStore, load, save, targetIdOf, upsertTarget, assignTarget, fingerprintOf, applyRun, setStatus, listFindings, stats, addRun, updateRun, HIDDEN };
