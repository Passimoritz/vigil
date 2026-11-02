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
    name: prev ? prev.name : (t.type === 'path' ? path.basename(String(t.value)) || String(t.value) : t.type === 'system' ? (require('./hostaudit').SYSTEMS[t.value] || String(t.value)) : String(t.value)),
    type: t.type,
    identifier: String(t.value),
    verified: t.type === 'path' || t.type === 'image' || t.type === 'system' || !!t.authorized || !!(prev && prev.verified),
    // Domain-Nachweis (DNS-TXT oder .well-known) – noetig fuer tiefe Web-Pruefungen
    ownershipVerified: !!(t.ownershipVerified || (prev && prev.ownershipVerified)),
    verificationToken: (prev && prev.verificationToken) || crypto.randomBytes(12).toString('hex'),
    internetExposed: prev && prev.internetExposed != null ? prev.internetExposed : (t.type === 'url' || t.type === 'endpoint'),
    environment: (prev && prev.environment) || 'PRODUCTION',
    baselineTimestamp: (prev && prev.baselineTimestamp) || null,
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
  const sys = runTargets.find((t) => t.type === 'system' && (f.sourceModule === 'system-' + t.value || f.source === 'system-' + t.value));
  if (sys) return sys.id;
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
    const isBaselineLegacy = prev ? !!prev.isBaselineLegacy : false;
    store.findings[fp] = {
      id: fp, fingerprint: fp, targetId,
      sourceScanner: primarySource(f), sourceModule: f.sourceModule || primarySource(f), category: f.category,
      ruleId: f.ruleId || '', title: f.title, severity: f.severity,
      cvssScore: f.cvss ?? null, epssScore: f.epssScore ?? null, inCisaKev: !!f.inCisaKev,
      contextualRiskScore: f.contextualRiskScore ?? null,
      location: f.location, evidence: f.evidence || (prev && prev.evidence) || undefined,
      status,
      statusNote: prev && status === prev.status ? prev.statusNote : (regression ? 'Wieder aufgetaucht (Regression).' : undefined),
      isBaselineLegacy,
      linkedFindingIds: [],
      firstSeenAt: prev ? prev.firstSeenAt : now,
      lastSeenAt: now,
      resolvedAt: status === 'RESOLVED' ? (prev && prev.resolvedAt) : null,
      statusChangedAt: prev && prev.status === status ? prev.statusChangedAt : now,
      finding: snapshot,
    };
    return { ...f, id: fp, targetId, status, isNew, regression, isBaselineLegacy, suppressed: HIDDEN.has(status), firstSeenAt: store.findings[fp].firstSeenAt };
  });

  // Angriffspfade: Verknuepfung ueber ruleId@location auf die gespeicherten IDs abbilden.
  const idByKey = new Map(annotated.map((f) => [`${f.ruleId}@${f.location}`, f.id]));
  for (const f of annotated) {
    if (!Array.isArray(f.linkedKeys)) continue;
    f.linkedFindingIds = f.linkedKeys.map((k) => idByKey.get(k)).filter(Boolean);
    store.findings[f.id].linkedFindingIds = f.linkedFindingIds;
  }
  // SBOM-Inventar je Ziel (letzter Stand) fuer die globale Paketsuche
  if (Array.isArray(run.sbom) && run.sbom.length) {
    store.sboms = store.sboms || {};
    for (const t of runTargets.filter((x) => x.type === 'path' || x.type === 'image')) store.sboms[t.id] = { at: now, packages: run.sbom.slice(0, 5000) };
  }

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
    rec.status = 'RESOLVED'; rec.statusChangedAt = now; rec.resolvedAt = now; rec.statusNote = 'Automatisch behoben: im letzten vollständigen Lauf nicht mehr gefunden.';
    counters.resolved++;
    resolvedNow.push({ id: rec.id, title: rec.title, location: rec.location, severity: rec.severity });
  }
  const toxic = annotated.filter((f) => f.toxic && !HIDDEN.has(f.status)).length;
  return { findings: annotated, counters: { ...counters, toxic }, resolved: resolvedNow, targetIds: runTargets.map((t) => t.id) };
}

// Baseline: alle derzeit offenen Befunde eines Ziels als "Altlast" markieren –
// danach zeigt "Neu seit Baseline" nur, was spaeter hinzugekommen ist.
function setBaseline(store, targetId, now = new Date().toISOString()) {
  const t = store.targets[targetId];
  if (!t) return { ok: false, error: 'Ziel nicht gefunden.' };
  t.baselineTimestamp = now;
  let n = 0;
  for (const f of Object.values(store.findings)) if (f.targetId === targetId && ACTIVE.has(f.status)) { f.isBaselineLegacy = true; n++; }
  return { ok: true, count: n, at: now };
}

// Globale SBOM-Suche: "lodash" oder "lodash@4.17" -> wo ist das Paket im Einsatz?
function searchSbom(store, q) {
  const [name, ver] = String(q || '').trim().toLowerCase().split('@').filter((x, i) => x || i > 0);
  if (!name) return [];
  const hits = [];
  for (const [targetId, s] of Object.entries(store.sboms || {})) {
    for (const p of s.packages) {
      if (!String(p.name).toLowerCase().includes(name)) continue;
      if (ver && !String(p.version).startsWith(ver)) continue;
      hits.push({ ...p, targetId, targetName: store.targets[targetId] ? store.targets[targetId].name : '?', at: s.at });
      if (hits.length >= 200) return hits;
    }
  }
  return hits;
}

function setTargetMeta(store, targetId, patch) {
  const t = store.targets[targetId];
  if (!t) return { ok: false, error: 'Ziel nicht gefunden.' };
  for (const k of ['ownershipVerified', 'internetExposed', 'environment', 'maxRequestsPerSecond']) if (k in patch) t[k] = patch[k];
  return { ok: true, target: t };
}

// --- Status & Abfragen -----------------------------------------------------
function setStatus(store, id, status, note) {
  if (!FINDING_STATUSES.includes(status)) return { ok: false, error: 'Unbekannter Status.' };
  const rec = store.findings[id];
  if (!rec) return { ok: false, error: 'Befund nicht gefunden.' };
  if (rec.status !== status) { rec.status = status; rec.statusChangedAt = new Date().toISOString(); rec.resolvedAt = status === 'RESOLVED' ? rec.statusChangedAt : null; }
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
  if (filter.newSinceBaseline) list = list.filter((f) => !f.isBaselineLegacy);
  if (filter.toxic) list = list.filter((f) => /^toxic-/.test(f.ruleId));
  list.sort((a, b) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || ((b.contextualRiskScore || 0) - (a.contextualRiskScore || 0)) || String(b.lastSeenAt).localeCompare(String(a.lastSeenAt)));
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
  const active = Object.values(store.findings).filter((f) => ACTIVE.has(f.status));
  const toxic = active.filter((f) => /^toxic-/.test(f.ruleId)).map((f) => ({ id: f.id, title: f.title, targetId: f.targetId, targetName: store.targets[f.targetId] ? store.targets[f.targetId].name : '?', linkedFindingIds: f.linkedFindingIds || [], location: f.location }));
  const kev = active.filter((f) => f.inCisaKev).length;
  // Sicherheitswert 0–100: Abzug je offenem Befund nach Schweregrad, Angriffspfade und KEV wiegen extra.
  const penalty = open.critical * 12 + open.high * 6 + open.medium * 2 + open.low * 0.5 + toxic.length * 15 + kev * 8;
  const posture = Math.max(0, Math.round(100 - penalty));
  const newSinceBaseline = active.filter((f) => !f.isBaselineLegacy).length;
  return { open, openTotal: Object.values(open).reduce((a, b) => a + b, 0), byStatus, targets, runs: store.runs.slice(0, 20), toxic, kev, posture, newSinceBaseline, sbomTargets: Object.keys(store.sboms || {}).length };
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

module.exports = { emptyStore, load, save, targetIdOf, upsertTarget, assignTarget, fingerprintOf, applyRun, setStatus, setBaseline, searchSbom, setTargetMeta, listFindings, stats, addRun, updateRun, HIDDEN };
