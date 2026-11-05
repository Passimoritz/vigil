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
const path = require('path');
const secure = require('./securefile');
const { splitLoc } = require('./schema');
const { FINDING_STATUSES } = require('./validation');

const MAX_RUNS = 300;
const HIDDEN = new Set(['FALSE_POSITIVE', 'ACCEPTED_RISK']);
const ACTIVE = new Set(['OPEN', 'IN_PROGRESS']);
// Fuer den Fingerabdruck zaehlt die stabilste Quelle eines zusammengefuehrten Befunds.
const SOURCE_PRIORITY = ['prescan', 'osv', 'webscan', 'gitleaks', 'trufflehog', 'trivy', 'grype', 'osv-scanner', 'semgrep', 'bandit', 'checkov', 'retire', 'hadolint', 'nmap', 'nuclei', 'binary', 'ai'];

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function emptyStore() { return { version: 1, targets: {}, findings: {}, runs: [] }; }

// Verschluesselung im Ruhezustand (securefile.js): der Main-Prozess setzt beim Start einen
// Schluessel (safeStorage). Ohne Schluessel (CLI, Tests) bleibt die Datei Klartext.
let cipher = null;
function setCipher(c) { cipher = c || null; }

function load(file) {
  let r;
  try { r = secure.readJson(file, cipher); }
  catch (e) {
    // Nicht entschluesselbar oder kaputt: Datei zur Seite legen statt sie mit leerem Stand zu ueberschreiben
    const moved = secure.quarantine(file);
    console.warn(`Befund-Speicher nicht lesbar (${e.message})${moved ? ' – gesichert als ' + path.basename(moved) : ''}`);
    return emptyStore();
  }
  const d = r.data;
  if (!d || typeof d !== 'object') return emptyStore();
  const out = { ...emptyStore(), ...d, targets: d.targets || {}, findings: d.findings || {}, runs: Array.isArray(d.runs) ? d.runs : [] };
  // Migration: Klartext-Datei sofort verschluesselt neu schreiben
  if (cipher && !r.encrypted) { try { save(file, out); } catch { /* beim naechsten Speichern */ } }
  return out;
}
// Atomar schreiben (erst Temp-Datei, dann umbenennen) – kein halb geschriebener Speicher.
function save(file, store) {
  secure.writeJson(file, store, cipher);
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
  expireAcceptedRisks(store, now); // abgelaufene Akzeptanzen vor dem Abgleich zuruecksetzen
  const runTargets = run.targets.map((t) => ({ ...t, id: upsertTarget(store, t, now) }));
  const seen = new Set();
  const counters = { created: 0, reopened: 0, resolved: 0, updated: 0 };

  // Fehlalarme lernen: gleiche Regel (bzw. gleicher Titel) in derselben Datei, nur andere Zeile
  const learnedFp = new Map();
  for (const r of Object.values(store.findings)) {
    if (r.status !== 'FALSE_POSITIVE') continue;
    const file = splitLoc(r.location).file || String(r.location || '').toLowerCase();
    learnedFp.set(`${r.targetId}|${r.ruleId}|${file}`, r);
    learnedFp.set(`${r.targetId}|t:${normTitle(r.title)}|${file}`, r);
  }
  counters.learned = 0;
  const annotated = run.findings.map((f) => {
    const targetId = assignTarget(f, runTargets);
    const fp = fingerprintOf(targetId, f);
    seen.add(fp);
    let prev = store.findings[fp];
    if (!prev) {
      const file = splitLoc(f.location).file || String(f.location || '').toLowerCase();
      const twin = learnedFp.get(`${targetId}|${f.ruleId || ''}|${file}`) || learnedFp.get(`${targetId}|t:${normTitle(f.title)}|${file}`);
      if (twin) {
        counters.learned++;
        prev = { status: 'FALSE_POSITIVE', statusNote: 'Automatisch als Fehlalarm übernommen: derselbe Befund in dieser Datei wurde früher als Fehlalarm markiert.', firstSeenAt: now, statusChangedAt: now, learned: true };
      }
    }
    const snapshot = { ...f };
    delete snapshot.id; delete snapshot.status; delete snapshot.isNew; delete snapshot.suppressed; delete snapshot.regression;
    let status = 'OPEN', isNew = false, regression = false;
    if (!prev || prev.learned) { isNew = !prev; if (!prev) counters.created++; if (prev && prev.learned) status = 'FALSE_POSITIVE'; }
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
      ...(prev && prev.learned ? { learnedFalsePositive: true } : {}),
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
  // Aenderungs-Waechter: Skripte und Formularziele je Webseite (letzter vollstaendiger Stand)
  if (run.webWatch && typeof run.webWatch === 'object') {
    store.webWatch = store.webWatch || {};
    for (const t of runTargets.filter((x) => x.type === 'url')) if (run.webWatch[t.value]) store.webWatch[t.id] = run.webWatch[t.value];
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
  // Verlauf ueber die Zeit: Stand nach jedem Lauf (fuer Grafiken in der Uebersicht)
  const s = stats(store);
  store.trend = [...(store.trend || []), { at: now, open: s.openTotal, critical: s.open.critical, high: s.open.high, posture: s.posture, created: counters.created, resolved: counters.resolved }].slice(-200);
  return { findings: annotated, counters: { ...counters, toxic }, resolved: resolvedNow, targetIds: runTargets.map((t) => t.id) };
}

// --- Loeschen ---------------------------------------------------------------------
// Befunde endgueltig entfernen. Ist die Luecke noch da, taucht sie beim naechsten Lauf als neu auf –
// zum dauerhaften Ausblenden ist "Fehlalarm" bzw. "Risiko akzeptiert" der richtige Weg.
function deleteFindings(store, ids) {
  let n = 0;
  for (const id of new Set((ids || []).map(String))) if (store.findings[id]) { delete store.findings[id]; n++; }
  for (const f of Object.values(store.findings)) if (Array.isArray(f.linkedFindingIds)) f.linkedFindingIds = f.linkedFindingIds.filter((x) => store.findings[x]);
  return { ok: true, deleted: n };
}
// Ziel mit allen Befunden und seinem Paket-Inventar entfernen; Laeufe behalten, aber Verweis loesen
function deleteTarget(store, targetId) {
  if (!store.targets[targetId]) return { ok: false, error: 'Ziel nicht gefunden.' };
  const ids = Object.values(store.findings).filter((f) => f.targetId === targetId).map((f) => f.id);
  deleteFindings(store, ids);
  delete store.targets[targetId];
  if (store.sboms) delete store.sboms[targetId];
  if (store.webWatch) delete store.webWatch[targetId];
  for (const r of store.runs) if (Array.isArray(r.targetIds)) r.targetIds = r.targetIds.filter((x) => x !== targetId);
  return { ok: true, deletedFindings: ids.length };
}
function deleteRun(store, runId) {
  const i = store.runs.findIndex((r) => r.id === runId);
  if (i < 0) return { ok: false, error: 'Lauf nicht gefunden.' };
  if (store.runs[i].status === 'RUNNING' || store.runs[i].status === 'QUEUED') return { ok: false, error: 'Ein laufender Lauf kann nicht gelöscht werden.' };
  store.runs.splice(i, 1);
  return { ok: true };
}
// Behobene Befunde aufraeumen (optional nur fuer ein Ziel)
function purgeResolved(store, targetId) {
  const ids = Object.values(store.findings).filter((f) => f.status === 'RESOLVED' && (!targetId || f.targetId === targetId)).map((f) => f.id);
  return deleteFindings(store, ids);
}

const normTitle = (t) => String(t || '').toLowerCase().replace(/\d+/g, '#').replace(/\s+/g, ' ').trim().slice(0, 80);

// Bestaetigte Fehlalarme der Ziele (neueste zuerst) – Hinweis fuer die KI
function falsePositivesFor(store, targetIds) {
  const ids = new Set(targetIds);
  return Object.values(store.findings)
    .filter((r) => ids.has(r.targetId) && r.status === 'FALSE_POSITIVE')
    .sort((a, b) => String(b.statusChangedAt).localeCompare(String(a.statusChangedAt)))
    .slice(0, 40).map((r) => ({ title: r.title, location: r.location }));
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
  for (const k of ['ownershipVerified', 'internetExposed', 'environment', 'maxRequestsPerSecond', 'hiddenFromPicker']) if (k in patch) t[k] = patch[k];
  return { ok: true, target: t };
}

// --- Status & Abfragen -----------------------------------------------------
// "Risiko akzeptiert" gilt nur befristet (Standard 90 Tage): danach wieder OPEN mit Hinweis.
const DEFAULT_ACCEPT_DAYS = 90;
const MAX_ACCEPT_DAYS = 3650;
function setStatus(store, id, status, note, opts = {}) {
  if (!FINDING_STATUSES.includes(status)) return { ok: false, error: 'Unbekannter Status.' };
  const rec = store.findings[id];
  if (!rec) return { ok: false, error: 'Befund nicht gefunden.' };
  const now = opts.now || new Date().toISOString();
  if (rec.status !== status) { rec.status = status; rec.statusChangedAt = now; rec.resolvedAt = status === 'RESOLVED' ? rec.statusChangedAt : null; }
  rec.statusNote = note || undefined;
  if (status === 'ACCEPTED_RISK') {
    const days = Math.min(MAX_ACCEPT_DAYS, Math.max(1, Math.round(Number(opts.expiresInDays) || DEFAULT_ACCEPT_DAYS)));
    rec.acceptedUntil = new Date(Date.parse(now) + days * 864e5).toISOString();
  } else delete rec.acceptedUntil;
  return { ok: true, finding: rec };
}

// Abgelaufene Risikoakzeptanzen zuruecksetzen. Alte Eintraege ohne Ablaufdatum bekommen
// einmalig eines (Standardfrist ab der Akzeptanz) statt sofort zu verfallen.
function expireAcceptedRisks(store, now = new Date().toISOString()) {
  const t = Date.parse(now);
  const expired = [];
  for (const rec of Object.values(store.findings)) {
    if (rec.status !== 'ACCEPTED_RISK') continue;
    if (!rec.acceptedUntil) {
      const since = Date.parse(rec.statusChangedAt) || t;
      rec.acceptedUntil = new Date(since + DEFAULT_ACCEPT_DAYS * 864e5).toISOString();
    }
    if (Date.parse(rec.acceptedUntil) > t) continue;
    const day = String(rec.acceptedUntil).slice(0, 10);
    rec.status = 'OPEN'; rec.statusChangedAt = now; rec.resolvedAt = null;
    rec.statusNote = `Risikoakzeptanz am ${day} abgelaufen – wieder offen. Bitte neu bewerten.`;
    rec.acceptanceExpiredAt = now;
    delete rec.acceptedUntil;
    expired.push({ id: rec.id, title: rec.title });
  }
  return { expired: expired.length, items: expired };
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
  // Behebungszeit: Durchschnitt (Tage) von "zuerst gesehen" bis "behoben"
  const resolved = Object.values(store.findings).filter((f) => f.status === 'RESOLVED' && f.resolvedAt && f.firstSeenAt);
  const days = resolved.map((f) => (Date.parse(f.resolvedAt) - Date.parse(f.firstSeenAt)) / 864e5).filter((d) => d >= 0);
  const mttrDays = days.length ? Math.round((days.reduce((a, b) => a + b, 0) / days.length) * 10) / 10 : null;
  const since = Date.now() - 30 * 864e5;
  const last30 = { resolved: resolved.filter((f) => Date.parse(f.resolvedAt) >= since).length, created: Object.values(store.findings).filter((f) => Date.parse(f.firstSeenAt) >= since).length };
  return { trend: (store.trend || []).slice(-60), mttrDays, last30, open, openTotal: Object.values(open).reduce((a, b) => a + b, 0), byStatus, targets, runs: store.runs.slice(0, 20), toxic, kev, posture, newSinceBaseline, sbomTargets: Object.keys(store.sboms || {}).length };
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

// Letzter Stand des Aenderungs-Waechters je Webadresse: { [targetValue]: {at, origin, scripts, forms} }
function webWatchFor(store, targets) {
  const out = {};
  for (const t of targets || []) { const w = store.webWatch && store.webWatch[targetIdOf(t)]; if (t.type === 'url' && w) out[t.value] = w; }
  return out;
}

module.exports = { webWatchFor, emptyStore, load, save, setCipher, targetIdOf, upsertTarget, assignTarget, fingerprintOf, applyRun, falsePositivesFor, deleteFindings, deleteTarget, deleteRun, purgeResolved, setStatus, setBaseline, searchSbom, setTargetMeta, listFindings, stats, addRun, updateRun, HIDDEN, expireAcceptedRisks, DEFAULT_ACCEPT_DAYS };
