'use strict';

// Dauer-Schaetzung, die aus echten Laeufen lernt.
//
// Vorher: feste Annahmen (35 s je lokalem KI-Aufruf, 45 s je Webseite) – lag oft um
// ein Vielfaches daneben. Jetzt:
//  1. Jeder Lauf misst, wie lange jede Phase wirklich gedauert hat (PhaseClock).
//  2. Daraus werden Kennzahlen gelernt (Sekunden je KI-Aufruf pro Modell, je Webseite,
//     je externem Werkzeug …) und als gleitender Mittelwert gespeichert.
//  3. Die Schaetzung rechnet mit diesen Kennzahlen; ohne Messung mit vorsichtigen
//     Startwerten, die eher zu lang als zu kurz sind.

const fs = require('fs');
const path = require('path');

// Startwerte (Sekunden), bewusst vorsichtig
const DEFAULTS = {
  perFile: 0.03,        // Einlesen + Vorpruefung je Datei
  base: 4,              // Start, Module, Abschluss
  cveBase: 4, perDep: 0.08,
  web: 90,              // passive Server-Checks je Webadresse (inkl. TLS, Pfade, Module)
  webDeep: 120,         // zusaetzlich: Browser-Pruefung + Rechtematrix fuer verifizierte Ziele
  image: 120,           // trivy je Container-Image
  tool: 25,             // je externem Werkzeug je Ordner (gitleaks, semgrep …)
  activeWeb: 300,       // nmap + nuclei je Webadresse
  gitHistory: 8,
  aiLocal: 75,          // je KI-Aufruf lokal (Mittelklasse-Rechner, grosses Modell)
  aiCloud: 25,          // je KI-Aufruf Cloud
  aiWarmup: 30,         // lokales Modell in den Speicher laden
};
const EXTERNAL_TOOLS = 10;
const ALPHA = 0.5;      // Gewicht der neuesten Messung

function load(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')) || {}; } catch { return {}; } }
function save(file, data) {
  try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(data, null, 1)); } catch { /* nicht kritisch */ }
}

const aiKey = (cfg) => `ai:${cfg.provider || '?'}:${cfg.model || '?'}`;
const learned = (calib, key, def) => (calib && calib[key] && calib[key].n ? calib[key].v : def);

// inputs: { targets, files, deps, calls, local, config }
function estimate({ targets = [], files = 0, deps = 0, calls = 0, local = false, config = {} }, calib = {}) {
  const parts = {};
  const paths = targets.filter((t) => t.type === 'path');
  const webs = targets.filter((t) => t.type === 'url' || t.type === 'endpoint');
  parts.prescan = learned(calib, 'base', DEFAULTS.base) + files * learned(calib, 'perFile', DEFAULTS.perFile);
  if (config.cveLookup !== false && deps) parts.cve = DEFAULTS.cveBase + deps * learned(calib, 'perDep', DEFAULTS.perDep);
  if (paths.length && config.gitHistory !== false) parts.git = paths.length * learned(calib, 'gitHistory', DEFAULTS.gitHistory);
  if (webs.length) {
    parts.web = webs.length * learned(calib, 'web', DEFAULTS.web);
    const deep = webs.filter((t) => t.verified || t.internal).length;
    if (deep) parts.web += deep * learned(calib, 'webDeep', DEFAULTS.webDeep);
  }
  const images = targets.filter((t) => t.type === 'image').length;
  if (images) parts.image = images * learned(calib, 'image', DEFAULTS.image);
  if (config.activeScan) {
    parts.active = paths.length * EXTERNAL_TOOLS * learned(calib, 'tool', DEFAULTS.tool) + webs.length * learned(calib, 'activeWeb', DEFAULTS.activeWeb);
  }
  if (calls) {
    const per = learned(calib, aiKey(config), local ? DEFAULTS.aiLocal : DEFAULTS.aiCloud);
    // Gegenpruefung: ein Zusatzaufruf je etwa 4 Hauptaufrufe
    const validate = config.aiValidation !== false ? Math.ceil(calls / 4) : 0;
    parts.ai = (calls + validate) * per + (local && !(calib[aiKey(config)] && calib[aiKey(config)].n) ? DEFAULTS.aiWarmup : 0);
  }
  const seconds = Math.round(Object.values(parts).reduce((a, b) => a + b, 0));
  const measured = !!(calls ? calib[aiKey(config)] && calib[aiKey(config)].n : Object.keys(calib).length);
  return { seconds, parts, measured };
}

// Misst die Phasen eines Laufs anhand der Fortschrittsmeldungen.
class PhaseClock {
  constructor(now = () => Date.now()) { this.now = now; this.t0 = now(); this.cur = null; this.since = this.t0; this.spent = {}; this.aiCalls = 0; this.validateCalls = 0; }
  tick(p) {
    const ph = p && p.phase;
    if (!ph) return;
    if (ph !== this.cur) { this.close(); this.cur = ph; this.since = this.now(); }
    if (ph === 'analyze' && p.total) this.aiCalls = Math.max(this.aiCalls, p.done || 0);
    if (ph === 'validate' && p.total) this.validateCalls = Math.max(this.validateCalls, p.done || 0);
  }
  close() { if (this.cur) this.spent[this.cur] = (this.spent[this.cur] || 0) + (this.now() - this.since) / 1000; }
  finish() { this.close(); this.cur = null; return { total: (this.now() - this.t0) / 1000, spent: this.spent, aiCalls: this.aiCalls, validateCalls: this.validateCalls }; }
}

function blend(calib, key, value) {
  if (!Number.isFinite(value) || value <= 0) return;
  const prev = calib[key];
  calib[key] = prev && prev.n ? { v: prev.v * (1 - ALPHA) + value * ALPHA, n: prev.n + 1 } : { v: value, n: 1 };
}

// Gemessene Zeiten in die Kennzahlen uebernehmen (nur vollstaendige Laeufe).
function learn(calib, m, { targets = [], files = 0, deps = 0, config = {} }) {
  const s = m.spent;
  const paths = targets.filter((t) => t.type === 'path').length;
  const webs = targets.filter((t) => t.type === 'url' || t.type === 'endpoint').length;
  const images = targets.filter((t) => t.type === 'image').length;
  if (files > 50 && s.prescan) blend(calib, 'perFile', ((s.ingest || 0) + s.prescan) / files);
  if (deps > 20 && s.cve) blend(calib, 'perDep', Math.max(0, s.cve - DEFAULTS.cveBase) / deps);
  if (webs && !images && s.webscan) blend(calib, 'web', s.webscan / webs);
  if (images && !webs && s.webscan) blend(calib, 'image', s.webscan / images);
  if (config.activeScan && paths && !webs && s.active) blend(calib, 'tool', s.active / (paths * EXTERNAL_TOOLS));
  const calls = m.aiCalls + m.validateCalls;
  if (calls && (s.analyze || s.validate)) blend(calib, aiKey(config), ((s.analyze || 0) + (s.validate || 0)) / calls);
  calib.updatedAt = new Date().toISOString();
  return calib;
}

module.exports = { estimate, learn, PhaseClock, load, save, DEFAULTS, aiKey };
