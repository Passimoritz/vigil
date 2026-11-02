'use strict';

// Fassade ueber die gesamte Pipeline: Ingest -> Prescan -> KI-Analyse.

const { ingestTargets } = require('./ingest');
const { prescan, ruleNames } = require('./prescan');
const { lookupCves } = require('./cve');
const { scanWeb } = require('./webscan');
const { runNmap, runNuclei, runGitleaks, runTrivyFs, runTrivyImage, runSemgrep, runCheckov, runRetire, runHadolint, runOsvScanner, runGrype, runTrufflehog, runBandit } = require('./tools');
const { analyze } = require('./analyze');
const { enrich } = require('./harness');
const report = require('./report');
const { fingerprint, atOrAbove, dedupeFindings, sortFindings, summarize } = require('./schema');
const { PROVIDERS, callProvider, pingProvider, fetchModels } = require('./providers');
const { runStaticModules } = require('./modules/static');
const { runWebModules } = require('./modules/web');
const { applyIntel, contextualRisk, correlate } = require('./intel');
const { enrichRemedy } = require('./remedies');
const { hostOf, isInternalHost } = require('./scope');

// Gemeinsamer Abschluss: Threat-Intel, Kontext-Risiko, Angriffspfade, Loesungswissen.
function finalize(findings, targets, config) {
  const exposed = targets.some((t) => (t.type === 'url' || t.type === 'endpoint') && !isInternalHost(hostOf(t)));
  let list = applyIntel(findings, config.intel);
  list = list.map((f) => ({ ...f, contextualRiskScore: f.contextualRiskScore ?? contextualRisk(f, { internetExposed: exposed || f.source === 'webscan' }) }));
  list = [...list, ...correlate(list)];
  return sortFindings(list.map(enrichRemedy));
}

// Hat ein Tool-Lauf wirklich stattgefunden? (Nur dann duerfen fehlende Befunde als behoben gelten.)
const DID_NOT_RUN = /nicht ausgefuehrt|nicht installiert|abgebrochen|nicht lesbar|unerwartet|nicht erreichbar|uebersprungen|fehlgeschlagen|konnte nicht/i;
const completed = (notes) => !(notes || []).some((n) => DID_NOT_RUN.test(n));

// targets: [{type:'path'|'url'|'endpoint'|'image', value, authorized?}]
// config:  { provider, model, apiKey, baseUrl, temperature, maxTokens }
async function runAudit(targets, config, onProgress = () => {}) {
  onProgress({ phase: 'ingest', message: 'Sammle Prüfmaterial …' });
  const ing = await ingestTargets(targets, onProgress);
  const scannersRun = []; // [{ target, source }] – vollstaendig gelaufene Pruefungen je Ziel
  for (const t of targets) if (t.type === 'path' && !ing.notes.some((n) => n.includes(t.value) && /nicht gefunden|Fehler/.test(n))) scannersRun.push({ target: t.value, source: 'prescan' });

  onProgress({ phase: 'prescan', message: 'Statische Vorprüfung (Secrets, Deps, Muster) …' });
  const pre = prescan(ing.units, { customSecrets: config.customRules, disabledRules: config.disabledRules });
  // Native Audit-Module (Lieferkette, Container, Code-Regeln, KI, Server-Konfiguration)
  const mods = runStaticModules(ing.units, onProgress);
  for (const t of targets) if (t.type === 'path') for (const id of mods.ran) scannersRun.push({ target: t.value, source: id });
  const moduleNotes = [...mods.errors];
  let throttled = false;
  // Paket-Inventar (SBOM) fuer die globale Suche nach betroffenen Versionen
  const sbom = pre.deps.map((d) => ({ ecosystem: d.ecosystem, name: d.name, version: d.version }));

  // CVE-Abgleich der erkannten Abhaengigkeiten (OSV.dev), optional.
  let cveFindings = [];
  let cveNotes = [];
  const aborted = () => !!(config.signal && config.signal.aborted);
  if (config.cveLookup !== false && pre.deps.length && !aborted()) {
    try {
      const cve = await lookupCves(pre.deps, onProgress, config.signal);
      cveFindings = cve.findings;
      cveNotes = cve.notes;
      if (completed(cve.notes)) for (const t of targets) if (t.type === 'path') scannersRun.push({ target: t.value, source: 'osv' });
    } catch (e) {
      cveNotes = ['CVE-Abgleich fehlgeschlagen: ' + e.message];
    }
  }
  // Zerstoerungsfreie Server-Checks fuer Web-Ziele (TLS, Header, Cookies, CORS, offene Pfade).
  let webFindings = [];
  let webNotes = [];
  const webTargets = targets.filter((t) => t.type === 'url' || t.type === 'endpoint');
  for (const t of webTargets) {
    if (aborted()) break;
    // Scope: nur bestaetigte bzw. freigegebene Ziele (die App setzt `authorized` erst nach Pruefung).
    const authorized = !!t.authorized;
    try {
      const w = await scanWeb(t.value, authorized, onProgress, config.signal);
      webFindings.push(...w.findings);
      webNotes.push(...w.notes);
      if (authorized && completed(w.notes)) scannersRun.push({ target: t.value, source: 'webscan' });
    } catch (e) {
      if (e.throttled) throttled = true;
      webNotes.push(e.throttled ? e.message : `Server-Pruefung ${t.value} fehlgeschlagen: ${e.message}`);
    }
    // Weitere Web-Module; tiefe Pruefung nur fuer verifizierte oder interne Ziele.
    if (authorized && !throttled && !aborted()) {
      const deep = !!t.verified || isInternalHost(hostOf(t));
      const wm = await runWebModules(t.value, { deep, rps: config.maxRequestsPerSecond || 4, signal: config.signal, onProgress });
      webFindings.push(...wm.findings); webNotes.push(...wm.notes);
      if (wm.throttled) throttled = true;
      else for (const id of wm.ran) scannersRun.push({ target: t.value, source: id });
      // Browser-Laufzeitpruefung (nur in der App verfuegbar, nur verifiziert/intern)
      if (deep && t.type === 'url' && typeof config.domAudit === 'function' && !throttled && !aborted()) {
        try {
          const d = await config.domAudit(t.value, { signal: config.signal, onProgress });
          webFindings.push(...d.findings); webNotes.push(...d.notes);
          if (d.ok) scannersRun.push({ target: t.value, source: 'headless-dom-audit' });
        } catch (e) { webNotes.push('Browser-Prüfung: ' + e.message); }
      }
      // API-Rechtematrix (BOLA/IDOR) fuer konfigurierte Endpunkte dieses Hosts
      if (deep && typeof config.apiMatrix === 'function' && !aborted()) {
        try {
          const a = await config.apiMatrix(t.value, { signal: config.signal, onProgress });
          webFindings.push(...a.findings); webNotes.push(...a.notes);
          if (a.ran) scannersRun.push({ target: t.value, source: 'api-auth-matrix' });
        } catch (e) { webNotes.push('API-Rechtematrix: ' + e.message); }
      }
    }

    // Aktive Pruefung ueber nmap/nuclei - nur mit Opt-in und bestaetigter Berechtigung.
    if (config.activeScan && authorized && !aborted()) {
      try {
        const nm = await runNmap(t.value, { signal: config.signal, onProgress });
        webFindings.push(...nm.findings); webNotes.push(...nm.notes);
      } catch (e) { webNotes.push(`nmap ${t.value}: ${e.message}`); }
      if (!aborted()) {
        try {
          const nu = await runNuclei(t.value, { signal: config.signal, onProgress });
          webFindings.push(...nu.findings); webNotes.push(...nu.notes);
        } catch (e) { webNotes.push(`nuclei ${t.value}: ${e.message}`); }
      }
    }
  }
  // Container-Images: SBOM + CVE-Abgleich ueber trivy (einziger sinnvolle Check fuer ein Image).
  for (const t of targets.filter((x) => x.type === 'image')) {
    if (aborted()) break;
    try {
      const r = await runTrivyImage(t.value, { signal: config.signal, onProgress });
      webFindings.push(...r.findings); webNotes.push(...r.notes);
      if (completed(r.notes)) scannersRun.push({ target: t.value, source: 'trivy' });
    } catch (e) { webNotes.push(`trivy ${t.value}: ${e.message}`); }
  }
  // Externe statische Scanner fuer Pfad-Ziele (gitleaks/trivy/semgrep) - opt-in + wenn installiert.
  if (config.activeScan) {
    const pathTargets = targets.filter((t) => t.type === 'path');
    for (const t of pathTargets) {
      if (aborted()) break;
      for (const [nm, fn] of [['gitleaks', runGitleaks], ['trufflehog', runTrufflehog], ['trivy', runTrivyFs], ['grype', runGrype], ['semgrep', runSemgrep], ['bandit', runBandit], ['checkov', runCheckov], ['retire', runRetire], ['hadolint', runHadolint], ['osv-scanner', runOsvScanner]]) {
        if (aborted()) break;
        try {
          const r = await fn(t.value, { signal: config.signal, onProgress });
          webFindings.push(...r.findings); webNotes.push(...r.notes);
          if (completed(r.notes)) scannersRun.push({ target: t.value, source: nm === 'retire' ? 'retire' : nm });
        } catch (e) { webNotes.push(`${nm} ${t.value}: ${e.message}`); }
      }
    }
  }
  // Zugangsdaten, die in alten Git-Versionen stehen (nur Ordner, die ein Git-Repository sind)
  const gitFindings = [];
  if (config.gitHistory !== false && !aborted()) {
    const { scanGitHistory } = require('./githistory');
    const currentText = ing.units.map((u) => u.content || '').join('
');
    for (const t of targets.filter((x) => x.type === 'path')) {
      try {
        const g = await scanGitHistory(t.value, { currentText, signal: config.signal, onProgress });
        gitFindings.push(...g.findings); moduleNotes.push(...g.notes);
        if (g.ran) scannersRun.push({ target: t.value, source: 'git-history' });
      } catch (e) { moduleNotes.push('Git-Historie: ' + e.message); }
    }
  }
  const staticFindings = [...pre.findings, ...gitFindings, ...mods.findings, ...cveFindings, ...webFindings, ...(ing.findings || [])];
  const extraMeta = { scannersRun, throttled, sbom, modulesRun: [...new Set(scannersRun.map((s) => s.source))] };

  if (!ing.units.length) {
    const findings = finalize(enrich(dedupeFindings(staticFindings)), targets, config);
    const empty = {
      findings,
      summary: summarize(findings),
      errors: [...(webTargets.length || targets.some((t) => t.type === 'image') ? [] : ['Kein lesbares Pruefmaterial gefunden.']), ...webNotes, ...cveNotes, ...moduleNotes, ...ing.notes],
      meta: { provider: config.provider, model: config.model, at: new Date().toISOString(), units: 0, batches: 0, ...extraMeta },
    };
    return { result: empty, ingest: ing, prescan: pre };
  }

  const result = await analyze({
    units: ing.units,
    facts: pre.facts,
    prescanFindings: staticFindings,
    config,
    onProgress,
  });
  result.findings = finalize(result.findings, targets, config);
  result.summary = summarize(result.findings);
  result.errors = [...result.errors, ...webNotes, ...cveNotes, ...moduleNotes, ...ing.notes];
  Object.assign(result.meta, extraMeta);
  onProgress({ phase: 'done', message: `Fertig: ${result.summary.total} Befund(e).` });
  return { result, ingest: ing, prescan: pre };
}

// Kosten-/Token-/Zeit-Vorschau vor dem Start: liest die Dateien ein (ohne Netz/KI) und rechnet hoch.
// Die Dauer kommt aus timing.js und beruecksichtigt gelernte Werte frueherer Laeufe (config.timingCalib).
async function estimateAudit(targets, config) {
  const { estimateRun } = require('./analyze');
  const timing = require('./timing');
  const ing = await ingestTargets(targets.filter((t) => t.type === 'path'), () => {});
  const pre = prescan(ing.units, { customSecrets: config.customRules, disabledRules: config.disabledRules });
  const run = estimateRun({ units: ing.units, facts: pre.facts, config });
  const t = timing.estimate({
    targets: targets.map((x) => ({ ...x, internal: (x.type === 'url' || x.type === 'endpoint') && isInternalHost(hostOf(x)) })),
    files: ing.units.length, deps: pre.deps.length, calls: ing.units.length ? run.calls : 0, local: run.local, config,
  }, config.timingCalib || {});
  return { ...run, seconds: t.seconds, timeParts: t.parts, timeMeasured: t.measured, files: ing.units.length, deps: pre.deps.length, truncated: ing.notes.some((n) => /Limit|uebersprungen|Uebersprungen/i.test(n)) };
}

module.exports = { runAudit, estimateAudit, report, fingerprint, atOrAbove, ruleNames, PROVIDERS, callProvider, pingProvider, fetchModels };
