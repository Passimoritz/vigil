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

// Hat ein Tool-Lauf wirklich stattgefunden? (Nur dann duerfen fehlende Befunde als behoben gelten.)
const DID_NOT_RUN = /nicht ausgefuehrt|nicht installiert|abgebrochen|nicht lesbar|unerwartet|nicht erreichbar|uebersprungen|fehlgeschlagen|konnte nicht/i;
const completed = (notes) => !(notes || []).some((n) => DID_NOT_RUN.test(n));

// targets: [{type:'path'|'url'|'endpoint'|'image', value, authorized?}]
// config:  { provider, model, apiKey, baseUrl, temperature, maxTokens }
async function runAudit(targets, config, onProgress = () => {}) {
  onProgress({ phase: 'ingest', message: 'Sammle Pruefmaterial …' });
  const ing = await ingestTargets(targets, onProgress);
  const scannersRun = []; // [{ target, source }] – vollstaendig gelaufene Pruefungen je Ziel
  for (const t of targets) if (t.type === 'path' && !ing.notes.some((n) => n.includes(t.value) && /nicht gefunden|Fehler/.test(n))) scannersRun.push({ target: t.value, source: 'prescan' });

  onProgress({ phase: 'prescan', message: 'Statische Vorpruefung (Secrets, Deps, Muster) …' });
  const pre = prescan(ing.units, { customSecrets: config.customRules, disabledRules: config.disabledRules });

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
    } catch (e) { webNotes.push(`Server-Pruefung ${t.value} fehlgeschlagen: ${e.message}`); }

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
  const staticFindings = [...pre.findings, ...cveFindings, ...webFindings, ...(ing.findings || [])];

  if (!ing.units.length) {
    const findings = sortFindings(enrich(dedupeFindings(staticFindings)));
    const empty = {
      findings,
      summary: summarize(findings),
      errors: [...(webTargets.length || targets.some((t) => t.type === 'image') ? [] : ['Kein lesbares Pruefmaterial gefunden.']), ...webNotes, ...cveNotes, ...ing.notes],
      meta: { provider: config.provider, model: config.model, at: new Date().toISOString(), units: 0, batches: 0, scannersRun },
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
  result.errors = [...result.errors, ...webNotes, ...cveNotes, ...ing.notes];
  result.meta.scannersRun = scannersRun;
  onProgress({ phase: 'done', message: `Fertig: ${result.summary.total} Befund(e).` });
  return { result, ingest: ing, prescan: pre };
}

module.exports = { runAudit, report, fingerprint, atOrAbove, ruleNames, PROVIDERS, callProvider, pingProvider, fetchModels };
