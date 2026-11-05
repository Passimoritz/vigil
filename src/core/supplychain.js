'use strict';

// Zusatzpruefungen fuer Lieferkette und Container, die Netz oder externe Werkzeuge brauchen:
//  - Live-Pruefung gefundener Schluessel (nur mit Einstellung, Standard AUS)
//  - Helm/Kustomize rendern und mit den Kubernetes-Regeln pruefen (wenn installiert)
//  - Pflegezustand und OpenSSF Scorecard der direkten Abhaengigkeiten (deps.dev)
//  - CMS-Kern/Plugins/Themes gegen die NVD (Projekt und freigegebene Webseiten)
// Alles nur lesend und gedrosselt; fehlende Werkzeuge werden still uebersprungen.

const { verifyLiveSecrets } = require('./secretlive');
const { renderAndCheck } = require('./modules/helm');
const { checkPackageHealth } = require('./pkghealth');
const cms = require('./modules/cms');

// webCms: [{ target, items }] aus dem Webseiten-Durchgang (nur freigegebene Ziele)
async function runSupplyExtras({ targets = [], units = [], deps = [], prescanFindings = [], webCms = [], config = {}, onProgress = () => {}, fetchImpl, run }) {
  const findings = [], notes = [], ran = [];
  const paths = targets.filter((t) => t.type === 'path');
  const signal = config.signal;
  const aborted = () => !!(signal && signal.aborted);
  const markRan = (source) => { for (const t of paths) ran.push({ target: t.value, source }); };
  let pf = prescanFindings;

  if (config.secretLiveCheck === true && pf.some((f) => f.category === 'Secrets') && !aborted()) {
    try { const sl = await verifyLiveSecrets(pf, units, { signal, onProgress, fetchImpl }); pf = sl.findings; notes.push(...sl.notes); }
    catch (e) { notes.push('Live-Prüfung: ' + e.message); }
  }
  if (paths.length && config.helmRender !== false && !aborted()) {
    try { const h = await renderAndCheck(units, { signal, onProgress, run }); findings.push(...h.findings); notes.push(...h.notes); h.ran.forEach(markRan); }
    catch (e) { notes.push('Helm/Kustomize: ' + e.message); }
  }
  const online = config.cveLookup !== false;
  if (online && config.packageHealth !== false && deps.length && !aborted()) {
    try { const p = await checkPackageHealth(deps, { signal, onProgress, fetchImpl }); findings.push(...p.findings); notes.push(...p.notes); if (p.ran) markRan('package-health'); }
    catch (e) { notes.push('Paket-Zustand: ' + e.message); }
  }
  const inv = cms.cmsInventory(units);
  if (online && inv.length && !aborted()) {
    onProgress({ phase: 'cve', message: `CMS-Abgleich: ${inv.length} Komponente(n) gegen die NVD …` });
    const r = await cms.lookupCmsVulns(inv, { signal, fetchImpl, apiKey: config.nvdApiKey });
    findings.push(...r.findings); notes.push(...r.notes);
    if (r.ran) markRan('cms-nvd');
  }
  for (const w of webCms) {
    const items = w.items || [];
    findings.push(...cms.webVersionFindings(items, w.target));
    const needLookup = items.some((x) => x.version && !x.weak && cms.cpeFor(x));
    let complete = !needLookup;
    if (online && needLookup && !aborted()) {
      const r = await cms.lookupCmsVulns(items.map((x) => ({ ...x, location: w.target })), { signal, fetchImpl, apiKey: config.nvdApiKey, max: 2 });
      findings.push(...r.findings); notes.push(...r.notes);
      complete = r.ran;
    }
    // Nur nach vollstaendigem Abgleich duerfen fehlende Befunde als behoben gelten
    if (complete) ran.push({ target: w.target, source: 'cms-web' });
  }
  return { prescanFindings: pf, findings, notes, ran };
}

module.exports = { runSupplyExtras };
