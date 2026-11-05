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
function finalize(findings, targets, config, units = []) {
  const exposed = targets.some((t) => (t.type === 'url' || t.type === 'endpoint') && !isInternalHost(hostOf(t)));
  let list = applyIntel(findings, config.intel);
  list = list.map((f) => ({ ...f, contextualRiskScore: f.contextualRiskScore ?? contextualRisk(f, { internetExposed: exposed || f.source === 'webscan' }) }));
  // Verwundbare Pakete: wird das Paket bzw. die betroffene Funktion ueberhaupt benutzt?
  list = require('./reach').applyReachability(list, units);
  list = [...list, ...correlate(list)];
  return sortFindings(require('./taxonomy').applyTaxonomy(list.map(enrichRemedy)));
}

// Hat ein Tool-Lauf wirklich stattgefunden? (Nur dann duerfen fehlende Befunde als behoben gelten.)
const DID_NOT_RUN = /nicht ausgefuehrt|nicht installiert|abgebrochen|nicht lesbar|unerwartet|nicht erreichbar|uebersprungen|fehlgeschlagen|konnte nicht/i;
const completed = (notes) => !(notes || []).some((n) => DID_NOT_RUN.test(n));

// Ein Absatz in Alltagssprache ueber den ganzen Lauf (KI, falls sie lief, sonst Regeln)
async function runSummaryOf(result, config) {
  const { summarizeRun, ruleSummary } = require('./aifix');
  if (config.signal && config.signal.aborted) return { text: ruleSummary(result, config), source: 'rules' };
  try { const s = await summarizeRun(result, config); return { text: s.text, source: s.source, ...(s.model ? { model: s.model } : {}), ...(s.cost ? { usd: s.cost.usd || 0 } : {}) }; }
  catch { return { text: ruleSummary(result, config), source: 'rules' }; }
}

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
  // In Programmen/JARs eingebaute Bibliotheken (z. B. log4j in einer WAR) zaehlen wie Abhaengigkeiten
  for (const d of ing.bundledDeps || []) if (!pre.deps.some((x) => x.ecosystem === d.ecosystem && x.name === d.name && x.version === d.version)) pre.deps.push(d);
  // Paket-Inventar (SBOM) fuer die globale Suche nach betroffenen Versionen
  const sbom = pre.deps.map((d) => ({ ecosystem: d.ecosystem, name: d.name, version: d.version }));

  // CVE-Abgleich der erkannten Abhaengigkeiten (OSV.dev), optional.
  let cveFindings = [];
  let cveNotes = [];
  const aborted = () => !!(config.signal && config.signal.aborted);
  // Pause-Haltepunkt (Orchestrator): wartet hier, solange der Lauf pausiert ist
  const checkpoint = async () => { if (typeof config.checkpoint === 'function') await config.checkpoint(); };
  await checkpoint();
  if (config.cveLookup !== false && pre.deps.length && !aborted()) {
    try {
      const cve = await lookupCves(pre.deps, onProgress, config.signal, { offline: config.osvOffline });
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
  const webCms = []; // CMS-Hinweise freigegebener Webseiten (Abgleich spaeter in supplychain.js)
  const webWatch = {}; // Skripte/Formularziele je Webseite fuer den Vergleich beim naechsten Lauf
  const webTargets = targets.filter((t) => t.type === 'url' || t.type === 'endpoint');
  for (const t of webTargets) {
    await checkpoint();
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
      // Unterseiten, Formulare, Schwachstellen-Proben und Login (Proben/Login nur verifiziert/intern)
      let dw = null, observed = null;
      if (!throttled && !aborted() && t.type === 'url' && config.webCrawl !== false) {
        const { runDeepWeb } = require('./modules/webdeep');
        const login = deep && typeof config.webLogin === 'function' ? config.webLogin(t.value) : null;
        dw = await runDeepWeb(t.value, { deep, login, rps: config.maxRequestsPerSecond || 4, signal: config.signal, onProgress });
        webFindings.push(...dw.findings); webNotes.push(...dw.notes);
        // Eingebundene Skripte gegen die taeglich aktualisierte retire.js-Datenbank
        if (config.feeds && config.feeds.retire.length && dw.scripts && dw.scripts.length) webFindings.push(...require('./feedscan').scanScriptUris(dw.scripts, config.feeds.retire, t.value));
        if (dw.throttled) throttled = true;
        else for (const id of dw.ran) scannersRun.push({ target: t.value, source: id });
        if (!dw.throttled && (dw.ran || []).includes('web-crawl')) webCms.push({ target: t.value, items: dw.cmsHints || [] });
      }
      // Browser-Laufzeitpruefung (nur in der App verfuegbar, nur verifiziert/intern)
      if (deep && t.type === 'url' && typeof config.domAudit === 'function' && !throttled && !aborted()) {
        try {
          const d = await config.domAudit(t.value, { signal: config.signal, onProgress });
          webFindings.push(...d.findings); webNotes.push(...d.notes);
          if (d.ok) scannersRun.push({ target: t.value, source: 'headless-dom-audit' });
          if (d.ok && d.observed) observed = d.observed;
        } catch (e) { webNotes.push('Browser-Prüfung: ' + e.message); }
      }
      // Zusatzpruefungen: security.txt, SEO, Impressum, Header-Note, TLS/DNS/Mail im Detail, Subdomains,
      // Shodan InternetDB, Tippfehler-Domains, JS-Bundles, SRI/CSP-Vorschlag, Datenschutz, Barrierefreiheit,
      // Ladezeit, defekte Links, API-Endpunkte (nur verifiziert) und Aenderungen seit dem letzten Lauf
      if (t.type === 'url' && config.webSuite !== false && !throttled && !aborted()) {
        try {
          const { runWebSuite } = require('./modules/websuite');
          const s = await runWebSuite(t.value, { deep, pages: (dw && dw.pages) || [], scripts: (dw && dw.scripts) || [], observed, allowlist: config.allowlist || [], previous: config.webWatch ? config.webWatch[t.value] : null, feeds: config.feeds, openApi: typeof config.openApiFor === 'function' ? config.openApiFor(t.value) : null, rps: config.maxRequestsPerSecond || 4, signal: config.signal, onProgress });
          webFindings.push(...s.findings); webNotes.push(...s.notes);
          if (s.throttled) throttled = true;
          else for (const id of s.ran) scannersRun.push({ target: t.value, source: id });
          if (s.watch) webWatch[t.value] = s.watch;
        } catch (e) { webNotes.push('Web-Zusatzprüfungen: ' + e.message); }
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
    // Schichten-Analyse: geloeschte, aber noch enthaltene Dateien mit Zugangsdaten (docker save)
    if (config.layerAnalysis !== false && !aborted()) {
      try {
        const l = await require('./layers').analyzeImageLayers(t.value, { signal: config.signal, onProgress });
        webFindings.push(...l.findings); webNotes.push(...l.notes);
        if (l.ran) scannersRun.push({ target: t.value, source: 'image-layers' });
      } catch (e) { webNotes.push(`Schichten-Analyse ${t.value}: ${e.message}`); }
    }
  }
  // System-Pruefungen: dieser PC, Docker, Cloud-Konten – nur lesend
  for (const t of targets.filter((x) => x.type === 'system')) {
    if (aborted()) break;
    try {
      const r = await require('./hostaudit').auditSystem(t.value, { signal: config.signal, onProgress, settings: config.systemSettings || {} });
      webFindings.push(...r.findings); webNotes.push(...r.notes);
      if (r.ok) scannersRun.push({ target: t.value, source: `system-${t.value}` });
    } catch (e) { webNotes.push(`System-Prüfung ${t.value}: ${e.message}`); }
  }
  // Externe statische Scanner fuer Pfad-Ziele (gitleaks/trivy/semgrep) - opt-in + wenn installiert.
  if (config.activeScan) {
    const pathTargets = targets.filter((t) => t.type === 'path');
    for (const t of pathTargets) {
      if (aborted()) break;
      for (const [nm, fn] of [['gitleaks', runGitleaks], ['trufflehog', runTrufflehog], ['trivy', runTrivyFs], ['grype', runGrype], ['semgrep', runSemgrep], ['bandit', runBandit], ['checkov', runCheckov], ['retire', runRetire], ['hadolint', runHadolint], ['osv-scanner', runOsvScanner]]) {
        if (aborted()) break;
        try {
          const r = await fn(t.value, { signal: config.signal, onProgress, rulesFile: nm === 'semgrep' && config.feeds ? config.feeds.semgrepFile : undefined });
          webFindings.push(...r.findings); webNotes.push(...r.notes);
          if (completed(r.notes)) scannersRun.push({ target: t.value, source: nm === 'retire' ? 'retire' : nm });
        } catch (e) { webNotes.push(`${nm} ${t.value}: ${e.message}`); }
      }
    }
  }
  // Tagesaktuelle Feeds: Zugangsdaten-Formate (gitleaks) und verwundbare JS-Bibliotheken (retire.js)
  if (config.feeds && ing.units.length) {
    const fs2 = require('./feedscan');
    const f1 = fs2.scanSecretsWithFeed(ing.units, config.feeds.secretRules);
    const f2 = fs2.scanJsLibs(ing.units, config.feeds.retire);
    webFindings.push(...f1, ...f2);
    if (config.feeds.secretRules.length) for (const t of targets.filter((x) => x.type === 'path')) scannersRun.push({ target: t.value, source: 'gitleaks-feed' });
    if (config.feeds.retire.length) for (const t of targets.filter((x) => x.type === 'path')) scannersRun.push({ target: t.value, source: 'retire-feed' });
  }
  // Phishing-Listen: Links aus Dokumenten/Mails und die eigenen (freigegebenen) Domains
  if (config.feeds && config.feeds.phish && config.feeds.phish.size) {
    const lc = require('./linkcheck');
    if (ing.links && ing.links.length) webFindings.push(...lc.checkLinks(ing.links, config.feeds.phish));
    const own = webTargets.filter((t) => t.authorized).map((t) => hostOf(t)).filter(Boolean);
    if (own.length) webFindings.push(...lc.checkOwnDomains(own, config.feeds.phish, config.feeds.phishLists));
  }
  // Optionale YARA-Regeln (nur wenn yara installiert ist und Regeln vorliegen)
  if (config.yara && !aborted()) {
    const { runYara } = require('./yara');
    for (const t of targets.filter((x) => x.type === 'path')) {
      try {
        const y = await runYara(t.value, { rulesDir: config.yara.rulesDir, feedFile: config.feeds && config.feeds.yaraFile, signal: config.signal, onProgress });
        webFindings.push(...y.findings); moduleNotes.push(...y.notes);
        if (y.ran) scannersRun.push({ target: t.value, source: 'yara' });
      } catch (e) { moduleNotes.push('YARA: ' + e.message); }
    }
  }
  // Schadsoftware: Defender (ohne Loeschen), Signaturen, Abgleich bekannter Schadprogramme
  if (config.malwareScan !== false && !aborted()) {
    const { scanMalware } = require('./malware');
    for (const t of targets.filter((x) => x.type === 'path')) {
      try {
        const m = await scanMalware(t.value, { signal: config.signal, onProgress, malwareBazaarKey: config.malwareBazaarKey });
        webFindings.push(...m.findings); moduleNotes.push(...m.notes);
        for (const src of m.ran) scannersRun.push({ target: t.value, source: src });
      } catch (e) { moduleNotes.push('Schadsoftware-Prüfung: ' + e.message); }
    }
  }
  // Zugangsdaten, die in alten Git-Versionen stehen (nur Ordner, die ein Git-Repository sind)
  const gitFindings = [];
  if (config.gitHistory !== false && !aborted()) {
    const { scanGitHistory } = require('./githistory');
    const currentText = ing.units.map((u) => u.content || '').join('\n');
    for (const t of targets.filter((x) => x.type === 'path')) {
      try {
        const g = await scanGitHistory(t.value, { currentText, signal: config.signal, onProgress });
        gitFindings.push(...g.findings); moduleNotes.push(...g.notes);
        if (g.ran) scannersRun.push({ target: t.value, source: 'git-history' });
      } catch (e) { moduleNotes.push('Git-Historie: ' + e.message); }
    }
  }
  // Lieferkette & Container: Live-Pruefung von Schluesseln (opt-in), Helm/Kustomize, deps.dev, CMS/NVD
  if (!aborted()) {
    try {
      const sx = await require('./supplychain').runSupplyExtras({ targets, units: ing.units, deps: pre.deps, prescanFindings: pre.findings, webCms, config, onProgress });
      pre.findings = sx.prescanFindings; webFindings.push(...sx.findings); moduleNotes.push(...sx.notes); scannersRun.push(...sx.ran);
    } catch (e) { moduleNotes.push('Lieferkette: ' + e.message); }
  }
  const staticFindings = [...pre.findings, ...gitFindings, ...mods.findings, ...cveFindings, ...webFindings, ...(ing.findings || [])];
  const extraMeta = { scannersRun, throttled, sbom, modulesRun: [...new Set(scannersRun.map((s) => s.source))], ...(Object.keys(webWatch).length ? { webWatch } : {}) };

  if (!ing.units.length) {
    const findings = finalize(enrich(dedupeFindings(staticFindings)), targets, config);
    const empty = {
      findings,
      summary: summarize(findings),
      errors: [...(webTargets.length || targets.some((t) => t.type === 'image' || t.type === 'system') ? [] : ['Kein lesbares Pruefmaterial gefunden.']), ...webNotes, ...cveNotes, ...moduleNotes, ...ing.notes],
      meta: { provider: config.provider, model: config.model, at: new Date().toISOString(), units: 0, batches: 0, ...extraMeta },
    };
    empty.meta.runSummary = await runSummaryOf(empty, config);
    return { result: empty, ingest: ing, prescan: pre };
  }

  await checkpoint();
  const result = await analyze({
    units: ing.units,
    facts: pre.facts,
    prescanFindings: staticFindings,
    config,
    onProgress,
  });
  result.findings = finalize(result.findings, targets, config, ing.units);
  result.summary = summarize(result.findings);
  result.errors = [...result.errors, ...webNotes, ...cveNotes, ...moduleNotes, ...ing.notes];
  Object.assign(result.meta, extraMeta);
  result.meta.runSummary = await runSummaryOf(result, config);
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
