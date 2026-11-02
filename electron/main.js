'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// .env aus dem Projektordner laden (Schluessel-Fallback).
try { require('dotenv').config({ path: path.join(__dirname, '..', '.env') }); } catch { /* optional */ }

const { runAudit, estimateAudit, report, ruleNames, PROVIDERS, pingProvider, fetchModels } = require('../src/core');
const { enforceScope, normalizeAllowlist } = require('../src/core/scope');
const { check, ScanRequestSchema, StatusUpdateSchema } = require('../src/core/validation');
const { createOrchestrator } = require('./orchestrator');
const { createApi } = require('./api');
const { safeStorage } = require('electron');
const { domAudit } = require('./domaudit');
const { loadIntel, syncIntel, needsSync } = require('../src/core/intel');
const { isAllowedLink } = require('../src/core/remedies');
const { runApiMatrix } = require('../src/core/modules/apimatrix');
const { verifyOwnership, hostOf: scopeHost } = require('../src/core/scope');

// --- Threat-Intel (CISA KEV + EPSS), taeglich im Hintergrund aktualisiert ---
// Version ohne Installation: Die portable EXE (bzw. eine Datei "portable" neben Vigil.exe)
// speichert alle Daten im Ordner "VigilData" daneben statt im Benutzerprofil.
const PORTABLE_DIR = process.env.PORTABLE_EXECUTABLE_DIR || (fs.existsSync(path.join(path.dirname(process.execPath), 'portable')) ? path.dirname(process.execPath) : '');
// Tests laufen mit eigenem, leerem Datenordner
if (process.env.VIGIL_E2E_DATA) { fs.mkdirSync(process.env.VIGIL_E2E_DATA, { recursive: true }); app.setPath('userData', process.env.VIGIL_E2E_DATA); }
else if (PORTABLE_DIR) { try { const d = path.join(PORTABLE_DIR, 'VigilData'); fs.mkdirSync(d, { recursive: true }); app.setPath('userData', d); } catch { /* dann Standardort */ } }

// Absturzberichte nur lokal: Minidumps (crashReporter ohne Upload) plus eine lesbare
// JSON-Datei je Fehler im Ordner "crash-reports". Es wird nichts uebertragen.
const CRASH_DIR = () => path.join(app.getPath('userData'), 'crash-reports');
try { require('electron').crashReporter.start({ uploadToServer: false, compress: true }); } catch { /* egal */ }
function writeCrash(kind, detail) {
  try {
    fs.mkdirSync(CRASH_DIR(), { recursive: true });
    const at = new Date().toISOString();
    const home = require('os').homedir();
    // Benutzername aus Pfaden entfernen – der Bericht soll weitergegeben werden koennen
    const clean = (s) => String(s || '').split(home).join('~');
    const rep = { at, kind, version: app.getVersion(), electron: process.versions.electron, os: `${process.platform} ${require('os').release()}`, message: clean(detail && detail.message || detail), stack: clean(detail && detail.stack || '') };
    fs.writeFileSync(path.join(CRASH_DIR(), `vigil-${kind}-${at.replace(/[:.]/g, '-')}.json`), JSON.stringify(rep, null, 2));
  } catch { /* nichts mehr zu retten */ }
}
process.on('uncaughtException', (e) => { writeCrash('main', e); console.error(e); });
process.on('unhandledRejection', (e) => { writeCrash('promise', e instanceof Error ? e : new Error(String(e))); });
app.on('render-process-gone', (_e, _wc, d) => writeCrash('renderer', new Error(`Fenster beendet: ${d.reason} (Code ${d.exitCode})`)));
app.on('child-process-gone', (_e, d) => { if (d.reason !== 'clean-exit') writeCrash('child', new Error(`${d.type}: ${d.reason} (Code ${d.exitCode})`)); });

const INTEL_PATH = () => path.join(app.getPath('userData'), 'threat-intel.json');
let intel = null;
let intelSyncing = null;
// Tagesaktuelle Erkennungsdaten (gitleaks-Regeln, retire.js) – geladen beim Start, alle 6 Std. geprueft
const feeds = require('../src/core/feeds');
const FEEDS_DIR = () => path.join(app.getPath('userData'), 'feeds');
let feedsCompiled = null;
let feedsSyncing = null;
const currentFeeds = () => (feedsCompiled = feedsCompiled || feeds.loadCompiled(FEEDS_DIR()));
function syncFeedsInBackground(force = false) {
  if (feedsSyncing) return feedsSyncing;
  if (!force && !feeds.needsFeedSync(FEEDS_DIR())) return Promise.resolve({ ok: true, skipped: true });
  feedsSyncing = feeds.syncFeeds(FEEDS_DIR(), { force }).then((r) => { feedsCompiled = feeds.loadCompiled(FEEDS_DIR()); return { ok: r.every((x) => x.ok || x.skipped), results: r }; })
    .catch((e) => ({ ok: false, error: e.message })).finally(() => { feedsSyncing = null; });
  return feedsSyncing;
}

function syncIntelInBackground(force = false) {
  if (intelSyncing) return intelSyncing;
  if (!force && intel && !needsSync(intel)) return Promise.resolve({ ok: true, skipped: true });
  intelSyncing = syncIntel(INTEL_PATH()).then((r) => { intel = loadIntel(INTEL_PATH()); return r; })
    .catch((e) => ({ ok: false, error: e.message })).finally(() => { intelSyncing = null; });
  return intelSyncing;
}

// --- API-Rechtematrix: Tokens nur verschluesselt (Windows DPAPI / Keychain) speichern ---
const enc = (s) => (s && safeStorage.isEncryptionAvailable() ? safeStorage.encryptString(s).toString('base64') : '');
const dec = (b) => { try { return b ? safeStorage.decryptString(Buffer.from(b, 'base64')) : ''; } catch { return ''; } };
function apiMatrixFor(cfg) {
  return async (targetUrl, opts) => {
    const host = (scopeHost({ type: 'url', value: targetUrl }) || '').replace(/^www\./, '');
    const entry = (cfg.apiMatrix || []).find((m) => String(m.host || '').toLowerCase().replace(/^www\./, '') === host);
    if (!entry) return { ran: false, findings: [], notes: [] };
    return runApiMatrix(targetUrl, { endpoints: entry.endpoints, resourceIdA: entry.resourceIdA, tokenA: dec(entry.tokenAEnc), tokenB: dec(entry.tokenBEnc) }, { ...opts, rps: cfg.maxRequestsPerSecond || 3 });
  };
}
// Login-Pruefung: Testkonto je Host (Passwort verschluesselt), nur fuer nachgewiesene Domains genutzt
function webLoginFor(cfg) {
  return (targetUrl) => {
    const host = (scopeHost({ type: 'url', value: targetUrl }) || '').replace(/^www\./, '');
    const e = (cfg.webLogins || []).find((m) => String(m.host || '').toLowerCase().replace(/^www\./, '') === host);
    if (!e || !e.loginUrl || !e.username || !e.passwordEnc) return null;
    return { loginUrl: e.loginUrl, username: e.username, password: dec(e.passwordEnc), userField: e.userField || '', passField: e.passField || '' };
  };
}
const { applyProxy, testProxy } = require('./proxy');
const ollama = require('./ollama');

let win;
let lastResult = null;
let lastTargets = [];
// Angaben fuer den Berichtskopf: gepruefte Ziele, Firma und Logo aus den Einstellungen
// Englische Berichte: Befundtexte und Vorlage nachtraeglich uebersetzen (Standard; Deutsch nur bei lang 'de')
const findingsI18n = require('../src/core/findings-i18n');
const reportEn = require('../src/core/report-en');
const reportEnglish = () => loadConfig().lang !== 'de';
const reportResult = () => (lastResult && reportEnglish() ? findingsI18n.localizeResult(lastResult) : lastResult);
const htmlReport = () => { const h = report.toHtml(reportResult(), reportOpts()); return reportEnglish() ? reportEn.localizeReportHtml(h) : h; };
const mdReport = () => { const m = report.toMarkdown(reportResult(), reportOpts()); return reportEnglish() ? reportEn.localizeReportMd(m) : m; };
const reportOpts = () => { const c = loadConfig(); return { targets: lastTargets, company: c.reportCompany || '', logoDataUrl: c.reportLogo || '' }; };
let orchestrator = null;
let api = null;

const CONFIG_PATH = () => path.join(app.getPath('userData'), 'config.json');
const STORE_PATH = () => path.join(app.getPath('userData'), 'findings-store.json');

// --- Scan-Verlauf (History) ---------------------------------------------
const HISTORY_PATH = () => path.join(app.getPath('userData'), 'history.json');
const HISTORY_DIR = () => path.join(app.getPath('userData'), 'history');
function loadHistory() {
  try { const j = JSON.parse(fs.readFileSync(HISTORY_PATH(), 'utf8')); return Array.isArray(j.runs) ? j.runs : []; }
  catch { return []; }
}
function recordHistory(result, targets) {
  try {
    fs.mkdirSync(HISTORY_DIR(), { recursive: true });
    const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const entry = {
      id, at: new Date().toISOString(),
      provider: (result.meta && result.meta.provider) || '', model: (result.meta && result.meta.model) || '',
      targets: (targets || []).map((t) => t.value).slice(0, 5),
      total: (result.summary && result.summary.total) || 0,
      counts: (result.summary && result.summary.counts) || {},
    };
    fs.writeFileSync(path.join(HISTORY_DIR(), id + '.json'), JSON.stringify(result), 'utf8');
    const runs = [entry, ...loadHistory()];
    const keep = runs.slice(0, 50);
    for (const old of runs.slice(50)) { try { fs.unlinkSync(path.join(HISTORY_DIR(), old.id + '.json')); } catch { /* egal */ } }
    fs.writeFileSync(HISTORY_PATH(), JSON.stringify({ runs: keep }, null, 2), 'utf8');
  } catch (e) { console.warn('History nicht gespeichert:', e.message); }
}

// Report als PDF schreiben: HTML-Report in einem unsichtbaren Fenster drucken.
// Kurzbericht fuer die Geschaeftsfuehrung: Logo/Firma aus den Einstellungen, Verlauf aus den Laeufen
function executiveHtml() {
  const c = loadConfig();
  const st = orchestrator.stats();
  const trend = st.trend || [];
  const h = report.toExecutive(reportResult(), { logoDataUrl: c.reportLogo || '', company: c.reportCompany || '', posture: st.posture, trend });
  return reportEnglish() ? reportEn.localizeReportHtml(h) : h;
}

async function saveReportPdf(outPath, kind) {
  const html = kind === 'exec' ? executiveHtml() : htmlReport();
  const en = reportEnglish();
  const tmp = path.join(app.getPath('temp'), `vigil-report-${Date.now()}.html`);
  fs.writeFileSync(tmp, html, 'utf8');
  const w = new BrowserWindow({ show: false, webPreferences: { sandbox: true, javascript: false } });
  try {
    await w.loadFile(tmp);
    // Fusszeile mit Seitenzahl
    const data = await w.webContents.printToPDF({
      printBackground: true, pageSize: 'A4', preferCSSPageSize: true, displayHeaderFooter: kind !== 'exec',
      headerTemplate: '<div></div>',
      footerTemplate: '<div style="width:100%;font:8.5px Segoe UI,sans-serif;color:#94a3b8;padding:0 14mm;display:flex;justify-content:space-between"><span>Vigil · ' + (en ? 'Security report' : 'Sicherheitsbericht') + '</span><span>' + (en ? 'Page' : 'Seite') + ' <span class="pageNumber"></span> ' + (en ? 'of' : 'von') + ' <span class="totalPages"></span></span></div>',
    });
    fs.writeFileSync(outPath, data);
  } finally { try { w.destroy(); } catch { /* egal */ } try { fs.unlinkSync(tmp); } catch { /* egal */ } }
}

// Gespeichertes Ergebnis (Verlauf) mit dem aktuellen Status aus dem Befund-Speicher abgleichen.
function refreshStatuses(result) {
  if (!result || !Array.isArray(result.findings) || !orchestrator) return result;
  const current = new Map(orchestrator.listFindings({ limit: 5000 }).map((f) => [f.id, f.status]));
  for (const f of result.findings) {
    if (!f.id || !current.has(f.id)) continue;
    f.status = current.get(f.id);
    f.suppressed = f.status === 'FALSE_POSITIVE' || f.status === 'ACCEPTED_RISK';
  }
  return result;
}

const ENV_KEY = {
  anthropic: 'ANTHROPIC_API_KEY',
  openai: 'OPENAI_API_KEY',
  gemini: 'GEMINI_API_KEY',
  compat: 'OPENAI_COMPAT_API_KEY',
};

function defaultConfig() {
  const providers = {};
  for (const [id, p] of Object.entries(PROVIDERS)) {
    providers[id] = { model: p.defaultModel, apiKey: '', baseUrl: p.defaultBaseUrl };
  }
  return { selected: 'ollama', lang: 'en', temperature: 0.1, maxTokens: 8192, cveLookup: true, analysisDepth: 'thorough', aiValidation: true, redactSecrets: true, activeScan: false, proxyUrl: '', customRules: [], disabledRules: [], allowlist: [], apiEnabled: false, apiPort: 7811, apiToken: '', providers };
}

function loadConfig() {
  let cfg;
  try {
    const saved = JSON.parse(fs.readFileSync(CONFIG_PATH(), 'utf8'));
    const def = defaultConfig();
    cfg = { ...def, ...saved, providers: { ...def.providers, ...(saved.providers || {}) } };
  } catch { cfg = defaultConfig(); }
  cfg.allowlist = normalizeAllowlist(cfg.allowlist);
  // Zufaelliges API-Token beim ersten Start erzeugen.
  if (!cfg.apiToken) { cfg.apiToken = crypto.randomBytes(24).toString('base64url'); saveConfig(cfg); }
  return cfg;
}

function saveConfig(cfg) {
  try { fs.writeFileSync(CONFIG_PATH(), JSON.stringify(cfg, null, 2), 'utf8'); return true; }
  catch (e) { return false; }
}

// Baut die effektive Anbieter-Config fuer einen Lauf (mit Env-Fallback fuer Keys).
function effectiveConfig(cfg, providerId) {
  const p = cfg.providers[providerId] || {};
  const envKey = ENV_KEY[providerId] ? process.env[ENV_KEY[providerId]] : '';
  return {
    provider: providerId,
    model: p.model || PROVIDERS[providerId]?.defaultModel || '',
    apiKey: p.apiKey || envKey || '',
    baseUrl: p.baseUrl || PROVIDERS[providerId]?.defaultBaseUrl || (providerId === 'ollama' ? process.env.OLLAMA_BASE_URL : '') || '',
    temperature: cfg.temperature ?? 0.1,
    maxTokens: cfg.maxTokens || 4096,
    cveLookup: cfg.cveLookup !== false,
    analysisDepth: cfg.analysisDepth === 'standard' ? 'standard' : 'thorough',
    activeScan: !!cfg.activeScan,
    aiValidation: cfg.aiValidation !== false,
    redactSecrets: cfg.redactSecrets !== false,
    customRules: Array.isArray(cfg.customRules) ? cfg.customRules : [],
    disabledRules: Array.isArray(cfg.disabledRules) ? cfg.disabledRules : [],
    gitHistory: cfg.gitHistory !== false,
    incremental: cfg.incremental !== false,
    // Kleines Modell zum Vorsortieren bzw. zweites Modell zum Gegenpruefen (je Anbieter, optional)
    triageModel: (p.triageModel || '').trim() || null,
    consensusModel: (p.consensusModel || '').trim() || null,
    // Sprache der KI-Befundtexte (wie die Oberflaeche)
    lang: cfg.lang === 'de' ? 'de' : 'en',
  };
}

// KI-Zwischenspeicher (nur Geaendertes neu pruefen) – eine Instanz je App-Lauf
const { openCache } = require('../src/core/aicache');
let aiCacheInst = null;
const aiCache = () => (aiCacheInst = aiCacheInst || openCache(path.join(app.getPath('userData'), 'ai-cache.json')));

function iconPath() {
  const ico = path.join(__dirname, '..', 'assets', 'icon.ico');
  const png = path.join(__dirname, '..', 'assets', 'icon.png');
  if (fs.existsSync(ico)) return ico;
  if (fs.existsSync(png)) return png;
  return undefined;
}

function createWindow() {
  win = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0a0e15',
    title: 'Vigil',
    icon: iconPath(),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.setMenuBarVisibility(false);
  // Das App-Fenster navigiert nie weg und oeffnet keine Fenster – Links laufen ueber link:open.
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.loadFile(path.join(__dirname, '..', 'src', 'ui', 'index.html'));
  // Automatische Oberflaechen-Tests (test/e2e.js): Skript im Fenster ausfuehren, Ergebnis schreiben, beenden
  if (process.env.VIGIL_E2E_SCRIPT) {
    win.webContents.once('did-finish-load', async () => {
      let out;
      try { out = await win.webContents.executeJavaScript(fs.readFileSync(process.env.VIGIL_E2E_SCRIPT, 'utf8'), true); }
      catch (e) { out = { ok: false, results: [{ name: 'Skript', ok: false, info: e.message }] }; }
      try { fs.writeFileSync(process.env.VIGIL_E2E_OUT, JSON.stringify(out, null, 2)); } catch { /* egal */ }
      app.exit(out && out.ok ? 0 : 1);
    });
  }
}

// Gespeicherten Proxy anwenden, aber nie am Start abstuerzen (ungueltige URL o. Ae.).
function applyProxySafe(cfg) {
  try { applyProxy((cfg || loadConfig()).proxyUrl || ''); }
  catch (e) { console.warn('Proxy konnte nicht gesetzt werden:', e.message); }
}

// REST-API je nach Einstellung starten/stoppen.
async function applyApi(cfg) {
  if (!api) return { ok: false, running: false };
  await api.stop();
  if (!cfg.apiEnabled) return { ok: true, running: false };
  const port = Math.min(65535, Math.max(1024, Number(cfg.apiPort) || 7811));
  const r = await api.start(port);
  return { ...r, running: r.ok };
}

// Nur eine Instanz: ein zweiter Start holt das vorhandene Fenster nach vorn.
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.quit();
app.on('second-instance', () => {
  if (!win || win.isDestroyed()) return;
  if (win.isMinimized()) win.restore();
  win.focus();
});

app.whenReady().then(() => {
  if (!gotLock) return;
  const cfg = loadConfig();
  applyProxySafe(cfg);
  orchestrator = createOrchestrator({
    storeFile: STORE_PATH(),
    runAudit,
    buildConfig: (providerId) => {
      const c = loadConfig(); applyProxySafe(c);
      return { ...effectiveConfig(c, providerId || c.selected), aiCache: aiCache(), intel, domAudit: c.domAudit !== false ? domAudit : null, apiMatrix: apiMatrixFor(c), webLogin: webLoginFor(c), feeds: currentFeeds(), webCrawl: c.webCrawl !== false, malwareScan: c.malwareScan !== false, malwareBazaarKey: dec(c.malwareBazaarKeyEnc || ''), maxRequestsPerSecond: c.maxRequestsPerSecond || 4 };
    },
  });
  api = createApi({ orchestrator, getConfig: loadConfig, enforceScope });
  applyApi(cfg);
  intel = loadIntel(INTEL_PATH());
  setTimeout(() => { syncIntelInBackground(); syncFeedsInBackground(); }, 5000); // nach dem Start, ohne ihn zu bremsen
  setInterval(() => { syncIntelInBackground(); syncFeedsInBackground(); }, 6 * 60 * 60 * 1000);
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('will-quit', () => { ollama.stop(); }); // nur den von Vigil gestarteten Dienst beenden

// --- IPC ----------------------------------------------------------------
ipcMain.handle('meta:providers', () => {
  // Liste fuer die UI (ohne Secrets).
  return Object.entries(PROVIDERS).map(([id, p]) => ({ id, label: p.label, needsKey: p.needsKey, defaultModel: p.defaultModel, defaultBaseUrl: p.defaultBaseUrl, envKeyPresent: ENV_KEY[id] ? !!process.env[ENV_KEY[id]] : false }));
});

ipcMain.handle('config:get', () => loadConfig());
ipcMain.handle('config:save', async (_e, cfg) => {
  const prev = loadConfig();
  // Geheimnisse setzt nur der Main-Prozess ueber eigene Handler (Testkonto, API-Rechtematrix,
  // MalwareBazaar-Schluessel, API-Token). Die Kopie im Fenster kann veraltet sein – immer die
  // gespeicherte Fassung behalten, sonst wuerde "Speichern" frisch eingetragene Zugaenge loeschen.
  cfg.allowlist = normalizeAllowlist(cfg.allowlist);
  for (const k of ['apiToken', 'webLogins', 'apiMatrix', 'malwareBazaarKeyEnc']) { if (prev[k] !== undefined) cfg[k] = prev[k]; else delete cfg[k]; }
  const ok = saveConfig(cfg);
  applyProxySafe(cfg);
  if (prev.apiEnabled !== !!cfg.apiEnabled || prev.apiPort !== cfg.apiPort) await applyApi(loadConfig());
  return { ok };
});

// Proxy testen: wendet die (noch ungespeicherte) Proxy-URL an und meldet die
// nach aussen sichtbare IP; stellt danach den gespeicherten Proxy wieder her.
ipcMain.handle('proxy:test', async (_e, proxyUrl) => {
  const r = await testProxy(proxyUrl);
  applyProxySafe(loadConfig());
  return r;
});

ipcMain.handle('dialog:pickFiles', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'] });
  return r.canceled ? [] : r.filePaths;
});
ipcMain.handle('dialog:pickFolder', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? [] : r.filePaths;
});

ipcMain.handle('provider:ping', async (_e, providerId) => {
  const cfg = loadConfig();
  applyProxySafe(cfg);
  try {
    const res = await pingProvider(effectiveConfig(cfg, providerId));
    return { ok: true, sample: res.sample };
  } catch (e) { return { ok: false, error: e.message }; }
});

// Modelle laden - nutzt ggf. noch ungespeicherte Key/URL-Eingaben aus dem Formular.
ipcMain.handle('provider:models', async (_e, { providerId, apiKey, baseUrl }) => {
  const cfg = loadConfig();
  applyProxySafe(cfg);
  const eff = effectiveConfig(cfg, providerId);
  if (apiKey) eff.apiKey = apiKey;
  if (baseUrl) eff.baseUrl = baseUrl;
  return fetchModels(eff);
});

// Gelernte Laufzeiten (timing.js) – eigene Datei, damit das Speichern der Einstellungen sie nicht ueberschreibt
const timing = require('../src/core/timing');
const TIMING_PATH = () => path.join(app.getPath('userData'), 'timing.json');
const withVerified = (targets) => targets.map((t) => { const rec = orchestrator.getTarget(require('../src/core/store').targetIdOf(t)); return { ...t, verified: !!(rec && rec.ownershipVerified) }; });

ipcMain.handle('audit:run', async (e, payload) => {
  const v = check(ScanRequestSchema, payload);
  if (!v.ok) return { ok: false, error: 'Ungültige Eingabe: ' + v.error };
  const cfg = loadConfig();
  // Scope: Webadressen/Server nur freigegeben oder nach ausdruecklicher Bestaetigung im UI.
  const scope = enforceScope(v.data.targets, cfg.allowlist, { interactive: true });
  if (!scope.ok) return { ok: false, error: scope.errors.join(' ') };
  if (scope.allow.length) { cfg.allowlist = normalizeAllowlist([...cfg.allowlist, ...scope.allow]); saveConfig(cfg); }
  const clock = new timing.PhaseClock();
  const providerId = v.data.providerId || cfg.selected;
  const job = orchestrator.enqueue({
    targets: scope.targets, providerId, origin: 'app',
    onProgress: (p) => { clock.tick(p); try { e.sender.send('audit:progress', p); } catch { /* Fenster weg */ } },
  });
  const out = await job.done;
  if (out.ok) { lastResult = out.result; lastTargets = scope.targets; recordHistory(out.result, scope.targets); }
  // Aus vollstaendigen Laeufen lernen, wie lange welche Phase wirklich dauert
  if (out.ok && !out.canceled) {
    try {
      const m = clock.finish();
      const meta = (out.result && out.result.meta) || {};
      const calib = timing.learn(timing.load(TIMING_PATH()), m, { targets: withVerified(scope.targets), files: meta.units || 0, deps: (meta.sbom || []).length, config: effectiveConfig(cfg, providerId) });
      timing.save(TIMING_PATH(), calib);
      out.timing = { seconds: Math.round(m.total) };
    } catch (err) { console.warn('Laufzeit nicht gelernt:', err.message); }
  }
  return out;
});

// --- Betroffener Code & Rueckfragen -------------------------------------------
// Ort "projekt/src/a.js:42" -> echte Datei. Erlaubt sind nur Dateien INNERHALB bereits
// gepruefter Ordner (Ziele vom Typ "path") – keine beliebigen Pfade aus dem Renderer.
function resolveFindingFile(location) {
  const m = String(location || '').replace(/\\/g, '/').match(/^(.*?):(\d+)(?::\d+)?$/);
  if (!m || /^[a-z]+:\/\//i.test(m[1]) || m[1].includes('!/')) return null;
  const rel = m[1], line = Number(m[2]);
  for (const t of orchestrator.targets().filter((x) => x.type === 'path')) {
    const root = path.resolve(t.identifier);
    let stat; try { stat = fs.statSync(root); } catch { continue; }
    const base = path.basename(root);
    const cands = stat.isFile() ? (rel.split('/').pop() === base ? [root] : [])
      : [path.resolve(root, rel), rel.startsWith(base + '/') ? path.resolve(root, rel.slice(base.length + 1)) : null].filter(Boolean);
    for (const c of cands) {
      const inside = c === root || c.startsWith(root.endsWith(path.sep) ? root : root + path.sep); // auch Laufwerks-Wurzel C:\
      try { if (inside && fs.statSync(c).isFile() && fs.statSync(c).size < 3 * 1024 * 1024) return { file: c, line, rel }; } catch { /* weiter */ }
    }
  }
  return null;
}
function readSnippet(location, around = 6) {
  const r = resolveFindingFile(location);
  if (!r) return null;
  const lines = fs.readFileSync(r.file, 'utf8').split(/\r?\n/);
  const from = Math.max(1, r.line - around), to = Math.min(lines.length, r.line + around);
  return { file: r.rel, line: r.line, from, lines: lines.slice(from - 1, to) };
}
ipcMain.handle('finding:snippet', (_e, location) => { try { const s = readSnippet(location, 6); return s ? { ok: true, ...s } : { ok: false }; } catch (e) { return { ok: false, error: e.message }; } });
ipcMain.handle('crash:info', () => { try { return { count: fs.readdirSync(CRASH_DIR()).filter((f) => f.endsWith('.json')).length }; } catch { return { count: 0 }; } });
ipcMain.handle('crash:open', () => { fs.mkdirSync(CRASH_DIR(), { recursive: true }); return shell.openPath(CRASH_DIR()).then((err) => ({ ok: !err })); });

const ASK_PROMPT = `Du bist ein erfahrener, defensiver Sicherheitsberater und beantwortest Rueckfragen zu EINEM Befund aus einer Sicherheitspruefung des eigenen Projekts des Nutzers.
- Antworte auf Deutsch, in Alltagssprache. KURZ: hoechstens 5 Saetze ODER 3-5 Stichpunkte, dazu bei Bedarf EIN kurzer Codeblock.
- Beginne direkt mit der Antwort (erste Zeile = Kernaussage, z. B. "**Ja, wahrscheinlich ausnutzbar**, weil …"). KEINE Einleitung, keine Wiederholung des Befunds oder der Frage, keine Hoeflichkeitsfloskeln, keine Zusammenfassung am Ende.
- Formatiere mit Markdown: **fett** fuer die Kernaussage, "- " fuer Stichpunkte, Backticks fuer Namen im Text und Codebloecke mit drei Backticks. Keine Tabellen, keine Ueberschriften.
- Beziehe dich auf den mitgelieferten Code-Ausschnitt. Reicht er nicht, sag in einem Satz, was man zusaetzlich pruefen muesste.
- Bei "Ist das bei mir ausnutzbar?": erklaere die Voraussetzungen konzeptionell (Eingang, Bedingungen, wie realistisch) und gib eine Einschaetzung – aber KEINE einsatzfertigen Angriffs-Payloads oder Schritt-fuer-Schritt-Anleitungen.
- Schwerpunkt: verstehen und beheben.`;
ipcMain.handle('finding:ask', async (_e, payload) => {
  const p = payload && typeof payload === 'object' ? payload : {};
  const question = String(p.question || '').trim().slice(0, 2000);
  if (!question) return { ok: false, error: 'Leere Frage.' };
  const f = p.finding || {};
  const cfg = loadConfig();
  const eff = effectiveConfig(cfg, cfg.selected);
  let code = '';
  try { const s = readSnippet(f.location, 30); if (s) code = `Datei ${s.file}, Zeilen ${s.from}–${s.from + s.lines.length - 1} (Befund in Zeile ${s.line}):\n` + s.lines.map((l, i) => `${String(s.from + i).padStart(5)}  ${l}`).join('\n'); } catch { /* ohne Code */ }
  const facts = [`Titel: ${f.title || ''}`, `Schwere: ${f.severity || ''}`, `Ort: ${f.location || ''}`, `Kategorie: ${f.category || ''}`, f.description && `Beschreibung: ${f.description}`, f.impact && `Auswirkung: ${f.impact}`, f.reachability && `Erreichbarkeit: ${f.reachability}`, f.remediation && `Behebung: ${f.remediation}`].filter(Boolean).map((x) => String(x).slice(0, 1500)).join('\n');
  const history = (Array.isArray(p.history) ? p.history : []).slice(-6).map((h) => `${h.role === 'user' ? 'Frage' : 'Antwort'}: ${String(h.text || '').slice(0, 1500)}`).join('\n\n');
  let user = `## Befund\n${facts}\n\n${code ? '## Code\n```\n' + code + '\n```\n\n' : '## Code\n(nicht verfuegbar)\n\n'}${history ? '## Bisheriges Gespraech\n' + history + '\n\n' : ''}## Neue Frage\n${question}`;
  const { shouldRedact, redactSecrets } = require('../src/core/harness');
  if (shouldRedact(eff)) user = redactSecrets(user).text;
  try {
    const { callProvider } = require('../src/core/providers');
    const r = await callProvider({ ...eff, maxTokens: 700 }, { system: ASK_PROMPT, user, json: false });
    let text = String(r.text || '').trim();
    // Manche lokalen Modelle antworten wegen JSON-Modus in JSON – dann den Text herausziehen
    try { const j = JSON.parse(text); text = j.answer || j.antwort || j.text || Object.values(j).find((v) => typeof v === 'string') || text; } catch { /* normaler Text */ }
    return { ok: true, answer: text, withCode: !!code, model: eff.model };
  } catch (e) { return { ok: false, error: e.message }; }
});

// Beispiel-Lauf beim ersten Start: Uebungsprojekt nur mit Regeln und Modulen pruefen (ohne KI, ohne Netz)
ipcMain.handle('sample:demo', async () => {
  try {
    const dir = path.join(app.getAppPath(), 'bench', 'vulnerable-app');
    const { ingestTargets } = require('../src/core/ingest');
    const { prescan } = require('../src/core/prescan');
    const { runStaticModules } = require('../src/core/modules/static');
    const { dedupeFindings, sortFindings, summarize } = require('../src/core/schema');
    const { enrichRemedy } = require('../src/core/remedies');
    const { applyTaxonomy } = require('../src/core/taxonomy');
    const ing = await ingestTargets([{ type: 'path', value: dir }]);
    const pre = prescan(ing.units, {});
    const findings = sortFindings(applyTaxonomy(dedupeFindings([...pre.findings, ...runStaticModules(ing.units).findings]).map(enrichRemedy)));
    return { ok: true, result: { findings, summary: summarize(findings), errors: ['Beispiel-Lauf: absichtlich unsicheres Übungsprojekt, nur feste Regeln (ohne KI).'], meta: { provider: 'regeln', model: 'ohne KI', at: new Date().toISOString(), units: ing.units.length, demo: true } } };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('aicache:info', () => ({ entries: aiCache().size() }));
ipcMain.handle('aicache:clear', () => { aiCache().clear(); return { ok: true }; });
ipcMain.handle('audit:cancel', () => ({ ok: orchestrator.cancel() }));

// Kosten-/Token-Vorschau: aktueller Modus + Vergleich mit dem jeweils anderen Modus.
ipcMain.handle('audit:estimate', async (_e, payload) => {
  const v = check(ScanRequestSchema, payload);
  if (!v.ok) return { ok: false, error: v.error };
  const cfg = loadConfig();
  const eff = { ...effectiveConfig(cfg, v.data.providerId || cfg.selected), timingCalib: timing.load(TIMING_PATH()) };
  const targets = withVerified(v.data.targets);
  try {
    const current = await estimateAudit(targets, eff);
    const other = await estimateAudit(targets, { ...eff, analysisDepth: eff.analysisDepth === 'thorough' ? 'standard' : 'thorough' });
    return { ok: true, current, other, model: eff.model, provider: eff.provider };
  } catch (e) { return { ok: false, error: e.message }; }
});

// --- Befund-Lebenszyklus & Uebersicht ------------------------------------
ipcMain.handle('finding:setStatus', (_e, id, body) => {
  const v = check(StatusUpdateSchema, body);
  if (!v.ok) return { ok: false, error: v.error };
  const r = orchestrator.setStatus(String(id || ''), v.data.status, v.data.note);
  if (r.ok && lastResult) refreshStatuses(lastResult);
  return r.ok ? { ok: true, status: r.finding.status } : r;
});
ipcMain.handle('dashboard:get', (_e, filter) => ({ stats: orchestrator.stats(), findings: orchestrator.listFindings(filter || {}) }));
ipcMain.handle('store:clear', () => { orchestrator.clear(); return { ok: true }; });
// Loeschen in der Uebersicht – IDs sind Hex-Fingerabdruecke bzw. UUIDs, alles andere wird verworfen
const idOk = (s) => typeof s === 'string' && /^[\w-]{6,80}$/.test(s);
ipcMain.handle('findings:delete', (_e, ids) => orchestrator.deleteFindings((Array.isArray(ids) ? ids : []).filter(idOk).slice(0, 5000)));
ipcMain.handle('target:delete', (_e, id) => (idOk(id) ? orchestrator.deleteTarget(id) : { ok: false, error: 'Ungültige ID.' }));
ipcMain.handle('run:delete', (_e, id) => (idOk(id) ? orchestrator.deleteRun(id) : { ok: false, error: 'Ungültige ID.' }));
// Leer = alle Ziele; eine ungueltige ID wird abgelehnt statt still auf "alle" auszuweichen
ipcMain.handle('findings:purgeResolved', (_e, targetId) => (!targetId ? orchestrator.purgeResolved('') : idOk(targetId) ? orchestrator.purgeResolved(targetId) : { ok: false, deleted: 0, error: 'Ungültige ID.' }));
ipcMain.handle('api:info', () => { const c = loadConfig(); return { enabled: !!c.apiEnabled, port: c.apiPort, token: c.apiToken, running: !!(api && api.running()) }; });
// --- Ziele: Verifizierung, Baseline, Einstellungen -------------------------
ipcMain.handle('target:verify', async (_e, id) => {
  const t = orchestrator.getTarget(String(id || ''));
  if (!t) return { ok: false, error: 'Ziel nicht gefunden.' };
  const r = await verifyOwnership({ type: t.type, value: t.identifier }, t.verificationToken);
  if (r.ok) orchestrator.setTargetMeta(t.id, { ownershipVerified: true });
  return { ...r, token: t.verificationToken };
});
ipcMain.handle('target:info', (_e, id) => { const t = orchestrator.getTarget(String(id || '')); return t ? { ok: true, target: t } : { ok: false }; });
ipcMain.handle('target:baseline', (_e, id) => orchestrator.setBaseline(String(id || '')));
ipcMain.handle('target:meta', (_e, id, patch) => {
  const p = {};
  if (patch && typeof patch.internetExposed === 'boolean') p.internetExposed = patch.internetExposed;
  if (patch && ['PRODUCTION', 'STAGING', 'INTERNAL'].includes(patch.environment)) p.environment = patch.environment;
  // Vertrauen entziehen (Domain-Nachweis zuruecknehmen) geht immer – setzen nur ueber target:verify
  if (patch && patch.ownershipVerified === false) p.ownershipVerified = false;
  if (patch && typeof patch.hiddenFromPicker === 'boolean') p.hiddenFromPicker = patch.hiddenFromPicker;
  return orchestrator.setTargetMeta(String(id || ''), p);
});
ipcMain.handle('sbom:search', (_e, q) => orchestrator.searchSbom(String(q || '').slice(0, 120)));

// --- Threat-Intel -------------------------------------------------------------
ipcMain.handle('intel:status', () => ({ updatedAt: intel && intel.updatedAt, kev: intel ? intel.kev.size : 0, epss: intel ? intel.epss.size : 0, syncing: !!intelSyncing }));
ipcMain.handle('intel:sync', () => syncIntelInBackground(true));
// Uebersicht aller Erkennungsquellen fuer die Einstellungen
ipcMain.handle('feeds:status', () => ({ feeds: feeds.feedStatus(FEEDS_DIR()), intel: { updatedAt: intel && intel.updatedAt, kev: intel ? intel.kev.size : 0, epss: intel ? intel.epss.size : 0 }, syncing: !!(feedsSyncing || intelSyncing) }));
ipcMain.handle('feeds:sync', async () => { const [a, b] = await Promise.all([syncFeedsInBackground(true), syncIntelInBackground(true)]); return { ok: !!(a && a.ok !== false) && !!(b && b.ok !== false), feeds: a, intel: b }; });

// --- Links: nur geprüfte Ziele im Standardbrowser öffnen --------------------
ipcMain.handle('link:open', (_e, url) => (isAllowedLink(String(url || '')) ? shell.openExternal(String(url)).then(() => ({ ok: true })) : { ok: false, error: 'Link nicht erlaubt.' }));

// --- API-Rechtematrix: Konfiguration (Tokens verschluesselt, nie zurueck an die UI) ---
ipcMain.handle('apimatrix:get', () => (loadConfig().apiMatrix || []).map((m) => ({ host: m.host, endpoints: m.endpoints, resourceIdA: m.resourceIdA, hasTokenA: !!m.tokenAEnc, hasTokenB: !!m.tokenBEnc })));
ipcMain.handle('apimatrix:save', (_e, list) => {
  const c = loadConfig();
  const prev = c.apiMatrix || [];
  c.apiMatrix = (Array.isArray(list) ? list : []).slice(0, 10).map((m) => {
    const old = prev.find((p) => p.host === m.host) || {};
    return {
      host: String(m.host || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''),
      endpoints: String(m.endpoints || '').split(/\n/).map((x) => x.trim()).filter((x) => x.startsWith('/')).slice(0, 20),
      resourceIdA: String(m.resourceIdA || '').trim().slice(0, 200),
      tokenAEnc: m.tokenA ? enc(String(m.tokenA)) : old.tokenAEnc || '',
      tokenBEnc: m.tokenB ? enc(String(m.tokenB)) : old.tokenBEnc || '',
    };
  }).filter((m) => m.host);
  return { ok: saveConfig(c), encrypted: safeStorage.isEncryptionAvailable() };
});

// --- Login-Pruefung & Schadsoftware-Schluessel (Geheimnisse verschluesselt, nie zurueck an die UI) ---
ipcMain.handle('weblogin:get', () => (loadConfig().webLogins || []).map((m) => ({ host: m.host, loginUrl: m.loginUrl, username: m.username, userField: m.userField, passField: m.passField, hasPassword: !!m.passwordEnc })));
ipcMain.handle('weblogin:save', (_e, list) => {
  const c = loadConfig();
  const prev = c.webLogins || [];
  c.webLogins = (Array.isArray(list) ? list : []).slice(0, 10).map((m) => {
    let host = '';
    try { host = new URL(String(m.loginUrl || '')).hostname.toLowerCase(); } catch { /* ungueltig */ }
    const old = prev.find((p) => p.host === host) || {};
    return { host, loginUrl: String(m.loginUrl || '').trim().slice(0, 500), username: String(m.username || '').trim().slice(0, 200), userField: String(m.userField || '').trim().slice(0, 80), passField: String(m.passField || '').trim().slice(0, 80), passwordEnc: m.password ? enc(String(m.password)) : old.passwordEnc || '' };
  }).filter((m) => m.host && /^https?:/i.test(m.loginUrl));
  return { ok: saveConfig(c), encrypted: safeStorage.isEncryptionAvailable() };
});
ipcMain.handle('malware:keyInfo', () => ({ hasKey: !!loadConfig().malwareBazaarKeyEnc }));
ipcMain.handle('malware:setKey', (_e, key) => { const c = loadConfig(); c.malwareBazaarKeyEnc = key ? enc(String(key).trim().slice(0, 200)) : ''; return { ok: saveConfig(c) }; });

ipcMain.handle('api:regenerateToken', () => { const c = loadConfig(); c.apiToken = crypto.randomBytes(24).toString('base64url'); saveConfig(c); return { token: c.apiToken }; });

// --- Ollama-Verwaltung --------------------------------------------------
const ollamaBase = () => effectiveConfig(loadConfig(), 'ollama').baseUrl;
let pullAbort = null;
ipcMain.handle('ollama:status', () => ollama.status(ollamaBase()));
ipcMain.handle('localai:detect', () => require('./localai').detectLocalAi());
ipcMain.handle('ollama:recommended', () => ollama.RECOMMENDED);
ipcMain.handle('ollama:start', () => ollama.start(ollamaBase()));
ipcMain.handle('ollama:install', async (e) => {
  const r = await ollama.install((line) => { try { e.sender.send('ollama:log', line); } catch { /* window weg */ } });
  if (r.ok) { const s = await ollama.start(ollamaBase()); return { ok: true, status: s.status || (await ollama.status(ollamaBase())) }; }
  return r;
});
ipcMain.handle('ollama:pull', async (e, model) => {
  if (!/^[\w.\-/:]{1,120}$/.test(String(model || ''))) return { ok: false, error: 'Ungültiger Modellname.' };
  if (pullAbort) return { ok: false, error: 'Es läuft bereits ein Download.' };
  pullAbort = new AbortController();
  try {
    return await ollama.pull(ollamaBase(), model, (p) => { try { e.sender.send('ollama:progress', { model, ...p }); } catch { /* window weg */ } }, pullAbort.signal);
  } finally { pullAbort = null; }
});
ipcMain.handle('ollama:cancelPull', () => { if (pullAbort) pullAbort.abort(); return { ok: true }; });
ipcMain.handle('ollama:remove', (_e, model) => ollama.remove(ollamaBase(), String(model || '')));
// Nur die feste offizielle Download-Seite – keine beliebigen URLs aus dem Renderer.
ipcMain.handle('ollama:openDownload', () => shell.openExternal(ollama.DOWNLOAD_URL));

// --- Scan-Verlauf -------------------------------------------------------
ipcMain.handle('history:list', () => loadHistory());
ipcMain.handle('history:open', (_e, id) => {
  const safe = String(id || '').replace(/[^a-z0-9]/gi, '');
  try {
    const result = JSON.parse(fs.readFileSync(path.join(HISTORY_DIR(), safe + '.json'), 'utf8'));
    refreshStatuses(result);
    lastResult = result;
    lastTargets = ((loadHistory().find((h) => h.id === safe) || {}).targets || []).map((v) => ({ value: v }));
    return { ok: true, result };
  } catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle('history:clear', () => {
  try {
    for (const r of loadHistory()) { try { fs.unlinkSync(path.join(HISTORY_DIR(), r.id + '.json')); } catch { /* egal */ } }
    fs.writeFileSync(HISTORY_PATH(), JSON.stringify({ runs: [] }, null, 2), 'utf8');
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

// Namen der eingebauten Regeln (fuer „Regeln deaktivieren" in den Einstellungen).
ipcMain.handle('meta:rules', () => ruleNames());

ipcMain.handle('report:save', async (_e, { format }) => {
  if (!lastResult) return { ok: false, error: 'Noch kein Ergebnis vorhanden.' };
  const exec = format === 'exec' || format === 'execpdf';
  const ext = format === 'md' ? 'md' : format === 'sarif' ? 'sarif' : format === 'pdf' || format === 'execpdf' ? 'pdf' : format === 'json' ? 'json' : 'html';
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
  const r = await dialog.showSaveDialog(win, {
    defaultPath: path.join(app.getPath('documents'), `vigil-${exec ? (reportEnglish() ? 'summary' : 'kurzbericht') : 'report'}-${stamp}.${ext}`),
    filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
  });
  if (r.canceled) return { ok: false, canceled: true };
  if (ext === 'pdf') {
    try { await saveReportPdf(r.filePath, exec ? 'exec' : 'full'); return { ok: true, path: r.filePath }; }
    catch (err) { return { ok: false, error: err.message }; }
  }
  const content = exec ? executiveHtml() : ext === 'md' ? mdReport()
    : ext === 'sarif' ? report.toSarif(reportResult()) : ext === 'json' ? report.toJson(reportResult(), orchestrator.stats()) : htmlReport();
  try { fs.writeFileSync(r.filePath, content, 'utf8'); return { ok: true, path: r.filePath }; }
  catch (err) { return { ok: false, error: err.message }; }
});
