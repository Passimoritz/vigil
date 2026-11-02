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
const INTEL_PATH = () => path.join(app.getPath('userData'), 'threat-intel.json');
let intel = null;
let intelSyncing = null;
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
const { applyProxy, testProxy } = require('./proxy');
const ollama = require('./ollama');

let win;
let lastResult = null;
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
async function saveReportPdf(outPath) {
  const html = report.toHtml(lastResult);
  const tmp = path.join(app.getPath('temp'), `vigil-report-${Date.now()}.html`);
  fs.writeFileSync(tmp, html, 'utf8');
  const w = new BrowserWindow({ show: false, webPreferences: { sandbox: true, javascript: false } });
  try {
    await w.loadFile(tmp);
    const data = await w.webContents.printToPDF({ printBackground: true, pageSize: 'A4' });
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
  return { selected: 'ollama', temperature: 0.1, maxTokens: 8192, cveLookup: true, analysisDepth: 'thorough', aiValidation: true, redactSecrets: true, activeScan: false, proxyUrl: '', customRules: [], disabledRules: [], allowlist: [], apiEnabled: false, apiPort: 7811, apiToken: '', providers };
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
  };
}

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
    backgroundColor: '#14171c',
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
      return { ...effectiveConfig(c, providerId || c.selected), intel, domAudit: c.domAudit !== false ? domAudit : null, apiMatrix: apiMatrixFor(c), maxRequestsPerSecond: c.maxRequestsPerSecond || 4 };
    },
  });
  api = createApi({ orchestrator, getConfig: loadConfig, enforceScope });
  applyApi(cfg);
  intel = loadIntel(INTEL_PATH());
  setTimeout(() => syncIntelInBackground(), 5000); // nach dem Start, ohne ihn zu bremsen
  setInterval(() => syncIntelInBackground(), 6 * 60 * 60 * 1000);
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
  // Das API-Token setzt nur der Main-Prozess; die Freigabeliste wird normalisiert.
  cfg.allowlist = normalizeAllowlist(cfg.allowlist);
  cfg.apiToken = prev.apiToken;
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

ipcMain.handle('audit:run', async (e, payload) => {
  const v = check(ScanRequestSchema, payload);
  if (!v.ok) return { ok: false, error: 'Ungültige Eingabe: ' + v.error };
  const cfg = loadConfig();
  // Scope: Webadressen/Server nur freigegeben oder nach ausdruecklicher Bestaetigung im UI.
  const scope = enforceScope(v.data.targets, cfg.allowlist, { interactive: true });
  if (!scope.ok) return { ok: false, error: scope.errors.join(' ') };
  if (scope.allow.length) { cfg.allowlist = normalizeAllowlist([...cfg.allowlist, ...scope.allow]); saveConfig(cfg); }
  const job = orchestrator.enqueue({
    targets: scope.targets, providerId: v.data.providerId || cfg.selected, origin: 'app',
    onProgress: (p) => { try { e.sender.send('audit:progress', p); } catch { /* Fenster weg */ } },
  });
  const out = await job.done;
  if (out.ok) { lastResult = out.result; recordHistory(out.result, scope.targets); }
  return out;
});

ipcMain.handle('audit:cancel', () => ({ ok: orchestrator.cancel() }));

// Kosten-/Token-Vorschau: aktueller Modus + Vergleich mit dem jeweils anderen Modus.
ipcMain.handle('audit:estimate', async (_e, payload) => {
  const v = check(ScanRequestSchema, payload);
  if (!v.ok) return { ok: false, error: v.error };
  const cfg = loadConfig();
  const eff = effectiveConfig(cfg, v.data.providerId || cfg.selected);
  try {
    const current = await estimateAudit(v.data.targets, eff);
    const other = await estimateAudit(v.data.targets, { ...eff, analysisDepth: eff.analysisDepth === 'thorough' ? 'standard' : 'thorough' });
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
  return orchestrator.setTargetMeta(String(id || ''), p);
});
ipcMain.handle('sbom:search', (_e, q) => orchestrator.searchSbom(String(q || '').slice(0, 120)));

// --- Threat-Intel -------------------------------------------------------------
ipcMain.handle('intel:status', () => ({ updatedAt: intel && intel.updatedAt, kev: intel ? intel.kev.size : 0, epss: intel ? intel.epss.size : 0, syncing: !!intelSyncing }));
ipcMain.handle('intel:sync', () => syncIntelInBackground(true));

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
  const ext = format === 'md' ? 'md' : format === 'sarif' ? 'sarif' : format === 'pdf' ? 'pdf' : format === 'json' ? 'json' : 'html';
  const stamp = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
  const r = await dialog.showSaveDialog(win, {
    defaultPath: path.join(app.getPath('documents'), `vigil-report-${stamp}.${ext}`),
    filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
  });
  if (r.canceled) return { ok: false, canceled: true };
  if (ext === 'pdf') {
    try { await saveReportPdf(r.filePath); return { ok: true, path: r.filePath }; }
    catch (err) { return { ok: false, error: err.message }; }
  }
  const content = ext === 'md' ? report.toMarkdown(lastResult)
    : ext === 'sarif' ? report.toSarif(lastResult) : ext === 'json' ? report.toJson(lastResult, orchestrator.stats()) : report.toHtml(lastResult);
  try { fs.writeFileSync(r.filePath, content, 'utf8'); return { ok: true, path: r.filePath }; }
  catch (err) { return { ok: false, error: err.message }; }
});
