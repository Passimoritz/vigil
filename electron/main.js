'use strict';

const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');

// .env aus dem Projektordner laden (Schluessel-Fallback).
try { require('dotenv').config({ path: path.join(__dirname, '..', '.env') }); } catch { /* optional */ }

const { runAudit, report, fingerprint, ruleNames, PROVIDERS, pingProvider, fetchModels } = require('../src/core');
const { applyProxy, testProxy } = require('./proxy');

let win;
let lastResult = null;
let currentAbort = null;

const CONFIG_PATH = () => path.join(app.getPath('userData'), 'config.json');
const BASELINE_PATH = () => path.join(app.getPath('userData'), 'baseline.json');
const SUPPRESS_PATH = () => path.join(app.getPath('userData'), 'suppressed.json');

// Kleine Fingerprint-Listen ({ items:[...], at:ISO }) laden/speichern.
function loadFpStore(p) {
  try { const j = JSON.parse(fs.readFileSync(p, 'utf8')); return { items: Array.isArray(j.items) ? j.items : [], at: j.at || null }; }
  catch { return { items: [], at: null }; }
}
function saveFpStore(p, obj) {
  try { fs.writeFileSync(p, JSON.stringify(obj, null, 2), 'utf8'); return true; } catch { return false; }
}

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

// Befunde mit stabilem Fingerabdruck versehen und gegen Baseline/Ausblend-Liste markieren.
function tagResult(result) {
  if (!result || !Array.isArray(result.findings)) return result;
  const base = loadFpStore(BASELINE_PATH());
  const supp = loadFpStore(SUPPRESS_PATH());
  const baseSet = new Set(base.items);
  const suppSet = new Set(supp.items);
  const hasBaseline = base.items.length > 0;
  let suppressedCount = 0;
  for (const f of result.findings) {
    const fp = fingerprint(f);
    f.id = fp;
    f.isNew = hasBaseline ? !baseSet.has(fp) : false;
    f.suppressed = suppSet.has(fp);
    if (f.suppressed) suppressedCount++;
  }
  result.hasBaseline = hasBaseline;
  result.baselineAt = base.at;
  result.suppressedCount = suppressedCount;
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
  return { selected: 'ollama', temperature: 0.1, maxTokens: 8192, cveLookup: true, analysisDepth: 'thorough', aiValidation: true, redactSecrets: true, activeScan: false, proxyUrl: '', customRules: [], disabledRules: [], providers };
}

function loadConfig() {
  try {
    const saved = JSON.parse(fs.readFileSync(CONFIG_PATH(), 'utf8'));
    const def = defaultConfig();
    return {
      ...def,
      ...saved,
      providers: { ...def.providers, ...(saved.providers || {}) },
    };
  } catch { return defaultConfig(); }
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
  win.loadFile(path.join(__dirname, '..', 'src', 'ui', 'index.html'));
}

// Gespeicherten Proxy anwenden, aber nie am Start abstuerzen (ungueltige URL o. Ae.).
function applyProxySafe(cfg) {
  try { applyProxy((cfg || loadConfig()).proxyUrl || ''); }
  catch (e) { console.warn('Proxy konnte nicht gesetzt werden:', e.message); }
}

app.whenReady().then(() => {
  applyProxySafe(loadConfig());
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// --- IPC ----------------------------------------------------------------
ipcMain.handle('meta:providers', () => {
  // Liste fuer die UI (ohne Secrets).
  return Object.entries(PROVIDERS).map(([id, p]) => ({ id, label: p.label, needsKey: p.needsKey, defaultModel: p.defaultModel, defaultBaseUrl: p.defaultBaseUrl, envKeyPresent: ENV_KEY[id] ? !!process.env[ENV_KEY[id]] : false }));
});

ipcMain.handle('config:get', () => loadConfig());
ipcMain.handle('config:save', (_e, cfg) => { const ok = saveConfig(cfg); applyProxySafe(cfg); return { ok }; });

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

ipcMain.handle('audit:run', async (e, { targets, providerId }) => {
  const cfg = loadConfig();
  applyProxySafe(cfg);
  const eff = effectiveConfig(cfg, providerId || cfg.selected);
  const ctrl = new AbortController();
  currentAbort = ctrl;
  eff.signal = ctrl.signal;
  try {
    const { result } = await runAudit(targets, eff, (p) => {
      try { e.sender.send('audit:progress', p); } catch { /* window weg */ }
    });
    tagResult(result);
    lastResult = result;
    recordHistory(result, targets);
    return { ok: true, result, canceled: ctrl.signal.aborted };
  } catch (err) {
    if (ctrl.signal.aborted) return { ok: true, result: lastResult, canceled: true, partial: true };
    return { ok: false, error: err.message };
  } finally {
    if (currentAbort === ctrl) currentAbort = null;
  }
});

ipcMain.handle('audit:cancel', () => {
  if (currentAbort) { currentAbort.abort(); return { ok: true }; }
  return { ok: false };
});

// --- Baseline (Scan-Vergleich) ------------------------------------------
ipcMain.handle('baseline:info', () => { const b = loadFpStore(BASELINE_PATH()); return { count: b.items.length, at: b.at }; });
ipcMain.handle('baseline:save', () => {
  if (!lastResult || !Array.isArray(lastResult.findings)) return { ok: false, error: 'Noch kein Ergebnis vorhanden.' };
  const items = [...new Set(lastResult.findings.map((f) => f.id || fingerprint(f)))];
  const at = new Date().toISOString();
  const ok = saveFpStore(BASELINE_PATH(), { items, at });
  if (ok) { for (const f of lastResult.findings) f.isNew = false; lastResult.hasBaseline = true; lastResult.baselineAt = at; }
  return { ok, count: items.length, at };
});
ipcMain.handle('baseline:clear', () => {
  const ok = saveFpStore(BASELINE_PATH(), { items: [], at: null });
  if (ok && lastResult) { lastResult.hasBaseline = false; lastResult.baselineAt = null; for (const f of lastResult.findings) f.isNew = false; }
  return { ok };
});

// --- Befunde dauerhaft ausblenden ---------------------------------------
ipcMain.handle('suppress:info', () => { const s = loadFpStore(SUPPRESS_PATH()); return { count: s.items.length }; });
ipcMain.handle('suppress:toggle', (_e, fp) => {
  if (!fp) return { ok: false };
  const s = loadFpStore(SUPPRESS_PATH());
  const set = new Set(s.items);
  const suppressed = !set.has(fp);
  if (suppressed) set.add(fp); else set.delete(fp);
  const ok = saveFpStore(SUPPRESS_PATH(), { items: [...set], at: new Date().toISOString() });
  if (ok && lastResult) {
    for (const f of lastResult.findings) if ((f.id || '') === fp) f.suppressed = suppressed;
    lastResult.suppressedCount = lastResult.findings.filter((f) => f.suppressed).length;
  }
  return { ok, suppressed };
});
ipcMain.handle('suppress:clear', () => {
  const ok = saveFpStore(SUPPRESS_PATH(), { items: [], at: null });
  if (ok && lastResult) { for (const f of lastResult.findings) f.suppressed = false; lastResult.suppressedCount = 0; }
  return { ok };
});

// --- Scan-Verlauf -------------------------------------------------------
ipcMain.handle('history:list', () => loadHistory());
ipcMain.handle('history:open', (_e, id) => {
  const safe = String(id || '').replace(/[^a-z0-9]/gi, '');
  try {
    const result = JSON.parse(fs.readFileSync(path.join(HISTORY_DIR(), safe + '.json'), 'utf8'));
    tagResult(result);
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
  const ext = format === 'md' ? 'md' : format === 'sarif' ? 'sarif' : format === 'pdf' ? 'pdf' : 'html';
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
    : ext === 'sarif' ? report.toSarif(lastResult) : report.toHtml(lastResult);
  try { fs.writeFileSync(r.filePath, content, 'utf8'); return { ok: true, path: r.filePath }; }
  catch (err) { return { ok: false, error: err.message }; }
});
