'use strict';

const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('vigil', {
  // Pfad einer per Drag-and-drop fallengelassenen Datei (Electron 32+).
  pathForFile: (file) => { try { return webUtils.getPathForFile(file); } catch { return null; } },

  getProviders: () => ipcRenderer.invoke('meta:providers'),
  getConfig: () => ipcRenderer.invoke('config:get'),
  saveConfig: (cfg) => ipcRenderer.invoke('config:save', cfg),

  pickFiles: () => ipcRenderer.invoke('dialog:pickFiles'),
  pickFolder: () => ipcRenderer.invoke('dialog:pickFolder'),

  testProxy: (proxyUrl) => ipcRenderer.invoke('proxy:test', proxyUrl),
  pingProvider: (providerId) => ipcRenderer.invoke('provider:ping', providerId),
  loadModels: (payload) => ipcRenderer.invoke('provider:models', payload),
  runAudit: (payload) => ipcRenderer.invoke('audit:run', payload),
  cancelAudit: () => ipcRenderer.invoke('audit:cancel'),
  estimateAudit: (payload) => ipcRenderer.invoke('audit:estimate', payload),
  saveReport: (format) => ipcRenderer.invoke('report:save', { format }),

  // Befund-Lebenszyklus & Uebersicht
  setFindingStatus: (id, status, note) => ipcRenderer.invoke('finding:setStatus', id, { status, ...(note ? { note } : {}) }),
  dashboard: (filter) => ipcRenderer.invoke('dashboard:get', filter),
  clearStore: () => ipcRenderer.invoke('store:clear'),
  apiInfo: () => ipcRenderer.invoke('api:info'),
  regenerateApiToken: () => ipcRenderer.invoke('api:regenerateToken'),
  verifyTarget: (id) => ipcRenderer.invoke('target:verify', id),
  targetInfo: (id) => ipcRenderer.invoke('target:info', id),
  setBaseline: (id) => ipcRenderer.invoke('target:baseline', id),
  setTargetMeta: (id, patch) => ipcRenderer.invoke('target:meta', id, patch),
  deleteFindings: (ids) => ipcRenderer.invoke('findings:delete', ids),
  deleteTarget: (id) => ipcRenderer.invoke('target:delete', id),
  deleteRun: (id) => ipcRenderer.invoke('run:delete', id),
  purgeResolved: (targetId) => ipcRenderer.invoke('findings:purgeResolved', targetId || ''),
  aiCacheInfo: () => ipcRenderer.invoke('aicache:info'),
  feedsStatus: () => ipcRenderer.invoke('feeds:status'),
  feedsSync: () => ipcRenderer.invoke('feeds:sync'),
  watchAlerts: () => ipcRenderer.invoke('watch:alerts'),
  watchDismiss: (key) => ipcRenderer.invoke('watch:dismiss', key),
  watchRun: () => ipcRenderer.invoke('watch:run'),
  yaraInfo: () => ipcRenderer.invoke('yara:info'),
  yaraOpenFolder: () => ipcRenderer.invoke('yara:openFolder'),
  osvOfflineStatus: () => ipcRenderer.invoke('osvoffline:status'),
  onWatchUpdate: (cb) => { const h = (_e, p) => cb(p); ipcRenderer.on('watch:update', h); ipcRenderer.on('watch:open', h); return () => { ipcRenderer.removeListener('watch:update', h); ipcRenderer.removeListener('watch:open', h); }; },
  onUsbScan: (cb) => { const h = (_e, drive) => cb(String(drive || '')); ipcRenderer.on('usb:scan', h); return () => ipcRenderer.removeListener('usb:scan', h); },
  findingSnippet: (location) => ipcRenderer.invoke('finding:snippet', String(location || '')),
  askFinding: (payload) => ipcRenderer.invoke('finding:ask', payload),
  crashInfo: () => ipcRenderer.invoke('crash:info'),
  crashOpen: () => ipcRenderer.invoke('crash:open'),
  sampleDemo: () => ipcRenderer.invoke('sample:demo'),
  aiCacheClear: () => ipcRenderer.invoke('aicache:clear'),
  searchSbom: (q) => ipcRenderer.invoke('sbom:search', q),
  intelStatus: () => ipcRenderer.invoke('intel:status'),
  syncIntel: () => ipcRenderer.invoke('intel:sync'),
  openLink: (url) => ipcRenderer.invoke('link:open', url),
  apiMatrixGet: () => ipcRenderer.invoke('apimatrix:get'),
  apiMatrixSave: (list) => ipcRenderer.invoke('apimatrix:save', list),
  webLoginGet: () => ipcRenderer.invoke('weblogin:get'),
  webLoginSave: (list) => ipcRenderer.invoke('weblogin:save', list),
  malwareKeyInfo: () => ipcRenderer.invoke('malware:keyInfo'),
  malwareSetKey: (key) => ipcRenderer.invoke('malware:setKey', key),

  historyList: () => ipcRenderer.invoke('history:list'),
  historyOpen: (id) => ipcRenderer.invoke('history:open', id),
  historyClear: () => ipcRenderer.invoke('history:clear'),
  getRuleNames: () => ipcRenderer.invoke('meta:rules'),

  ollama: {
    status: () => ipcRenderer.invoke('ollama:status'),
    detectLocal: () => ipcRenderer.invoke('localai:detect'),
    recommended: () => ipcRenderer.invoke('ollama:recommended'),
    start: () => ipcRenderer.invoke('ollama:start'),
    install: () => ipcRenderer.invoke('ollama:install'),
    pull: (model) => ipcRenderer.invoke('ollama:pull', model),
    cancelPull: () => ipcRenderer.invoke('ollama:cancelPull'),
    remove: (model) => ipcRenderer.invoke('ollama:remove', model),
    openDownload: () => ipcRenderer.invoke('ollama:openDownload'),
    onProgress: (cb) => { const h = (_e, p) => cb(p); ipcRenderer.on('ollama:progress', h); return () => ipcRenderer.removeListener('ollama:progress', h); },
    onLog: (cb) => { const h = (_e, l) => cb(l); ipcRenderer.on('ollama:log', h); return () => ipcRenderer.removeListener('ollama:log', h); },
  },

  onProgress: (cb) => {
    const h = (_e, p) => cb(p);
    ipcRenderer.on('audit:progress', h);
    return () => ipcRenderer.removeListener('audit:progress', h);
  },
});
