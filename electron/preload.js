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
  saveReport: (format) => ipcRenderer.invoke('report:save', { format }),

  baselineInfo: () => ipcRenderer.invoke('baseline:info'),
  saveBaseline: () => ipcRenderer.invoke('baseline:save'),
  clearBaseline: () => ipcRenderer.invoke('baseline:clear'),
  suppressInfo: () => ipcRenderer.invoke('suppress:info'),
  toggleSuppress: (fp) => ipcRenderer.invoke('suppress:toggle', fp),
  clearSuppress: () => ipcRenderer.invoke('suppress:clear'),

  historyList: () => ipcRenderer.invoke('history:list'),
  historyOpen: (id) => ipcRenderer.invoke('history:open', id),
  historyClear: () => ipcRenderer.invoke('history:clear'),
  getRuleNames: () => ipcRenderer.invoke('meta:rules'),

  onProgress: (cb) => {
    const h = (_e, p) => cb(p);
    ipcRenderer.on('audit:progress', h);
    return () => ipcRenderer.removeListener('audit:progress', h);
  },
});
