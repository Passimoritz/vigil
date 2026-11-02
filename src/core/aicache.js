'use strict';

// KI-Zwischenspeicher je Datei ("nur Geaendertes neu pruefen"): Schluessel ist ein Hash aus
// Dateiinhalt, Modell und Modus (analyze.unitKey), Wert die KI-Befunde dieser Datei.
// Lokale JSON-Datei, haelt hoechstens MAX Eintraege (aelteste fliegen zuerst raus).
// Inhalte bleiben auf dem Rechner; gespeichert werden nur Befunde, kein Quelltext.

const fs = require('fs');
const path = require('path');

const MAX = 5000;

function openCache(file) {
  let data = {};
  try { data = JSON.parse(fs.readFileSync(file, 'utf8')) || {}; } catch { data = {}; }
  let dirty = false;
  return {
    get(key) { const e = data[key]; if (!e) return undefined; e.at = Date.now(); dirty = true; return e.findings; },
    set(key, findings) { data[key] = { at: Date.now(), findings: findings || [] }; dirty = true; },
    flush() {
      if (!dirty) return;
      const keys = Object.keys(data);
      if (keys.length > MAX) keys.sort((a, b) => data[a].at - data[b].at).slice(0, keys.length - MAX).forEach((k) => delete data[k]);
      try { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file + '.tmp', JSON.stringify(data)); fs.renameSync(file + '.tmp', file); dirty = false; } catch { /* nicht kritisch */ }
    },
    size: () => Object.keys(data).length,
    clear() { data = {}; dirty = true; this.flush(); },
  };
}

module.exports = { openCache };
