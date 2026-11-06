'use strict';

// Gespeicherter Stand einer Pruefung: Jeder fertige Schritt landet sofort auf der Platte. So kann eine pausierte
// oder durch Schliessen unterbrochene Pruefung spaeter dort weitermachen. Nur der Schritt, der gerade lief, beginnt
// von vorn. Es gibt genau einen Stand; Befunde liegen verschluesselt wie der Verlauf (securefile.js).

const fs = require('fs');
const secure = require('./securefile');

function createRunState({ file, cipher = null }) {
  const read = () => {
    try { const d = secure.readJson(file, cipher).data; return d && d.id && Array.isArray(d.targets) ? d : null; } catch { return null; }
  };
  const clear = () => { try { fs.rmSync(file, { force: true }); } catch { /* egal */ } };
  return {
    read,
    clear,
    // Fuer die Anzeige: ohne die Ergebnisse der Schritte
    info() {
      const d = read();
      return d ? { id: d.id, targets: d.targets, providerId: d.providerId || null, paused: !!d.paused, savedAt: d.savedAt, steps: Object.keys(d.steps || {}).length } : null;
    },
    // Oeffnet den Stand eines Laufs. Ziele ohne Freigabe-Vermerk: Beim Fortsetzen prueft die App die Freigabe neu.
    open({ id, targets, providerId, useGreenbone }, { resume = false } = {}) {
      const old = resume ? read() : null;
      const data = old && old.id === id ? old : { id, steps: {} };
      Object.assign(data, { targets: targets.map((t) => ({ type: t.type, value: t.value })), providerId: providerId || null, useGreenbone, paused: false });
      const save = () => { data.savedAt = new Date().toISOString(); try { secure.writeJson(file, data, cipher); } catch (e) { console.warn('Prüfungsstand nicht gespeichert:', e.message); } };
      save();
      return {
        get: (key) => data.steps[key],
        set: (key, value) => { data.steps[key] = value === undefined ? null : value; save(); },
        setPaused: (on) => { data.paused = !!on; save(); },
        clear,
      };
    },
  };
}

module.exports = { createRunState };
