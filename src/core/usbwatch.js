'use strict';

// Wechseldatentraeger erkennen (Windows): neue Laufwerksbuchstaben vom Typ "Wechseldatentraeger"
// (DriveType 2). Vigil fragt danach per Benachrichtigung, ob geprueft werden soll – geprueft wird
// erst nach dem Klick. Standardmaessig AUS (Einstellungen › Prüfungen).

const fs = require('fs');
const { execFile } = require('child_process');

const LETTERS = 'DEFGHIJKLMNOPQRSTUVWXYZ'.split('');

async function presentLetters() {
  const out = [];
  await Promise.all(LETTERS.map(async (l) => { try { await fs.promises.access(`${l}:\\`); out.push(l); } catch { /* nicht da */ } }));
  return out.sort();
}
function driveType(letter) {
  return new Promise((resolve) => {
    if (!/^[A-Z]$/.test(letter)) return resolve(0);
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `(Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${letter}:'").DriveType`], { windowsHide: true, timeout: 15000 }, (err, stdout) => resolve(err ? 0 : Number(String(stdout).trim()) || 0));
  });
}
const diffDrives = (prev, cur) => cur.filter((l) => !prev.includes(l));

// onNew(letter) wird fuer jedes neu eingesteckte Wechsel-Laufwerk einmal aufgerufen
function createUsbWatcher({ onNew, intervalMs = 4000, list = presentLetters, type = driveType, isEnabled = () => true } = {}) {
  let prev = null, timer = null, busy = false;
  const tick = async () => {
    if (busy) return; busy = true;
    try {
      const cur = await list();
      if (prev && isEnabled()) for (const l of diffDrives(prev, cur)) { if ((await type(l)) === 2) onNew(`${l}:\\`); }
      prev = cur;
    } catch { /* naechster Versuch */ } finally { busy = false; }
  };
  return {
    start() { if (!timer) { tick(); timer = setInterval(tick, intervalMs); if (timer.unref) timer.unref(); } },
    stop() { if (timer) clearInterval(timer); timer = null; prev = null; },
    tick,
  };
}

module.exports = { createUsbWatcher, diffDrives, presentLetters, driveType };
