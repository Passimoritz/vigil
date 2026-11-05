'use strict';

// Optional app lock (Settings → Advanced): password on start and after an idle timeout.
//
//  - password stored only as scrypt hash in config.json ("appLock.secret"), never sent to the UI
//  - while locked, every IPC channel except a small allowlist is refused in the MAIN process –
//    the overlay in the window is only the visible part; the data stays out of reach either way
//  - idle = system idle time (powerMonitor), plus locking when Windows locks the screen
//  - biometrics: Electron offers Touch ID on macOS only (systemPreferences.promptTouchID).
//    Windows Hello has no Electron API; it would need a native addon (see docs/THREAT_MODEL.md).
//  - the local REST API is not affected (it has its own token)

const { ipcMain, powerMonitor, systemPreferences } = require('electron');
const core = require('../src/core/applock');

// Allowed while locked: what the window needs to render the lock screen.
const OPEN_WHILE_LOCKED = new Set(['applock:status', 'applock:unlock', 'applock:biometric', 'meta:providers', 'crash:info']);

function createAppLock({ loadConfig, saveConfig, getWindow }) {
  const state = core.createLockState();
  let idleTimer = null;
  const settings = () => core.normalizeSettings(loadConfig().appLock);
  const biometricAvailable = () => { try { return process.platform === 'darwin' && systemPreferences.canPromptTouchID(); } catch { return false; } };

  function notify() { const w = getWindow(); try { if (w && !w.isDestroyed()) w.webContents.send('applock:state', { locked: state.isLocked() }); } catch { /* window gone */ } }
  function lockNow() { if (!settings().enabled) return false; state.lock(); notify(); return true; }

  // Wraps ipcMain.handle so that handlers registered afterwards are refused while locked.
  function guardIpc() {
    const orig = ipcMain.handle.bind(ipcMain);
    ipcMain.handle = (channel, fn) => orig(channel, (...args) => {
      if (state.isLocked() && !OPEN_WHILE_LOCKED.has(channel)) return { ok: false, locked: true, error: 'Vigil ist gesperrt.' };
      return fn(...args);
    });
  }

  function startIdleWatch() {
    clearInterval(idleTimer);
    idleTimer = setInterval(() => {
      const s = settings();
      if (!s.enabled || !s.idleMinutes || state.isLocked()) return;
      try { if (powerMonitor.getSystemIdleTime() >= s.idleMinutes * 60) lockNow(); } catch { /* not available */ }
    }, 15000);
    if (idleTimer.unref) idleTimer.unref();
    try { powerMonitor.on('lock-screen', () => lockNow()); } catch { /* not supported */ }
  }

  function init() {
    if (settings().enabled) state.lock(); // locked on start
    startIdleWatch();
  }

  function registerIpc() {
    ipcMain.handle('applock:status', () => { const s = settings(); return { enabled: s.enabled, locked: state.isLocked(), idleMinutes: s.idleMinutes, biometric: s.enabled && biometricAvailable(), minLength: core.MIN_LEN }; });
    ipcMain.handle('applock:unlock', (_e, password) => {
      const s = settings();
      if (!s.enabled) { state.unlock(); return { ok: true }; }
      const r = state.attempt(String(password || ''), s.secret);
      if (r.ok) notify();
      return r.ok ? { ok: true } : { ok: false, waitMs: r.waitMs, error: r.waitMs ? 'Zu viele Versuche – bitte kurz warten.' : 'Falsches Passwort.' };
    });
    ipcMain.handle('applock:biometric', async () => {
      if (!settings().enabled || !biometricAvailable()) return { ok: false };
      try { await systemPreferences.promptTouchID('Vigil entsperren'); state.unlock(); notify(); return { ok: true }; } catch { return { ok: false }; }
    });
    ipcMain.handle('applock:lock', () => ({ ok: lockNow() }));
    // enable / change / disable – always needs the current password once a lock exists
    ipcMain.handle('applock:configure', (_e, p) => {
      const body = p && typeof p === 'object' ? p : {};
      const cfg = loadConfig();
      const s = core.normalizeSettings(cfg.appLock);
      if (s.enabled && !core.verifyPassword(String(body.current || ''), s.secret)) return { ok: false, error: 'Das aktuelle Passwort stimmt nicht.' };
      const idleMinutes = core.normalizeSettings({ idleMinutes: body.idleMinutes }).idleMinutes;
      if (body.enabled === false) { cfg.appLock = { enabled: false, idleMinutes }; return { ok: saveConfig(cfg), enabled: false }; }
      let secret = s.secret;
      if (body.password) { const err = core.validateNewPassword(String(body.password)); if (err) return { ok: false, error: err }; secret = core.hashPassword(String(body.password)); }
      if (!secret) return { ok: false, error: 'Bitte ein Passwort festlegen.' };
      cfg.appLock = { enabled: true, idleMinutes, secret };
      return { ok: saveConfig(cfg), enabled: true, idleMinutes };
    });
  }

  return { init, guardIpc, registerIpc, lockNow, isLocked: () => state.isLocked() };
}

module.exports = { createAppLock, OPEN_WHILE_LOCKED };
