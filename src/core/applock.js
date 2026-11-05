'use strict';

// App lock: password hashing (scrypt) and the lock state machine, without Electron.
// The Electron wiring (IPC, idle timer, guarding IPC channels) lives in electron/applock.js.

const crypto = require('crypto');

const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 96 * 1024 * 1024 };
const KEYLEN = 32;
const MIN_LEN = 6;
const MAX_LEN = 256;

function hashPassword(password, salt = crypto.randomBytes(16)) {
  const s = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt), 'base64');
  const hash = crypto.scryptSync(String(password).normalize('NFC'), s, KEYLEN, SCRYPT);
  return { algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: s.toString('base64'), hash: hash.toString('base64') };
}

function verifyPassword(password, rec) {
  if (!rec || rec.algo !== 'scrypt' || !rec.salt || !rec.hash) return false;
  if (typeof password !== 'string' || password.length > MAX_LEN) return false;
  const expected = Buffer.from(rec.hash, 'base64');
  let got;
  try { got = crypto.scryptSync(password.normalize('NFC'), Buffer.from(rec.salt, 'base64'), expected.length, { N: rec.N || SCRYPT.N, r: rec.r || SCRYPT.r, p: rec.p || SCRYPT.p, maxmem: SCRYPT.maxmem }); }
  catch { return false; }
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}

function validateNewPassword(pw) {
  if (typeof pw !== 'string' || pw.length < MIN_LEN) return `Das Passwort braucht mindestens ${MIN_LEN} Zeichen.`;
  if (pw.length > MAX_LEN) return 'Das Passwort ist zu lang.';
  return null;
}

// Lock state with brute-force throttling: after 5 wrong attempts each further attempt waits
// exponentially longer (2 s, 4 s, ... up to 5 min).
function createLockState({ now = () => Date.now() } = {}) {
  let locked = false, failures = 0, blockedUntil = 0;
  return {
    isLocked: () => locked,
    lock() { locked = true; },
    unlock() { locked = false; failures = 0; blockedUntil = 0; },
    // returns { ok, waitMs? }
    attempt(password, rec) {
      const t = now();
      if (t < blockedUntil) return { ok: false, waitMs: blockedUntil - t };
      if (verifyPassword(password, rec)) { this.unlock(); return { ok: true }; }
      failures++;
      if (failures >= 5) blockedUntil = t + Math.min(300000, 2000 * 2 ** (failures - 5));
      return { ok: false, waitMs: Math.max(0, blockedUntil - t) };
    },
    failures: () => failures,
  };
}

// Normalised settings as stored in config.json under "appLock"
function normalizeSettings(s) {
  const x = s && typeof s === 'object' ? s : {};
  const idle = Number(x.idleMinutes);
  return {
    enabled: !!(x.enabled && x.secret && x.secret.hash),
    idleMinutes: Number.isFinite(idle) ? Math.max(0, Math.min(240, Math.round(idle))) : 10,
    secret: x.secret && x.secret.hash ? x.secret : null,
  };
}

module.exports = { hashPassword, verifyPassword, validateNewPassword, createLockState, normalizeSettings, MIN_LEN };
