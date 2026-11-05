'use strict';

// Encryption at rest for Vigil's own data (findings store, scan history).
//
//  Format   "VGLE1" | iv (12 bytes) | GCM tag (16 bytes) | AES-256-GCM ciphertext of the JSON text
//  Key      32 random bytes, stored only wrapped by the OS (Electron safeStorage = Windows DPAPI,
//           macOS Keychain, libsecret) in "<userData>/data.key". Without safeStorage (CLI, tests,
//           Linux without a keyring) files stay plaintext – nothing breaks, nothing is lost.
//  Migration  plaintext files are read as before and re-written encrypted on the next save
//           (store.load/migrateFile do it immediately).
//  Safety   a file that cannot be decrypted is never overwritten: it is moved aside to
//           "<name>.unreadable-<time>" before an empty store is used.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const MAGIC = Buffer.from('VGLE1');
const IV_LEN = 12, TAG_LEN = 16, KEY_LEN = 32;

function createCipher(key) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) throw new Error('key must be 32 bytes');
  return {
    encrypt(plain) {
      const iv = crypto.randomBytes(IV_LEN);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(MAGIC);
      const ct = Buffer.concat([c.update(Buffer.isBuffer(plain) ? plain : Buffer.from(String(plain), 'utf8')), c.final()]);
      return Buffer.concat([MAGIC, iv, c.getAuthTag(), ct]);
    },
    decrypt(buf) {
      if (!isEncrypted(buf)) throw new Error('not an encrypted Vigil file');
      const iv = buf.subarray(MAGIC.length, MAGIC.length + IV_LEN);
      const tag = buf.subarray(MAGIC.length + IV_LEN, MAGIC.length + IV_LEN + TAG_LEN);
      const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
      d.setAAD(MAGIC);
      d.setAuthTag(tag);
      return Buffer.concat([d.update(buf.subarray(MAGIC.length + IV_LEN + TAG_LEN)), d.final()]);
    },
  };
}

const isEncrypted = (buf) => Buffer.isBuffer(buf) && buf.length >= MAGIC.length + IV_LEN + TAG_LEN && buf.subarray(0, MAGIC.length).equals(MAGIC);

// Reads JSON (encrypted or plaintext). Returns { data, encrypted, exists }.
// Throws on decryption errors (wrong key, tampering) – the caller decides what to do.
function readJson(file, cipher) {
  let buf;
  try { buf = fs.readFileSync(file); } catch { return { data: null, encrypted: false, exists: false }; }
  if (isEncrypted(buf)) {
    if (!cipher) throw new Error('file is encrypted, but no key is available');
    return { data: JSON.parse(cipher.decrypt(buf).toString('utf8')), encrypted: true, exists: true };
  }
  const text = buf.toString('utf8').replace(/^﻿/, '');
  return { data: text.trim() ? JSON.parse(text) : null, encrypted: false, exists: true };
}

// Atomic write (temp file + rename), encrypted when a cipher is set.
function writeJson(file, data, cipher, { pretty = false } = {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const text = JSON.stringify(data, null, pretty ? 2 : 0);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, cipher ? cipher.encrypt(text) : text, cipher ? undefined : 'utf8');
  fs.renameSync(tmp, file);
}

// Unreadable file: keep it for manual recovery instead of overwriting it with an empty store.
function quarantine(file) {
  try { const to = `${file}.unreadable-${new Date().toISOString().replace(/[:.]/g, '-')}`; fs.renameSync(file, to); return to; } catch { return null; }
}

// Encrypts a plaintext JSON file in place (no-op if already encrypted, missing or no cipher).
function migrateFile(file, cipher) {
  if (!cipher) return false;
  let buf;
  try { buf = fs.readFileSync(file); } catch { return false; }
  if (isEncrypted(buf)) return false;
  let data;
  try { data = JSON.parse(buf.toString('utf8').replace(/^﻿/, '')); } catch { return false; }
  writeJson(file, data, cipher);
  return true;
}
function migrateDir(dir, cipher) {
  let n = 0;
  try { for (const f of fs.readdirSync(dir)) if (f.endsWith('.json') && migrateFile(path.join(dir, f), cipher)) n++; } catch { /* no dir */ }
  return n;
}

// Data key wrapped by the OS. protector = { isEncryptionAvailable(), encryptString(s), decryptString(buf) }
// (Electron's safeStorage). Returns a cipher, or null when the OS cannot protect a key.
function loadOrCreateKey(keyFile, protector) {
  try { if (!protector || !protector.isEncryptionAvailable()) return null; } catch { return null; }
  try {
    const wrapped = fs.readFileSync(keyFile, 'utf8').trim();
    const key = Buffer.from(protector.decryptString(Buffer.from(wrapped, 'base64')), 'base64');
    if (key.length === KEY_LEN) return createCipher(key);
  } catch (e) {
    if (fs.existsSync(keyFile)) { quarantine(keyFile); } // unusable key: keep it, start a new one
  }
  const key = crypto.randomBytes(KEY_LEN);
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  fs.writeFileSync(keyFile, protector.encryptString(key.toString('base64')).toString('base64'), 'utf8');
  return createCipher(key);
}

module.exports = { createCipher, isEncrypted, readJson, writeJson, migrateFile, migrateDir, quarantine, loadOrCreateKey, MAGIC };
