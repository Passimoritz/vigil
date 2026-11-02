'use strict';

// Browser-Laufzeitpruefung (headless-dom-audit): laedt die Seite in einem unsichtbaren,
// isolierten Fenster mit fluechtiger Sitzung und prueft, was erst nach JavaScript sichtbar wird.
// Nur lesend: alle Anfragen ausser GET/HEAD/OPTIONS werden blockiert. Fenster und Sitzung
// werden im finally-Block immer entfernt; harte Zeitgrenze pro Seite.

const { BrowserWindow, session } = require('electron');
const crypto = require('crypto');
const { normalizeFinding, redactSecret } = require('../src/core/schema');

const LOAD_TIMEOUT = 25000;
const SETTLE_MS = 2500;
const JWT = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/;
const SECRETISH_KEY = /token|jwt|auth|session|bearer|secret|password|api[_-]?key|refresh/i;
const CONSOLE_LEAK = /eyJ[A-Za-z0-9_-]{10,}\.|bearer\s+[a-z0-9._-]{20,}|api[_-]?key["':= ]+[a-z0-9_-]{16,}|password["':= ]+\S{4,}|at\s+\S+\s+\(\S+:\d+:\d+\)/i;

const F = (o) => normalizeFinding({ ...o, sourceModule: 'headless-dom-audit' }, 'headless-dom-audit');

async function domAudit(url, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'webscan', message: `Browser-Prüfung: ${url} …` });
  const part = 'vigil-dom-' + crypto.randomUUID(); // ohne "persist:" -> nur im Speicher
  const ses = session.fromPartition(part, { cache: false });
  const requests = [];
  const consoleMsgs = [];
  let blocked = 0;
  ses.webRequest.onBeforeRequest((details, cb) => {
    requests.push({ url: details.url, method: details.method, type: details.resourceType });
    if (!['GET', 'HEAD', 'OPTIONS'].includes(details.method)) { blocked++; return cb({ cancel: true }); }
    cb({});
  });
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false)); // Kamera, Standort … immer ablehnen

  const win = new BrowserWindow({
    show: false, width: 1280, height: 900,
    webPreferences: { session: ses, sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, javascript: true },
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  ses.on('will-download', (e) => e.preventDefault());
  win.webContents.on('console-message', (_e, level, message) => { if (consoleMsgs.length < 200) consoleMsgs.push({ level, message: String(message) }); });

  const findings = [];
  const notes = [];
  try {
    const loaded = new Promise((resolve) => {
      const t = setTimeout(() => resolve('timeout'), LOAD_TIMEOUT);
      win.webContents.once('did-finish-load', () => { clearTimeout(t); resolve('ok'); });
      win.webContents.once('did-fail-load', (_e, code, desc) => { clearTimeout(t); resolve('fail:' + desc); });
      if (signal) signal.addEventListener('abort', () => { clearTimeout(t); resolve('abort'); }, { once: true });
    });
    win.loadURL(url).catch(() => {});
    const state = await loaded;
    if (state !== 'ok' && state !== 'timeout') return { ok: false, findings, notes: [`Browser-Prüfung: Seite nicht geladen (${state}).`] };
    await new Promise((r) => setTimeout(r, SETTLE_MS));

    const data = await win.webContents.executeJavaScript(`(() => {
      const dump = (s) => { const o = {}; try { for (let i = 0; i < s.length && i < 100; i++) { const k = s.key(i); o[k] = String(s.getItem(k) || '').slice(0, 400); } } catch (e) {} return o; };
      const scripts = [...document.querySelectorAll('script[src]')].map((s) => ({ src: s.src, integrity: s.integrity || '' }));
      return { origin: location.origin, local: dump(localStorage), session: dump(sessionStorage), scripts };
    })()`, true);

    const origin = data.origin;
    // Tokens im Browser-Speicher
    for (const [area, store] of [['localStorage', data.local], ['sessionStorage', data.session]]) {
      for (const [k, v] of Object.entries(store)) {
        if (JWT.test(v) || (SECRETISH_KEY.test(k) && v.length >= 16)) {
          findings.push(F({ ruleId: 'dom-token-in-storage', severity: 'high', category: 'Auth', title: `Token im ${area}: „${k}“`, location: `${url} ${area}.${k}`, evidence: `${area}.${k} = ${redactSecret(v)}`, description: `Nach dem Laden liegt unter „${k}“ ein Token bzw. Geheimnis im ${area}. Jedes Skript auf der Seite kann es lesen.`, remediation: 'Token in ein HttpOnly-Cookie verschieben.', confidence: JWT.test(v) ? 'high' : 'medium' }));
        }
      }
    }
    // Drittskripte ohne SRI
    const ext = data.scripts.filter((s) => { try { return new URL(s.src).origin !== origin; } catch { return false; } });
    const noSri = ext.filter((s) => !/^sha(256|384|512)-/.test(s.integrity));
    for (const s of noSri.slice(0, 8)) {
      findings.push(F({ ruleId: 'dom-missing-sri', severity: 'medium', category: 'Dependencies', title: `Externes Skript ohne Integritätsprüfung: ${new URL(s.src).host}`, location: s.src.slice(0, 280), description: 'Das Skript wird von einer fremden Domain geladen, ohne dass der Browser seinen Inhalt prüft. Wird der Anbieter kompromittiert, läuft dessen Code mit vollen Rechten auf deiner Seite.', remediation: 'integrity-Attribut setzen oder Skript selbst hosten.', confidence: 'high' }));
    }
    // Unverschluesselte Anfragen aus einer HTTPS-Seite
    if (origin.startsWith('https:')) {
      const insecure = [...new Set(requests.filter((r) => /^(http|ws):\/\//i.test(r.url)).map((r) => r.url))];
      for (const u of insecure.slice(0, 6)) findings.push(F({ ruleId: 'dom-mixed-content', severity: 'high', category: 'Transport', title: `Unverschlüsselte Anfrage aus HTTPS-Seite: ${u.split('/').slice(0, 3).join('/')}`, location: u.slice(0, 280), description: 'Die Seite lädt Daten bzw. öffnet einen WebSocket ohne Verschlüsselung.', remediation: 'https:// bzw. wss:// verwenden.', confidence: 'high' }));
    }
    // Konsolen-Leaks
    const leaks = consoleMsgs.filter((m) => CONSOLE_LEAK.test(m.message));
    if (leaks.length) findings.push(F({ ruleId: 'dom-console-leak', severity: leaks.some((m) => JWT.test(m.message)) ? 'medium' : 'low', category: 'Logging', title: `${leaks.length} auffällige Konsolenausgabe(n) in Produktion`, location: url, evidence: redactSecret(leaks[0].message.slice(0, 200)), description: 'Die Seite schreibt Tokens, Schlüssel oder Stacktraces in die Browser-Konsole.', remediation: 'console-Ausgaben im Produktions-Build entfernen.', confidence: 'medium' }));

    notes.push(`Browser-Prüfung: ${requests.length} Anfragen beobachtet${blocked ? `, ${blocked} schreibende blockiert` : ''}, ${ext.length} Drittskripte.`);
    return { ok: true, findings, notes };
  } catch (e) {
    return { ok: false, findings, notes: ['Browser-Prüfung fehlgeschlagen: ' + e.message] };
  } finally {
    try { win.destroy(); } catch { /* schon weg */ }
    try { await ses.clearStorageData(); await ses.clearCache(); } catch { /* egal */ }
  }
}

module.exports = { domAudit };
