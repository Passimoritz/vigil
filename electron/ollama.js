'use strict';

// Ollama-Verwaltung aus der App heraus: erkennen, installieren (winget), starten,
// Modelle herunterladen (mit Fortschritt) und entfernen.
// Lokale Anfragen laufen immer direkt – nie ueber einen gesetzten Proxy.

const { spawn, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const { fetch, Agent } = require('undici');

const DIRECT = new Agent();
const DEFAULT_BASE = 'http://localhost:11434';
const DOWNLOAD_URL = 'https://ollama.com/download';

// Empfohlene Modelle fuer Code-Audits (Groessen laut Ollama-Bibliothek, gerundet).
const RECOMMENDED = [
  { name: 'qwen2.5-coder:7b', label: 'Qwen 2.5 Coder 7B', size: '4,7 GB', ram: '8 GB RAM', note: 'Empfohlen – starker Code-Prüfer, läuft auf den meisten Rechnern.' },
  { name: 'qwen2.5-coder:3b', label: 'Qwen 2.5 Coder 3B', size: '1,9 GB', ram: '4 GB RAM', note: 'Klein und schnell – für schwächere Rechner.' },
  { name: 'qwen2.5-coder:14b', label: 'Qwen 2.5 Coder 14B', size: '9 GB', ram: '16 GB RAM', note: 'Gründlicher, braucht mehr Speicher.' },
  { name: 'llama3.1:8b', label: 'Llama 3.1 8B', size: '4,9 GB', ram: '8 GB RAM', note: 'Guter Allrounder.' },
];

const baseOf = (b) => String(b || DEFAULT_BASE).replace(/\/$/, '');

async function api(base, p, opts = {}, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  if (opts.signal) opts.signal.addEventListener('abort', () => ctrl.abort(), { once: true });
  try {
    return await fetch(baseOf(base) + p, { ...opts, signal: ctrl.signal, dispatcher: DIRECT });
  } finally { clearTimeout(t); }
}

// Pfad zur ollama.exe (Standard-Installationsort oder PATH) – oder null.
function findBinary() {
  const candidates = [
    process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs', 'Ollama', 'ollama.exe'),
    process.env.ProgramFiles && path.join(process.env.ProgramFiles, 'Ollama', 'ollama.exe'),
    '/usr/local/bin/ollama', '/usr/bin/ollama', '/opt/homebrew/bin/ollama',
  ].filter(Boolean);
  for (const c of candidates) if (fs.existsSync(c)) return c;
  for (const dir of String(process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const exe of ['ollama.exe', 'ollama']) {
      const p = path.join(dir, exe);
      if (fs.existsSync(p)) return p;
    }
  }
  return null;
}

// { installed, running, version, models: [{name, size}] }
async function status(base) {
  const bin = findBinary();
  try {
    const v = await api(base, '/api/version');
    const version = (await v.json()).version || '';
    const t = await api(base, '/api/tags');
    const models = ((await t.json()).models || []).map((m) => ({ name: m.name, size: m.size || 0 }));
    return { installed: true, running: true, version, models };
  } catch {
    return { installed: !!bin, running: false, version: '', models: [] };
  }
}

// Nur den unsichtbaren Hintergrunddienst "ollama serve" starten – nie die Desktop-App, und
// hoechstens einen Prozess. Kein "detached": unter Windows oeffnet das trotz windowsHide
// fuer jeden Start ein eigenes Konsolenfenster. Der Dienst endet mit Vigil.
let serveChild = null;
let starting = null;
async function waitRunning(base) {
  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 500));
    const s = await status(base);
    if (s.running) return { ok: true, status: s };
  }
  return { ok: false, error: 'Der Ollama-Dienst antwortet nicht. Läuft schon ein anderes Programm auf Port 11434?' };
}
async function start(base) {
  const pre = await status(base);
  if (pre.running) return { ok: true, status: pre };   // laeuft schon (z. B. eigener Dienst) – nichts starten
  if (starting) return starting;                         // paralleler Aufruf: auf denselben Start warten
  const bin = findBinary();
  if (!bin) return { ok: false, error: 'Ollama ist nicht installiert.' };
  starting = (async () => {
    if (!serveChild || serveChild.exitCode !== null) {
      try {
        serveChild = spawn(bin, ['serve'], { stdio: 'ignore', windowsHide: true, env: { ...process.env, OLLAMA_HOST: '127.0.0.1:11434' } });
        serveChild.on('error', () => {});
      } catch (e) { return { ok: false, error: e.message }; }
    }
    return waitRunning(base);
  })();
  try { return await starting; } finally { starting = null; }
}
function stop() { try { if (serveChild && serveChild.exitCode === null) serveChild.kill(); } catch { /* egal */ } }

function hasWinget() {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve(false);
    execFile('winget', ['--version'], { windowsHide: true, timeout: 8000 }, (err) => resolve(!err));
  });
}

// Installation ueber winget (offizielles Paket Ollama.Ollama). onLine bekommt Ausgabezeilen.
// Laeuft die Ollama-Desktop-App (Tray)? Der Installer startet sie sonst ungefragt.
function desktopAppRunning() {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve(false);
    execFile('tasklist', ['/FI', 'IMAGENAME eq ollama app.exe', '/NH'], { windowsHide: true, timeout: 8000 }, (err, out) => resolve(!err && /ollama app.exe/i.test(out || '')));
  });
}
async function install(onLine = () => {}) {
  const appWasRunning = await desktopAppRunning();
  if (!(await hasWinget())) return { ok: false, fallback: DOWNLOAD_URL, error: 'winget ist nicht verfügbar – bitte Ollama von der offiziellen Seite installieren.' };
  return new Promise((resolve) => {
    const args = ['install', '--id', 'Ollama.Ollama', '-e', '--silent', '--accept-package-agreements', '--accept-source-agreements', '--disable-interactivity'];
    const child = spawn('winget', args, { windowsHide: true });
    const feed = (buf) => String(buf).split(/\r?\n|\r/).map((l) => l.trim()).filter((l) => l.length > 2).forEach(onLine);
    child.stdout.on('data', feed);
    child.stderr.on('data', feed);
    child.on('error', (e) => resolve({ ok: false, fallback: DOWNLOAD_URL, error: e.message }));
    child.on('close', (code) => {
      // Ollama liegt danach unter %LOCALAPPDATA%; der PATH dieses Prozesses kennt es evtl. noch nicht.
      if (code === 0 || findBinary()) {
        // Vom Installer gestartete Desktop-App wieder schliessen – Vigil nutzt nur den Hintergrunddienst.
        if (!appWasRunning && process.platform === 'win32') execFile('taskkill', ['/IM', 'ollama app.exe', '/F'], { windowsHide: true }, () => resolve({ ok: true }));
        else resolve({ ok: true });
      }
      else resolve({ ok: false, fallback: DOWNLOAD_URL, error: `Installation fehlgeschlagen (winget-Code ${code}).` });
    });
  });
}

// Modell herunterladen. onProgress({ status, completed, total, percent }).
async function pull(base, model, onProgress = () => {}, signal) {
  let res;
  try {
    res = await api(base, '/api/pull', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model, stream: true }), signal }, 6 * 60 * 60 * 1000);
  } catch {
    return { ok: false, error: signal && signal.aborted ? 'Abgebrochen.' : 'Ollama antwortet nicht – läuft der Dienst?' };
  }
  if (!res.ok) return { ok: false, error: `Ollama: HTTP ${res.status}` };
  const decoder = new TextDecoder();
  let buf = '';
  try {
    for await (const chunk of res.body) {
      buf += decoder.decode(chunk, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line) continue;
        let j; try { j = JSON.parse(line); } catch { continue; }
        if (j.error) return { ok: false, error: /not found|does not exist/i.test(j.error) ? `Modell „${model}“ gibt es in der Ollama-Bibliothek nicht.` : j.error };
        const percent = j.total ? Math.round(((j.completed || 0) / j.total) * 100) : null;
        onProgress({ status: j.status || '', completed: j.completed || 0, total: j.total || 0, percent });
        if (j.status === 'success') return { ok: true };
      }
    }
  } catch (e) {
    return { ok: false, error: signal && signal.aborted ? 'Abgebrochen.' : e.message };
  }
  return { ok: true };
}

async function remove(base, model) {
  try {
    const res = await api(base, '/api/delete', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model }) }, 15000);
    return res.ok ? { ok: true } : { ok: false, error: `HTTP ${res.status}` };
  } catch (e) { return { ok: false, error: e.message }; }
}

module.exports = { RECOMMENDED, DOWNLOAD_URL, status, start, stop, install, pull, remove, findBinary };
