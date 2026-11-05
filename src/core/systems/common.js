'use strict';

// Gemeinsame Bausteine der erweiterten System-Pruefungen (PC, Netz, Server, Cloud, Konten).
// Grundsatz wie in hostaudit.js: AUSSCHLIESSLICH LESEND. Befehle sind feste Werte, HTTP nur GET
// (einzige Ausnahme: OAuth-Token-Abruf mit den vom Nutzer hinterlegten App-Zugangsdaten).

const { spawn } = require('child_process');
const { normalizeFinding } = require('../schema');

const RISKY = { 22: 'SSH', 3389: 'Remotedesktop', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 23: 'Telnet', 21: 'FTP', 445: 'SMB', 11211: 'Memcached' };

// Programme starten. viaCmd nur fuer .cmd-Wrapper (az, gcloud, aws) unter Windows – dann nur mit
// geprueften Argumenten. input = Text fuer stdin (z. B. festes Skript fuer ssh). env = Zusatz-Variablen
// (Passwoerter gehen so nie in die Befehlszeile).
function run(cmd, args, { signal, timeoutMs = 60000, env, input, viaCmd } = {}) {
  const wrap = process.platform === 'win32' && viaCmd;
  if (wrap && args.some((a) => /[&|<>^%"\r\n]/.test(String(a)))) return Promise.resolve({ ok: false, error: 'unzulässiges Zeichen im Argument', stdout: '', stderr: '' });
  const [c, a] = wrap ? ['cmd.exe', ['/d', '/s', '/c', cmd, ...args]] : [cmd, args];
  return new Promise((resolve) => {
    let child;
    try { child = spawn(c, a, { windowsHide: true, signal, env: env ? { ...process.env, ...env } : process.env }); } catch (e) { return resolve({ ok: false, error: e.message, stdout: '', stderr: '' }); }
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch { /* egal */ } }, timeoutMs);
    child.stdout.on('data', (d) => { if (stdout.length < 30e6) stdout += d; });
    child.stderr.on('data', (d) => { if (stderr.length < 1e6) stderr += d; });
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, error: e.code === 'ENOENT' ? 'nicht installiert' : e.message, stdout, stderr }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ ok: code === 0, code, stdout, stderr, error: code ? (stderr.split('\n').find(Boolean) || `Exit ${code}`).slice(0, 200) : null }); });
    if (child.stdin) { try { if (input != null) child.stdin.write(input); child.stdin.end(); } catch { /* egal */ } }
  });
}

const json = (s) => { try { return JSON.parse(String(s || '').trim()); } catch { return null; } };
const mk = (kind, o) => normalizeFinding({ category: 'Config', confidence: 'high', ...o, sourceModule: `system-${kind}` }, `system-${kind}`);

// HTTP-Abruf mit Zeitgrenze (fetchImpl austauschbar fuer Tests). Gibt nie eine Ausnahme weiter.
async function http(url, { method = 'GET', headers = {}, body, signal, fetchImpl, timeoutMs = 20000 } = {}) {
  const f = fetchImpl || globalThis.fetch;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const onAbort = () => ctl.abort();
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
  try {
    const r = await f(url, { method, headers: { 'User-Agent': 'Vigil-Audit', ...headers }, body, signal: ctl.signal });
    const text = await r.text();
    const hdr = (k) => (r.headers && typeof r.headers.get === 'function' ? r.headers.get(k) : null);
    return { ok: r.ok, status: r.status, data: json(text), text: String(text).slice(0, 2e6), header: hdr };
  } catch (e) {
    return { ok: false, status: 0, data: null, text: '', header: () => null, error: e.name === 'AbortError' ? 'Zeitüberschreitung' : e.message };
  } finally { clearTimeout(timer); if (signal) signal.removeEventListener('abort', onAbort); }
}

// Versionen vergleichen ("1.2.10" > "1.2.9"); nicht-numerische Teile werden ignoriert.
function cmpVer(a, b) {
  const pa = String(a || '').split(/[^\d]+/).filter(Boolean).map(Number);
  const pb = String(b || '').split(/[^\d]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const x = pa[i] || 0, y = pb[i] || 0; if (x !== y) return x < y ? -1 : 1; }
  return 0;
}

const isPrivateIPv4 = (ip) => /^(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}$/.test(String(ip || ''));
const isLocalHost = (h) => /^(localhost|127\.\d+\.\d+\.\d+|::1|\[::1\])$/i.test(String(h || ''));
const daysSince = (d, now = Date.now()) => { const t = new Date(d).getTime(); return Number.isFinite(t) ? Math.floor((now - t) / 86400000) : null; };
const list = (arr, n = 10) => arr.slice(0, n).join(', ') + (arr.length > n ? ` (+${arr.length - n})` : '');
// Port-Angaben wie "22", "20-25", "*", "all" gegen die riskanten Ports pruefen
function riskyPortIn(spec) {
  const s = String(spec == null ? '*' : spec).trim().toLowerCase();
  const ports = Object.keys(RISKY).map(Number);
  if (s === '*' || s === 'all' || s === '0' || s === 'any' || s === '') return ports[0];
  const m = s.match(/^(\d+)(?:\s*-\s*(\d+))?$/);
  if (!m) return null;
  const lo = +m[1], hi = m[2] ? +m[2] : lo;
  return ports.find((p) => p >= lo && p <= hi) || null;
}
const openToWorld = (arr) => (arr || []).some((x) => x === '0.0.0.0/0' || x === '::/0' || x === '0.0.0.0' || x === '*');

module.exports = { RISKY, run, json, mk, http, cmpVer, isPrivateIPv4, isLocalHost, daysSince, list, riskyPortIn, openToWorld };
