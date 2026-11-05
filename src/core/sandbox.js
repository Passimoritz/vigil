'use strict';

// Least-privilege runner for external tools (trivy, semgrep, gitleaks, nmap, nuclei, ...).
//
//  - never through a shell (shell: false, arguments passed as an array, no string concatenation)
//  - minimal environment: only an allowlist of OS variables plus tool-specific prefixes; anything
//    that looks like a secret (TOKEN, KEY, SECRET, PASSWORD, CREDENTIAL, AUTH, COOKIE, SESSION)
//    is removed – an external tool never sees the user's AI API keys or cloud credentials
//  - working directory limited to the scan target (or a fresh temp dir for network targets)
//  - hard timeout, abort via AbortSignal, output size caps per stream (the tool is killed when a
//    cap is exceeded), process runs at below-normal priority
//
// Windows job objects / restricted tokens are not available from Node without a native addon,
// and building them via PowerShell would need Add-Type (runtime C# compilation), which Smart App
// Control and AppLocker policies rightly block. See docs/THREAT_MODEL.md ("Tool sandbox").

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_TIMEOUT_MS = 300000;
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024; // per stream

// OS variables a typical CLI needs to start, find its cache and reach the network (proxy).
const ENV_ALLOW = new Set([
  'PATH', 'PATHEXT', 'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP', 'TMPDIR',
  'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
  'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)',
  'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'OS', 'USERNAME', 'USERDOMAIN', 'COMPUTERNAME',
  'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TERM', 'NO_COLOR',
  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY',
  'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
  'PYTHONIOENCODING', 'PYTHONUTF8', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE',
]);
// Tool-specific configuration (cache dirs, offline flags) – still filtered by SECRET_RE.
const ENV_PREFIX = ['TRIVY_', 'SEMGREP_', 'GITLEAKS_', 'NUCLEI_', 'GRYPE_', 'SYFT_', 'OSV_', 'CHECKOV_', 'BANDIT_', 'HADOLINT_'];
const SECRET_RE = /TOKEN|KEY|SECRET|PASSW|PWD|CREDENTIAL|AUTH|COOKIE|SESSION|PRIVATE|CERT_PASS/i;

// Proxy URLs can carry user:password – keep the variable but drop the credentials.
function stripUrlCredentials(v) {
  try { const u = new URL(v); if (u.username || u.password) { u.username = ''; u.password = ''; return u.toString(); } } catch { /* not a URL */ }
  return v;
}

function minimalEnv(src = process.env, extra = {}) {
  const out = {};
  for (const [k, v] of Object.entries(src)) {
    if (v == null) continue;
    const up = k.toUpperCase();
    const allowed = ENV_ALLOW.has(up) || ENV_PREFIX.some((p) => up.startsWith(p));
    if (!allowed) continue;
    if (SECRET_RE.test(up) && !ENV_ALLOW.has(up)) continue;
    out[k] = /PROXY$/.test(up) ? stripUrlCredentials(String(v)) : String(v);
  }
  for (const [k, v] of Object.entries(extra || {})) if (v != null && !SECRET_RE.test(k)) out[k] = String(v);
  return out;
}

// Working directory: the scan target itself (directory, or the folder of a file). Network targets
// and images get the OS temp dir – never Vigil's own folder or the user's profile.
function targetCwd(args) {
  for (const a of args || []) {
    if (typeof a !== 'string' || !path.isAbsolute(a)) continue;
    try { const st = fs.statSync(a); return st.isDirectory() ? a : path.dirname(a); } catch { /* next */ }
  }
  return os.tmpdir();
}

function runSandboxed(cmd, args, { signal, timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = DEFAULT_MAX_BYTES, cwd, env, spawnImpl = spawn } = {}) {
  return new Promise((resolve) => {
    if (typeof cmd !== 'string' || !cmd) return resolve({ ok: false, error: 'no command', stdout: '', stderr: '' });
    if (!Array.isArray(args) || args.some((a) => typeof a !== 'string' || a.includes('\0'))) return resolve({ ok: false, error: 'invalid arguments', stdout: '', stderr: '' });
    let child;
    const opts = { windowsHide: true, shell: false, cwd: cwd || targetCwd(args), env: minimalEnv(process.env, env), stdio: ['ignore', 'pipe', 'pipe'] };
    try { child = spawnImpl(cmd, args, opts); }
    catch (e) { return resolve({ ok: false, error: e.message, stdout: '', stderr: '' }); }
    try { if (child.pid) os.setPriority(child.pid, os.constants.priority.PRIORITY_BELOW_NORMAL); } catch { /* best effort */ }
    const out = [], err = [];
    let outLen = 0, errLen = 0, truncated = false, timedOut = false, settled = false;
    const kill = () => { try { child.kill(); } catch { /* ignore */ } };
    const onAbort = () => kill();
    if (signal) { if (signal.aborted) onAbort(); else signal.addEventListener('abort', onAbort, { once: true }); }
    const timer = setTimeout(() => { timedOut = true; kill(); }, timeoutMs);
    const take = (buf, arr, which) => {
      const len = which === 'out' ? outLen : errLen;
      if (len >= maxBytes) return;
      const room = maxBytes - len;
      const piece = buf.length > room ? buf.subarray(0, room) : buf;
      arr.push(piece);
      if (which === 'out') outLen += piece.length; else errLen += piece.length;
      if (buf.length > room) { truncated = true; kill(); }
    };
    if (child.stdout) child.stdout.on('data', (d) => take(d, out, 'out'));
    if (child.stderr) child.stderr.on('data', (d) => take(d, err, 'err'));
    const finish = (r) => {
      if (settled) return; settled = true;
      clearTimeout(timer);
      if (signal && signal.removeEventListener) signal.removeEventListener('abort', onAbort);
      resolve({ ...r, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8'), truncated, timedOut, aborted: !!(signal && signal.aborted) });
    };
    child.on('error', (e) => finish({ ok: false, error: e.message }));
    child.on('close', (code) => finish({ ok: true, code }));
  });
}

module.exports = { runSandboxed, minimalEnv, targetCwd, SECRET_RE, DEFAULT_MAX_BYTES };
