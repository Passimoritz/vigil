'use strict';

// Haelt die Werkzeuge von Vigil aktuell, hoechstens einmal am Tag. Aktualisiert wird nur, was schon da ist;
// nichts wird neu installiert.
//
// Sicherheit beim Tausch:
//  - Quellen sind fest: GitHub-Releases der jeweiligen Projekte bzw. nmap.org. Geprueft wird die SHA-256-Summe
//    des Herausgebers, bei nmap zusaetzlich die digitale Signatur.
//  - Die alte Datei bleibt liegen, bis die neue nachweislich laeuft. Blockiert Windows die neue Datei
//    (Smart App Control), kommt automatisch die alte zurueck. Vigil umgeht die Sperre nicht.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const DAY = 24 * 60 * 60 * 1000;
const MAX_DOWNLOAD = 400 * 1024 * 1024;
const RETRY_NMAP_MS = 7 * DAY; // Windows-Abfrage abgelehnt: nicht jeden Tag erneut fragen
const TAR = process.platform === 'win32' && process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32', 'tar.exe') : 'tar';

const GITHUB_TOOLS = [
  { id: 'nuclei', repo: 'projectdiscovery/nuclei', asset: /^nuclei_[\d.]+_windows_amd64\.zip$/, sums: /_checksums\.txt$/, versionArgs: ['-version'] },
  { id: 'gitleaks', repo: 'gitleaks/gitleaks', asset: /^gitleaks_[\d.]+_windows_x64\.zip$/, sums: /_checksums\.txt$/, versionArgs: ['version'] },
  { id: 'trufflehog', repo: 'trufflesecurity/trufflehog', asset: /^trufflehog_[\d.]+_windows_amd64\.tar\.gz$/, sums: /_checksums\.txt$/, versionArgs: ['--version'] },
  { id: 'trivy', repo: 'aquasecurity/trivy', asset: /^trivy_[\d.]+_windows-64bit\.zip$/, sums: /_checksums\.txt$/, versionArgs: ['--version'] },
  { id: 'grype', repo: 'anchore/grype', asset: /^grype_[\d.]+_windows_amd64\.zip$/, sums: /_checksums\.txt$/, versionArgs: ['version'] },
  { id: 'osv-scanner', repo: 'google/osv-scanner', asset: /^osv-scanner_windows_amd64\.exe$/, sums: /_SHA256SUMS$/, versionArgs: ['--version'] },
  { id: 'hadolint', repo: 'hadolint/hadolint', asset: /^hadolint-windows-x86_64\.exe$/, sums: /checksums\.sha256$/, versionArgs: ['--version'] },
];
// Ueber pipx installierte Werkzeuge: nur diese Namen, nie "alles aktualisieren"
const PIPX_TOOLS = ['semgrep', 'checkov', 'bandit'];

const verParts = (v) => String(v).replace(/^v/, '').split('.').map((x) => parseInt(x, 10) || 0);
function isNewer(latest, current) {
  const a = verParts(latest), b = verParts(current);
  for (let i = 0; i < Math.max(a.length, b.length); i++) { const d = (a[i] || 0) - (b[i] || 0); if (d) return d > 0; }
  return false;
}
const versionIn = (text) => (String(text || '').replace(/\x1b\[[0-9;]*m/g, '').match(/\bv?(\d+\.\d+(?:\.\d+)*)\b/) || [])[1] || null;
const timeout = (ms, signal) => (signal ? AbortSignal.any([AbortSignal.timeout(ms), signal]) : AbortSignal.timeout(ms));
const HEAD = { 'User-Agent': 'Vigil-Audit' };

// "<sha256>  <name>" oder "<name> <sha256>"; Pfadteile vor dem Namen zaehlen nicht
function checksumFor(text, name) {
  for (const line of String(text || '').split(/\r?\n/)) {
    const hash = (line.match(/\b[a-f0-9]{64}\b/i) || [])[0];
    if (!hash) continue;
    const rest = line.replace(hash, '').trim().replace(/^\*/, '');
    if (path.basename(rest.replace(/\\/g, '/')) === name) return hash.toLowerCase();
  }
  return null;
}
// Format von nmap.org: "SHA256 = 22E5928D 1738A1B9 …" (acht Blöcke)
function nmapDigest(text) {
  const m = String(text || '').match(/SHA256\s*=\s*((?:[0-9A-F]{8}\s*){8})/i);
  return m ? m[1].replace(/\s/g, '').toLowerCase() : null;
}

async function download(url, file, fetchImpl, signal) {
  const r = await fetchImpl(url, { headers: HEAD, redirect: 'follow', signal: timeout(15 * 60 * 1000, signal) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > MAX_DOWNLOAD) throw new Error('Datei zu groß');
  fs.writeFileSync(file, buf);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function findFile(dir, name) {
  for (const it of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, it.name);
    if (it.isDirectory()) { const hit = findFile(p, name); if (hit) return hit; } else if (it.name.toLowerCase() === name.toLowerCase()) return p;
  }
  return null;
}

// Windows sperrt frische oder gerade beendete Programme kurz (Virenschutz, Indexdienst). Dann kurz warten.
async function withRetry(fn, { tries = 8, delayMs = 1500 } = {}) {
  for (let i = 1; ; i++) {
    try { return fn(); } catch (e) {
      if (i >= tries || !['EBUSY', 'EPERM', 'EACCES'].includes(e.code)) throw e;
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

// { id, status: 'current'|'updated'|'rolled-back'|'failed'|'missing', from, to, error }
async function updateGithubTool(tool, exePath, { run, fetchImpl = fetch, signal } = {}) {
  const res = (status, extra = {}) => ({ id: tool.id, status, ...extra });
  // Ein abgebrochener Austausch hinterlaesst nur die Sicherung: zuerst zurueckholen
  if (exePath && !fs.existsSync(exePath) && fs.existsSync(`${exePath}.bak`)) { try { fs.renameSync(`${exePath}.bak`, exePath); } catch { /* bleibt fehlend */ } }
  if (!exePath || !fs.existsSync(exePath)) return res('missing');
  const before = await run(exePath, tool.versionArgs, { timeoutMs: 30000, signal });
  const from = versionIn(`${before.stdout || ''} ${before.stderr || ''}`);
  const meta = await fetchImpl(`https://api.github.com/repos/${tool.repo}/releases/latest`, { headers: { ...HEAD, Accept: 'application/vnd.github+json' }, signal: timeout(30000, signal) });
  if (!meta.ok) return res('failed', { from, error: `GitHub HTTP ${meta.status}` });
  const rel = await meta.json();
  const to = String(rel.tag_name || '').replace(/^v/, '');
  if (!to || (from && !isNewer(to, from))) return res('current', { from, to: to || null });
  const assets = rel.assets || [];
  const asset = assets.find((a) => tool.asset.test(a.name));
  const sums = assets.find((a) => tool.sums.test(a.name));
  if (!asset || !sums) return res('failed', { from, to, error: 'Datei im Release nicht gefunden' });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `vigil-up-${tool.id}-`));
  const bak = `${exePath}.bak`;
  let swapped = false;
  try {
    const s = await fetchImpl(sums.browser_download_url, { headers: HEAD, signal: timeout(30000, signal) });
    if (!s.ok) return res('failed', { from, to, error: `Prüfsummen HTTP ${s.status}` });
    const want = checksumFor(await s.text(), asset.name);
    if (!want) return res('failed', { from, to, error: 'Keine Prüfsumme für diese Datei' });
    const file = path.join(tmp, asset.name);
    const got = await download(asset.browser_download_url, file, fetchImpl, signal);
    if (got !== want) return res('failed', { from, to, error: 'Prüfsumme stimmt nicht' });
    const exeName = path.basename(exePath);
    let fresh = file;
    if (!/\.exe$/i.test(asset.name)) {
      const out = path.join(tmp, 'x');
      fs.mkdirSync(out);
      const x = await run(TAR, ['-xf', file, '-C', out], { timeoutMs: 120000, signal });
      if (!x.ok) return res('failed', { from, to, error: 'Entpacken fehlgeschlagen' });
      fresh = findFile(out, exeName);
      if (!fresh) return res('failed', { from, to, error: 'Programm nicht im Paket' });
    }
    // Umbenennen klappt auch, wenn das alte Programm gerade laeuft
    await withRetry(() => fs.renameSync(exePath, bak));
    swapped = true;
    await withRetry(() => fs.copyFileSync(fresh, exePath));
    const check = await run(exePath, tool.versionArgs, { timeoutMs: 60000, signal });
    const now = versionIn(`${check.stdout || ''} ${check.stderr || ''}`);
    if (!now || isNewer(to, now)) {
      await withRetry(() => fs.copyFileSync(bak, exePath));
      return res('rolled-back', { from, to, error: 'Die neue Datei lief nicht (eventuell von Windows blockiert). Die alte bleibt in Betrieb.' });
    }
    return res('updated', { from, to: now });
  } catch (e) {
    if (swapped) { try { await withRetry(() => fs.copyFileSync(bak, exePath)); } catch { /* alte Datei bleibt als .bak */ } }
    return res('failed', { from, to, error: e.message });
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* egal */ }
    // Die Sicherung nur loeschen, wenn wieder ein Programm am Platz ist
    try { if (fs.existsSync(bak) && fs.existsSync(exePath)) fs.unlinkSync(bak); } catch { /* egal */ }
  }
}

// nmap: Nur der Installer ist aktuell; er ist signiert und laeuft still durch, Windows fragt einmal nach
// Administratorrechten. Lehnt der Nutzer ab, fragt Vigil eine Woche lang nicht erneut.
async function updateNmap(exePath, { run, fetchImpl = fetch, signal, lastAttempt = 0, now = Date.now(), onPrompt = () => {} } = {}) {
  const res = (status, extra = {}) => ({ id: 'nmap', status, ...extra });
  const verOf = (r) => (String(r.stdout || '').match(/Nmap version (\d+(?:\.\d+)+)/i) || [])[1] || null;
  const before = await run(exePath, ['--version'], { timeoutMs: 20000, signal });
  if (!before.ok) return res('missing');
  const from = verOf(before);
  const page = await fetchImpl('https://nmap.org/download.html', { headers: HEAD, signal: timeout(30000, signal) });
  if (!page.ok) return res('failed', { from, error: `nmap.org HTTP ${page.status}` });
  const to = (String(await page.text()).match(/nmap-(\d+(?:\.\d+)+)-setup\.exe/) || [])[1];
  if (!to) return res('failed', { from, error: 'Version auf nmap.org nicht gefunden' });
  if (from && !isNewer(to, from)) return res('current', { from, to });
  if (now - lastAttempt < RETRY_NMAP_MS) return res('waiting', { from, to });
  const name = `nmap-${to}-setup.exe`;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-up-nmap-'));
  try {
    const d = await fetchImpl(`https://nmap.org/dist/sigs/${name}.digest.txt`, { headers: HEAD, signal: timeout(30000, signal) });
    if (!d.ok) return res('failed', { from, to, error: `Prüfsumme HTTP ${d.status}` });
    const want = nmapDigest(await d.text());
    if (!want) return res('failed', { from, to, error: 'Prüfsumme nicht lesbar' });
    const file = path.join(tmp, name);
    const got = await download(`https://nmap.org/dist/${name}`, file, fetchImpl, signal);
    if (got !== want) return res('failed', { from, to, error: 'Prüfsumme stimmt nicht' });
    const q = file.replace(/'/g, "''");
    const sig = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', `$s=Get-AuthenticodeSignature -LiteralPath '${q}'; $s.Status.ToString(); $s.SignerCertificate.Subject`], { timeoutMs: 60000, signal });
    if (!/^Valid/m.test(sig.stdout || '') || !/(Nmap Software|Insecure\.Com)/i.test(sig.stdout || '')) return res('failed', { from, to, error: 'Signatur des Installers nicht gültig' });
    onPrompt(to);
    const inst = await run('powershell', ['-NoProfile', '-NonInteractive', '-Command', `$p=Start-Process -FilePath '${q}' -ArgumentList '/S' -Verb RunAs -Wait -PassThru; exit $p.ExitCode`], { timeoutMs: 15 * 60 * 1000, signal });
    const v = verOf(await run(exePath, ['--version'], { timeoutMs: 20000, signal }));
    if (v && !isNewer(to, v)) return res('updated', { from, to: v, attempted: true });
    return res('failed', { from, to, attempted: true, error: inst.ok ? 'Version unverändert' : 'Administratorrechte nicht erteilt oder Installation abgebrochen' });
  } catch (e) {
    return res('failed', { from, to, error: e.message });
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* egal */ }
  }
}

// retire.js liegt als globales npm-Paket vor; nur aktualisieren, wenn es schon installiert ist
const RETIRE_PKG = path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'npm', 'node_modules', 'retire', 'package.json');
const pkgVersion = (file) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')).version || null; } catch { return null; } };
async function updateRetire({ run, signal, pkgFile = RETIRE_PKG } = {}) {
  const from = pkgVersion(pkgFile);
  if (!from) return null;
  const r = await run('npm install -g retire@latest --no-audit --no-fund', [], { timeoutMs: 10 * 60 * 1000, signal, shell: true });
  if (!r.ok) return { id: 'retire.js', status: 'failed', from, error: String(r.stderr || '').trim().slice(0, 200) };
  const to = pkgVersion(pkgFile);
  return to && to !== from ? { id: 'retire.js', status: 'updated', from, to } : { id: 'retire.js', status: 'current' };
}

async function updatePackaged({ run, signal, retirePkg } = {}) {
  const out = [];
  const ret = await updateRetire({ run, signal, pkgFile: retirePkg });
  if (ret) out.push(ret);
  const pipx = await run('pipx', ['list', '--short'], { timeoutMs: 60000, signal });
  if (!pipx.ok) return out;
  for (const id of PIPX_TOOLS) {
    if (!new RegExp(`^${id}\\b`, 'm').test(pipx.stdout || '')) continue;
    const r = await run('pipx', ['upgrade', id], { timeoutMs: 10 * 60 * 1000, signal });
    const m = String(r.stdout || '').match(/upgraded .*? from (\S+) to (\S+)/);
    out.push(r.ok ? (m ? { id, status: 'updated', from: m[1], to: m[2] } : { id, status: 'current' }) : { id, status: 'failed', error: String(r.stderr || '').trim().slice(0, 200) });
  }
  return out;
}

// Vigil selbst, wenn es aus einer Git-Kopie laeuft: nur vorspulen, nur auf main und nur ohne eigene
// Aenderungen. Wirksam beim naechsten Start.
async function updateSelf(dir, { run, signal } = {}) {
  const git = (args, t = 60000) => run('git', ['-C', dir, ...args], { timeoutMs: t, signal });
  if (!fs.existsSync(path.join(dir, '.git'))) return { id: 'vigil', status: 'skipped' };
  const branch = await git(['rev-parse', '--abbrev-ref', 'HEAD']);
  if (!branch.ok || String(branch.stdout).trim() !== 'main') return { id: 'vigil', status: 'skipped', error: 'nicht auf main' };
  const dirty = await git(['status', '--porcelain']);
  if (!dirty.ok || String(dirty.stdout).trim()) return { id: 'vigil', status: 'skipped', error: 'eigene Änderungen vorhanden' };
  const before = String((await git(['rev-parse', 'HEAD'])).stdout).trim();
  const fetched = await git(['fetch', '--quiet', 'origin', 'main'], 180000);
  if (!fetched.ok) return { id: 'vigil', status: 'failed', error: 'GitHub nicht erreichbar' };
  const pulled = await git(['merge', '--ff-only', '--quiet', 'origin/main']);
  if (!pulled.ok) return { id: 'vigil', status: 'skipped', error: 'eigene Commits vorhanden' };
  const after = String((await git(['rev-parse', 'HEAD'])).stdout).trim();
  if (before === after) return { id: 'vigil', status: 'current' };
  const changed = await git(['diff', '--name-only', before, after]);
  if (/^package(-lock)?\.json$/m.test(String(changed.stdout))) {
    const inst = await run('npm install --no-audit --no-fund', [], { timeoutMs: 15 * 60 * 1000, signal, cwd: dir, shell: true });
    if (!inst.ok) return { id: 'vigil', status: 'failed', error: 'Pakete konnten nicht aktualisiert werden' };
  }
  return { id: 'vigil', status: 'updated', restart: true, from: before.slice(0, 7), to: after.slice(0, 7) };
}

function readState(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; } }

// paths: { nuclei: exe, nmap: exe, … }; force = auch innerhalb eines Tages. Kein Fehler stoppt die uebrigen Werkzeuge.
async function runAll({ stateFile, paths, appDir, run, fetchImpl = fetch, signal, force = false, now = Date.now(), onDone = () => {}, onNmapPrompt = () => {} }) {
  const st = readState(stateFile);
  if (!force && st.lastCheck && now - st.lastCheck < DAY * 0.8) return { skipped: true, ...st };
  const results = [];
  const step = async (fn, id) => { try { const r = await fn(); if (Array.isArray(r)) results.push(...r); else if (r) results.push(r); } catch (e) { results.push({ id, status: 'failed', error: e.message }); } };
  for (const t of GITHUB_TOOLS) await step(() => updateGithubTool(t, paths[t.id], { run, fetchImpl, signal }), t.id);
  await step(() => updatePackaged({ run, signal }), 'pipx');
  let attempted = false;
  const nmapAttempt = st.nmapAttempt || 0;
  if (paths.nmap) await step(async () => { const r = await updateNmap(paths.nmap, { run, fetchImpl, signal, lastAttempt: force ? 0 : nmapAttempt, now, onPrompt: onNmapPrompt }); attempted = !!r.attempted; return r; }, 'nmap');
  if (appDir) await step(() => updateSelf(appDir, { run, signal }), 'vigil');
  const next = { lastCheck: now, nmapAttempt: attempted ? now : nmapAttempt, results };
  try { fs.writeFileSync(stateFile, JSON.stringify(next, null, 1)); } catch { /* naechstes Mal neu */ }
  onDone(next);
  return next;
}

module.exports = { withRetry, GITHUB_TOOLS, PIPX_TOOLS, isNewer, versionIn, checksumFor, nmapDigest, updateGithubTool, updateNmap, updatePackaged, updateSelf, runAll, readState };
