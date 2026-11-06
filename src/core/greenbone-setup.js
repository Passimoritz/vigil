'use strict';

// Greenbone Community Edition ohne Docker Desktop: eigene WSL-Umgebung "vigil-gvm" mit Docker Engine.
// Keine Lizenzabfrage und keine Administratorrechte, solange WSL schon vorhanden ist. Andere
// WSL-Umgebungen des Nutzers bleiben unberuehrt.
//
// Gestartet wird nur nach Zustimmung des Nutzers (electron/main.js): Es werden viele GB geladen.
//
// Speicher: Greenbone laeuft nur waehrend eines Scans (Sitzung). Danach wird die Umgebung beendet und
// belegt keinen Arbeitsspeicher mehr. Jeder Schritt der Einrichtung prueft zuerst, ob er schon erledigt
// ist; sie laesst sich also jederzeit fortsetzen.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');

const DISTRO = 'vigil-gvm';
const IMAGE = 'Ubuntu-24.04';
const BASE = '/opt/vigil';
const COMPOSE = `${BASE}/compose.yaml`;
const COMPOSE_URL = 'https://greenbone.github.io/docs/latest/_static/compose.yaml';
const MIN_RAM_GB = 4;
const AUTO_MIN_RAM_GB = 8; // Darunter nur auf ausdruecklichen Wunsch: Greenbone wuerde den Rechner ausbremsen
const MIN_DISK_GB = 40;
const DATA_SERVICES = 'notus-data vulnerability-tests scap-data dfn-cert-data cert-bund-data report-formats data-objects';

// Hilfsskripte in der Umgebung: Zugangsdaten kommen ueber stdin, nie ueber eine Befehlszeile.
const GMP_SH = `#!/bin/sh
exec docker compose -f ${COMPOSE} run --rm -T --no-deps -e GMP_USER="$1" gvm-tools sh -c 'IFS= read -r P; X=$(cat); exec gvm-cli --gmp-username "$GMP_USER" --gmp-password "$P" socket --xml "$X"'
`;
const SETPW_SH = `#!/bin/sh
exec docker compose -f ${COMPOSE} exec -T -u gvmd gvmd sh -c 'IFS= read -r P; exec gvmd --user=admin --new-password="$P"'
`;
const INSTALL_DOCKER = `set -e
command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && exit 0
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends docker.io docker-compose-v2 >/dev/null
systemctl enable --now docker >/dev/null 2>&1 || service docker start
`;
// Tests hoechstens einmal am Tag aktualisieren, Greenbone selbst und das System der Umgebung einmal pro Woche.
// Scheitert ein Update (kein Netz), laeuft der Scan mit dem vorhandenen Stand.
const START_SH = `set -e
if [ -z "$(find ${BASE}/.weekly -mmin -10080 2>/dev/null)" ]; then
  export DEBIAN_FRONTEND=noninteractive
  { apt-get update -qq && apt-get upgrade -y -qq >/dev/null; } || true
  systemctl start docker 2>/dev/null || service docker start
  { docker compose -f ${COMPOSE} pull -q && touch ${BASE}/.weekly ${BASE}/.feed; } || true
fi
systemctl start docker 2>/dev/null || service docker start
if [ -z "$(find ${BASE}/.feed -mmin -1440 2>/dev/null)" ]; then
  { docker compose -f ${COMPOSE} pull -q ${DATA_SERVICES} && touch ${BASE}/.feed; } || true
fi
docker compose -f ${COMPOSE} up -d --quiet-pull
`;

// Schritte fuer die Anzeige, in dieser Reihenfolge
const STEPS = [
  { id: 'distro', label: 'WSL-Umgebung anlegen' },
  { id: 'docker', label: 'Docker Engine einrichten' },
  { id: 'compose', label: 'Konfiguration laden' },
  { id: 'pull', label: 'Greenbone herunterladen' },
  { id: 'up', label: 'Greenbone starten' },
  { id: 'password', label: 'Eigenes Passwort setzen' },
  { id: 'sync', label: 'Tests laden' },
];
// Anzahl verschiedener Images in der compose.yaml = Pakete im Download
const countImages = (text) => new Set([...String(text).matchAll(/^\s+image:\s*(\S+)/gm)].map((m) => m[1])).size;
const IMAGE_COUNT_SH = `docker image ls --format '{{.Repository}}' | grep -v '<none>' | sort -u | wc -l; docker system df --format '{{.Type}} {{.Size}}' | grep Images\n`;
// "12\nImages 8.424GB" -> { done: 12, size: '8,4 GB' }
function parseImageCount(out) {
  const lines = String(out || '').trim().split(/\r?\n/);
  const done = parseInt(lines[0], 10);
  const m = (lines[1] || '').match(/([\d.]+)\s*([kMGT]?B)/);
  return { done: Number.isNaN(done) ? null : done, size: m ? `${Number(m[1]).toFixed(1).replace('.', ',')} ${m[2]}` : null };
}

const heredoc = (file, text, mode) => `cat > ${file} <<'VIGIL_EOF'\n${text}\nVIGIL_EOF\n${mode ? `chmod ${mode} ${file}\n` : ''}`;

// Programm starten und warten; Ausgabe begrenzt, Abbruch und Zeitgrenze wie bei den anderen Werkzeugen.
function runCmd(cmd, args, { input, timeoutMs = 120000, signal, cwd, shell = false } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn(cmd, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'], cwd, shell, env: { ...process.env, WSL_UTF8: '1' } }); } catch (e) { resolve({ ok: false, code: -1, stdout: '', stderr: e.message }); return; }
    let out = '', err = '', done = false;
    const kill = () => { try { child.kill(); } catch { /* schon weg */ } };
    const fin = (r) => { if (done) return; done = true; clearTimeout(timer); if (signal) signal.removeEventListener('abort', kill); resolve(r); };
    const timer = setTimeout(() => { kill(); fin({ ok: false, code: -1, stdout: out, stderr: 'Zeitüberschreitung' }); }, timeoutMs);
    if (signal) { if (signal.aborted) kill(); else signal.addEventListener('abort', kill); }
    child.stdout.on('data', (d) => { if (out.length < 1024 * 1024) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 256 * 1024) err += d; });
    child.on('error', (e) => fin({ ok: false, code: -1, stdout: out, stderr: e.code === 'ENOENT' ? `${cmd} wurde nicht gefunden.` : e.message }));
    child.on('close', (code) => fin({ ok: code === 0, code, stdout: out, stderr: err }));
    child.stdin.on('error', () => {});
    child.stdin.end(input || '');
  });
}

const inDistro = (args) => ['-d', DISTRO, '-u', 'root', '--exec', ...args];
const lastLines = (r) => String(r.stderr || r.stdout || '').replace(/\0/g, '').trim().split(/\r?\n/).slice(-2).join(' ').slice(0, 300);

// Haelt die Umgebung am Leben: Ohne offene Sitzung beendet WSL sie von selbst.
function defaultKeepAlive() {
  const child = spawn('wsl', inDistro(['sleep', '86400']), { windowsHide: true, stdio: 'ignore' });
  child.on('error', () => {});
  return () => { try { child.kill(); } catch { /* schon weg */ } };
}

function prerequisites({ platform = process.platform, totalMem = os.totalmem(), freeDisk, auto = false } = {}) {
  if (platform !== 'win32') return { ok: false, error: 'Die automatische Einrichtung gibt es nur unter Windows.' };
  const ram = totalMem / 2 ** 30;
  const need = auto ? AUTO_MIN_RAM_GB : MIN_RAM_GB;
  if (ram < need - 0.5) return { ok: false, error: `Greenbone braucht mindestens ${need} GB Arbeitsspeicher, hier sind es ${Math.round(ram)} GB.` };
  let free = freeDisk;
  if (free == null) { try { const s = fs.statfsSync(process.env.SystemDrive ? `${process.env.SystemDrive}\\` : 'C:\\'); free = s.bavail * s.bsize; } catch { free = null; } }
  if (free != null && free / 2 ** 30 < MIN_DISK_GB) return { ok: false, error: `Greenbone braucht mindestens ${MIN_DISK_GB} GB freien Speicher, hier sind es ${Math.round(free / 2 ** 30)} GB.` };
  return { ok: true };
}

const validCompose = (text) => /^name:\s*greenbone-community-edition\s*$/m.test(text) && /^\s{2}gvm-tools:/m.test(text) && /^\s{2}gvmd:/m.test(text);
const distroExists = async (run) => { const r = await run('wsl', ['-l', '-q'], { timeoutMs: 30000 }); return String(r.stdout || '').replace(/\0/g, '').split(/\r?\n/).some((l) => l.trim() === DISTRO); };

// Ergebnis: { ok, state: 'ready' | 'needs_wsl' | 'error', error? }. onPassword speichert sofort, damit ein
// Neustart mitten im Abgleich der Tests das Passwort nicht verliert. checkReady(password) -> status()
// force: alles neu laden ("Einrichtung wiederholen"). Sonst zaehlt, was in der Umgebung schon liegt: Der Stand steht
// dort auf der Platte und ueberlebt Neustarts, Pausen und Abstuerze.
async function runSetup({ password = '', auto = false, force = false, signal, onStep = () => {}, onPassword = () => {}, deps = {} }) {
  const { run = runCmd, keepAlive = defaultKeepAlive, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), prereq = prerequisites, waitMs = 10 * 60 * 1000, syncWaitMs = 8 * 60 * 60 * 1000, pollMs = 15000, progressMs = 8000, checkReady } = deps;
  const fail = (error) => ({ ok: false, state: 'error', error });
  const stopped = () => signal && signal.aborted;
  const p = prereq({ auto });
  if (!p.ok) return fail(p.error);
  const wsl = (args, o = {}) => run('wsl', inDistro(args), { ...o, signal });
  const script = (text, o = {}) => wsl(['bash', '-s'], { ...o, input: text });

  // 1. WSL und eigene Umgebung
  const st = await run('wsl', ['--status'], { timeoutMs: 30000 });
  if (!st.ok) return { ok: false, state: 'needs_wsl', error: 'WSL fehlt. Einmal „wsl --install“ als Administrator ausführen und neu starten, dann setzt Vigil die Einrichtung fort.' };
  if (!(await distroExists(run))) {
    onStep({ step: 'distro', message: 'Lege die eigene WSL-Umgebung an …' });
    const made = await run('wsl', ['--install', IMAGE, '--name', DISTRO, '--no-launch'], { timeoutMs: 30 * 60 * 1000, signal });
    if (stopped()) return fail('Abgebrochen.');
    if (!made.ok || !(await distroExists(run))) return fail(`Die WSL-Umgebung konnte nicht angelegt werden (${lastLines(made)}). Eventuell hilft „wsl --update“.`);
  }
  const release = keepAlive();
  try {
    // 2. Docker Engine in der Umgebung
    onStep({ step: 'docker', message: 'Richte Docker Engine ein …' });
    const dock = await script(INSTALL_DOCKER, { timeoutMs: 30 * 60 * 1000 });
    if (stopped()) return fail('Abgebrochen.');
    if (!dock.ok) return fail(`Docker Engine konnte nicht eingerichtet werden (${lastLines(dock)}).`);

    // 3. Offizielle compose.yaml und Hilfsskripte
    onStep({ step: 'compose', message: 'Lade die Greenbone-Konfiguration …' });
    let text;
    // Schon heruntergeladen? Dann weiter, auch ohne Netz
    const have = force ? null : await script(`[ -x ${BASE}/gmp.sh ] && [ -x ${BASE}/setpw.sh ] && cat ${COMPOSE}\n`, { timeoutMs: 60000 });
    if (have && have.ok && validCompose(have.stdout || '')) text = have.stdout;
    else try {
      const r = await fetchImpl(COMPOSE_URL, { redirect: 'error', signal: signal ? AbortSignal.any([AbortSignal.timeout(60000), signal]) : AbortSignal.timeout(60000) });
      if (!r.ok) return fail(`Greenbone-Konfiguration nicht geladen (HTTP ${r.status}).`);
      text = await r.text();
    } catch (e) { return fail(`Greenbone-Konfiguration nicht geladen (${e.message}).`); }
    if (text.length > 512 * 1024 || !validCompose(text) || text.includes('VIGIL_EOF')) return fail('Die heruntergeladene Greenbone-Konfiguration sieht nicht wie erwartet aus.');
    const wrote = await script(`set -e\nmkdir -p ${BASE}\n${heredoc(COMPOSE, text.replace(/\n$/, ''))}${heredoc(`${BASE}/gmp.sh`, GMP_SH, '700')}${heredoc(`${BASE}/setpw.sh`, SETPW_SH, '700')}`, { timeoutMs: 60000 });
    if (!wrote.ok) return fail(`Greenbone-Konfiguration nicht gespeichert (${lastLines(wrote)}).`);

    // 4. Images laden und starten
    const totalImages = countImages(text);
    // .feed entsteht erst nach einem vollstaendigen Download
    const pulledBefore = !force && /VIGIL_PULLED/.test((await script(`[ -f ${BASE}/.feed ] && echo VIGIL_PULLED; true\n`, { timeoutMs: 60000 })).stdout || '');
    if (!pulledBefore) {
    onStep({ step: 'pull', message: 'Greenbone wird heruntergeladen …', done: 0, total: totalImages });
    // Fortschritt aus dem, was schon fertig da ist: unabhaengig vom Ausgabeformat von docker compose
    const watch = setInterval(async () => {
      const c = await script(IMAGE_COUNT_SH, { timeoutMs: 20000 }).catch(() => null);
      const n = c && c.ok ? parseImageCount(c.stdout) : null;
      if (n && n.done != null && !stopped()) onStep({ step: 'pull', message: 'Greenbone wird heruntergeladen …', done: Math.min(n.done, totalImages), total: totalImages, size: n.size });
    }, progressMs);
    const pulled = await script(`set -e\nsystemctl start docker 2>/dev/null || service docker start\ndocker compose -f ${COMPOSE} pull -q\ntouch ${BASE}/.feed ${BASE}/.weekly\n`, { timeoutMs: 6 * 60 * 60 * 1000 }).finally(() => clearInterval(watch));
    if (stopped()) return fail('Abgebrochen.');
    if (!pulled.ok) return fail(`Greenbone konnte nicht geladen werden (${lastLines(pulled)}).`);
    }
    onStep({ step: 'up', message: 'Starte Greenbone …' });
    const started = await script(`docker compose -f ${COMPOSE} up -d --quiet-pull\n`, { timeoutMs: 30 * 60 * 1000 });
    if (stopped()) return fail('Abgebrochen.');
    if (!started.ok) return fail(`Greenbone konnte nicht gestartet werden (${lastLines(started)}).`);

    // 5. Standard-Passwort "admin" sofort durch ein zufaelliges ersetzen
    let pw = password;
    if (!pw) {
      onStep({ step: 'password', message: 'Setze ein eigenes Passwort …' });
      const fresh = crypto.randomBytes(24).toString('base64url');
      let set = { ok: false };
      for (const t0 = Date.now(); !set.ok && Date.now() - t0 < waitMs && !stopped();) {
        set = await wsl([`${BASE}/setpw.sh`], { input: `${fresh}\n`, timeoutMs: 120000 });
        if (!set.ok) await sleep(pollMs);
      }
      if (stopped()) return fail('Abgebrochen.');
      if (!set.ok) return fail(`Das Passwort konnte nicht gesetzt werden (${lastLines(set)}).`);
      pw = fresh;
      onPassword(pw);
    }

    // 6. Erst fertig, wenn die Tests geladen sind (beim ersten Mal kann das Stunden dauern)
    if (checkReady) {
      onStep({ step: 'sync', message: 'Beim ersten Mal kann das Stunden dauern. Du kannst Vigil normal weiter benutzen.' });
      let info = null;
      for (const t0 = Date.now(); Date.now() - t0 < syncWaitMs && !stopped();) {
        try { info = await checkReady(pw); } catch { info = null; }
        if (info && !info.syncing && info.nvts) break;
        if (info && info.nvts) onStep({ step: 'sync', message: 'Beim ersten Mal kann das Stunden dauern. Du kannst Vigil normal weiter benutzen.', count: info.nvts });
        info = null;
        await sleep(pollMs * 4);
      }
      if (stopped()) return fail('Abgebrochen.');
      if (!info) return fail('Greenbone ist nach 8 Stunden noch nicht fertig. „Einrichtung fortsetzen“ macht an derselben Stelle weiter.');
    }
    return { ok: true, state: 'ready', nvts: undefined };
  } finally {
    release();
    await run('wsl', ['--terminate', DISTRO], { timeoutMs: 60000 }).catch(() => {});
  }
}

// Sitzung fuer Scans: startet die Umgebung und Greenbone; stop() gibt den Arbeitsspeicher wieder frei.
async function startSession({ signal, deps = {} } = {}) {
  const { run = runCmd, keepAlive = defaultKeepAlive } = deps;
  const release = keepAlive();
  const stop = async () => { release(); await run('wsl', ['--terminate', DISTRO], { timeoutMs: 60000 }).catch(() => {}); };
  const r = await run('wsl', inDistro(['bash', '-s']), { input: START_SH, timeoutMs: 90 * 60 * 1000, signal });
  if (!r.ok) { await stop(); return { ok: false, error: lastLines(r) || 'Greenbone konnte nicht gestartet werden.' }; }
  return { ok: true, stop };
}

// Gibt den belegten Plattenplatz frei. Betrifft nur die eigene Umgebung.
async function removeSetup({ deps = {} } = {}) {
  const { run = runCmd } = deps;
  if (!(await distroExists(run))) return { ok: true };
  const r = await run('wsl', ['--unregister', DISTRO], { timeoutMs: 5 * 60 * 1000 });
  return r.ok ? { ok: true } : { ok: false, error: lastLines(r) };
}

// Laeuft Greenbone in dieser Pruefung mit? Eingerichtet muss es immer sein. Die Wahl fuer den Lauf geht vor der Einstellung.
function greenboneActive(g, choice) {
  const c = g || {};
  if ((c.setup || {}).state !== 'ready') return false;
  return typeof choice === 'boolean' ? choice : !!c.enabled;
}

module.exports = { greenboneActive, STEPS, countImages, parseImageCount, DISTRO, COMPOSE_URL, GMP_SH, SETPW_SH, START_SH, BASE, inDistro, prerequisites, validCompose, runSetup, startSession, removeSetup, runCmd };
