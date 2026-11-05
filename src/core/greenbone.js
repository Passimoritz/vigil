'use strict';

// Optionale Anbindung an die Greenbone Community Edition (OpenVAS) im Docker-Container.
// Vigil baut die Schwachstellentests nicht nach, sondern steuert den Scanner ueber dessen Protokoll (GMP)
// und uebernimmt die Ergebnisse als normale Befunde.
//
// Zugriff: gvm-cli im Dienst "gvm-tools" der offiziellen compose.yaml, ueber den Unix-Socket von gvmd,
// in der eigenen WSL-Umgebung (greenbone-setup.js). Das Passwort geht ueber stdin, nie ueber eine Befehlszeile.
//
// Schonend: Eigene Scan-Konfiguration "Vigil schonend" auf Basis von "Full and fast" ohne die Familien
// fuer Passwort-Rateversuche, Standard-Zugaenge und Denial of Service. Laesst sie sich nicht einrichten
// oder pruefen, startet KEIN Scan. Aufrufer prueft die Freigabe des Ziels (index.js).

const { spawn } = require('child_process');
const { normalizeFinding, cvssToSeverity, clampScore } = require('./schema');

const FULL_AND_FAST = 'daba56c8-73ec-11df-a475-002264764cea';
const OPENVAS_SCANNER = '08b69003-5fc2-4037-a479-93b440f2ec4b';
const ALL_IANA_TCP = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5';
const REPORT_XML = 'a994b278-1f62-11e1-96ac-406186ea4fc5';
const CONFIG_NAME = 'Vigil schonend';
const BANNED_FAMILIES = ['Brute force attacks', 'Default Accounts', 'Denial of Service'];
const MAX_FINDINGS = 500;

const xmlEsc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
const xmlUnesc = (s) => s.replace(/&(#x?[0-9a-f]+|lt|gt|amp|quot|apos);/gi, (m, e) => {
  if (e[0] === '#') { const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : ''; }
  return { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" }[e.toLowerCase()];
});

// Kleiner XML-Leser ohne DTD und ohne Entitaeten-Erweiterung (Antworten gelten als nicht vertrauenswuerdig).
function parseXml(src) {
  const root = { tag: '#root', attrs: {}, children: [], text: '' };
  const stack = [root];
  const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/([\w:.-]+)\s*>|<([\w:.-]+)((?:\s+[\w:.-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>/g;
  let last = 0, m;
  const addText = (t) => { if (t) stack[stack.length - 1].text += t; };
  while ((m = re.exec(src))) {
    addText(xmlUnesc(src.slice(last, m.index)));
    last = re.lastIndex;
    if (m[1] != null) addText(m[1]);
    else if (m[2]) { if (stack.length > 1 && stack[stack.length - 1].tag === m[2]) stack.pop(); }
    else if (m[3]) {
      const attrs = {};
      for (const a of (m[4] || '').matchAll(/([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[a[1]] = xmlUnesc(a[2] != null ? a[2] : a[3]);
      const node = { tag: m[3], attrs, children: [], text: '' };
      stack[stack.length - 1].children.push(node);
      if (!m[5] && stack.length < 64) stack.push(node);
    }
  }
  return root.children[0] || root;
}
const kid = (n, tag) => (n && n.children.find((c) => c.tag === tag)) || null;
const kids = (n, tag) => (n ? n.children.filter((c) => c.tag === tag) : []);
const txt = (n, tag) => { const k = kid(n, tag); return k ? k.text.trim() : ''; };

// Standard-Ausfuehrung: Hilfsskript in der WSL-Umgebung; Ausgabe auf 64 MB begrenzt.
function wslExec(args, { input, timeoutMs = 180000, signal } = {}) {
  return new Promise((resolve) => {
    let child;
    try { child = spawn('wsl', args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }); } catch (e) { resolve({ ok: false, code: -1, stdout: '', stderr: e.message }); return; }
    let out = '', err = '', done = false;
    const fin = (r) => { if (done) return; done = true; clearTimeout(timer); if (signal) signal.removeEventListener('abort', kill); resolve(r); };
    const kill = () => { try { child.kill(); } catch { /* schon weg */ } };
    const timer = setTimeout(() => { kill(); fin({ ok: false, code: -1, stdout: out, stderr: 'Zeitüberschreitung' }); }, timeoutMs);
    if (signal) { if (signal.aborted) kill(); else signal.addEventListener('abort', kill); }
    child.stdout.on('data', (d) => { if (out.length < 64 * 1024 * 1024) out += d; });
    child.stderr.on('data', (d) => { if (err.length < 64 * 1024) err += d; });
    child.on('error', (e) => fin({ ok: false, code: -1, stdout: out, stderr: e.code === 'ENOENT' ? 'WSL ist nicht verfügbar.' : e.message }));
    child.on('close', (code) => fin({ ok: code === 0, code, stdout: out, stderr: err }));
    child.stdin.on('error', () => {});
    child.stdin.end(input || '');
  });
}

function createClient({ user = 'admin', password = '', exec = wslExec, signal } = {}) {
  if (!/^[\w.@-]{1,64}$/.test(String(user))) throw new Error('Ungültiger Benutzername.');
  if (/[\r\n]/.test(String(password))) throw new Error('Ungültiges Passwort.');
  const { inDistro, BASE } = require('./greenbone-setup');
  return async function call(xml, { timeoutMs } = {}) {
    const r = await exec(inDistro([`${BASE}/gmp.sh`, String(user)]), { input: `${password}\n${xml}\n`, timeoutMs, signal });
    const at = (r.stdout || '').indexOf('<');
    if (!r.ok || at < 0) throw new Error(String(r.stderr || r.stdout || `WSL meldete Code ${r.code}`).trim().split(/\r?\n/).slice(-2).join(' ').slice(0, 300));
    const node = parseXml(r.stdout.slice(at));
    const st = String(node.attrs.status || '');
    if (st && !st.startsWith('2')) throw new Error(`Greenbone: ${node.attrs.status_text || st}`.slice(0, 300));
    return node;
  };
}

// Verbindungstest fuer die Einstellungen: Version, Feed-Stand, Anzahl der Tests.
async function status(call) {
  const v = await call('<get_version/>');
  const out = { ok: true, version: txt(v, 'version'), syncing: false, feeds: [], nvts: null };
  try {
    const f = await call('<get_feeds/>');
    for (const x of kids(f, 'feed')) {
      out.feeds.push({ type: txt(x, 'type'), version: txt(x, 'version') });
      if (kid(x, 'currently_syncing')) out.syncing = true;
    }
  } catch { /* aeltere Fassung: ohne Feed-Angaben */ }
  try {
    const n = await call('<get_nvt_families/>');
    const fam = kid(n, 'families');
    out.nvts = kids(fam, 'family').reduce((a, x) => a + (parseInt(txt(x, 'max_nvt_count'), 10) || 0), 0);
  } catch { /* egal */ }
  return out;
}

const familiesOf = (cfgNode) => kids(kid(cfgNode, 'families'), 'family').map((f) => ({ name: txt(f, 'name'), count: parseInt(txt(f, 'nvt_count'), 10) || 0 }));
const bannedActive = (fams) => fams.filter((f) => BANNED_FAMILIES.includes(f.name) && f.count > 0).map((f) => f.name);

async function ensureGentleConfig(call) {
  const list = await call(`<get_configs filter="name=&quot;${xmlEsc(CONFIG_NAME)}&quot; rows=1" families="1"/>`);
  let cfg = kids(list, 'config').find((c) => txt(c, 'name') === CONFIG_NAME);
  let id = cfg && cfg.attrs.id;
  if (!id) {
    const made = await call(`<create_config><copy>${FULL_AND_FAST}</copy><name>${xmlEsc(CONFIG_NAME)}</name><comment>Von Vigil angelegt: ohne Rateversuche, Standard-Zugaenge und DoS</comment></create_config>`);
    id = made.attrs.id;
    if (!id) throw new Error('Scan-Konfiguration konnte nicht angelegt werden.');
    cfg = null;
  }
  const read = async () => kids(await call(`<get_configs config_id="${xmlEsc(id)}" families="1"/>`), 'config')[0];
  if (!cfg) cfg = await read();
  if (bannedActive(familiesOf(cfg)).length || !familiesOf(cfg).length) {
    const keep = familiesOf(cfg).filter((f) => !BANNED_FAMILIES.includes(f.name));
    if (!keep.length) throw new Error('Greenbone hat noch keine Tests geladen (Feed-Abgleich läuft vermutlich noch).');
    await call(`<modify_config config_id="${xmlEsc(id)}"><family_selection><growing>1</growing>${keep.map((f) => `<family><name>${xmlEsc(f.name)}</name><all>1</all><growing>1</growing></family>`).join('')}</family_selection></modify_config>`);
    const still = bannedActive(familiesOf(await read()));
    if (still.length) throw new Error(`Scan-Konfiguration enthält weiter: ${still.join(', ')} – Scan nicht gestartet.`);
  }
  // Sichere Pruefungen sind Standard; ausdruecklich setzen schadet nicht ("yes" als base64).
  try { await call(`<modify_config config_id="${xmlEsc(id)}"><preference><name>safe_checks</name><value>eWVz</value></preference></modify_config>`); } catch { /* Standardwert bleibt */ }
  return id;
}

async function findOrCreate(call, kind, name, createXml) {
  const list = await call(`<get_${kind}s filter="name=&quot;${xmlEsc(name)}&quot; rows=1"/>`);
  const hit = kids(list, kind).find((x) => txt(x, 'name') === name);
  if (hit && hit.attrs.id) return hit;
  const made = await call(createXml);
  if (!made.attrs.id) throw new Error(`Greenbone: ${kind} konnte nicht angelegt werden.`);
  return { attrs: { id: made.attrs.id }, children: [], text: '', tag: kind, created: true };
}

function tagsOf(nvt) {
  const out = {};
  for (const part of txt(nvt, 'tags').split('|')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim(); }
  return out;
}

function resultToFinding(r, host) {
  const nvt = kid(r, 'nvt');
  const tags = tagsOf(nvt);
  const score = clampScore(parseFloat(txt(r, 'severity')));
  if (score == null || score <= 0) return null; // Reine Protokollmeldungen sind kein Befund
  const cves = [...new Set(kids(kid(nvt, 'refs'), 'ref').filter((x) => /^cve$/i.test(x.attrs.type || '')).map((x) => x.attrs.id).filter((x) => /^CVE-\d{4}-\d+$/i.test(x || '')))];
  const qod = parseInt(txt(kid(r, 'qod'), 'value'), 10);
  const port = txt(r, 'port');
  const oid = (nvt && nvt.attrs.oid) || '';
  const links = cves.slice(0, 5).map((c) => ({ label: c, url: `https://nvd.nist.gov/vuln/detail/${c}` }));
  const solution = txt(nvt, 'solution') || tags.solution || '';
  return normalizeFinding({
    ruleId: `greenbone-${oid || txt(r, 'name').slice(0, 60)}`,
    title: (txt(r, 'name') || txt(nvt, 'name') || 'Greenbone-Befund').slice(0, 200) + (cves[0] ? ` (${cves[0]})` : ''),
    severity: cvssToSeverity(score), cvss: score,
    category: cves.length ? 'Dependencies' : 'Config',
    location: `${host}${port && port !== 'general/tcp' ? `:${port.split('/')[0]}` : ''}`,
    locationDetail: port || undefined,
    description: (tags.summary || txt(r, 'description') || '').slice(0, 2000),
    impact: (tags.impact || tags.insight || '').slice(0, 1500) || undefined,
    remediation: solution.slice(0, 1500) || 'Siehe Hinweise des Herstellers; betroffene Software aktualisieren oder den Dienst einschränken.',
    evidence: txt(r, 'description').slice(0, 600) || undefined,
    confidence: qod >= 80 ? 'high' : 'medium', links, sourceModule: 'greenbone',
    reachability: 'Vom Scanner über das Netzwerk festgestellt.',
  }, 'greenbone');
}

function parseReport(node, host) {
  const report = kid(kid(node, 'report'), 'report') || kid(node, 'report');
  const results = kids(kid(report, 'results'), 'result');
  return results.map((r) => resultToFinding(r, host)).filter(Boolean).slice(0, MAX_FINDINGS);
}

const validHost = (h) => /^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$/i.test(h) || /^[0-9a-f:]{2,45}$/i.test(h);
const sleep = (ms, signal) => new Promise((res) => { const t = setTimeout(res, ms); if (signal) signal.addEventListener('abort', () => { clearTimeout(t); res(); }, { once: true }); });

// Scan eines freigegebenen Hosts bis zum Ende. Abbruch oder Zeitgrenze stoppt die Aufgabe im Scanner.
async function scanHost(host, call, { signal, onProgress = () => {}, pollMs = 30000, maxMs = 6 * 60 * 60 * 1000, readyWaitMs = 0 } = {}) {
  if (!validHost(host)) return { ran: false, findings: [], notes: [`Greenbone: ungültiger Host ${host}.`] };
  const say = (message, done) => onProgress({ phase: 'active', message, ...(done != null ? { total: 100, done } : {}) });
  say(`Greenbone: Scan für ${host} wird vorbereitet …`);
  let st = null;
  // Direkt nach dem Start ist gvmd noch nicht erreichbar, und nach einem Update gleicht es seine Tests ab
  for (const t0 = Date.now(); ;) {
    try { st = await status(call); if (!st.syncing) break; } catch (e) { if (Date.now() - t0 >= readyWaitMs) throw e; }
    if (Date.now() - t0 >= readyWaitMs || (signal && signal.aborted)) break;
    say('Greenbone startet und gleicht seine Tests ab …');
    await sleep(pollMs, signal);
  }
  if (st.syncing) return { ran: false, findings: [], notes: ['Greenbone gleicht gerade seine Tests ab – Scan übersprungen, bitte später erneut.'] };
  const configId = await ensureGentleConfig(call);
  const name = `Vigil ${host}`;
  const target = await findOrCreate(call, 'target', name, `<create_target><name>${xmlEsc(name)}</name><hosts>${xmlEsc(host)}</hosts><port_list id="${ALL_IANA_TCP}"/></create_target>`);
  const task = await findOrCreate(call, 'task', name, `<create_task><name>${xmlEsc(name)}</name><comment>Von Vigil angelegt</comment><config id="${xmlEsc(configId)}"/><target id="${xmlEsc(target.attrs.id)}"/><scanner id="${OPENVAS_SCANNER}"/></create_task>`);
  const taskId = task.attrs.id;
  // Bestehende Aufgabe aus einer aelteren Fassung: Konfiguration muss die schonende sein
  const cfgOfTask = kid(task, 'config');
  if (cfgOfTask && cfgOfTask.attrs.id && cfgOfTask.attrs.id !== configId) return { ran: false, findings: [], notes: [`Greenbone: Die Aufgabe „${name}“ nutzt eine andere Scan-Konfiguration – Scan nicht gestartet.`] };
  const started = await call(`<start_task task_id="${xmlEsc(taskId)}"/>`);
  const reportId = txt(started, 'report_id');
  if (!reportId) throw new Error('Greenbone hat keinen Bericht gemeldet.');
  const stop = () => call(`<stop_task task_id="${xmlEsc(taskId)}"/>`).catch(() => {});
  const t0 = Date.now();
  let state = 'Requested';
  for (;;) {
    if (signal && signal.aborted) { await stop(); return { ran: false, findings: [], notes: ['Greenbone: Scan abgebrochen.'] }; }
    if (Date.now() - t0 > maxMs) { await stop(); return { ran: false, findings: [], notes: ['Greenbone: Zeitgrenze erreicht, Scan gestoppt.'] }; }
    const info = kids(await call(`<get_tasks task_id="${xmlEsc(taskId)}"/>`), 'task')[0];
    state = txt(info, 'status');
    const pct = parseInt(txt(info, 'progress'), 10);
    say(`Greenbone: ${host} – ${state}${pct >= 0 ? ` (${pct} %)` : ''}`, pct >= 0 ? pct : undefined);
    if (state === 'Done') break;
    if (['Stopped', 'Interrupted'].includes(state)) return { ran: false, findings: [], notes: [`Greenbone: Scan ${state === 'Stopped' ? 'gestoppt' : 'unterbrochen'}.`] };
    await sleep(pollMs, signal);
  }
  const rep = await call(`<get_reports report_id="${xmlEsc(reportId)}" format_id="${REPORT_XML}" details="1" ignore_pagination="1" filter="apply_overrides=0 min_qod=70 rows=${MAX_FINDINGS} sort-reverse=severity"/>`, { timeoutMs: 600000 });
  const findings = parseReport(rep, host);
  return { ran: true, findings, notes: [`Greenbone: ${findings.length} Befund(e) auf ${host}${st.nvts ? ` (${st.nvts} Tests verfügbar)` : ''}.`] };
}

module.exports = { parseXml, createClient, wslExec, status, ensureGentleConfig, scanHost, parseReport, resultToFinding, BANNED_FAMILIES, CONFIG_NAME, validHost };
