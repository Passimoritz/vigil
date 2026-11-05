'use strict';

// Entfernte Systeme mit vom Nutzer hinterlegtem Zugang – nur lesend:
//  - Linux-Server per SSH (System-ssh, eigener Schluessel, festes Skript aus einer Erlaubt-Liste)
//  - Datenbanken (PostgreSQL, MySQL, MongoDB, Redis): kleine Protokoll-Abfragen ohne Login-Versuch,
//    Rechte-Abfragen nur mit der hinterlegten Verbindung und installierten Kommandozeilen-Clients
//  - Kubernetes ueber kubectl (aktueller Kontext, nur "get")

const fs = require('fs');
const net = require('net');
const tls = require('tls');
const { run, json, mk, cmpVer, isLocalHost, list, RISKY } = require('./common');
const eol = require('../eol');
const { cvssFromVector } = require('../cve');
const { cvssToSeverity } = require('../schema');

// --- Linux per SSH ---------------------------------------------------------------------
// Erlaubt-Liste: jede Zeile ist ein fester, nur lesender Befehl. Es wird nie etwas anderes geschickt.
const SSH_ALLOWED = [
  'export LANG=C LC_ALL=C',
  "echo '@@os'; grep -E '^(PRETTY_NAME|ID|VERSION_ID)=' /etc/os-release 2>/dev/null",
  "echo '@@updates'; if command -v apt-get >/dev/null 2>&1; then apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst' | awk '{n++; if (tolower($0) ~ /security/) s++} END {print n+0; print s+0}'; elif command -v dnf >/dev/null 2>&1; then dnf -q check-update 2>/dev/null | grep -c '[.]'; dnf -q updateinfo list --security 2>/dev/null | wc -l; elif command -v yum >/dev/null 2>&1; then yum -q check-update 2>/dev/null | grep -c '[.]'; echo 0; fi",
  "echo '@@reboot'; test -f /var/run/reboot-required && echo yes",
  "echo '@@sshd'; (sshd -T 2>/dev/null || cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null) | grep -iE '^[[:space:]]*(permitrootlogin|passwordauthentication|permitemptypasswords|x11forwarding|maxauthtries)[[:space:]]'",
  "echo '@@uid0'; awk -F: '$3==0{print $1}' /etc/passwd",
  "echo '@@emptypw'; awk -F: '$2==\"\"{print $1}' /etc/shadow 2>/dev/null",
  "echo '@@sudoers'; cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^[[:space:]]*#' | grep NOPASSWD",
  "echo '@@firewall'; if command -v ufw >/dev/null 2>&1; then ufw status 2>/dev/null | head -n 1; fi; if command -v firewall-cmd >/dev/null 2>&1; then echo \"firewalld: $(firewall-cmd --state 2>&1)\"; fi; if command -v nft >/dev/null 2>&1; then echo \"nft-input: $(nft list ruleset 2>/dev/null | grep -c 'hook input')\"; fi; iptables -S INPUT 2>/dev/null | head -n 3",
  "echo '@@listen'; (ss -tulnH 2>/dev/null || netstat -tuln 2>/dev/null)",
  // Installierte Pakete fuer den Abgleich mit OSV (Quellpaket und Version, wie OSV sie fuehrt)
  "echo '@@pkgs'; if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\n' 2>/dev/null | awk -F'\\t' '$1 ~ /^ii/ {print $2 \"\\t\" $3}' | sort -u | head -n 6000; elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\\n' 2>/dev/null | sort -u | head -n 6000; fi",
  "echo '@@end'",
];
const SSH_SCRIPT = SSH_ALLOWED.join('\n') + '\n';

function splitSections(text) {
  const out = {};
  let cur = null;
  for (const l of String(text || '').replace(/\r/g, '').split('\n')) {
    const m = l.match(/^@@(\w+)$/);
    if (m) { cur = m[1]; out[cur] = []; continue; }
    if (cur && l.trim()) out[cur].push(l);
  }
  return out;
}

// ID und Version aus /etc/os-release
function osOf(s) {
  const get = (k) => { const l = (s.os || []).find((x) => x.startsWith(`${k}=`)); return l ? l.slice(k.length + 1).replace(/^"|"$/g, '').trim() : ''; };
  return { id: get('ID').toLowerCase(), version: get('VERSION_ID'), pretty: get('PRETTY_NAME') };
}
// Name des Paketbestands bei OSV; null = OSV fuehrt diese Distribution nicht
function osvEcosystem({ id, version }) {
  if (!version) return null;
  const major = version.split('.')[0];
  if (id === 'debian') return `Debian:${major}`;
  if (id === 'ubuntu') return /^\d*[02468]\.04$/.test(version) ? `Ubuntu:${version}:LTS` : `Ubuntu:${version}`;
  if (id === 'rocky') return `Rocky Linux:${major}`;
  if (id === 'almalinux') return `AlmaLinux:${major}`;
  return null;
}
function packagesOf(text) {
  const s = splitSections(text);
  const os = osOf(s);
  const ecosystem = osvEcosystem(os);
  const pkgs = [];
  for (const l of s.pkgs || []) {
    const [name, version] = l.split('\t');
    if (name && version && /^[\w.+-]{1,120}$/.test(name) && /^[\w.+:~-]{1,120}$/.test(version)) pkgs.push({ ecosystem, name, version });
  }
  return { os, ecosystem, pkgs };
}
const OSV_SEV = { critical: 'critical', high: 'high', important: 'high', moderate: 'medium', medium: 'medium', low: 'low', negligible: 'low', unimportant: 'low', 'not yet assigned': 'medium' };
const SEV_ORDER = ['low', 'medium', 'high', 'critical'];
// Gibt es fuer dieses Paket im Bestand eine Korrektur, und wie schwer ist die Luecke?
function judgeVuln(v, name, ecosystem) {
  let fixed = false, label = null;
  for (const a of (v && v.affected) || []) {
    if (a.package && a.package.name && a.package.name !== name) continue;
    // Ein Eintrag gilt oft fuer viele Versionen der Distribution: nur der eigene Bestand zaehlt
    if (ecosystem && a.package && a.package.ecosystem !== ecosystem) continue;
    for (const r of a.ranges || []) if ((r.events || []).some((e) => e.fixed)) fixed = true;
    const lbl = String((a.ecosystem_specific && a.ecosystem_specific.urgency) || (a.database_specific && a.database_specific.severity) || (a.ecosystem_specific && a.ecosystem_specific.severity) || '').toLowerCase();
    if (OSV_SEV[lbl] && lbl !== 'not yet assigned') label = OSV_SEV[lbl];
  }
  // Bewertung der Distribution (z. B. Ubuntu "low") vor dem allgemeinen CVSS-Wert
  const sevs = (v && v.severity) || [];
  const own = sevs.find((x) => x && !/^CVSS/i.test(x.type || '') && OSV_SEV[String(x.score).toLowerCase()]);
  if (own) return { fixed, sev: OSV_SEV[String(own.score).toLowerCase()] };
  if (label) return { fixed, sev: label };
  const top = String((v && v.database_specific && v.database_specific.severity) || '').toLowerCase();
  if (OSV_SEV[top] && top !== 'not yet assigned') return { fixed, sev: OSV_SEV[top] };
  const vec = sevs.find((x) => x && /^CVSS_V3/i.test(x.type || ''));
  const score = vec ? cvssFromVector(vec.score) : null;
  return { fixed, sev: score != null ? cvssToSeverity(score) : null };
}
const MAX_DETAILS = 120;
// Abgleich installierter Pakete gegen OSV. Es gehen nur Paketnamen und Versionen an osv.dev.
async function auditPackages(host, { ecosystem, pkgs }, { signal, say, osvQuery, osvDetails }) {
  say(`Linux-Server ${host}: ${pkgs.length} Pakete gegen bekannte Lücken abgleichen …`);
  const hits = await osvQuery(pkgs, { signal });
  const affected = pkgs.map((p) => ({ ...p, ids: (hits.get(`${p.ecosystem}|${p.name}|${p.version}`) || []).map((x) => x.id) })).filter((p) => p.ids.length).sort((a, b) => b.ids.length - a.ids.length);
  const out = [];
  const add = (o) => out.push(mk('linuxssh', { location: `ssh://${host}`, category: 'Dependencies', confidence: 'medium', ...o }));
  const total = affected.reduce((a, p) => a + p.ids.length, 0);
  if (!affected.length) return { findings: out, notes: [`Linux-Server ${host}: ${pkgs.length} Pakete abgeglichen (${ecosystem}), keine bekannten Lücken bei OSV.`] };
  // Details nur begrenzt laden: die Pakete mit den meisten Treffern zuerst
  const queue = [];
  for (const p of affected) for (const id of p.ids) if (queue.length < MAX_DETAILS) queue.push({ p, id });
  const judged = new Map();
  let i = 0;
  await Promise.all(Array.from({ length: 6 }, async () => {
    while (i < queue.length && !(signal && signal.aborted)) {
      const q = queue[i++];
      const d = await Promise.resolve(osvDetails(q.id)).catch(() => null);
      if (!d) continue;
      const seen = judged.get(q.p.name) || [];
      seen.push({ id: q.id, ...judgeVuln(d, q.p.name, ecosystem) });
      judged.set(q.p.name, seen);
    }
  }));
  const fixable = [];
  for (const p of affected) {
    const fx = (judged.get(p.name) || []).filter((x) => x.fixed);
    if (fx.length) fixable.push({ p, fx, sev: fx.reduce((a, x) => (SEV_ORDER.indexOf(x.sev) > SEV_ORDER.indexOf(a) ? x.sev : a), 'medium') });
  }
  fixable.sort((a, b) => SEV_ORDER.indexOf(b.sev) - SEV_ORDER.indexOf(a.sev) || b.fx.length - a.fx.length);
  for (const { p, fx, sev } of fixable.slice(0, 15)) {
    add({ ruleId: `linux-pkg-cve-${p.name}`, severity: sev, title: `${p.name} ${p.version}: ${fx.length} bekannte Lücke(n) mit verfügbarem Update (${host})`, description: `Für das Paket ${p.name} gibt es in ${ecosystem} Korrekturen, die auf dem Server noch fehlen: ${fx.slice(0, 8).map((x) => x.id).join(', ')}.`, evidence: fx.slice(0, 20).map((x) => x.id).join(', '), impact: 'Öffentlich bekannte Lücken werden gezielt und automatisiert gesucht.', remediation: 'Paket-Updates einspielen (z. B. „sudo apt upgrade“ bzw. „sudo dnf upgrade“) und den betroffenen Dienst neu starten.', links: [{ label: `OSV: ${fx[0].id}`, url: `https://osv.dev/vulnerability/${encodeURIComponent(fx[0].id)}` }] });
  }
  add({ ruleId: 'linux-pkg-cves-summary', severity: 'info', title: `${affected.length} von ${pkgs.length} Paketen haben bei OSV bekannte Lücken (${host})`, description: `Insgesamt ${total} Einträge in ${ecosystem}. Viele davon haben noch keine Korrektur oder gelten für diese Installation nicht; deshalb erscheinen als eigene Befunde nur Pakete mit verfügbarem Update (geprüft: ${queue.length} Einträge).`, evidence: affected.slice(0, 25).map((p) => `${p.name} (${p.ids.length})`).join(', '), remediation: 'Updates regelmäßig einspielen; einzelne Einträge bei Bedarf im Sicherheits-Tracker der Distribution nachlesen.' });
  return { findings: out, notes: [`Linux-Server ${host}: ${pkgs.length} Pakete abgeglichen (${ecosystem}); nur Paketnamen und Versionen gingen an osv.dev.`] };
}

function parseLinux(text, host) {
  const s = splitSections(text);
  const out = [];
  const add = (o) => out.push(mk('linuxssh', { location: `ssh://${host}`, ...o }));
  const os = osOf(s);
  const lifeProduct = { debian: 'debian', ubuntu: 'ubuntu', rocky: 'rocky-linux', almalinux: 'almalinux' }[os.id];
  const life = lifeProduct && os.version ? eol.status(lifeProduct, os.version) : null;
  if (life && life.isEol) add({ ruleId: 'linux-os-eol', severity: 'high', category: 'Dependencies', title: `Betriebssystem ohne Sicherheitsupdates: ${os.pretty || os.id + ' ' + os.version} (${host})`, description: `Für diese Version gibt es seit ${life.eolFrom || 'einiger Zeit'} keine regulären Sicherheitsupdates mehr (Quelle: endoflife.date).`, impact: 'Neu bekannte Lücken bleiben dauerhaft offen.', remediation: 'Auf eine unterstützte Version des Betriebssystems aktualisieren.' });
  const [n, sec] = (s.updates || []).map((x) => parseInt(x, 10) || 0);
  if (sec > 0) add({ ruleId: 'linux-security-updates', severity: 'high', category: 'Dependencies', title: `${sec} Sicherheitsupdates ausstehend (${host})`, description: 'Für installierte Pakete gibt es Sicherheitskorrekturen, die noch nicht eingespielt sind. Bekannte Lücken werden automatisiert ausgenutzt.', remediation: 'Updates einspielen (z. B. „sudo apt upgrade“ bzw. „sudo dnf upgrade“) und unattended-upgrades bzw. dnf-automatic einrichten.' });
  else if (n > 0) add({ ruleId: 'linux-updates-pending', severity: n > 20 ? 'medium' : 'low', category: 'Dependencies', title: `${n} Paket-Updates ausstehend (${host})`, description: 'Der Server ist nicht auf dem aktuellen Stand.', remediation: 'Updates regelmäßig und automatisch einspielen.' });
  if ((s.reboot || []).includes('yes')) add({ ruleId: 'linux-reboot-required', severity: 'low', title: `Neustart nach Updates ausstehend (${host})`, description: 'Ein Teil der Korrekturen (z. B. am Kernel) wirkt erst nach einem Neustart.', remediation: 'Neustart in einem Wartungsfenster durchführen.' });
  const cfg = {};
  for (const l of s.sshd || []) { const m = l.trim().match(/^(\w+)\s+(\S+)/); if (m && !(m[1].toLowerCase() in cfg)) cfg[m[1].toLowerCase()] = m[2].toLowerCase(); }
  if (cfg.permitrootlogin === 'yes') add({ ruleId: 'linux-ssh-root-login', severity: 'high', category: 'Auth', title: `SSH erlaubt die direkte Anmeldung als root (${host})`, description: 'Angreifer müssen nur das root-Passwort erraten und kennen den Benutzernamen bereits.', remediation: 'In /etc/ssh/sshd_config „PermitRootLogin no“ (oder prohibit-password) setzen und sshd neu laden.' });
  if (cfg.passwordauthentication === 'yes') add({ ruleId: 'linux-ssh-password-auth', severity: 'medium', category: 'Auth', title: `SSH erlaubt Anmeldung mit Passwort (${host})`, description: 'Passwörter lassen sich automatisiert durchprobieren. SSH-Schlüssel sind deutlich sicherer.', remediation: '„PasswordAuthentication no“ setzen, nachdem alle Nutzer einen SSH-Schlüssel haben; zusätzlich fail2ban o. Ä. nutzen.' });
  if (cfg.permitemptypasswords === 'yes') add({ ruleId: 'linux-ssh-empty-passwords', severity: 'critical', category: 'Auth', title: `SSH erlaubt leere Passwörter (${host})`, description: 'Konten ohne Passwort können sich ohne jede Hürde anmelden.', remediation: '„PermitEmptyPasswords no“ setzen und sshd neu laden.' });
  if (cfg.x11forwarding === 'yes') add({ ruleId: 'linux-ssh-x11', severity: 'low', title: `SSH-X11-Weiterleitung ist an (${host})`, description: 'Wird auf Servern praktisch nie gebraucht und vergrößert die Angriffsfläche.', remediation: '„X11Forwarding no“ setzen.' });
  if (Number(cfg.maxauthtries) > 4) add({ ruleId: 'linux-ssh-maxauthtries', severity: 'low', category: 'Auth', title: `SSH erlaubt ${cfg.maxauthtries} Anmeldeversuche je Verbindung (${host})`, description: 'Die CIS-Empfehlung sind höchstens 4 Versuche, um Rateangriffe zu bremsen.', remediation: '„MaxAuthTries 4“ setzen.' });
  const uid0 = (s.uid0 || []).map((x) => x.trim()).filter((x) => x && x !== 'root');
  if (uid0.length) add({ ruleId: 'linux-uid0', severity: 'critical', category: 'AccessControl', title: `Weitere Konten mit root-Rechten (UID 0): ${list(uid0)} (${host})`, description: 'Neben root haben weitere Konten volle Rechte. Das ist ein typisches Zeichen für eine Hintertür.', remediation: 'Prüfen, wer das Konto angelegt hat; nicht benötigte Konten löschen oder eine eigene UID vergeben.' });
  const empty = (s.emptypw || []).map((x) => x.trim()).filter(Boolean);
  if (empty.length) add({ ruleId: 'linux-empty-password', severity: 'critical', category: 'Auth', title: `Konten ohne Passwort: ${list(empty)} (${host})`, description: 'Diese Konten haben ein leeres Passwort.', remediation: 'Für jedes Konto ein Passwort setzen oder es mit „passwd -l“ sperren.' });
  const nopw = (s.sudoers || []).filter((l) => /NOPASSWD/.test(l));
  if (nopw.length) add({ ruleId: 'linux-sudo-nopasswd', severity: 'medium', category: 'AccessControl', title: `sudo ohne Passwort erlaubt (${host})`, description: 'Wer eines dieser Konten übernimmt, bekommt ohne weitere Hürde root-Rechte.', remediation: 'NOPASSWD nur für eng begrenzte Befehle einzelner Dienstkonten erlauben, sonst entfernen.', evidence: nopw.slice(0, 5).join('\n') });
  const fw = (s.firewall || []).join('\n');
  const ufwOff = /Status:\s*inactive/i.test(fw), fwdOff = /firewalld:\s*not running/i.test(fw) || !/firewalld:/.test(fw);
  const nftIn = Number((fw.match(/nft-input:\s*(\d+)/) || [])[1] || 0);
  const iptOpen = /-P INPUT ACCEPT/.test(fw) && !/^-A INPUT/m.test(fw);
  if (ufwOff && fwdOff && !nftIn && (iptOpen || !/-P INPUT/.test(fw))) add({ ruleId: 'linux-no-firewall', severity: 'medium', title: `Keine aktive Firewall erkannt (${host})`, description: 'Alle lauschenden Dienste sind direkt aus dem Netz erreichbar.', remediation: 'ufw bzw. firewalld einschalten und nur benötigte Ports (z. B. 22, 443) freigeben.' });
  const seen = new Set();
  for (const l of s.listen || []) {
    const m = l.match(/(?:^|\s)(0\.0\.0\.0|\*|\[?::\]?):(\d+)\s/);
    if (!m) continue;
    const port = Number(m[2]);
    if (!RISKY[port] || port === 22 || seen.has(port)) continue;
    seen.add(port);
    add({ ruleId: 'linux-service-public', severity: [23, 6379, 27017, 9200, 11211].includes(port) ? 'high' : 'medium', category: 'AccessControl', title: `${RISKY[port]} lauscht auf allen Schnittstellen (Port ${port}, ${host})`, description: 'Der Dienst nimmt Verbindungen von jeder Adresse an, nicht nur vom Server selbst. Datenbanken und Caches sind so oft direkt aus dem Internet angreifbar.', remediation: 'Den Dienst nur an 127.0.0.1 bzw. das interne Netz binden und per Firewall abschirmen.' });
  }
  return out;
}

const SSH_TARGET = /^([a-z_][\w.-]{0,31})@([a-z0-9][\w.-]{0,252})(?::(\d{1,5}))?$/i;
async function auditLinuxSsh({ signal, say, run: r = run, settings = {}, osvQuery = (p, o) => require('../watch').osvQueryOnline(p, o), osvDetails = (id) => require('../watch').osvDetails(id, fetch) }) {
  const m = String(settings.sshTarget || '').trim().match(SSH_TARGET);
  if (!m) return { findings: [], notes: ['Linux-Prüfung übersprungen: kein SSH-Ziel (benutzer@server) in den Einstellungen.'] };
  const key = String(settings.sshKeyPath || '').trim();
  if (!key || key.startsWith('-') || !fs.existsSync(key)) return { findings: [], notes: ['Linux-Prüfung übersprungen: SSH-Schlüsseldatei nicht gefunden.'] };
  const [, user, host, port] = m;
  say(`Linux-Server ${host}: Updates, SSH, Konten, Firewall (nur lesend) …`);
  const args = ['-i', key, '-p', String(port || 22), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no', '-T', '--', `${user}@${host}`, 'sh -s'];
  const res = await r('ssh', args, { signal, timeoutMs: 180000, input: SSH_SCRIPT });
  if (!/@@end/.test(res.stdout || '')) return { findings: [], notes: [`Linux-Prüfung nicht ausgeführt (${res.error || 'keine Antwort'}). Ist der Server-Schlüssel bekannt (einmal von Hand verbinden) und der SSH-Schlüssel freigegeben?`] };
  const findings = parseLinux(res.stdout, host);
  const notes = [`Linux-Server ${host} geprüft.`];
  if (settings.osvLookup !== false) {
    const pk = packagesOf(res.stdout);
    if (pk.ecosystem && pk.pkgs.length) {
      try { const a = await auditPackages(host, pk, { signal, say, osvQuery, osvDetails }); findings.push(...a.findings); notes.push(...a.notes); }
      catch (e) { notes.push(`Paket-Abgleich mit OSV nicht möglich (${e.message}).`); }
    } else if (pk.pkgs.length) notes.push(`Paket-Abgleich: OSV führt ${pk.os.pretty || pk.os.id || 'diese Distribution'} nicht; nur die Update-Anzeige des Systems wurde ausgewertet.`);
  }
  return { findings, notes, ok: true };
}

// --- Datenbanken ------------------------------------------------------------------------
// Erste Version mit Korrektur fuer eine bekannte, schwere Luecke je Versionszweig (Herstellerangaben)
const DB_FIXES = {
  postgres: { cve: 'CVE-2025-1094', branch: (v) => v.split('.')[0], fixed: { 17: '17.3', 16: '16.7', 15: '15.11', 14: '14.16', 13: '13.19' } },
  redis: { cve: 'CVE-2025-49844', branch: (v) => v.split('.').slice(0, 2).join('.'), fixed: { '7.2': '7.2.11', '7.4': '7.4.6', '8.0': '8.0.4', '8.2': '8.2.2' } },
  mongodb: { cve: 'CVE-2025-14847', branch: (v) => v.split('.').slice(0, 2).join('.'), fixed: { '6.0': '6.0.27', '7.0': '7.0.28', '8.0': '8.0.17', '8.2': '8.2.3' } },
};
// Aelter als diese Versionen = ohne Sicherheitsupdates des Herstellers (Stand Ende 2026)
const DB_MIN_SUPPORTED = { postgres: '14', mysql: '8.4', mariadb: '10.11', mongodb: '7.0', redis: '7.2' };
const DB_EOL_PRODUCT = { postgres: 'postgresql', mysql: 'mysql', mariadb: 'mariadb', mongodb: 'mongodb', redis: 'redis' };
const DB_LABEL = { postgres: 'PostgreSQL', mysql: 'MySQL', mariadb: 'MariaDB', mongodb: 'MongoDB', redis: 'Redis' };

function tcpExchange(host, port, { send, until, timeoutMs = 6000, useTls = false } = {}) {
  return new Promise((resolve) => {
    let buf = Buffer.alloc(0), done = false;
    const sock = useTls ? tls.connect({ host, port, rejectUnauthorized: false, servername: net.isIP(host) ? undefined : host }) : net.connect({ host, port });
    const fin = (err) => { if (done) return; done = true; sock.destroy(); resolve({ ok: !err && buf.length > 0, data: buf, error: err }); };
    sock.setTimeout(timeoutMs, () => fin('Zeitüberschreitung'));
    sock.once(useTls ? 'secureConnect' : 'connect', () => { if (send) for (const b of [].concat(send)) sock.write(b); });
    sock.on('data', (d) => { buf = Buffer.concat([buf, d]); if (!until || until(buf)) fin(null); });
    sock.once('error', (e) => fin(e.code || e.message));
    sock.once('close', () => fin(buf.length ? null : 'Verbindung geschlossen'));
  });
}

// Minimales BSON (nur was hello/buildInfo/listDatabases brauchen)
function bsonEncode(doc) {
  const parts = [];
  for (const [k, v] of Object.entries(doc)) {
    const key = Buffer.concat([Buffer.from(k), Buffer.from([0])]);
    if (typeof v === 'string') { const s = Buffer.from(v + '\0'); const l = Buffer.alloc(4); l.writeInt32LE(s.length); parts.push(Buffer.from([2]), key, l, s); }
    else if (typeof v === 'boolean') parts.push(Buffer.from([8]), key, Buffer.from([v ? 1 : 0]));
    else if (v && typeof v === 'object') parts.push(Buffer.from([Array.isArray(v) ? 4 : 3]), key, bsonEncode(Array.isArray(v) ? Object.fromEntries(v.map((x, i) => [String(i), x])) : v));
    else { const n = Buffer.alloc(4); n.writeInt32LE(v | 0); parts.push(Buffer.from([16]), key, n); }
  }
  const body = Buffer.concat(parts);
  const len = Buffer.alloc(4); len.writeInt32LE(body.length + 5);
  return Buffer.concat([len, body, Buffer.from([0])]);
}
function bsonDecode(buf, off = 0) {
  const end = off + buf.readInt32LE(off);
  const out = {};
  let p = off + 4;
  while (p < end - 1) {
    const t = buf[p++];
    const z = buf.indexOf(0, p); const k = buf.slice(p, z).toString(); p = z + 1;
    if (t === 1) { out[k] = buf.readDoubleLE(p); p += 8; }
    else if (t === 2) { const l = buf.readInt32LE(p); out[k] = buf.slice(p + 4, p + 3 + l).toString(); p += 4 + l; }
    else if (t === 3 || t === 4) { const l = buf.readInt32LE(p); const d = bsonDecode(buf, p); out[k] = t === 4 ? Object.values(d) : d; p += l; }
    else if (t === 8) { out[k] = !!buf[p]; p += 1; }
    else if (t === 16) { out[k] = buf.readInt32LE(p); p += 4; }
    else if (t === 18 || t === 9 || t === 17) { out[k] = Number(buf.readBigInt64LE(p)); p += 8; }
    else if (t === 7) { p += 12; }
    else if (t === 10) { out[k] = null; }
    else break; // unbekannter Typ: Rest ignorieren
  }
  return out;
}
function mongoMsg(doc, id = 1) {
  const body = bsonEncode(doc);
  const h = Buffer.alloc(21);
  h.writeInt32LE(21 + body.length, 0); h.writeInt32LE(id, 4); h.writeInt32LE(0, 8); h.writeInt32LE(2013, 12); h.writeUInt32LE(0, 16); h[20] = 0;
  return Buffer.concat([h, body]);
}
const mongoReply = (buf) => { try { return buf.readInt32LE(12) === 2013 ? bsonDecode(buf, 21) : null; } catch { return null; } };
const mongoComplete = (b) => b.length >= 4 && b.length >= b.readInt32LE(0);

const pgSslRequest = () => { const b = Buffer.alloc(8); b.writeInt32BE(8, 0); b.writeInt32BE(80877103, 4); return b; };
// MySQL-Begruessung: Protokoll 10, Version, Faehigkeiten (CLIENT_SSL = 0x0800)
function parseMysqlGreeting(buf) {
  if (!buf || buf.length < 40 || buf[4] !== 10) return null;
  const z = buf.indexOf(0, 5);
  const version = buf.slice(5, z).toString();
  const capLow = buf.readUInt16LE(z + 1 + 4 + 8 + 1);
  return { version, ssl: !!(capLow & 0x0800) };
}
function redisComplete(b) {
  const t = b.toString();
  // INFO kommt als Bulk-String "$<laenge>\r\n…\r\n"; Fehler als "-…\r\n"
  const m = t.match(/\$(\d+)\r\n/);
  if (m) return Buffer.byteLength(t.slice(0, t.indexOf(m[0]))) + m[0].length + Number(m[1]) + 2 <= b.length;
  return /(^|\n)-[^\r\n]*\r\n$/.test(t);
}
const respCmd = (...a) => Buffer.from(`*${a.length}\r\n` + a.map((x) => `$${Buffer.byteLength(String(x))}\r\n${x}\r\n`).join(''));

function parseDbUrl(line) {
  let u;
  try { u = new URL(String(line).trim()); } catch { return null; }
  const proto = u.protocol.replace(/:$/, '').toLowerCase();
  const kind = { postgres: 'postgres', postgresql: 'postgres', mysql: 'mysql', mariadb: 'mysql', mongodb: 'mongodb', redis: 'redis', rediss: 'redis' }[proto];
  if (!kind || !u.hostname) return null;
  const port = Number(u.port) || { postgres: 5432, mysql: 3306, mongodb: 27017, redis: 6379 }[kind];
  return { kind, tls: proto === 'rediss' || /ssl=true|tls=true|sslmode=(require|verify)/i.test(u.search), host: u.hostname.replace(/^\[|\]$/g, ''), port, user: decodeURIComponent(u.username || ''), password: decodeURIComponent(u.password || ''), db: u.pathname.replace(/^\//, '') || '', label: `${proto}://${u.hostname}:${port}` };
}

// Reine Auswertung aller gesammelten Fakten einer Datenbank
function assessDb(c, f) {
  const out = [];
  const name = DB_LABEL[f.flavor || c.kind];
  const add = (o) => out.push(mk('dbdirect', { location: c.label, ...o }));
  const remote = !isLocalHost(c.host);
  if (f.version) {
    const flavor = f.flavor || c.kind;
    // Gepflegte Quelle zuerst; die Tabelle gilt nur, wenn der Feed fehlt oder die Reihe unbekannt ist
    const life = eol.status(DB_EOL_PRODUCT[flavor], f.version);
    const min = DB_MIN_SUPPORTED[flavor];
    if (life) { if (life.isEol) add({ ruleId: 'db-version-eol', severity: 'medium', category: 'Dependencies', title: `${name} ${f.version} bekommt keine Sicherheitsupdates mehr`, description: `Die Versionsreihe ${life.cycle} wird vom Hersteller seit ${life.eolFrom || 'einiger Zeit'} nicht mehr gepflegt (Quelle: endoflife.date). Neue Lücken bleiben offen.`, remediation: 'Auf eine unterstützte Version aktualisieren.' }); }
    else if (min && cmpVer(f.version, min) < 0) add({ ruleId: 'db-version-eol', severity: 'medium', category: 'Dependencies', title: `${name} ${f.version} bekommt keine Sicherheitsupdates mehr`, description: `Versionen vor ${min} werden vom Hersteller nicht mehr gepflegt. Neue Lücken bleiben offen.`, remediation: `Auf eine unterstützte Version (${min} oder neuer) aktualisieren.` });
    const fx = DB_FIXES[flavor];
    const fixed = fx && fx.fixed[fx.branch(f.version)];
    if (fixed && cmpVer(f.version, fixed) < 0) add({ ruleId: 'db-version-vuln', severity: 'high', category: 'Dependencies', confidence: 'medium', title: `${name} ${f.version} hat eine bekannte Sicherheitslücke (${fx.cve})`, description: `Die Lücke ist ab Version ${fixed} behoben.`, remediation: `Mindestens auf ${fixed} aktualisieren.` });
  }
  if (f.tls === false && remote) add({ ruleId: 'db-no-tls', severity: 'high', category: 'Transport', title: `${name} nimmt unverschlüsselte Verbindungen an (${c.host})`, description: 'Zugangsdaten und Daten gehen im Klartext über das Netz und lassen sich unterwegs mitlesen.', remediation: 'TLS am Server einschalten und erzwingen (z. B. PostgreSQL hostssl, MySQL require_secure_transport, MongoDB requireTLS, Redis tls-port).' });
  if (f.requireTls === false && f.tls !== false && remote) add({ ruleId: 'db-tls-optional', severity: 'medium', category: 'Transport', title: `${name} erzwingt keine Verschlüsselung (${c.host})`, description: 'TLS ist möglich, aber nicht vorgeschrieben. Falsch eingerichtete Programme verbinden sich unverschlüsselt.', remediation: 'Verschlüsselung erzwingen (z. B. MySQL require_secure_transport=ON, PostgreSQL nur hostssl-Einträge).' });
  if (f.anonymous) add({ ruleId: 'db-anonymous-access', severity: remote ? 'critical' : 'high', category: 'Auth', title: `${name} ist ohne Anmeldung lesbar (${c.host})`, description: 'Die Datenbank beantwortet Abfragen ohne Benutzer und Passwort. Automatisierte Scanner finden solche Server in Minuten und kopieren oder löschen die Daten.', remediation: 'Anmeldung einschalten (Redis requirepass/ACL, MongoDB security.authorization: enabled) und den Dienst nur im internen Netz erreichbar machen.' });
  if (f.emptyPwUsers && f.emptyPwUsers.length) add({ ruleId: 'db-empty-password', severity: 'critical', category: 'Auth', title: `${name}-Konten ohne Passwort: ${list(f.emptyPwUsers)}`, description: 'Diese Konten können sich ohne Passwort anmelden.', remediation: 'Für jedes Konto ein starkes Passwort setzen oder das Konto löschen.' });
  if (f.superusers && f.superusers.length > 2) add({ ruleId: 'db-many-superusers', severity: 'medium', category: 'AccessControl', title: `${f.superusers.length} Konten mit vollen Rechten in ${name}`, description: `Superuser: ${list(f.superusers)}. Jedes dieser Konten kann alles lesen, ändern und löschen.`, remediation: 'Superuser-Rechte auf ein Verwaltungskonto beschränken; Anwendungen eigene Konten mit nur nötigen Rechten geben.' });
  if (f.selfSuper) add({ ruleId: 'db-audit-user-superuser', severity: 'low', category: 'AccessControl', title: `Hinterlegter Prüf-Zugang hat volle Rechte (${name})`, description: 'Für die Prüfung reicht ein Konto mit Leserechten. Ein Superuser-Zugang in einer Konfiguration ist ein unnötiges Risiko.', remediation: 'Ein eigenes Konto nur mit Leserechten anlegen (z. B. PostgreSQL pg_read_all_settings/pg_monitor) und dieses hinterlegen.' });
  if (f.publicCreate) add({ ruleId: 'db-pg-public-create', severity: 'medium', category: 'AccessControl', title: 'Jeder darf im Schema „public“ Objekte anlegen (PostgreSQL)', description: 'Jedes Konto kann im Schema public Tabellen und Funktionen anlegen und so andere Nutzer zu unbeabsichtigtem Code verleiten (CVE-2018-1058).', remediation: 'REVOKE CREATE ON SCHEMA public FROM PUBLIC; ausführen.' });
  if (f.trustAuth) add({ ruleId: 'db-pg-trust', severity: 'high', category: 'Auth', title: 'PostgreSQL erlaubt Anmeldung ohne Passwort (trust)', description: 'In pg_hba.conf stehen Einträge mit der Methode trust – dort genügt der Benutzername.', remediation: 'trust durch scram-sha-256 ersetzen und die Konfiguration neu laden.' });
  return out;
}

const firstLines = (s) => String(s || '').replace(/\r/g, '').split('\n').map((x) => x.trim()).filter(Boolean);

async function probeDb(c, { signal, run: r, wire }) {
  const f = {}, notes = [];
  const ex = wire || tcpExchange;
  if (c.kind === 'postgres') {
    const res = await ex(c.host, c.port, { send: pgSslRequest(), until: (b) => b.length >= 1 });
    if (!res.ok) return { error: res.error };
    f.tls = res.data[0] === 0x53;
    const env = { PGPASSWORD: c.password, PGCONNECT_TIMEOUT: '10', PGSSLMODE: f.tls ? 'require' : 'prefer' };
    const q = async (sql) => { const o = await r('psql', ['--no-psqlrc', '-At', '-h', c.host, '-p', String(c.port), '-U', c.user || 'postgres', '-d', c.db || 'postgres', '-c', sql], { signal, env, timeoutMs: 30000 }); return o.ok ? firstLines(o.stdout) : null; };
    const v = await q('SHOW server_version');
    if (v) {
      f.version = (v[0] || '').split(' ')[0];
      f.superusers = await q('SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin') || undefined;
      f.selfSuper = ((await q('SELECT rolsuper FROM pg_roles WHERE rolname = current_user')) || [])[0] === 't';
      f.publicCreate = ((await q("SELECT has_schema_privilege('public', 'public', 'CREATE')")) || [])[0] === 't';
      const tr = await q("SELECT count(*) FROM pg_hba_file_rules WHERE auth_method = 'trust' AND type <> 'local'");
      f.trustAuth = !!tr && Number(tr[0]) > 0;
      const ssl = await q("SELECT count(*) FROM pg_hba_file_rules WHERE type = 'host'");
      if (ssl && f.tls) f.requireTls = Number(ssl[0]) === 0;
    } else notes.push(`${c.label}: Rechte und Version nicht gelesen (psql nicht installiert oder Anmeldung fehlgeschlagen).`);
  } else if (c.kind === 'mysql') {
    const res = await ex(c.host, c.port, { until: (b) => b.length >= 4 && b.length >= 4 + b.readUIntLE(0, 3) });
    const g = res.ok && parseMysqlGreeting(res.data);
    if (!g) return { error: res.error || 'keine MySQL-Begrüßung' };
    f.version = g.version.split('-')[0];
    f.flavor = /MariaDB/i.test(g.version) ? 'mariadb' : 'mysql';
    f.tls = g.ssl;
    const env = { MYSQL_PWD: c.password };
    const q = async (sql) => { const o = await r('mysql', ['-h', c.host, '-P', String(c.port), '-u', c.user || 'root', '-N', '-B', '--connect-timeout=10', '-e', sql], { signal, env, timeoutMs: 30000 }); return o.ok ? firstLines(o.stdout) : null; };
    const st = await q("SHOW GLOBAL VARIABLES LIKE 'require_secure_transport'");
    if (st) {
      if (f.tls) f.requireTls = !/\bON\b/i.test(st.join(' '));
      const su = await q("SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Super_priv='Y'");
      if (su) f.superusers = su;
      const ep = await q("SELECT CONCAT(user,'@',host) FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND plugin NOT IN ('auth_socket','unix_socket','mysql_no_login')");
      if (ep) f.emptyPwUsers = ep;
    } else notes.push(`${c.label}: Rechte nicht gelesen (mysql-Client nicht installiert oder Anmeldung fehlgeschlagen).`);
  } else if (c.kind === 'mongodb') {
    const hello = await ex(c.host, c.port, { send: mongoMsg({ hello: 1, $db: 'admin' }, 1), until: mongoComplete, useTls: c.tls });
    const h = hello.ok && mongoReply(hello.data);
    if (!h) return { error: hello.error || 'keine MongoDB-Antwort' };
    if (!c.tls && h.ok === 1) f.tls = false;
    const bi = mongoReply((await ex(c.host, c.port, { send: mongoMsg({ buildInfo: 1, $db: 'admin' }, 2), until: mongoComplete, useTls: c.tls })).data || Buffer.alloc(0));
    if (bi && bi.version) f.version = bi.version;
    if (!c.user) {
      const ld = mongoReply((await ex(c.host, c.port, { send: mongoMsg({ listDatabases: 1, nameOnly: true, $db: 'admin' }, 3), until: mongoComplete, useTls: c.tls })).data || Buffer.alloc(0));
      f.anonymous = !!(ld && ld.ok === 1 && Array.isArray(ld.databases));
    } else notes.push(`${c.label}: Rechte mit Anmeldung werden für MongoDB nicht geprüft (nur Zugriff ohne Anmeldung).`);
  } else if (c.kind === 'redis') {
    const cmds = [...(c.password ? [c.user ? respCmd('AUTH', c.user, c.password) : respCmd('AUTH', c.password)] : []), respCmd('INFO', 'server')];
    const res = await ex(c.host, c.port, { send: cmds, until: redisComplete, useTls: c.tls });
    if (!res.ok) return { error: res.error };
    const txt = res.data.toString();
    const v = txt.match(/redis_version:([\d.]+)/);
    if (v) f.version = v[1];
    if (!c.password && v) f.anonymous = true;
    if (!c.tls) f.tls = false;
    if (!v && /NOAUTH|WRONGPASS|invalid password/i.test(txt)) notes.push(`${c.label}: Anmeldung abgelehnt – Zugang in den Einstellungen prüfen.`);
  }
  return { facts: f, notes };
}

async function auditDb({ signal, say, run: r = run, settings = {}, deps = {} }) {
  const conns = String(settings.dbUrls || '').split(/\r?\n/).map(parseDbUrl).filter(Boolean).slice(0, 10);
  if (!conns.length) return { findings: [], notes: ['Datenbank-Prüfung übersprungen: keine Verbindung in den Einstellungen hinterlegt.'] };
  const findings = [], notes = [];
  let okAll = true;
  for (const c of conns) {
    if (signal && signal.aborted) break;
    say(`Datenbank ${c.label} (nur lesend) …`);
    const p = await probeDb(c, { signal, run: r, wire: deps.wire });
    if (p.error) { okAll = false; notes.push(`${c.label}: nicht erreichbar (${p.error}).`); continue; }
    findings.push(...assessDb(c, p.facts));
    notes.push(...p.notes, p.facts.version ? `${c.label} geprüft (Version ${p.facts.version}).` : `${c.label} geprüft.`);
  }
  return { findings, notes, ok: okAll };
}

// --- Kubernetes (kubectl, aktueller Kontext) ----------------------------------------------
const owner = (p) => { const o = ((p.metadata || {}).ownerReferences || [])[0]; const n = o ? o.name : (p.metadata || {}).name; return String(n || '?').replace(/-[a-z0-9]{8,10}$/, ''); };
function parseK8s({ pods = [], crbs = [], netpols = [], namespaces = [] }, ctx = '') {
  const out = [];
  const add = (o) => out.push(mk('k8s', { ...o }));
  const SYS_NS = /^(kube-system|kube-public|kube-node-lease|gatekeeper-system|calico-system|tigera-operator|cert-manager|local-path-storage)$/;
  const seen = new Set();
  const once = (k) => (seen.has(k) ? false : (seen.add(k), true));
  for (const p of pods) {
    const ns = (p.metadata || {}).namespace || 'default';
    if (SYS_NS.test(ns)) continue;
    const w = `${ns}/${owner(p)}`;
    const spec = p.spec || {};
    const cs = [...(spec.containers || []), ...(spec.initContainers || [])];
    if (cs.some((c) => c.securityContext && c.securityContext.privileged) && once('priv' + w)) add({ ruleId: 'k8s-live-privileged', severity: 'critical', location: `k8s://${w}`, title: `Privilegierter Container läuft: ${w}`, description: 'Ein privilegierter Container hat vollen Zugriff auf den Knoten und kann aus dem Cluster ausbrechen.', remediation: 'privileged: false setzen und nur einzelne Capabilities freigeben; Pod Security Admission „restricted“ für den Namespace aktivieren.' });
    const hp = (spec.volumes || []).filter((v) => v.hostPath).map((v) => v.hostPath.path);
    if (hp.length && once('hp' + w)) add({ ruleId: 'k8s-live-hostpath', severity: hp.some((x) => /^\/($|etc|var\/run|run|proc|root|var\/lib\/kubelet)/.test(x)) ? 'high' : 'medium', location: `k8s://${w}`, title: `Pod bindet Verzeichnisse des Knotens ein: ${w}`, description: `hostPath: ${list(hp, 5)}. Darüber kann der Container Dateien des Knotens lesen oder verändern.`, remediation: 'hostPath durch persistentVolumeClaims oder emptyDir ersetzen; wenn unvermeidbar, readOnly: true setzen.' });
    if ((spec.hostNetwork || spec.hostPID) && once('hn' + w)) add({ ruleId: 'k8s-live-host-namespace', severity: 'high', location: `k8s://${w}`, title: `Pod teilt Netz oder Prozesse mit dem Knoten: ${w}`, description: 'Mit hostNetwork bzw. hostPID sieht der Pod den Netzverkehr bzw. alle Prozesse des Knotens.', remediation: 'hostNetwork und hostPID entfernen.' });
    const sec = cs.flatMap((c) => (c.env || []).filter((e) => e.valueFrom && e.valueFrom.secretKeyRef).map((e) => e.name));
    if (sec.length && once('se' + w)) add({ ruleId: 'k8s-live-secret-env', severity: 'low', category: 'Secrets', location: `k8s://${w}`, title: `Secrets als Umgebungsvariablen: ${w}`, description: `Variablen: ${list([...new Set(sec)], 6)}. Umgebungsvariablen landen leicht in Logs, Fehlerberichten und Kindprozessen.`, remediation: 'Secrets als Datei einbinden (volume mit secret) statt als env.' });
  }
  for (const b of crbs) {
    if (((b.roleRef || {}).name) !== 'cluster-admin') continue;
    const subj = (b.subjects || []).filter((s) => !/^system:/.test(s.name || '') && !/^(kube-system)$/.test(s.namespace || ''));
    if (subj.length) add({ ruleId: 'k8s-live-cluster-admin', severity: 'high', category: 'AccessControl', location: `k8s://clusterrolebinding/${(b.metadata || {}).name}`, title: `cluster-admin vergeben: ${(b.metadata || {}).name}`, description: `Volle Rechte im ganzen Cluster für: ${list(subj.map((s) => `${s.kind} ${s.namespace ? s.namespace + '/' : ''}${s.name}`), 5)}.`, remediation: 'cluster-admin nur für Notfall-Konten; sonst Rollen mit den tatsächlich nötigen Rechten je Namespace vergeben.' });
  }
  const withPolicy = new Set(netpols.map((n) => (n.metadata || {}).namespace));
  const withPods = new Set(pods.map((p) => (p.metadata || {}).namespace));
  for (const n of namespaces) {
    const name = (n.metadata || {}).name;
    if (!name || SYS_NS.test(name) || !withPods.has(name) || withPolicy.has(name)) continue;
    add({ ruleId: 'k8s-live-no-networkpolicy', severity: 'medium', category: 'AccessControl', location: `k8s://namespace/${name}`, title: `Namespace ohne NetworkPolicy: ${name}`, description: 'Ohne NetworkPolicy darf jeder Pod im Cluster jeden Pod in diesem Namespace erreichen. Ein übernommener Pod kommt so überall hin.', remediation: 'Eine Default-Deny-Policy anlegen und benötigte Verbindungen gezielt erlauben.' });
  }
  return out;
}

async function auditK8s({ signal, say, run: r = run }) {
  const ctx = await r('kubectl', ['config', 'current-context'], { signal, timeoutMs: 20000 });
  if (!ctx.ok) return { findings: [], notes: [`Kubernetes-Prüfung nicht ausgeführt (${ctx.error}). kubectl installiert und ein Kontext gesetzt?`] };
  const name = ctx.stdout.trim();
  say(`Kubernetes (${name}): Pods, Rollen, NetworkPolicies (nur lesend) …`);
  const get = async (what, all) => { const o = await r('kubectl', ['get', what, ...(all ? ['--all-namespaces'] : []), '-o', 'json', '--request-timeout=60s'], { signal, timeoutMs: 90000 }); return o.ok ? ((json(o.stdout) || {}).items || []) : null; };
  const pods = await get('pods', true);
  if (!pods) return { findings: [], notes: [`Kubernetes-Prüfung fehlgeschlagen: Pods nicht lesbar (Kontext ${name}).`] };
  const [crbs, netpols, namespaces] = [await get('clusterrolebindings'), await get('networkpolicies', true), await get('namespaces')];
  return { findings: parseK8s({ pods, crbs: crbs || [], netpols: netpols || [], namespaces: namespaces || [] }, name), notes: [`Kubernetes-Kontext ${name} geprüft (${pods.length} Pods).`], ok: !!(crbs && netpols && namespaces) };
}

module.exports = { packagesOf, osvEcosystem, auditPackages, judgeVuln, SSH_ALLOWED, SSH_SCRIPT, splitSections, parseLinux, auditLinuxSsh, parseDbUrl, assessDb, probeDb, auditDb, bsonEncode, bsonDecode, mongoMsg, mongoReply, parseMysqlGreeting, pgSslRequest, parseK8s, auditK8s };
