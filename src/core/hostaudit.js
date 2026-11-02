'use strict';

// System-Pruefungen fuer die Zielart "system": dieser Windows-PC, laufende Docker-Container
// und Cloud-Konten (AWS, Azure, Google Cloud). Alles AUSSCHLIESSLICH LESEND:
//  - Windows: PowerShell-Abfragen (Get-…, Registry lesen), keine Set-/Enable-Befehle
//  - Docker: docker ps / docker inspect
//  - Cloud: die offiziellen CLIs mit list/get/describe und den Anmeldedaten des Nutzers
// Die Auswertung steckt in reinen Funktionen (parse*), damit sie ohne System testbar ist.

const { spawn } = require('child_process');
const { normalizeFinding } = require('./schema');

const SYSTEMS = { windows: 'Dieser Windows-PC', docker: 'Laufende Docker-Container', aws: 'AWS-Konto', azure: 'Azure-Abonnement', gcp: 'Google-Cloud-Projekt' };
const RISKY = { 22: 'SSH', 3389: 'Remotedesktop', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 23: 'Telnet', 21: 'FTP', 445: 'SMB', 11211: 'Memcached' };

function run(cmd, args, { signal, timeoutMs = 60000 } = {}) {
  // .cmd-Wrapper (az, gcloud) brauchen unter Windows cmd.exe; Argumente sind feste Werte.
  const win = process.platform === 'win32' && !/powershell|docker/i.test(cmd);
  const [c, a] = win ? ['cmd.exe', ['/d', '/s', '/c', cmd, ...args]] : [cmd, args];
  return new Promise((resolve) => {
    let child;
    try { child = spawn(c, a, { windowsHide: true, signal }); } catch (e) { return resolve({ ok: false, error: e.message, stdout: '' }); }
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { child.kill(); } catch { /* egal */ } }, timeoutMs);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', (e) => { clearTimeout(timer); resolve({ ok: false, error: e.code === 'ENOENT' ? 'nicht installiert' : e.message, stdout }); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ ok: code === 0, code, stdout, stderr, error: code ? (stderr.split('\n').find(Boolean) || `Exit ${code}`).slice(0, 200) : null }); });
  });
}
const json = (s) => { try { return JSON.parse(s); } catch { return null; } };
const mk = (sys, o) => normalizeFinding({ category: 'Config', confidence: 'high', ...o, sourceModule: `system-${sys}` }, `system-${sys}`);

// --- Windows --------------------------------------------------------------------
// Ein einziger PowerShell-Aufruf sammelt alles als JSON (ohne Adminrechte lesbar).
const WIN_PS = `
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$d=Get-MpComputerStatus; if($d){$o.defender=@{av=$d.AntivirusEnabled;rt=$d.RealTimeProtectionEnabled;age=$d.AntivirusSignatureAge;tamper=$d.IsTamperProtected}}
$o.firewall=@(Get-NetFirewallProfile | ForEach-Object { @{name=[string]$_.Name;enabled=[bool]$_.Enabled} })
$o.bitlocker=(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection')
$h=Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; if($h){$o.lastUpdateDays=[int]((Get-Date)-$h.InstalledOn).TotalDays}
$o.uac=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA
$o.rdpDeny=(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections
$o.rdpNla=(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication
$o.smb1=[bool](Get-Service mrxsmb10)
$g=Get-LocalUser | Where-Object { $_.SID -like '*-501' }; if($g){$o.guest=[bool]$g.Enabled}
$o.autorun=(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer').NoDriveTypeAutoRun
$o.os=(Get-CimInstance Win32_OperatingSystem).Caption
$o | ConvertTo-Json -Depth 4 -Compress`;

function parseWindows(d) {
  const out = [];
  const add = (o) => out.push(mk('windows', { location: 'Dieser PC', ...o }));
  if (!d) return out;
  if (d.defender) {
    if (d.defender.av === false || d.defender.rt === false) add({ ruleId: 'win-defender-off', severity: 'critical', title: 'Virenschutz ist ausgeschaltet', description: 'Der Echtzeitschutz von Microsoft Defender ist aus, und es läuft kein anderer erkannter Virenschutz. Schadprogramme werden dann nicht mehr abgefangen.', remediation: 'Windows-Sicherheit → Viren- & Bedrohungsschutz → Echtzeitschutz einschalten.' });
    else if (d.defender.age > 7) add({ ruleId: 'win-defender-outdated', severity: 'medium', title: `Virendefinitionen ${d.defender.age} Tage alt`, description: 'Der Virenschutz kennt die neuesten Schadprogramme nicht.', remediation: 'Windows-Sicherheit öffnen → Schutzupdates → Nach Updates suchen.' });
    if (d.defender.tamper === false) add({ ruleId: 'win-tamper-off', severity: 'low', title: 'Manipulationsschutz ist aus', description: 'Schadprogramme können den Virenschutz leichter abschalten.', remediation: 'Windows-Sicherheit → Viren- & Bedrohungsschutz → Einstellungen → Manipulationsschutz einschalten.' });
  }
  for (const p of d.firewall || []) if (p.enabled === false) add({ ruleId: 'win-firewall-off', severity: p.name === 'Public' ? 'high' : 'medium', title: `Firewall für das Profil „${({ Domain: 'Domäne', Private: 'Privat', Public: 'Öffentlich' })[p.name] || p.name}“ ist aus`, description: 'Ohne Firewall sind Dienste auf diesem PC für alle Geräte im selben Netz erreichbar – in öffentlichen WLANs besonders gefährlich.', remediation: 'Windows-Sicherheit → Firewall- & Netzwerkschutz → Firewall für alle Profile einschalten.' });
  // BitLocker: 1 = an, 3/5 = wird verschluesselt, 2/0 = aus
  if (d.bitlocker === 2 || d.bitlocker === 0) add({ ruleId: 'win-bitlocker-off', severity: 'high', category: 'Crypto', title: 'Systemfestplatte ist nicht verschlüsselt', description: 'Wird der Laptop gestohlen, kann man die Festplatte ausbauen und alle Dateien lesen – auch ohne Windows-Passwort.', remediation: 'Einstellungen → Datenschutz & Sicherheit → Geräteverschlüsselung (bzw. BitLocker) einschalten. Wiederherstellungsschlüssel sicher aufbewahren.' });
  if (d.lastUpdateDays > 45) add({ ruleId: 'win-updates-old', severity: d.lastUpdateDays > 90 ? 'high' : 'medium', category: 'Dependencies', title: `Letztes Windows-Update vor ${d.lastUpdateDays} Tagen`, description: 'Microsoft schließt jeden Monat Sicherheitslücken. Ein länger nicht aktualisierter PC ist über bekannte Lücken angreifbar.', remediation: 'Einstellungen → Windows Update → Nach Updates suchen und installieren.' });
  if (d.uac === 0) add({ ruleId: 'win-uac-off', severity: 'high', category: 'AccessControl', title: 'Benutzerkontensteuerung (UAC) ist aus', description: 'Programme bekommen ohne Rückfrage Administratorrechte. Ein Schadprogramm kann so das ganze System verändern.', remediation: 'Systemsteuerung → Benutzerkonten → Einstellungen der Benutzerkontensteuerung ändern → mindestens Standard.' });
  if (d.rdpDeny === 0) add({ ruleId: d.rdpNla === 0 ? 'win-rdp-no-nla' : 'win-rdp-on', severity: d.rdpNla === 0 ? 'high' : 'low', category: 'Auth', title: d.rdpNla === 0 ? 'Remotedesktop an – ohne vorherige Anmeldung (NLA)' : 'Remotedesktop ist eingeschaltet', description: d.rdpNla === 0 ? 'Remotedesktop nimmt Verbindungen an, bevor sich jemand angemeldet hat. Mehrere schwere Lücken (z. B. BlueKeep) nutzen genau das aus.' : 'Andere Rechner können sich per Remotedesktop anmelden. Das ist nur sinnvoll, wenn es gebraucht wird.', remediation: 'Einstellungen → System → Remotedesktop ausschalten oder „Netzwerkebenenauthentifizierung erforderlich“ aktivieren.' });
  if (d.smb1) add({ ruleId: 'win-smb1', severity: 'high', title: 'Veraltetes Dateifreigabe-Protokoll SMBv1 aktiv', description: 'Über SMBv1 hat sich 2017 die Erpressungssoftware WannaCry verbreitet. Es wird heute praktisch nie mehr gebraucht.', remediation: 'Windows-Features aktivieren oder deaktivieren → „Unterstützung für SMB 1.0/CIFS-Dateifreigabe“ abwählen.' });
  if (d.guest) add({ ruleId: 'win-guest-enabled', severity: 'medium', category: 'Auth', title: 'Gastkonto ist aktiv', description: 'Über das Gastkonto kann man sich ohne eigenes Passwort am PC anmelden.', remediation: 'Computerverwaltung → Lokale Benutzer → Gast → Konto ist deaktiviert.' });
  return out;
}

// --- Docker ---------------------------------------------------------------------
function parseDocker(list) {
  const out = [];
  for (const c of list || []) {
    const name = String(c.Name || c.Id || '?').replace(/^\//, '');
    const hc = c.HostConfig || {};
    const add = (o) => out.push(mk('docker', { location: `docker://${name}`, ...o, title: `${o.title} („${name}“)` }));
    if (hc.Privileged) add({ ruleId: 'container-privileged', severity: 'critical', title: 'Laufender Container ist privilegiert', description: 'Der Container hat praktisch vollen Zugriff auf den Rechner, auf dem Docker läuft.', remediation: 'Container ohne --privileged neu starten und nur einzelne benötigte Rechte freigeben.' });
    if ((c.Mounts || []).some((m) => /docker\.sock$/.test(m.Source || ''))) add({ ruleId: 'container-docker-sock', severity: 'critical', title: 'Docker-Steuerung in den Container eingebunden', description: 'Mit docker.sock kann der Container weitere Container mit vollen Rechten starten und so den Rechner übernehmen.', remediation: 'Mount entfernen oder einen eingeschränkten Socket-Proxy verwenden.' });
    if (hc.NetworkMode === 'host') add({ ruleId: 'container-host-network', severity: 'high', title: 'Container nutzt das Netzwerk des Rechners', description: 'Er erreicht alle lokalen Dienste und kann auf allen Schnittstellen lauschen.', remediation: 'Eigenes Docker-Netz verwenden und Ports gezielt freigeben.' });
    if (hc.PidMode === 'host') add({ ruleId: 'container-host-pid', severity: 'high', title: 'Container sieht alle Prozesse des Rechners', description: 'Mit --pid=host lassen sich andere Prozesse beobachten und beeinflussen.', remediation: 'Ohne --pid=host neu starten.' });
    if ((hc.CapAdd || []).some((x) => /SYS_ADMIN|ALL|NET_ADMIN/.test(x))) add({ ruleId: 'container-cap-sys-admin', severity: 'high', title: 'Gefährliche Zusatzrechte (Capabilities)', description: 'SYS_ADMIN, NET_ADMIN oder ALL sind bekannte Wege aus dem Container heraus.', remediation: 'Zusatzrechte entfernen und nur das Nötigste freigeben.' });
    if (!c.Config || !c.Config.User || /^(root|0)(:0)?$/.test(c.Config.User)) add({ ruleId: 'container-root-user', severity: 'low', title: 'Container läuft als root', description: 'Eine Lücke in der App bedeutet dann root im Container.', remediation: 'Image mit eigenem Benutzer bauen (USER im Dockerfile) oder mit --user starten.' });
    for (const [port, binds] of Object.entries(hc.PortBindings || {})) {
      const inner = Number(String(port).split('/')[0]);
      for (const b of binds || []) if (RISKY[inner] && (!b.HostIp || b.HostIp === '0.0.0.0' || b.HostIp === '::')) add({ ruleId: 'container-db-port-public', severity: inner === 22 ? 'medium' : 'high', title: `${RISKY[inner]}-Port ${b.HostPort} auf allen Netzwerk-Schnittstellen`, description: 'Der Dienst ist nicht nur lokal, sondern für alle Geräte im Netz erreichbar.', remediation: `Nur an 127.0.0.1 binden: -p 127.0.0.1:${b.HostPort}:${inner}` });
    }
  }
  return out;
}

// --- Cloud ----------------------------------------------------------------------
function parseAws({ summary, passwordPolicy, buckets = [], groups = [] }) {
  const out = [];
  const add = (o) => out.push(mk('aws', { location: o.location || 'AWS-Konto', ...o }));
  const s = summary && summary.SummaryMap;
  if (s && s.AccountMFAEnabled === 0) add({ ruleId: 'aws-root-no-mfa', severity: 'critical', category: 'Auth', title: 'Haupt-Konto (root) ohne Zwei-Faktor-Anmeldung', description: 'Wer das Passwort des root-Kontos kennt, hat vollen Zugriff auf alles – inklusive Rechnungen und Löschen des Kontos.', remediation: 'In der AWS-Konsole unter „Sicherheitsanmeldeinformationen“ für root einen MFA-Schlüssel einrichten.' });
  if (s && s.AccountAccessKeysPresent === 1) add({ ruleId: 'aws-root-access-keys', severity: 'high', category: 'Secrets', title: 'Zugriffsschlüssel für das root-Konto vorhanden', description: 'Ein root-Schlüssel kann alles und lässt sich nicht einschränken. Gelangt er in Code oder Logs, ist das Konto verloren.', remediation: 'root-Schlüssel löschen und für Programme eigene IAM-Rollen mit wenig Rechten verwenden.' });
  if (passwordPolicy === null) add({ ruleId: 'aws-no-password-policy', severity: 'medium', category: 'Auth', title: 'Keine Passwort-Richtlinie für IAM-Benutzer', description: 'Benutzer dürfen beliebig kurze und einfache Passwörter verwenden.', remediation: 'IAM → Kontoeinstellungen → Passwortrichtlinie mit mindestens 14 Zeichen festlegen.' });
  for (const b of buckets) {
    if (b.isPublic) add({ ruleId: 'cloud-bucket-public', severity: 'critical', category: 'AccessControl', location: `s3://${b.name}`, title: `S3-Bucket ist öffentlich: ${b.name}`, description: 'Die Bucket-Richtlinie gibt den Inhalt für jeden im Internet frei.', remediation: 'Richtlinie prüfen und „Öffentlichen Zugriff blockieren“ für den Bucket einschalten.' });
    else if (b.blockMissing) add({ ruleId: 'cloud-bucket-no-block', severity: 'low', category: 'AccessControl', location: `s3://${b.name}`, title: `S3-Bucket ohne Sperre gegen öffentliche Freigabe: ${b.name}`, description: 'Ein einziger Fehler in einer Richtlinie würde den Bucket öffentlich machen.', remediation: 'Für den Bucket „Öffentlichen Zugriff blockieren“ mit allen vier Optionen einschalten.' });
  }
  for (const g of groups) for (const p of g.IpPermissions || []) {
    const open = (p.IpRanges || []).some((r) => r.CidrIp === '0.0.0.0/0') || (p.Ipv6Ranges || []).some((r) => r.CidrIpv6 === '::/0');
    if (!open) continue;
    const all = p.IpProtocol === '-1';
    const hit = Object.keys(RISKY).map(Number).find((port) => all || (port >= p.FromPort && port <= p.ToPort));
    if (hit) add({ ruleId: 'cloud-firewall-open', severity: 'high', location: `${g.GroupId} (${g.GroupName})`, title: all ? `Firewall-Regel „${g.GroupName}“ erlaubt alles aus dem Internet` : `${RISKY[hit]}-Port ${hit} in „${g.GroupName}“ für das ganze Internet offen`, description: 'Die Sicherheitsgruppe nimmt Verbindungen von jeder Adresse an. Solche Ports werden ständig automatisch angegriffen.', remediation: 'Quelle auf feste Adressen oder ein VPN beschränken.' });
  }
  return out;
}

function parseAzure({ storage = [], nsgs = [] }) {
  const out = [];
  const add = (o) => out.push(mk('azure', o));
  for (const a of storage) {
    if (a.allowBlobPublicAccess) add({ ruleId: 'cloud-bucket-public', severity: 'high', category: 'AccessControl', location: `azure://${a.name}`, title: `Speicherkonto erlaubt öffentliche Container: ${a.name}`, description: 'Container in diesem Konto können ohne Anmeldung gelesen werden.', remediation: 'Speicherkonto → Konfiguration → „Anonymen Blobzugriff zulassen“ deaktivieren.' });
    if (a.enableHttpsTrafficOnly === false) add({ ruleId: 'iac-azure-http', severity: 'medium', category: 'Transport', location: `azure://${a.name}`, title: `Speicherkonto erlaubt HTTP: ${a.name}`, description: 'Daten können unverschlüsselt übertragen werden.', remediation: '„Sichere Übertragung erforderlich“ aktivieren.' });
    if (/TLS1_[01]$/.test(a.minimumTlsVersion || '')) add({ ruleId: 'iac-azure-old-tls', severity: 'medium', category: 'Transport', location: `azure://${a.name}`, title: `Speicherkonto erlaubt veraltetes TLS: ${a.name}`, description: 'TLS 1.0/1.1 gelten als unsicher.', remediation: 'Minimale TLS-Version auf 1.2 setzen.' });
  }
  for (const n of nsgs) for (const r of n.securityRules || []) {
    if (r.direction !== 'Inbound' || r.access !== 'Allow' || !/^(\*|Internet|0\.0\.0\.0\/0|Any)$/i.test(r.sourceAddressPrefix || '')) continue;
    const ranges = [r.destinationPortRange, ...(r.destinationPortRanges || [])].filter(Boolean);
    const hit = Object.keys(RISKY).map(Number).find((p) => ranges.some((x) => x === '*' || x === String(p) || (/^\d+-\d+$/.test(x) && p >= +x.split('-')[0] && p <= +x.split('-')[1])));
    if (hit) add({ ruleId: 'cloud-firewall-open', severity: 'high', location: `${n.name}/${r.name}`, title: `${RISKY[hit]}-Port ${hit} in „${n.name}“ für das ganze Internet offen`, description: 'Die Netzwerk-Sicherheitsgruppe lässt Verbindungen von überall zu.', remediation: 'Quelle auf feste Adressen beschränken oder Azure Bastion verwenden.' });
  }
  return out;
}

function parseGcp({ buckets = [], firewalls = [] }) {
  const out = [];
  const add = (o) => out.push(mk('gcp', o));
  for (const b of buckets) if (b.public) add({ ruleId: 'cloud-bucket-public', severity: 'critical', category: 'AccessControl', location: `gs://${b.name}`, title: `Cloud-Storage-Bucket ist öffentlich: ${b.name}`, description: 'allUsers bzw. allAuthenticatedUsers haben Zugriff.', remediation: 'Öffentliche Mitglieder entfernen und „Öffentlichen Zugriff verhindern“ erzwingen.' });
  for (const f of firewalls) {
    if (f.disabled || (f.direction && f.direction !== 'INGRESS') || !(f.sourceRanges || []).includes('0.0.0.0/0')) continue;
    for (const a of f.allowed || []) {
      const ports = a.ports || (a.IPProtocol === 'all' ? ['0-65535'] : []);
      const hit = Object.keys(RISKY).map(Number).find((p) => ports.some((x) => x === String(p) || (/^\d+-\d+$/.test(x) && p >= +x.split('-')[0] && p <= +x.split('-')[1])));
      if (hit) { add({ ruleId: 'cloud-firewall-open', severity: 'high', location: `firewall/${f.name}`, title: `${RISKY[hit]}-Port ${hit} in „${f.name}“ für das ganze Internet offen`, description: 'Die Firewall-Regel lässt Verbindungen von überall zu.', remediation: 'sourceRanges auf feste Adressen beschränken oder Identity-Aware Proxy verwenden.' }); break; }
    }
  }
  return out;
}

const BUCKET_RE = /^[a-z0-9][a-z0-9._-]{1,220}$/;

async function auditSystem(kind, { signal, onProgress = () => {} } = {}) {
  const say = (m) => onProgress({ phase: 'webscan', message: m });
  if (kind === 'windows') {
    if (process.platform !== 'win32') return { findings: [], notes: ['Windows-Prüfung ist nur unter Windows möglich.'] };
    say('Windows: Virenschutz, Firewall, Verschlüsselung, Updates …');
    const r = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', WIN_PS], { signal, timeoutMs: 90000 });
    const d = json(r.stdout.trim());
    if (!d) return { findings: [], notes: [`Windows-Prüfung fehlgeschlagen: ${r.error || 'keine Daten'}`] };
    return { findings: parseWindows(d), notes: [`Windows geprüft (${d.os || 'unbekannte Version'}).`], ok: true };
  }
  if (kind === 'docker') {
    say('Docker: laufende Container …');
    const ps = await run('docker', ['ps', '-q'], { signal });
    if (!ps.ok) return { findings: [], notes: [`Docker-Prüfung nicht ausgeführt (${ps.error}). Läuft Docker?`] };
    const ids = ps.stdout.split(/\s+/).filter((x) => /^[a-f0-9]{6,64}$/.test(x)).slice(0, 100);
    if (!ids.length) return { findings: [], notes: ['Docker: keine laufenden Container.'], ok: true };
    const ins = await run('docker', ['inspect', ...ids], { signal });
    return { findings: parseDocker(json(ins.stdout) || []), notes: [`Docker: ${ids.length} laufende Container geprüft.`], ok: ins.ok };
  }
  if (kind === 'aws') {
    say('AWS: Konto, Speicher, Firewall-Regeln (nur lesend) …');
    const id = await run('aws', ['sts', 'get-caller-identity', '--output', 'json'], { signal });
    if (!id.ok) return { findings: [], notes: [`AWS-Prüfung nicht ausgeführt (${id.error}). AWS-CLI installiert und angemeldet (aws configure)?`] };
    const summary = json((await run('aws', ['iam', 'get-account-summary', '--output', 'json'], { signal })).stdout);
    const pp = await run('aws', ['iam', 'get-account-password-policy', '--output', 'json'], { signal });
    const passwordPolicy = pp.ok ? json(pp.stdout) : /NoSuchEntity/.test(pp.stderr || '') ? null : undefined;
    const names = ((json((await run('aws', ['s3api', 'list-buckets', '--output', 'json'], { signal })).stdout) || {}).Buckets || []).map((b) => b.Name).filter((n) => BUCKET_RE.test(n)).slice(0, 40);
    const buckets = [];
    for (const name of names) {
      const st = json((await run('aws', ['s3api', 'get-bucket-policy-status', '--bucket', name, '--output', 'json'], { signal, timeoutMs: 20000 })).stdout);
      const blk = await run('aws', ['s3api', 'get-public-access-block', '--bucket', name, '--output', 'json'], { signal, timeoutMs: 20000 });
      buckets.push({ name, isPublic: !!(st && st.PolicyStatus && st.PolicyStatus.IsPublic), blockMissing: !blk.ok && /NoSuchPublicAccessBlockConfiguration/.test(blk.stderr || '') });
    }
    const groups = (json((await run('aws', ['ec2', 'describe-security-groups', '--output', 'json'], { signal })).stdout) || {}).SecurityGroups || [];
    return { findings: parseAws({ summary, passwordPolicy, buckets, groups }), notes: [`AWS-Konto geprüft (${buckets.length} Buckets, ${groups.length} Sicherheitsgruppen).`], ok: true };
  }
  if (kind === 'azure') {
    say('Azure: Speicherkonten, Netzwerkregeln (nur lesend) …');
    const acc = await run('az', ['account', 'show', '--output', 'json'], { signal });
    if (!acc.ok) return { findings: [], notes: [`Azure-Prüfung nicht ausgeführt (${acc.error}). Azure-CLI installiert und angemeldet (az login)?`] };
    const storage = json((await run('az', ['storage', 'account', 'list', '--output', 'json'], { signal })).stdout) || [];
    const nsgs = json((await run('az', ['network', 'nsg', 'list', '--output', 'json'], { signal })).stdout) || [];
    return { findings: parseAzure({ storage, nsgs }), notes: [`Azure geprüft (${storage.length} Speicherkonten, ${nsgs.length} Netzwerkgruppen).`], ok: true };
  }
  if (kind === 'gcp') {
    say('Google Cloud: Buckets, Firewall-Regeln (nur lesend) …');
    const proj = await run('gcloud', ['config', 'get-value', 'project'], { signal });
    if (!proj.ok || !proj.stdout.trim()) return { findings: [], notes: [`Google-Cloud-Prüfung nicht ausgeführt (${proj.error || 'kein Projekt gesetzt'}). gcloud installiert und angemeldet?`] };
    const list = json((await run('gcloud', ['storage', 'buckets', 'list', '--format=json'], { signal })).stdout) || [];
    const buckets = [];
    for (const b of list.slice(0, 40)) {
      const name = String(b.name || '').replace(/^gs:\/\//, '');
      if (!BUCKET_RE.test(name)) continue;
      const pol = json((await run('gcloud', ['storage', 'buckets', 'get-iam-policy', `gs://${name}`, '--format=json'], { signal, timeoutMs: 20000 })).stdout);
      buckets.push({ name, public: !!(pol && (pol.bindings || []).some((x) => (x.members || []).some((m) => /^all(Authenticated)?Users$/.test(m)))) });
    }
    const firewalls = json((await run('gcloud', ['compute', 'firewall-rules', 'list', '--format=json'], { signal })).stdout) || [];
    return { findings: parseGcp({ buckets, firewalls }), notes: [`Google Cloud geprüft (Projekt ${proj.stdout.trim()}).`], ok: true };
  }
  return { findings: [], notes: [`Unbekannte System-Prüfung: ${kind}`] };
}

module.exports = { auditSystem, parseWindows, parseDocker, parseAws, parseAzure, parseGcp, SYSTEMS };
