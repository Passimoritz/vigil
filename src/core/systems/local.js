'use strict';

// Pruefungen auf DIESEM Rechner (nur lesend): installierte Programme, Browser-Erweiterungen,
// Datensicherung (Windows) und macOS-Grundschutz. Auswertung in reinen parse*-Funktionen.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { run, json, mk, http, cmpVer, list } = require('./common');

// --- Installierte Programme (winapps) ----------------------------------------------
const APPS_PS = `
$ErrorActionPreference='SilentlyContinue'
$k='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
$a=@(Get-ItemProperty $k | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object { @{n=[string]$_.DisplayName;v=[string]$_.DisplayVersion;p=[string]$_.Publisher} })
ConvertTo-Json -InputObject $a -Depth 3 -Compress`;

// Haeufig angegriffene Programme mit bekannter Luecke und erster behobener Version (Hersteller-/NVD-Angaben).
const VULN_APPS = [
  { re: /^7-Zip\b/i, fixed: '24.09', cve: 'CVE-2025-0411', note: 'Beim Entpacken geht der Internet-Herkunftsvermerk verloren – Schadprogramme umgehen so Windows-Warnungen' },
  { re: /^WinRAR\b/i, fixed: '7.13', cve: 'CVE-2025-8088', note: 'Ein präpariertes Archiv kann Dateien außerhalb des Zielordners ablegen – wird aktiv ausgenutzt' },
  { re: /^PuTTY\b/i, fixed: '0.81', cve: 'CVE-2024-31497', note: 'Aus wenigen Signaturen lässt sich der private SSH-Schlüssel berechnen' },
  { re: /^VLC media player\b/i, fixed: '3.0.21', cve: 'CVE-2024-46461', note: 'Eine präparierte Videodatei kann Schadcode ausführen' },
  { re: /^Notepad\+\+/i, fixed: '8.8.2', cve: 'CVE-2025-49144', note: 'Das Installationsprogramm lässt sich zur Rechteausweitung missbrauchen' },
  { re: /^Git(\s+version\s+[\d.]+)?$/i, fixed: '2.45.1', cve: 'CVE-2024-32002', note: 'Das Klonen eines präparierten Repositorys kann Schadcode ausführen' },
  { re: /^KeePass Password Safe 2/i, fixed: '2.54', cve: 'CVE-2023-32784', note: 'Das Hauptpasswort lässt sich aus dem Arbeitsspeicher zurückgewinnen' },
  { re: /^OpenVPN\b/i, fixed: '2.6.10', cve: 'CVE-2024-27459', note: 'Lokale Rechteausweitung über den OpenVPN-Dienst' },
];

// Tabellenausgabe von "winget upgrade" (Spaltenpositionen aus der Kopfzeile, sprachunabhaengig)
function parseWingetUpgrade(text) {
  const lines = String(text || '').split('\n').map((l) => l.split('\r').pop());
  const di = lines.findIndex((l) => /^-{10,}$/.test(l.trim()));
  if (di < 1) return [];
  const head = lines[di - 1];
  const cols = [...head.matchAll(/\S+/g)].map((m) => m.index);
  if (cols.length < 4) return [];
  const out = [];
  for (const l of lines.slice(di + 1)) {
    if (!l.trim() || /^\d+\s/.test(l.trim()) || l.length < cols[3]) break;
    const cut = (i) => l.slice(cols[i], cols[i + 1] != null ? cols[i + 1] : undefined).trim();
    const row = { name: cut(0), id: cut(1), version: cut(2), available: cut(3) };
    if (row.name && row.available) out.push(row);
  }
  return out;
}

function parseWinApps({ apps = [], upgrades = [] }) {
  const out = [];
  const flagged = new Set();
  for (const a of apps) {
    const rule = VULN_APPS.find((r) => r.re.test(a.n || ''));
    if (!rule || !a.v || cmpVer(a.v, rule.fixed) >= 0 || flagged.has(a.n)) continue;
    flagged.add(a.n);
    out.push(mk('winapps', { ruleId: 'winapp-vulnerable', severity: 'high', category: 'Dependencies', confidence: 'medium', location: `Programm: ${a.n}`, title: `Verwundbare Version installiert: ${a.n} ${a.v}`, description: `${rule.note} (${rule.cve}). Behoben ab Version ${rule.fixed}.`, remediation: `${a.n} auf Version ${rule.fixed} oder neuer aktualisieren (Hersteller-Webseite oder „winget upgrade“).` }));
  }
  for (const u of upgrades.slice(0, 40)) {
    if ([...flagged].some((n) => n.startsWith(u.name.replace(/…$/, '')))) continue;
    out.push(mk('winapps', { ruleId: 'winapp-update-available', severity: 'low', category: 'Dependencies', location: `Programm: ${u.name}`, title: `Update verfügbar: ${u.name} (${u.version} → ${u.available})`, description: 'Für dieses Programm gibt es eine neuere Version. Updates schließen oft Sicherheitslücken.', remediation: `Aktualisieren, z. B. mit: winget upgrade --id ${u.id}` }));
  }
  return out;
}

async function auditWinApps({ signal, say, run: r = run, platform = process.platform }) {
  if (platform !== 'win32') return { findings: [], notes: ['Programm-Prüfung ist nur unter Windows möglich.'] };
  say('Programme: installierte Versionen und verfügbare Updates …');
  const reg = await r('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', APPS_PS], { signal, timeoutMs: 90000 });
  const apps = json(reg.stdout);
  if (!Array.isArray(apps)) return { findings: [], notes: [`Programm-Prüfung fehlgeschlagen: ${reg.error || 'keine Daten'}`] };
  const wg = await r('winget', ['upgrade', '--include-unknown', '--disable-interactivity'], { signal, timeoutMs: 120000 });
  const upgrades = parseWingetUpgrade(wg.stdout);
  const notes = [`${apps.length} installierte Programme gelesen.`];
  if (!wg.stdout) notes.push(`winget nicht verfügbar (${wg.error || 'keine Ausgabe'}) – nur bekannte Lücken geprüft.`);
  else notes.push(`${upgrades.length} Updates verfügbar (winget).`);
  return { findings: parseWinApps({ apps, upgrades }), notes, ok: true };
}

// --- Browser-Erweiterungen (browserext) --------------------------------------------
const EXT_FEED = 'https://raw.githubusercontent.com/palant/malicious-extensions-list/main/list.txt';
const ALL_SITES = /^(<all_urls>|\*:\/\/\*\/\*?|https?:\/\/\*\/\*?|\*:\/\/\*\.?[^/]*\/\*|file:\/\/\/\*)$/;
const STRONG = ['webRequest', 'webRequestBlocking', 'debugger', 'proxy', 'cookies', 'history', 'clipboardRead', 'scripting', 'tabCapture', 'desktopCapture', 'declarativeNetRequestWithHostAccess', 'management'];
// Mit dem Browser ausgelieferte Bestandteile
const BUILTIN_EXT = new Set(['ahfgeienlihckogmohjhadlkjgocpleb', 'nmmhkkegccagdldgiimedpiccmgmieda', 'pkedcjkdefgpdelpbcmbmeomcjbeemfm', 'mhjfbmdgcfjbbpaeojofohoefgiehjai', 'ghbmnnjooekpmoecnnnilnnbdlolhkhi', 'jmjflgjpcpepeafmmgdpfkogkghcpiha']);

function assessExtension(e, malicious = new Set()) {
  const out = [];
  if (BUILTIN_EXT.has(e.id)) return out;
  const perms = (e.permissions || []).filter((p) => typeof p === 'string');
  const hosts = (e.hosts || []).filter((p) => typeof p === 'string');
  const name = String(e.name || e.id).slice(0, 80);
  const loc = `${e.browser}: ${name} (${e.id})`;
  const add = (o) => out.push(mk('browserext', { category: 'AccessControl', location: loc, ...o }));
  if (malicious.has(e.id)) add({ ruleId: 'browserext-malicious', severity: 'critical', category: 'Other', title: `Bekannt schädliche Browser-Erweiterung: ${name} (${e.browser})`, description: 'Diese Erweiterung steht auf einer öffentlichen Liste bekannter Schad-Erweiterungen. Sie kann Passwörter, Sitzungen und Eingaben mitlesen.', remediation: 'Erweiterung sofort entfernen, danach wichtige Passwörter ändern und überall abmelden.' });
  const all = [...perms, ...hosts].some((x) => ALL_SITES.test(x));
  const strong = perms.filter((p) => STRONG.includes(p));
  if (perms.includes('nativeMessaging')) add({ ruleId: 'browserext-native-messaging', severity: 'medium', title: `Erweiterung darf Programme auf dem PC ansprechen: ${name} (${e.browser})`, description: 'Mit nativeMessaging kann die Erweiterung mit installierten Programmen außerhalb des Browsers sprechen und so dessen Schutz umgehen.', remediation: 'Nur behalten, wenn sie zu einem bewusst installierten Programm gehört (z. B. Passwort-Manager), sonst entfernen.' });
  if (all && strong.length) add({ ruleId: 'browserext-broad-access', severity: 'medium', title: `Erweiterung liest und verändert alle Webseiten: ${name} (${e.browser})`, description: `Sie hat Zugriff auf jede Webseite und zusätzlich auf: ${strong.join(', ')}. Damit könnte sie Logins, Cookies und Eingaben überall mitlesen.`, remediation: 'Prüfen, ob die Erweiterung wirklich gebraucht wird. Im Browser unter Erweiterungen → Details den Webseitenzugriff auf „Bei Klick“ oder bestimmte Seiten beschränken.' });
  else if (all) add({ ruleId: 'browserext-all-sites', severity: 'low', title: `Erweiterung hat Zugriff auf alle Webseiten: ${name} (${e.browser})`, description: 'Die Erweiterung kann den Inhalt jeder geöffneten Webseite lesen und verändern.', remediation: 'Webseitenzugriff auf „Bei Klick“ oder bestimmte Seiten beschränken, nicht genutzte Erweiterungen entfernen.' });
  return out;
}

function msgName(dir, manifest) {
  const m = String(manifest.name || '').match(/^__MSG_(.+)__$/);
  if (!m) return manifest.name;
  for (const loc of [manifest.default_locale, 'en', 'en_US', 'de'].filter(Boolean)) {
    const msgs = json(readSmall(path.join(dir, '_locales', loc, 'messages.json')));
    if (!msgs) continue;
    const key = Object.keys(msgs).find((k) => k.toLowerCase() === m[1].toLowerCase());
    if (key && msgs[key].message) return msgs[key].message;
  }
  return manifest.name;
}
function readSmall(f) { try { const st = fs.statSync(f); return st.size < 2e6 ? fs.readFileSync(f, 'utf8').replace(/^﻿/, '') : null; } catch { return null; } }
const dirs = (d) => { try { return fs.readdirSync(d, { withFileTypes: true }).filter((x) => x.isDirectory()).map((x) => x.name); } catch { return []; } };

function browserRoots(platform = process.platform, env = process.env, home = os.homedir()) {
  if (platform === 'win32') {
    const la = env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    return { chromium: [['Chrome', path.join(la, 'Google', 'Chrome', 'User Data')], ['Edge', path.join(la, 'Microsoft', 'Edge', 'User Data')], ['Brave', path.join(la, 'BraveSoftware', 'Brave-Browser', 'User Data')]], firefox: path.join(env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Mozilla', 'Firefox', 'Profiles') };
  }
  if (platform === 'darwin') {
    const as = path.join(home, 'Library', 'Application Support');
    return { chromium: [['Chrome', path.join(as, 'Google', 'Chrome')], ['Edge', path.join(as, 'Microsoft Edge')], ['Brave', path.join(as, 'BraveSoftware', 'Brave-Browser')]], firefox: path.join(as, 'Firefox', 'Profiles') };
  }
  const cfg = path.join(home, '.config');
  return { chromium: [['Chrome', path.join(cfg, 'google-chrome')], ['Chromium', path.join(cfg, 'chromium')], ['Edge', path.join(cfg, 'microsoft-edge')], ['Brave', path.join(cfg, 'BraveSoftware', 'Brave-Browser')]], firefox: path.join(home, '.mozilla', 'firefox') };
}

// Alle Erweiterungen aus den lokalen Profilen lesen (nur Dateien lesen, nichts aendern)
function collectExtensions(roots) {
  const out = [];
  for (const [browser, root] of roots.chromium) {
    for (const prof of dirs(root).filter((p) => /^(Default|Profile \d+)$/.test(p))) {
      const extDir = path.join(root, prof, 'Extensions');
      for (const id of dirs(extDir).filter((x) => /^[a-p]{32}$/.test(x))) {
        const vers = dirs(path.join(extDir, id)).sort(cmpVer);
        const dir = path.join(extDir, id, vers[vers.length - 1] || '');
        const man = json(readSmall(path.join(dir, 'manifest.json')));
        if (!man) continue;
        const hosts = [...(man.host_permissions || []), ...(man.content_scripts || []).flatMap((c) => c.matches || [])];
        out.push({ browser: prof === 'Default' ? browser : `${browser} (${prof})`, id, name: msgName(dir, man), version: man.version, permissions: man.permissions || [], hosts });
      }
    }
  }
  for (const prof of dirs(roots.firefox)) {
    const data = json(readSmall(path.join(roots.firefox, prof, 'extensions.json')));
    for (const a of (data && data.addons) || []) {
      if (a.type !== 'extension' || a.location !== 'app-profile') continue;
      const up = a.userPermissions || {};
      out.push({ browser: 'Firefox', id: String(a.id || ''), name: (a.defaultLocale && a.defaultLocale.name) || a.id, version: a.version, permissions: up.permissions || [], hosts: up.origins || [] });
    }
  }
  return out;
}
const parseExtFeed = (text) => new Set(String(text || '').match(/\b[a-p]{32}\b/g) || []);

async function auditBrowserExt({ signal, say, fetchImpl, roots }) {
  say('Browser: Erweiterungen in den lokalen Profilen …');
  const exts = collectExtensions(roots || browserRoots());
  const notes = [`${exts.length} Browser-Erweiterungen gelesen.`];
  const feed = await http(EXT_FEED, { signal, fetchImpl, timeoutMs: 15000 });
  const bad = feed.ok ? parseExtFeed(feed.text) : new Set();
  if (!feed.ok) notes.push('Liste bekannter Schad-Erweiterungen nicht erreichbar – nur Berechtigungen geprüft.');
  return { findings: exts.flatMap((e) => assessExtension(e, bad)), notes, ok: true };
}

// --- Datensicherung (backup, Windows) ------------------------------------------------
const BACKUP_PS = `
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$c="$env:LOCALAPPDATA\\Microsoft\\Windows\\FileHistory\\Configuration\\Config1.xml"
if(Test-Path $c){$o.fh=$true; $x=Get-Content $c -Raw; if($x -match '<TargetUrl>([^<]*)</TargetUrl>'){$o.fhTarget=$matches[1]}}
$f=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\FileHistory'; if($f.ProtectedUpToTime){$o.fhDays=[int]((Get-Date)-[DateTime]::FromFileTime([long]$f.ProtectedUpToTime)).TotalDays}
$s=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore'; $o.srDisabled=$s.DisableSR; $o.srInterval=$s.RPSessionInterval
$r=Get-ComputerRestorePoint | Sort-Object SequenceNumber -Descending | Select-Object -First 1; if($r){$o.rpDays=[int]((Get-Date)-$r.ConvertToDateTime($r.CreationTime)).TotalDays}
$u=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders'; $k=@()
if([string]$u.Desktop -match 'OneDrive'){$k+='Desktop'}; if([string]$u.Personal -match 'OneDrive'){$k+='Documents'}; if([string]$u.'My Pictures' -match 'OneDrive'){$k+='Pictures'}; $o.kfm=$k
$sh=New-Object -ComObject Shell.Application
$o.drives=@(Get-CimInstance Win32_LogicalDisk | Where-Object { ($_.DriveType -eq 2 -or $_.DriveType -eq 3) -and $_.DeviceID -ne $env:SystemDrive } | ForEach-Object { @{id=[string]$_.DeviceID;type=[int]$_.DriveType;bl=$sh.NameSpace($_.DeviceID+'\\').Self.ExtendedProperty('System.Volume.BitLockerProtection')} })
$o | ConvertTo-Json -Depth 4 -Compress`;
const RESTORE_HINT = 'Eine Sicherung ist nur so gut wie ihre Wiederherstellung: einmal im Quartal testweise eine Datei zurückholen.';

function parseBackup(d) {
  const out = [];
  if (!d) return out;
  const add = (o) => out.push(mk('backup', { category: 'Config', location: 'Dieser PC – Datensicherung', ...o }));
  const kfm = d.kfm ? [].concat(d.kfm) : [];
  if (!d.fh && !kfm.length) add({ ruleId: 'backup-none', severity: 'medium', title: 'Keine automatische Datensicherung erkannt', description: 'Weder Dateiversionsverlauf noch OneDrive-Ordnersicherung sind eingerichtet. Bei Defekt, Diebstahl oder Erpressungssoftware sind die Dateien verloren.', remediation: `Einstellungen → Konten → Windows-Sicherung (OneDrive-Ordner) oder Systemsteuerung → Dateiversionsverlauf einschalten, am besten zusätzlich auf eine externe Festplatte. ${RESTORE_HINT}` });
  if (d.fh && d.fhDays > 14) add({ ruleId: 'backup-filehistory-stale', severity: 'low', title: `Letzte Sicherung per Dateiversionsverlauf vor ${d.fhDays} Tagen`, description: 'Das Sicherungslaufwerk war wohl länger nicht angeschlossen. Neue Dateien sind seitdem nicht gesichert.', remediation: `Sicherungslaufwerk anschließen und im Dateiversionsverlauf „Jetzt ausführen“ wählen. ${RESTORE_HINT}` });
  if (!d.fh && kfm.length) add({ ruleId: 'backup-cloud-only', severity: 'low', title: 'Nur Cloud-Synchronisierung, keine getrennte Sicherung', description: 'OneDrive synchronisiert auch Löschungen und verschlüsselte Dateien. Ohne zweite, getrennte Sicherung kann Erpressungssoftware beide Kopien zerstören.', remediation: `Zusätzlich eine externe Sicherung (Dateiversionsverlauf) einrichten und die OneDrive-Wiederherstellung kennen. ${RESTORE_HINT}` });
  if (d.srDisabled === 1 || d.srInterval === 0) add({ ruleId: 'backup-restore-off', severity: 'low', title: 'Systemwiederherstellung ist ausgeschaltet', description: 'Ohne Wiederherstellungspunkte lässt sich ein fehlerhaftes Update oder ein Schadprogramm schwerer rückgängig machen.', remediation: 'Systemsteuerung → System → Computerschutz → für das Systemlaufwerk „Schutz aktivieren“.' });
  else if (d.rpDays > 30) add({ ruleId: 'backup-restore-old', severity: 'info', title: `Letzter Wiederherstellungspunkt vor ${d.rpDays} Tagen`, description: 'Windows legt Wiederherstellungspunkte normalerweise vor Updates an. Ein alter Stand hilft im Notfall wenig.', remediation: 'Computerschutz → „Erstellen“ für einen frischen Wiederherstellungspunkt.' });
  const target = (String(d.fhTarget || '').match(/^([A-Z]:)/i) || [])[1];
  for (const dr of [].concat(d.drives || [])) {
    if (!(dr.bl === 2 || dr.bl === 0)) continue;
    const isTarget = target && dr.id.toUpperCase() === target.toUpperCase();
    if (!isTarget && dr.type !== 2) continue;
    add({ ruleId: 'backup-drive-unencrypted', severity: 'low', category: 'Crypto', location: `Laufwerk ${dr.id}`, title: isTarget ? `Sicherungslaufwerk ${dr.id} ist nicht verschlüsselt` : `Wechsellaufwerk ${dr.id} ist nicht verschlüsselt`, description: 'Wer das Laufwerk mitnimmt, kann alle darauf gesicherten Dateien lesen.', remediation: 'Im Explorer Rechtsklick auf das Laufwerk → „BitLocker aktivieren“ (BitLocker To Go).' });
  }
  add({ ruleId: 'backup-restore-test', severity: 'info', title: 'Wiederherstellung regelmäßig testen', description: 'Vigil sieht nur, ob gesichert wird – nicht, ob sich die Daten auch zurückholen lassen.', remediation: RESTORE_HINT });
  return out;
}

async function auditBackup({ signal, say, run: r = run, platform = process.platform }) {
  if (platform !== 'win32') return { findings: [], notes: ['Sicherungs-Prüfung ist nur unter Windows möglich.'] };
  say('Datensicherung: Dateiversionsverlauf, Wiederherstellung, OneDrive …');
  const res = await r('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', BACKUP_PS], { signal, timeoutMs: 90000 });
  const d = json(res.stdout);
  if (!d) return { findings: [], notes: [`Sicherungs-Prüfung fehlgeschlagen: ${res.error || 'keine Daten'}`] };
  return { findings: parseBackup(d), notes: ['Datensicherung geprüft.'], ok: true };
}

// --- macOS (macos) ---------------------------------------------------------------------
const MAC_CMDS = {
  filevault: ['fdesetup', ['status']],
  gatekeeper: ['spctl', ['--status']],
  sip: ['csrutil', ['status']],
  firewall: ['/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate']],
  autoInstall: ['defaults', ['read', '/Library/Preferences/com.apple.SoftwareUpdate', 'AutomaticallyInstallMacOSUpdates']],
  version: ['sw_vers', ['-productVersion']],
  updates: ['softwareupdate', ['-l']],
};

function parseMacos(o) {
  const out = [];
  const add = (x) => out.push(mk('macos', { location: 'Dieser Mac', ...x }));
  if (/FileVault is Off/i.test(o.filevault || '')) add({ ruleId: 'mac-filevault-off', severity: 'high', category: 'Crypto', title: 'FileVault ist ausgeschaltet', description: 'Die Festplatte ist nicht verschlüsselt. Bei Verlust oder Diebstahl lassen sich alle Dateien lesen.', remediation: 'Systemeinstellungen → Datenschutz & Sicherheit → FileVault einschalten und den Wiederherstellungsschlüssel sicher aufbewahren.' });
  if (/assessments disabled/i.test(o.gatekeeper || '')) add({ ruleId: 'mac-gatekeeper-off', severity: 'high', title: 'Gatekeeper ist ausgeschaltet', description: 'macOS prüft heruntergeladene Programme nicht mehr auf Signatur und Beglaubigung.', remediation: 'Im Terminal „sudo spctl --master-enable“ ausführen bzw. unter Datenschutz & Sicherheit nur Programme aus dem App Store und von verifizierten Entwicklern erlauben.' });
  if (/status:\s*disabled/i.test(o.sip || '')) add({ ruleId: 'mac-sip-off', severity: 'high', title: 'Systemintegritätsschutz (SIP) ist aus', description: 'Schadprogramme mit Administratorrechten können Systemdateien verändern und sich tief einnisten.', remediation: 'Im Wiederherstellungsmodus im Terminal „csrutil enable“ ausführen und neu starten.' });
  if (/disabled|State = 0/i.test(o.firewall || '')) add({ ruleId: 'mac-firewall-off', severity: 'medium', title: 'macOS-Firewall ist aus', description: 'Dienste auf diesem Mac sind für alle Geräte im selben Netz erreichbar – in öffentlichen WLANs besonders riskant.', remediation: 'Systemeinstellungen → Netzwerk → Firewall einschalten.' });
  const n = (String(o.updates || '').match(/^\s*\*\s/gm) || []).length;
  if (n) add({ ruleId: 'mac-updates-pending', severity: n > 2 ? 'high' : 'medium', category: 'Dependencies', title: `${n} macOS-Updates verfügbar`, description: 'Apple schließt mit Updates regelmäßig Sicherheitslücken, darunter aktiv ausgenutzte.', remediation: 'Systemeinstellungen → Allgemein → Softwareupdate → jetzt installieren.' });
  if (/^\s*0\s*$/.test(o.autoInstall || '')) add({ ruleId: 'mac-autoupdate-off', severity: 'low', category: 'Dependencies', title: 'Automatische macOS-Updates sind aus', description: 'Sicherheitsupdates werden nur installiert, wenn jemand daran denkt.', remediation: 'Softwareupdate → Automatische Updates → „macOS-Updates installieren“ und „Sicherheitsmaßnahmen installieren“ einschalten.' });
  return out;
}

async function auditMacos({ signal, say, run: r = run, platform = process.platform }) {
  if (platform !== 'darwin') return { findings: [], notes: ['macOS-Prüfung ist nur auf einem Mac möglich.'] };
  say('macOS: FileVault, Gatekeeper, SIP, Firewall, Updates …');
  const o = {};
  for (const [k, [cmd, args]] of Object.entries(MAC_CMDS)) {
    const res = await r(cmd, args, { signal, timeoutMs: k === 'updates' ? 180000 : 20000 });
    o[k] = `${res.stdout || ''}\n${res.stderr || ''}`;
  }
  if (!/FileVault|assessments|status/i.test(o.filevault + o.gatekeeper + o.sip)) return { findings: [], notes: ['macOS-Prüfung fehlgeschlagen: keine Daten'] };
  return { findings: parseMacos(o), notes: [`macOS geprüft (${o.version.trim() || 'unbekannte Version'}).`], ok: true };
}

module.exports = { parseWingetUpgrade, parseWinApps, auditWinApps, assessExtension, collectExtensions, parseExtFeed, browserRoots, auditBrowserExt, parseBackup, auditBackup, parseMacos, auditMacos, VULN_APPS };
