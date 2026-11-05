'use strict';

// Router und Geraete im EIGENEN lokalen Netz – nur lesend:
//  - Standard-Gateway: Startseite per HTTP-GET, UPnP per SSDP-Suche (nur Antworten lesen),
//    Firmware-Stand, wo der Router ihn ohne Anmeldung nennt (z. B. FRITZ!Box)
//  - Geraete: ARP-Tabelle des Rechners, mDNS- und SSDP-Antworten (passiv)
//  - optional (vom Nutzer bestaetigt): TCP-Verbindungsversuch auf wenige Verwaltungs-Ports,
//    ausschliesslich an privaten Adressen (RFC 1918) im eigenen Subnetz. Kein Port-Scan, keine Logins.

const os = require('os');
const dgram = require('dgram');
const net = require('net');
const { run, mk, cmpVer, isPrivateIPv4 } = require('./common');

const ADMIN_PORTS = [21, 22, 23, 80, 443, 445, 3389, 5900, 8080, 8443];
const MAX_HOSTS = 64;

// --- Bausteine ----------------------------------------------------------------------
function httpGet(url, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve(null); }
    const mod = u.protocol === 'https:' ? require('https') : require('http');
    let done = false;
    const fin = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      const req = mod.get(u, { timeout: timeoutMs, rejectUnauthorized: false, headers: { 'User-Agent': 'Vigil-Audit' } }, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (d) => { body += d; if (body.length > 65536) res.destroy(); });
        const end = () => fin({ status: res.statusCode, headers: res.headers, body });
        res.on('end', end); res.on('close', end);
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => fin(null));
    } catch { fin(null); }
  });
}

function tcpOpen(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    const fin = (v) => { s.destroy(); resolve(v); };
    s.setTimeout(timeoutMs, () => fin(false));
    s.once('connect', () => fin(true));
    s.once('error', () => fin(false));
  });
}

const parseSsdpMsg = (text) => {
  const h = {};
  for (const l of String(text).split(/\r?\n/).slice(1)) { const i = l.indexOf(':'); if (i > 0) h[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); }
  return h;
};

function ssdpDiscover(timeoutMs = 3000) {
  return new Promise((resolve) => {
    const out = [];
    let sock;
    try { sock = dgram.createSocket({ type: 'udp4', reuseAddr: true }); } catch { return resolve(out); }
    const msg = Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n');
    sock.on('message', (m, rinfo) => { if (out.length < 500) out.push({ ip: rinfo.address, headers: parseSsdpMsg(m.toString('utf8')) }); });
    sock.on('error', () => { try { sock.close(); } catch { /* egal */ } resolve(out); });
    sock.bind(0, () => { try { sock.send(msg, 1900, '239.255.255.250'); } catch { /* egal */ } });
    setTimeout(() => { try { sock.close(); } catch { /* egal */ } resolve(out); }, timeoutMs);
  });
}

// mDNS: eine einzige Anfrage nach allen angebotenen Dienst-Arten (_services._dns-sd._udp.local)
function dnsName(buf, off, depth = 0) {
  const labels = [];
  let jumped = false, end = off;
  while (off < buf.length && depth < 20) {
    const len = buf[off];
    if (len === 0) { off++; break; }
    if ((len & 0xc0) === 0xc0) { if (!jumped) end = off + 2; off = ((len & 0x3f) << 8) | buf[off + 1]; jumped = true; depth++; continue; }
    labels.push(buf.slice(off + 1, off + 1 + len).toString('utf8'));
    off += 1 + len;
  }
  return [labels.join('.'), jumped ? end : off];
}
function parseMdns(buf) {
  const names = [];
  try {
    const qd = buf.readUInt16BE(4), rr = buf.readUInt16BE(6) + buf.readUInt16BE(8) + buf.readUInt16BE(10);
    let off = 12;
    for (let i = 0; i < qd; i++) { off = dnsName(buf, off)[1] + 4; }
    for (let i = 0; i < rr && off < buf.length; i++) {
      const [name, o2] = dnsName(buf, off);
      const type = buf.readUInt16BE(o2), len = buf.readUInt16BE(o2 + 8);
      const data = o2 + 10;
      if (type === 12) names.push(dnsName(buf, data)[0]);
      else if (type === 33 || type === 16) names.push(name);
      off = data + len;
    }
  } catch { /* unvollstaendiges Paket */ }
  return names;
}
function mdnsQuery() {
  const q = Buffer.alloc(12);
  q.writeUInt16BE(1, 4);
  const labels = '_services._dns-sd._udp.local'.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  return Buffer.concat([q, ...labels, Buffer.from([0, 0, 12, 0x80, 1])]);
}
function mdnsDiscover(timeoutMs = 3000) {
  return new Promise((resolve) => {
    const out = {};
    let sock;
    try { sock = dgram.createSocket({ type: 'udp4', reuseAddr: true }); } catch { return resolve(out); }
    sock.on('message', (m, rinfo) => { const n = parseMdns(m); if (n.length) out[rinfo.address] = [...new Set([...(out[rinfo.address] || []), ...n])].slice(0, 30); });
    sock.on('error', () => { try { sock.close(); } catch { /* egal */ } resolve(out); });
    sock.bind(0, () => { try { sock.send(mdnsQuery(), 5353, '224.0.0.251'); } catch { /* egal */ } });
    setTimeout(() => { try { sock.close(); } catch { /* egal */ } resolve(out); }, timeoutMs);
  });
}

function parseArp(text) {
  const out = [];
  for (const l of String(text || '').split(/\r?\n/)) {
    const m = l.match(/\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2}){5})/i);
    if (!m) continue;
    const mac = m[2].toLowerCase().replace(/-/g, ':');
    if (/^ff:ff:ff|^01:00:5e|^33:33/.test(mac) || /\.255$/.test(m[1])) continue;
    out.push({ ip: m[1], mac });
  }
  return out;
}

function parseGateway(text) {
  const s = String(text || '');
  const m = s.match(/(?:via|gateway:)\s*(\d{1,3}(?:\.\d{1,3}){3})/i) || s.match(/^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/m);
  return m ? m[1] : null;
}

const toInt = (ip) => ip.split('.').reduce((a, b) => (a * 256) + Number(b), 0);
// Eigene IPv4-Schnittstellen; als "eigenes Subnetz" gilt die Netzmaske der Schnittstelle, hoechstens /24
function ownNets(ifaces = os.networkInterfaces()) {
  const out = [];
  for (const l of Object.values(ifaces)) for (const a of l || []) {
    if (a.family !== 'IPv4' && a.family !== 4) continue;
    if (a.internal || !isPrivateIPv4(a.address)) continue;
    const bits = String(a.netmask || '255.255.255.0').split('.').map(Number).reduce((n, o) => n + (o.toString(2).match(/1/g) || []).length, 0);
    out.push({ address: a.address, bits: Math.max(bits, 24) });
  }
  return out;
}
const inOwnNet = (ip, nets) => isPrivateIPv4(ip) && nets.some((n) => (toInt(ip) >>> (32 - n.bits)) === (toInt(n.address) >>> (32 - n.bits)));

const VENDORS = [['FRITZ!Box', /FRITZ!Box|AVM/i], ['Speedport', /Speedport/i], ['TP-Link', /TP-?Link|Archer/i], ['NETGEAR', /NETGEAR/i], ['ASUS', /ASUSWRT|ASUS/], ['Linksys', /Linksys/i], ['UniFi', /UniFi|Ubiquiti/i], ['MikroTik', /MikroTik|RouterOS/i], ['OpenWrt', /OpenWrt|LuCI/i], ['DD-WRT', /DD-WRT/i], ['Vodafone Station', /Vodafone/i], ['Huawei', /Huawei/i], ['ZyXEL', /ZyXEL/i], ['DrayTek', /DrayTek|Vigor/i], ['pfSense', /pfSense/i], ['OPNsense', /OPNsense/i], ['Telekom Digitalisierungsbox', /Digitalisierungsbox/i]];
const detectVendor = (...texts) => { const t = texts.filter(Boolean).join(' '); const v = VENDORS.find(([, re]) => re.test(t)); return v ? v[0] : null; };
const xmlTag = (xml, tag) => { const m = String(xml || '').match(new RegExp(`<(?:\\w+:)?${tag}>([^<]{1,120})</(?:\\w+:)?${tag}>`, 'i')); return m ? m[1].trim() : null; };
const titleOf = (html) => { const m = String(html || '').match(/<title[^>]*>([^<]{1,120})<\/title>/i); return m ? m[1].trim() : ''; };
const IGD = /InternetGatewayDevice|WANIPConnection|WANPPPConnection/i;

// --- Router -------------------------------------------------------------------------
function parseRouter({ gateway, http80, https443, ssdp = [], boxinfo, desc }) {
  const out = [];
  const loc = `Router ${gateway}`;
  const add = (o) => out.push(mk('router', { location: loc, ...o }));
  const vendor = detectVendor(http80 && http80.body, http80 && http80.headers && http80.headers.server, https443 && https443.body, xmlTag(desc, 'manufacturer'), xmlTag(desc, 'modelName'), xmlTag(boxinfo, 'Name'));
  const model = xmlTag(boxinfo, 'Name') || [xmlTag(desc, 'modelName'), xmlTag(desc, 'modelNumber')].filter(Boolean).join(' ');
  let firmware = null;
  const bv = xmlTag(boxinfo, 'Version');
  if (bv) firmware = bv.split('.').slice(1).join('.');
  add({ ruleId: 'router-info', severity: 'info', title: `Router erkannt: ${model || vendor || 'unbekanntes Modell'} (${gateway})`, description: firmware ? `Firmware-Stand ${firmware}.` : 'Der Firmware-Stand ist ohne Anmeldung nicht lesbar.', remediation: 'In der Router-Oberfläche automatische Firmware-Updates einschalten und den Stand gelegentlich prüfen.' });
  const ok80 = http80 && http80.status === 200;
  const redirectsToTls = http80 && http80.status >= 300 && http80.status < 400 && /^https:/i.test(String((http80.headers || {}).location || ''));
  if (ok80 && !redirectsToTls && (/type=["']?password/i.test(http80.body || '') || vendor)) add({ ruleId: 'router-admin-http', severity: 'low', category: 'Transport', title: 'Router-Oberfläche nur unverschlüsselt (HTTP) erreichbar', description: 'Das Router-Passwort geht unverschlüsselt durch das Heimnetz. Ein kompromittiertes Gerät im WLAN könnte es mitlesen.', remediation: 'Die Oberfläche per https:// aufrufen bzw. in den Router-Einstellungen HTTPS erzwingen; ein langes, eigenes Router-Passwort verwenden.' });
  if (ssdp.some((r) => r.ip === gateway && IGD.test(`${r.headers.st || ''} ${r.headers.usn || ''}`))) add({ ruleId: 'router-upnp', severity: 'medium', category: 'AccessControl', title: 'UPnP ist am Router eingeschaltet', description: 'Programme und Geräte im Heimnetz können über UPnP selbstständig Ports zum Internet öffnen – auch Schadprogramme oder unsichere Kameras.', remediation: 'In der Router-Oberfläche UPnP bzw. „Selbstständige Portfreigaben“ ausschalten und nötige Freigaben gezielt von Hand einrichten.' });
  if (firmware && /FRITZ/i.test(model || vendor || '') && cmpVer(firmware, '7.50') < 0) add({ ruleId: 'router-firmware-old', severity: 'medium', category: 'Dependencies', title: `Veraltete FRITZ!OS-Version ${firmware}`, description: 'AVM liefert Sicherheitsupdates nur für aktuelle FRITZ!OS-Versionen. Ältere Stände enthalten bekannte Lücken.', remediation: 'FRITZ!Box-Oberfläche → System → Update → „Neues FRITZ!OS suchen“. Gibt es für das Modell keine Updates mehr, das Gerät ersetzen.' });
  return out;
}

async function auditRouter({ signal, say, run: r = run, platform = process.platform, deps = {} }) {
  const get = deps.httpGet || httpGet, ssdpFn = deps.ssdp || ssdpDiscover;
  say('Router: Standard-Gateway, Weboberfläche, UPnP …');
  const gwCmd = platform === 'win32' ? ['powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop"]]
    : platform === 'darwin' ? ['route', ['-n', 'get', 'default']] : ['ip', ['route', 'show', 'default']];
  const gateway = parseGateway((await r(gwCmd[0], gwCmd[1], { signal, timeoutMs: 20000 })).stdout);
  if (!gateway) return { findings: [], notes: ['Router-Prüfung nicht ausgeführt: kein Standard-Gateway gefunden.'] };
  if (!isPrivateIPv4(gateway)) return { findings: [], notes: [`Router-Prüfung übersprungen: Gateway ${gateway} ist keine private Adresse.`] };
  const [http80, https443, ssdp] = await Promise.all([get(`http://${gateway}/`), get(`https://${gateway}/`), ssdpFn()]);
  let boxinfo = null, desc = null;
  if (/FRITZ/i.test(`${http80 && http80.body} ${https443 && https443.body}`)) { const b = await get(`http://${gateway}/jason_boxinfo.xml`); boxinfo = b && b.status === 200 ? b.body : null; }
  const igd = ssdp.find((x) => x.ip === gateway && x.headers.location);
  if (igd) {
    try { const u = new URL(igd.headers.location); if (u.hostname === gateway && /^https?:$/.test(u.protocol)) { const d = await get(u.href); desc = d && d.status === 200 ? d.body : null; } } catch { /* ungueltige Adresse */ }
  }
  if (!http80 && !https443 && !ssdp.length) return { findings: parseRouter({ gateway, ssdp }), notes: [`Router ${gateway}: keine Weboberfläche erreichbar.`], ok: true };
  return { findings: parseRouter({ gateway, http80, https443, ssdp, boxinfo, desc }), notes: [`Router ${gateway} geprüft.`], ok: true };
}

// --- Geraete im lokalen Netz --------------------------------------------------------------
const TYPES = [[/_ipp|_printer|_pdl-datastream|_scanner|Printer/i, 'printer'], [/_googlecast/i, 'chromecast'], [/_airplay|_raop/i, 'airplay'], [/_hap|_homekit/i, 'homekit'], [/_sonos|Sonos/i, 'sonos'], [/MediaRenderer|DIAL|_spotify/i, 'media'], [/_smb|_afpovertcp|_adisk|NAS|Synology|QNAP/i, 'nas'], [/Camera|_rtsp|onvif/i, 'camera'], [/InternetGatewayDevice/i, 'router'], [/_workstation|_device-info/i, 'computer']];
function deviceType(texts) { const t = texts.join(' '); const m = TYPES.find(([re]) => re.test(t)); return m ? m[1] : 'unknown'; }

function parseLan({ nets = [], arp = [], ssdp = [], mdns = {}, ports = {}, titles = {}, portCheck = false }) {
  const out = [];
  const own = new Set(nets.map((n) => n.address));
  const devs = new Map();
  const dev = (ip) => { if (!devs.has(ip)) devs.set(ip, { ip, via: new Set(), info: [] }); return devs.get(ip); };
  for (const a of arp) if (inOwnNet(a.ip, nets) && !own.has(a.ip)) dev(a.ip).via.add('arp');
  for (const s of ssdp) if (inOwnNet(s.ip, nets) && !own.has(s.ip)) { const d = dev(s.ip); d.via.add('ssdp'); d.info.push(s.headers.server || '', s.headers.st || ''); }
  for (const [ip, names] of Object.entries(mdns)) if (inOwnNet(ip, nets) && !own.has(ip)) { const d = dev(ip); d.via.add('mdns'); d.info.push(...names); }
  const list = [...devs.values()].sort((a, b) => toInt(a.ip) - toInt(b.ip));
  const lines = list.map((d) => `${d.ip} ${deviceType(d.info)} [${[...d.via].join('+')}]${(ports[d.ip] || []).length ? ' ports ' + ports[d.ip].join(',') : ''}`);
  out.push(mk('lan', { ruleId: 'lan-inventory', severity: 'info', location: 'Lokales Netz', title: `${list.length} Geräte im lokalen Netz gefunden`, description: portCheck ? 'Gefunden über ARP-Tabelle, mDNS und SSDP; zusätzlich wurden wenige Verwaltungs-Ports geprüft. Unbekannte Geräte sollten zugeordnet oder aus dem Netz genommen werden.' : 'Gefunden über ARP-Tabelle, mDNS und SSDP (nur passiv). Unbekannte Geräte sollten zugeordnet oder aus dem Netz genommen werden.', remediation: 'Liste mit der Geräteübersicht im Router vergleichen; Gäste und smarte Geräte am besten in ein eigenes WLAN (Gastnetz) legen.', evidence: lines.join('\n').slice(0, 500) }));
  for (const d of list) {
    const p = new Set(ports[d.ip] || []);
    const add = (o) => out.push(mk('lan', { location: `Gerät ${d.ip}`, ...o }));
    const t = Object.values(titles[d.ip] || {}).find(Boolean);
    if (p.has(23)) add({ ruleId: 'lan-telnet', severity: 'high', category: 'Transport', title: `Telnet offen auf ${d.ip}`, description: 'Telnet überträgt Benutzername und Passwort im Klartext und ist ein beliebter Weg, um Router, Kameras und IoT-Geräte zu übernehmen (z. B. Mirai).', remediation: 'Telnet in den Geräteeinstellungen abschalten, Firmware aktualisieren und ein eigenes Passwort setzen. Geht das nicht, das Gerät ersetzen.' });
    if (p.has(21)) add({ ruleId: 'lan-ftp', severity: 'medium', category: 'Transport', title: `FTP-Dienst offen auf ${d.ip}`, description: 'FTP überträgt Zugangsdaten und Dateien unverschlüsselt.', remediation: 'FTP abschalten oder durch SFTP bzw. SMB mit Verschlüsselung ersetzen.' });
    if (p.has(5900)) add({ ruleId: 'lan-vnc', severity: 'medium', category: 'Auth', title: `Fernsteuerung (VNC) offen auf ${d.ip}`, description: 'Über VNC lässt sich das Gerät fernsteuern. Viele VNC-Server haben schwache oder gar keine Passwörter.', remediation: 'VNC abschalten, wenn es nicht gebraucht wird, sonst nur mit starkem Passwort und über VPN nutzen.' });
    if (p.has(3389)) add({ ruleId: 'lan-rdp', severity: 'low', category: 'Auth', title: `Remotedesktop offen auf ${d.ip}`, description: 'Andere Geräte im Netz können sich per Remotedesktop anmelden.', remediation: 'Remotedesktop nur einschalten, wenn er gebraucht wird, und Netzwerkebenenauthentifizierung (NLA) verlangen.' });
    if ((p.has(80) || p.has(8080)) && !p.has(443) && !p.has(8443)) add({ ruleId: 'lan-admin-http', severity: 'low', category: 'Transport', title: t ? `Weboberfläche nur über HTTP: ${t} (${d.ip})` : `Weboberfläche nur über HTTP auf ${d.ip}`, description: 'Die Verwaltungsseite des Geräts ist nur unverschlüsselt erreichbar. Passwörter gehen im Klartext durch das Netz.', remediation: 'In den Geräteeinstellungen HTTPS einschalten, Standard-Passwort ändern und Firmware aktualisieren.' });
  }
  return out;
}

async function auditLan({ signal, say, run: r = run, settings = {}, deps = {} }) {
  const nets = deps.nets || ownNets();
  if (!nets.length) return { findings: [], notes: ['Netz-Prüfung nicht ausgeführt: keine private Netzwerk-Schnittstelle gefunden.'] };
  say('Lokales Netz: ARP-Tabelle, mDNS, SSDP (passiv) …');
  const [arpRes, ssdp, mdns] = await Promise.all([r('arp', ['-a'], { signal, timeoutMs: 20000 }), (deps.ssdp || ssdpDiscover)(), (deps.mdns || mdnsDiscover)()]);
  const arp = parseArp(arpRes.stdout);
  const notes = [];
  const ports = {}, titles = {};
  const portCheck = settings.lanPortCheck === true;
  if (portCheck) {
    const ips = [...new Set([...arp.map((a) => a.ip), ...ssdp.map((s) => s.ip), ...Object.keys(mdns)])].filter((ip) => inOwnNet(ip, nets) && !nets.some((n) => n.address === ip)).slice(0, MAX_HOSTS);
    say(`Lokales Netz: ${ips.length} Geräte, wenige Verwaltungs-Ports …`);
    const tcp = deps.tcp || tcpOpen, get = deps.httpGet || httpGet;
    for (const ip of ips) {
      if (signal && signal.aborted) break;
      const res = await Promise.all(ADMIN_PORTS.map((p) => tcp(ip, p).then((o) => (o ? p : null))));
      ports[ip] = res.filter(Boolean);
      for (const p of ports[ip].filter((x) => [80, 443, 8080, 8443].includes(x))) {
        const pg = await get(`${p === 443 || p === 8443 ? 'https' : 'http'}://${ip}:${p}/`, { timeoutMs: 3000 });
        (titles[ip] = titles[ip] || {})[p] = titleOf(pg && pg.body);
      }
    }
    notes.push(`Lokales Netz: ${ips.length} Geräte, ${ADMIN_PORTS.length} Verwaltungs-Ports je Gerät geprüft.`);
  } else notes.push('Lokales Netz: Port-Prüfung aus – nur passive Erkennung (ARP, mDNS, SSDP).');
  return { findings: parseLan({ nets, arp, ssdp, mdns, ports, titles, portCheck }), notes, ok: true };
}

module.exports = { parseGateway, parseArp, parseMdns, mdnsQuery, parseSsdpMsg, parseRouter, auditRouter, parseLan, auditLan, ownNets, inOwnNet, detectVendor, ADMIN_PORTS };
