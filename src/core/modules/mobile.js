'use strict';

// Handy-Apps: Android (APK) und iOS (IPA).
//  - decodeAxml: wandelt das binaere AndroidManifest.xml einer APK in lesbares XML
//  - decodeBplist: wandelt eine binaere Info.plist (iOS) in XML-Plist-Text
//  - runMobile: Regeln auf Manifest und Plist (Berechtigungen, Debug, Backup, Klartext,
//    offene Komponenten). Eingebaute Schluessel findet die Vorpruefung in den Zeichenketten.

const { normalizeFinding } = require('../schema');

const M = 'mobile-audit';
const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;

// --- Android Binary XML ------------------------------------------------------
// Bekannte Attribut-IDs (falls die Namen in der APK verschleiert sind)
const ATTR_IDS = { 0x01010003: 'name', 0x01010006: 'permission', 0x01010010: 'exported', 0x0101000f: 'debuggable', 0x01010280: 'allowBackup', 0x010104ec: 'usesCleartextTraffic', 0x0101020c: 'minSdkVersion', 0x01010270: 'targetSdkVersion', 0x01010527: 'networkSecurityConfig' };
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');

function readStringPool(b, at) {
  const count = b.readUInt32LE(at + 8);
  const flags = b.readUInt32LE(at + 16);
  const stringsStart = b.readUInt32LE(at + 20);
  const utf8 = !!(flags & 0x100);
  const out = [];
  for (let i = 0; i < count; i++) {
    let p = at + stringsStart + b.readUInt32LE(at + 28 + i * 4);
    try {
      if (utf8) {
        let n = b[p++]; if (n & 0x80) p++;               // Zeichenzahl (ignoriert)
        let len = b[p++]; if (len & 0x80) len = ((len & 0x7f) << 8) | b[p++];
        out.push(b.toString('utf8', p, p + len));
      } else {
        let len = b.readUInt16LE(p); p += 2;
        if (len & 0x8000) { len = ((len & 0x7fff) << 16) | b.readUInt16LE(p); p += 2; }
        out.push(b.toString('utf16le', p, p + len * 2));
      }
    } catch { out.push(''); }
  }
  return out;
}

function decodeAxml(b) {
  if (!Buffer.isBuffer(b) || b.length < 8 || b.readUInt16LE(0) !== 0x0003) return null;
  let strings = [], resIds = [];
  const lines = [];
  let depth = 0;
  let p = 8;
  while (p + 8 <= b.length) {
    const type = b.readUInt16LE(p);
    const size = b.readUInt32LE(p + 4);
    if (size < 8 || p + size > b.length) break;
    if (type === 0x0001) strings = readStringPool(b, p);
    else if (type === 0x0180) { for (let i = 8; i < size; i += 4) resIds.push(b.readUInt32LE(p + i)); }
    else if (type === 0x0102) {
      const name = strings[b.readUInt32LE(p + 20)] || '?';
      const attrStart = b.readUInt16LE(p + 24), attrSize = b.readUInt16LE(p + 26), attrCount = b.readUInt16LE(p + 28);
      const attrs = [];
      for (let i = 0; i < attrCount; i++) {
        const a = p + 16 + attrStart + i * attrSize;
        const nameIdx = b.readUInt32LE(a + 4);
        let an = strings[nameIdx] || ATTR_IDS[resIds[nameIdx]] || `attr${nameIdx}`;
        const raw = b.readInt32LE(a + 8);
        const dtype = b[a + 15];
        const data = b.readUInt32LE(a + 16);
        let val;
        if (raw !== -1) val = strings[raw];
        else if (dtype === 0x12) val = data ? 'true' : 'false';
        else if (dtype === 0x10) val = String(data | 0);
        else if (dtype === 0x11) val = '0x' + data.toString(16);
        else if (dtype === 0x03) val = strings[data];
        else if (dtype === 0x01) val = '@0x' + data.toString(16);
        else val = String(data);
        attrs.push(`android:${an}="${esc(val == null ? '' : val)}"`);
      }
      lines.push(`${'  '.repeat(depth)}<${name}${attrs.length ? ' ' + attrs.join(' ') : ''}>`);
      depth++;
    } else if (type === 0x0103) {
      depth = Math.max(0, depth - 1);
      lines.push(`${'  '.repeat(depth)}</${strings[b.readUInt32LE(p + 20)] || '?'}>`);
    }
    p += size;
  }
  return lines.length ? lines.join('\n') : null;
}

// --- iOS Binary Plist (bplist00) ----------------------------------------------
function decodeBplist(b) {
  if (!Buffer.isBuffer(b) || b.length < 40 || b.toString('ascii', 0, 8) !== 'bplist00') return null;
  const t = b.length - 32;
  const offSize = b[t + 6], refSize = b[t + 7];
  const numObjects = Number(b.readBigUInt64BE(t + 8));
  const top = Number(b.readBigUInt64BE(t + 16));
  const tableAt = Number(b.readBigUInt64BE(t + 24));
  const readN = (at, n) => { let v = 0; for (let i = 0; i < n; i++) v = v * 256 + b[at + i]; return v; };
  const offset = (i) => readN(tableAt + i * offSize, offSize);
  const seen = new Set();
  function obj(i, depth) {
    if (i >= numObjects || depth > 30) return '';
    let at = offset(i);
    const marker = b[at], hi = marker >> 4, lo = marker & 0xf;
    const count = () => { if (lo !== 0xf) return [lo, at + 1]; const ib = b[at + 1] & 0xf; return [readN(at + 2, 1 << ib), at + 2 + (1 << ib)]; };
    if (marker === 0x08) return '<false/>';
    if (marker === 0x09) return '<true/>';
    if (hi === 0x1) return `<integer>${readN(at + 1, 1 << lo)}</integer>`;
    if (hi === 0x5) { const [n, s] = count(); return `<string>${esc(b.toString('ascii', s, s + n))}</string>`; }
    if (hi === 0x6) { const [n, s] = count(); return `<string>${esc(Buffer.from(b.subarray(s, s + n * 2)).swap16().toString('utf16le'))}</string>`; }
    if (hi === 0xA || hi === 0xD) {
      if (seen.has(i)) return '';
      seen.add(i);
      const [n, s] = count();
      if (hi === 0xA) { const items = []; for (let k = 0; k < n; k++) items.push(obj(readN(s + k * refSize, refSize), depth + 1)); return `<array>${items.join('')}</array>`; }
      const parts = [];
      for (let k = 0; k < n; k++) {
        const key = obj(readN(s + k * refSize, refSize), depth + 1).replace(/^<string>|<\/string>$/g, '');
        parts.push(`<key>${key}</key>\n${obj(readN(s + (n + k) * refSize, refSize), depth + 1)}`);
      }
      return `<dict>\n${parts.join('\n')}\n</dict>`;
    }
    return '';
  }
  try { return `<?xml version="1.0"?>\n<plist>\n${obj(top, 0)}\n</plist>`; } catch { return null; }
}

// --- Regeln ---------------------------------------------------------------------
const DANGEROUS = {
  READ_SMS: 'SMS lesen', SEND_SMS: 'SMS senden', RECEIVE_SMS: 'SMS empfangen', READ_CONTACTS: 'Kontakte lesen', READ_CALL_LOG: 'Anrufliste lesen',
  RECORD_AUDIO: 'Mikrofon', CAMERA: 'Kamera', ACCESS_FINE_LOCATION: 'genauer Standort', ACCESS_BACKGROUND_LOCATION: 'Standort im Hintergrund',
  READ_EXTERNAL_STORAGE: 'Speicher lesen', MANAGE_EXTERNAL_STORAGE: 'kompletter Speicher', REQUEST_INSTALL_PACKAGES: 'Apps installieren',
  SYSTEM_ALERT_WINDOW: 'über anderen Apps einblenden', BIND_ACCESSIBILITY_SERVICE: 'Bedienungshilfen (liest den Bildschirm)', QUERY_ALL_PACKAGES: 'alle installierten Apps sehen',
  READ_PHONE_STATE: 'Telefonstatus und Gerätenummer', BODY_SENSORS: 'Körpersensoren', READ_CALENDAR: 'Kalender lesen',
};

function manifestRules(u) {
  const out = [];
  const c = u.content || '';
  const add = (idx, o) => out.push(normalizeFinding({ category: 'Config', confidence: 'high', ...o, location: `${base(u)}:${lineOf(c, Math.max(0, idx))}`, sourceModule: M }, M));
  const app = c.search(/<application\b/);
  const appTag = app >= 0 ? c.slice(app, c.indexOf('>', app) + 1) : '';
  if (/android:debuggable="true"/.test(appTag)) add(app, { ruleId: 'android-debuggable', severity: 'high', title: 'App ist im Debug-Modus gebaut', description: 'Eine debugfähige App lässt sich auf jedem Gerät mit einem Kabel untersuchen und steuern – inklusive aller gespeicherten Daten.', remediation: 'android:debuggable entfernen; Release-Builds setzen es automatisch auf false.' });
  if (/android:allowBackup="true"/.test(appTag)) add(app, { ruleId: 'android-allow-backup', severity: 'low', title: 'App-Daten landen in Backups', description: 'Mit allowBackup lassen sich die Daten der App per Kabel oder Cloud-Backup auslesen – auch Anmelde-Tokens.', remediation: 'android:allowBackup="false" setzen oder mit dataExtractionRules sensible Dateien ausschließen.' });
  if (/android:usesCleartextTraffic="true"/.test(appTag)) add(app, { ruleId: 'android-cleartext', severity: 'medium', category: 'Transport', title: 'App erlaubt unverschlüsselte Verbindungen', description: 'Die App darf Daten über einfaches HTTP senden. In öffentlichen WLANs kann sie dabei jeder mitlesen.', remediation: 'usesCleartextTraffic entfernen und nur HTTPS verwenden; Ausnahmen gezielt in network_security_config.' });
  // Offene Komponenten ohne Schutz
  const re = /<(activity|activity-alias|service|receiver|provider)\b([^>]*)>([\s\S]*?)<\/\1>/g; let m, n = 0;
  while ((m = re.exec(c)) && n < 8) {
    const attrs = m[2];
    if (!/android:exported="true"/.test(attrs) || /android:permission="/.test(attrs)) continue;
    if (/android\.intent\.action\.MAIN/.test(m[3]) && /android\.intent\.category\.LAUNCHER/.test(m[3])) continue;
    n++;
    const name = (attrs.match(/android:name="([^"]+)"/) || [])[1] || m[1];
    const label = { activity: 'Bildschirm', 'activity-alias': 'Bildschirm', service: 'Hintergrund-Dienst', receiver: 'Empfänger', provider: 'Datenquelle' }[m[1]];
    add(m.index, { ruleId: m[1] === 'provider' ? 'android-exported-provider' : 'android-exported-component', severity: m[1] === 'provider' ? 'high' : 'medium', category: 'AccessControl', title: `${label} ist für andere Apps offen: ${name.split('.').pop()}`, description: `„${name}“ ist mit exported="true" und ohne Berechtigung freigegeben. Jede andere App auf dem Gerät kann ihn aufrufen${m[1] === 'provider' ? ' und Daten daraus lesen oder ändern' : ''}.`, remediation: 'exported="false" setzen, wenn kein anderer Zugriff nötig ist, sonst eine eigene Berechtigung mit protectionLevel="signature" verlangen.' });
  }
  const perms = [...c.matchAll(/<uses-permission\b[^>]*android:name="android\.permission\.(\w+)"/g)].map((x) => x[1]).filter((p) => DANGEROUS[p]);
  if (perms.length >= 3) add(c.indexOf('uses-permission'), { ruleId: 'android-many-permissions', severity: perms.length >= 6 ? 'medium' : 'low', category: 'AccessControl', confidence: 'medium', title: `App verlangt ${perms.length} sensible Berechtigungen`, description: `Die App möchte: ${perms.map((p) => DANGEROUS[p]).join(', ')}. Jede davon ist ein Risiko, falls die App oder ein eingebauter Baustein kompromittiert wird – und viele Nutzer brechen die Installation dann ab.`, remediation: 'Jede Berechtigung prüfen und streichen, was nicht unbedingt nötig ist; Standort und Speicher möglichst nur zur Laufzeit anfragen.' });
  const tsdk = c.match(/android:targetSdkVersion="(\d+)"/);
  if (tsdk && Number(tsdk[1]) < 30) add(c.indexOf('targetSdkVersion'), { ruleId: 'android-old-target-sdk', severity: 'low', title: `Veraltete Ziel-Android-Version (API ${tsdk[1]})`, description: 'Ältere Zielversionen schalten moderne Schutzmechanismen von Android ab, etwa beim Speicherzugriff.', remediation: 'targetSdkVersion auf die aktuelle Version anheben.' });
  return out;
}

function plistRules(u) {
  const out = [];
  const c = u.content || '';
  const add = (re, o) => { const i = c.search(re); if (i >= 0) out.push(normalizeFinding({ category: 'Transport', confidence: 'high', ...o, location: `${base(u)}:${lineOf(c, i)}`, sourceModule: M }, M)); };
  add(/<key>NSExceptionAllowsInsecureHTTPLoads<\/key>\s*<true\/>/, { ruleId: 'ios-ats-exception', severity: 'low', title: 'Einzelne Domains dürfen unverschlüsselt laden (iOS)', description: 'Für mindestens eine Domain ist HTTP ohne Verschlüsselung erlaubt.', remediation: 'Die Domain auf HTTPS umstellen und die Ausnahme entfernen.' });
  add(/<key>UIFileSharingEnabled<\/key>\s*<true\/>/, { ruleId: 'ios-file-sharing', severity: 'low', category: 'Config', title: 'App-Dateien über iTunes/Finder zugänglich (iOS)', description: 'Mit UIFileSharingEnabled kann man die Dokumente der App per Kabel auslesen.', remediation: 'Nur aktivieren, wenn nötig, und keine sensiblen Daten im Documents-Ordner ablegen.' });
  return out;
}

function runMobile(units) {
  const out = [];
  for (const u of units) {
    const p = base(u);
    if (/AndroidManifest\.xml$/i.test(p) && /<manifest\b/.test(u.content || '')) out.push(...manifestRules(u));
    else if (/Info\.plist$/i.test(p)) out.push(...plistRules(u));
  }
  return out;
}

module.exports = { runMobile, decodeAxml, decodeBplist };
