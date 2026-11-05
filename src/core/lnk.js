'use strict';

// Windows-Verknuepfungen (.lnk, MS-SHLLINK) lesen: Ziel, Argumente, Arbeitsordner, Symbol.
// Angreifer verschicken .lnk-Dateien, die mit Dokument-Symbol aussehen wie ein PDF, aber
// PowerShell, cmd oder mshta mit versteckten Befehlen starten. Nur Lesen, nie Ausfuehren.

const path = require('path');
const { normalizeFinding } = require('./schema');

const CLSID = Buffer.from('0114020000000000c000000000000046', 'hex');
const LOLBINS = /^(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|forfiles|conhost|schtasks|curl|wmic|msbuild|installutil|regasm|regsvcs|hh|bash)(\.exe)?$/i;
const HIGH_RISK = /^(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil|regasm|regsvcs)(\.exe)?$/i;

function readStr(buf, off, unicode) {
  if (off + 2 > buf.length) return { value: '', next: buf.length };
  const n = buf.readUInt16LE(off);
  const bytes = unicode ? n * 2 : n;
  const s = buf.subarray(off + 2, Math.min(buf.length, off + 2 + bytes));
  return { value: unicode ? s.toString('utf16le') : s.toString('latin1'), next: off + 2 + bytes };
}
const cz = (buf, off) => { if (off <= 0 || off >= buf.length) return ''; const e = buf.indexOf(0, off); return buf.subarray(off, e < 0 ? buf.length : e).toString('latin1'); };
const cz16 = (buf, off) => { if (off <= 0 || off >= buf.length) return ''; let e = off; while (e + 1 < buf.length && (buf[e] || buf[e + 1])) e += 2; return buf.subarray(off, e).toString('utf16le'); };

function parseLnk(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 0x4c || buf.readUInt32LE(0) !== 0x4c || !buf.subarray(4, 20).equals(CLSID)) return null;
  const flags = buf.readUInt32LE(0x14);
  const unicode = !!(flags & 0x80);
  const out = { flags, showCommand: buf.readUInt32LE(0x3c), target: '', name: '', relativePath: '', workingDir: '', arguments: '', iconLocation: '', idStrings: [] };
  let off = 0x4c;
  if (flags & 0x1) {
    const n = buf.readUInt16LE(off);
    const idl = buf.subarray(off + 2, off + 2 + n);
    // Ziel steckt oft nur in der ID-Liste (Shell-Items): lesbare Dateinamen herausziehen
    const re = /[\x20-\x7e]{3,}/g;
    out.idStrings = [...(idl.toString('latin1').match(re) || []), ...(idl.toString('utf16le').match(/[\x20-\x7e]{3,}/g) || [])].filter((s) => /\.[a-z0-9]{2,4}$/i.test(s) || /\\/.test(s)).slice(0, 20);
    off += 2 + n;
  }
  if (flags & 0x2 && off + 28 <= buf.length) {
    const size = buf.readUInt32LE(off);
    const li = buf.subarray(off, off + size);
    if (li.length >= 28) {
      const hdr = li.readUInt32LE(4), liFlags = li.readUInt32LE(8);
      if (liFlags & 1) {
        out.target = hdr >= 0x24 && li.length >= 0x20 ? cz16(li, li.readUInt32LE(0x1c)) || cz(li, li.readUInt32LE(16)) : cz(li, li.readUInt32LE(16));
        const suffix = cz(li, li.readUInt32LE(24));
        if (suffix && out.target && !out.target.endsWith(suffix)) out.target += suffix;
      }
    }
    off += size;
  }
  for (const [bit, key] of [[0x4, 'name'], [0x8, 'relativePath'], [0x10, 'workingDir'], [0x20, 'arguments'], [0x40, 'iconLocation']]) {
    if (!(flags & bit)) continue;
    const r = readStr(buf, off, unicode); out[key] = r.value; off = r.next;
  }
  if (!out.target) out.target = out.relativePath || out.idStrings.find((s) => /\.(exe|com|bat|cmd|ps1|vbs|js|hta|scr|msi)$/i.test(s)) || '';
  return out;
}

function analyzeLnk(buf, label) {
  const l = parseLnk(buf);
  if (!l) return [];
  const exe = path.win32.basename(l.target || '');
  const args = String(l.arguments || '');
  const signs = [];
  if (/-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}/i.test(args)) signs.push('kodierter Befehl');
  if (/https?:\/\/|\\\\[\w.-]+\\/i.test(args)) signs.push('Adresse im Internet oder Netzwerk');
  if (/-w(indowstyle)?\s+h|hidden|-nop\b|bypass/i.test(args)) signs.push('versteckte Ausführung');
  if (/DownloadString|Invoke-WebRequest|iwr |wget |curl |bitsadmin|certutil.*-urlcache|FromBase64String|iex\b/i.test(args)) signs.push('lädt etwas herunter');
  if (args.length > 260 || /^\s{30,}/.test(args)) signs.push('überlanges, aufgefülltes Argument (versteckt den Befehl in den Eigenschaften)');
  const docIcon = /\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png)\b/i.test(l.iconLocation) || /imageres\.dll|shell32\.dll/i.test(l.iconLocation);
  if (docIcon && LOLBINS.test(exe)) signs.push('tarnt sich mit einem Dokument-Symbol');
  const out = [];
  const where = String(label).replace(/\\/g, '/');
  if (LOLBINS.test(exe) && (args.trim() || signs.length)) {
    const sev = signs.length || HIGH_RISK.test(exe) ? (signs.length >= 2 ? 'critical' : 'high') : 'medium';
    out.push(normalizeFinding({
      ruleId: 'lnk-launches-system-tool', severity: sev, category: 'Other', confidence: 'high',
      title: `Verknüpfung startet ${exe}: ${path.basename(where)}`,
      description: [
        args ? `Die Verknüpfung ruft „${l.target.slice(0, 160)}“ mit den Argumenten „${args.trim().slice(0, 200)}${args.trim().length > 200 ? ' …' : ''}“ auf.` : `Die Verknüpfung ruft „${l.target.slice(0, 160)}“ auf.`,
        'Echte Dokument-Verknüpfungen starten kein System-Werkzeug.',
        signs.length ? `Auffällig: ${signs.join(', ')}.` : '',
      ].filter(Boolean).join(' '),
      impact: 'Ein Doppelklick führt die Befehle mit den Rechten des Benutzers aus – ein beliebter Weg, Schadsoftware per E-Mail-Anhang oder in ZIP/ISO-Dateien zu verteilen.',
      remediation: 'Verknüpfung nicht öffnen. In den Eigenschaften (Rechtsklick → Eigenschaften → Ziel) sieht man nur die ersten 260 Zeichen – Vigil zeigt den ganzen Befehl.',
      location: where, sourceModule: 'lnk-audit',
    }, 'lnk-audit'));
  } else if (signs.length && args) {
    out.push(normalizeFinding({
      ruleId: 'lnk-suspicious-arguments', severity: 'medium', category: 'Other', confidence: 'medium',
      title: `Verknüpfung mit auffälligen Argumenten: ${path.basename(where)}`,
      description: `Ziel „${(l.target || 'unbekannt').slice(0, 160)}“, Argumente „${args.trim().slice(0, 200)}“. Auffällig: ${signs.join(', ')}.`,
      remediation: 'Nur öffnen, wenn die Verknüpfung aus sicherer Quelle stammt.',
      location: where, sourceModule: 'lnk-audit',
    }, 'lnk-audit'));
  }
  return out;
}

module.exports = { parseLnk, analyzeLnk };
