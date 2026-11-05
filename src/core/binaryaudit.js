'use strict';

// Leichte, defensive Binary-Triage fuer EIGENE Artefakte: Dateityp am Magic-Byte,
// Hinweis auf Packer/Verschleierung (hohe Entropie, UPX), gehaeufte
// sicherheitsrelevante API-Aufrufe, eingebettete URLs/IPs. KEINE Dekompilierung,
// keine Ausfuehrung - nur statische Hinweise zum Priorisieren.

const { normalizeFinding } = require('./schema');

// Shannon-Entropie (0-8 Bit/Byte) ueber bis zu ~2 MB (Anfang + Ende).
function entropy(buf) {
  const cap = 2 * 1024 * 1024;
  let sample = buf;
  if (buf.length > cap) sample = Buffer.concat([buf.subarray(0, cap / 2), buf.subarray(buf.length - cap / 2)]);
  const freq = new Array(256).fill(0);
  for (let i = 0; i < sample.length; i++) freq[sample[i]]++;
  const n = sample.length || 1;
  let h = 0;
  for (const f of freq) { if (!f) continue; const p = f / n; h -= p * Math.log2(p); }
  return h;
}

function detectType(buf) {
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return 'PE/Windows (MZ)';
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'ELF/Linux';
  if (buf.length >= 4 && ((buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) || (buf[0] === 0xfe && buf[1] === 0xed && buf[2] === 0xfa))) return 'Mach-O/macOS oder Java-Class';
  if (buf.length >= 2 && buf[0] === 0x50 && buf[1] === 0x4b) return 'ZIP/JAR';
  return 'unbekannt';
}

// Sicherheitsrelevante API-/Funktionsnamen (Windows + generisch). Ihr blosses
// Vorkommen ist KEIN Fund - erst eine Haeufung ist ein Hinweis zum Pruefen.
const SUSPECT_APIS = [
  'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
  'NtCreateThreadEx', 'QueueUserAPC', 'SetWindowsHookEx', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
  'WinExec', 'ShellExecute', 'CreateProcess', 'URLDownloadToFile', 'InternetOpen', 'WinHttpOpen',
  'RegSetValue', 'RegCreateKey', 'CryptEncrypt', 'CryptAcquireContext', 'CreateService', 'IsDebuggerPresent',
  'VirtualAllocEx', 'OpenProcess', 'AdjustTokenPrivileges', 'WScript.Shell', 'cmd.exe', 'powershell',
];

function bufHas(buf, needle) {
  try { return buf.includes(Buffer.from(needle, 'ascii')); } catch { return false; }
}

// buf = Rohdaten, label = Anzeigename. Gibt normalisierte Befunde zurueck.
function analyzeBinary(buf, label) {
  const out = [];
  if (!buf || !buf.length) return out;
  const where = label || 'binary';
  const type = detectType(buf);
  const h = entropy(buf);

  // Gehaeufte verdaechtige APIs.
  const hits = SUSPECT_APIS.filter((a) => bufHas(buf, a));
  if (hits.length >= 2) {
    const many = hits.length >= 4;
    out.push(normalizeFinding({
      title: `Binary: ${hits.length} sicherheitsrelevante API-Aufrufe (${type})`,
      severity: many ? 'medium' : 'info', category: 'Other', location: where,
      description: `In der Binaerdatei kommen mehrere sicherheitsrelevante Aufrufe vor: ${hits.slice(0, 12).join(', ')}${hits.length > 12 ? ' …' : ''}.`,
      reachability: 'Nur statisch aus dem Datei-Inhalt abgelesen (keine Ausfuehrung).',
      impact: 'Solche Aufrufe sind in Packern/Loadern/Malware ueblich, kommen aber auch in legitimer Software vor - im Zweifel Herkunft/Build pruefen.',
      remediation: 'Sicherstellen, dass die Datei aus einem vertrauenswuerdigen Build stammt (eigene Quelle, signiert). Bei Unklarheit nicht ausfuehren und gezielt analysieren.',
      confidence: 'low',
    }, 'binary'));
  }

  // Packer/Verschleierung.
  const upx = bufHas(buf, 'UPX!') || bufHas(buf, 'UPX0') || bufHas(buf, 'UPX1');
  if (upx) {
    out.push(normalizeFinding({
      title: `Binary: mit UPX gepackt (${type})`,
      severity: 'low', category: 'Other', location: where,
      description: 'Die Datei enthaelt UPX-Marker, ist also vermutlich mit UPX gepackt.',
      reachability: 'Statischer Hinweis.',
      impact: 'Packen erschwert die Analyse; bei eigener Software meist harmlos, bei unbekannter Herkunft ein Pruefgrund.',
      remediation: 'Falls es eigene Software ist: ok. Sonst Herkunft pruefen; ggf. mit „upx -d" entpacken und erneut scannen.',
      confidence: 'medium',
    }, 'binary'));
  } else if (h >= 7.2) {
    out.push(normalizeFinding({
      title: `Binary: hohe Entropie (${h.toFixed(2)}/8) - evtl. gepackt/verschluesselt (${type})`,
      severity: 'info', category: 'Other', location: where,
      description: `Die Datei hat eine sehr hohe Entropie (${h.toFixed(2)} Bit/Byte). Das deutet auf Kompression, Packer oder Verschluesselung hin.`,
      reachability: 'Statischer Hinweis.',
      impact: 'Hohe Entropie allein ist kein Problem (auch Installer/Medien sind so), erschwert aber die Analyse.',
      remediation: 'Nur relevant, wenn die Herkunft unklar ist - dann Datei nicht ausfuehren und gezielt pruefen.',
      confidence: 'low',
    }, 'binary'));
  }

  // Windows-Programme: fehlende Schutzfunktionen (ASLR, DEP, CFG …)
  if (type.startsWith('PE')) out.push(...require('./pehard').analyzePeHardening(buf, where));

  return out;
}

module.exports = { analyzeBinary, entropy, detectType, SUSPECT_APIS };
