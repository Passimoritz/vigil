'use strict';

// Verschleierte Skripte erkennen (PowerShell, VBScript, JScript/JavaScript, Batch, HTA/WSF):
// Base64-kodierte Befehle (-enc), Zeichencode-Ketten, zerstueckelte Zeichenketten, Escape-Zeichen
// mitten in Befehlen, lange Zufallsdaten. Rein statisch – das Skript wird nie ausgefuehrt, kodierte
// Teile werden nur zur Anzeige dekodiert.

const path = require('path');
const { normalizeFinding } = require('./schema');

const SCRIPT_EXT = new Set(['.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.bat', '.cmd', '.sct']);
const KIND = { '.ps1': 'PowerShell', '.psm1': 'PowerShell', '.psd1': 'PowerShell', '.vbs': 'VBScript', '.vbe': 'VBScript', '.js': 'JavaScript', '.jse': 'JScript', '.wsf': 'Windows Script', '.wsh': 'Windows Script', '.hta': 'HTML-Anwendung (HTA)', '.bat': 'Batch', '.cmd': 'Batch', '.sct': 'Windows Script' };

const shannon = (s) => { const m = new Map(); for (const ch of s) m.set(ch, (m.get(ch) || 0) + 1); let h = 0; for (const n of m.values()) { const p = n / s.length; h -= p * Math.log2(p); } return h; };
const count = (re, t) => (t.match(re) || []).length;
const printable = (s) => s.length && [...s].filter((c) => /[\x20-\x7e\t\r\n]/.test(c)).length / s.length > 0.9;
const clip = (s, n = 140) => s.replace(/[\r\n\t]+/g, ' ').replace(/[^\x20-\x7e]/g, '?').slice(0, n);

function decodePsEncoded(b64) {
  try {
    const buf = Buffer.from(b64, 'base64');
    const u16 = buf.toString('utf16le');
    if (printable(u16)) return u16;
    const a = buf.toString('latin1');
    return printable(a) ? a : null;
  } catch { return null; }
}

// Liefert { score, techniques[], decoded } – mehr Punkte = sicherer verschleiert
function scoreScript(text, ext) {
  let t = String(text || '').slice(0, 2 * 1024 * 1024);
  const tech = [];
  let score = 0, decoded = null;
  const add = (pts, what) => { score += pts; tech.push(what); };

  const enc = t.match(/(?:^|[\s"'])-(?:e|ec|en|enc|enco|encod|encode|encodedcommand)\s+["']?([A-Za-z0-9+/]{40,}={0,2})/im);
  if (enc && /powershell|pwsh|^\s*-|\.ps1/i.test(t + ext)) { decoded = decodePsEncoded(enc[1]); add(decoded ? 3 : 2, 'Base64-kodierter PowerShell-Befehl (-EncodedCommand)'); }
  // Der dekodierte Befehl wird mitbewertet (z. B. Download + Ausfuehren darin)
  if (decoded) t = `${t}\n${decoded}`;
  if (/FromBase64String/i.test(t) && /\b(iex|Invoke-Expression|\.Invoke\(|Reflection\.Assembly\]::Load|\[Reflection\.Assembly\])/i.test(t)) add(3, 'dekodiert Base64 und führt das Ergebnis aus');
  if (/(DownloadString|DownloadData|Invoke-WebRequest|\biwr\b|Net\.WebClient|Start-BitsTransfer|XMLHTTP|WinHttp)/i.test(t) && /\b(iex|Invoke-Expression|eval\s*\(|Execute(Global)?\s*\(|\.Run\b)/i.test(t)) add(3, 'lädt Code aus dem Internet und führt ihn direkt aus');
  const charcodes = count(/\[char\]\s*(0x)?[0-9a-f]+/gi, t) + count(/\bChrW?\s*\(\s*&?h?[0-9a-f]+\s*\)/gi, t);
  const fromCC = (t.match(/fromCharCode\s*\(([^)]{0,4000})\)/gi) || []).reduce((a, m) => a + (m.match(/\d+/g) || []).length, 0);
  if (charcodes >= 12 || fromCC >= 15) add(2, 'setzt Befehle aus Zeichencodes zusammen');
  const pieces = count(/["'][^"'\n]{1,3}["']\s*[+&]\s*(?=["'])/g, t);
  if (pieces >= 15) add(2, 'zerstückelt Zeichenketten in viele kleine Teile');
  if (/\.ps1$|powershell/i.test(ext + t.slice(0, 2000)) || ext === '.ps1') {
    const ticks = count(/[A-Za-z]`[A-Za-z]/g, t);
    if (ticks >= 6) add(2, 'versteckt Befehle mit Escape-Zeichen (`)');
    if (count(/["'](\{\d+\}){2,}["']\s*-f\b/gi, t) >= 2) add(2, 'ordnet Befehlsteile über den Format-Operator neu (-f)');
  }
  if (ext === '.bat' || ext === '.cmd') {
    if (count(/[A-Za-z]\^[A-Za-z]/g, t) >= 6) add(2, 'versteckt Befehle mit Escape-Zeichen (^)');
    if (count(/%[A-Za-z0-9_]+:~-?\d+(,-?\d+)?%/g, t) >= 6) add(2, 'setzt Befehle aus Teilen von Variablen zusammen');
  }
  // Lange Zufallsdaten in einer Zeichenkette (Base64/Hex mit hoher Entropie)
  const blob = (t.match(/[A-Za-z0-9+/=]{400,}/g) || []).find((b) => shannon(b.slice(0, 4000)) >= 5.0);
  if (blob) add(1, 'enthält einen langen kodierten Datenblock');
  if (/\b(iex|Invoke-Expression)\b|\beval\s*\(|new\s+Function\s*\(|\bExecute(Global)?\s*[( ]/i.test(t)) { if (score) add(1, 'führt erzeugten Text als Code aus'); }
  if (/-w(indowstyle)?\s+h(idden)?\b|-nop\b|-noni\b|-ep\s+bypass|-exec(utionpolicy)?\s+bypass/i.test(t)) add(1, 'startet versteckt bzw. umgeht die Ausführungsrichtlinie');
  if (/ActiveXObject|WScript\.Shell|Shell\.Application/i.test(t) && /\.(Run|Exec|ShellExecute)\s*\(/i.test(t) && ext !== '.ps1') add(1, 'startet Programme über WScript.Shell');
  return { score, techniques: tech, decoded };
}

function analyzeScript(text, label, ext) {
  ext = (ext || path.extname(String(label))).toLowerCase();
  if (!SCRIPT_EXT.has(ext)) return [];
  const { score, techniques, decoded } = scoreScript(text, ext);
  // Normales JavaScript (minifizierte Bibliotheken) ist oft "komisch" – dort nur bei starken Zeichen melden
  const need = ext === '.js' ? 5 : 3;
  if (score < need) return [];
  return [normalizeFinding({
    ruleId: 'script-obfuscated', severity: score >= 5 ? 'high' : 'medium', category: 'Other', confidence: score >= 5 ? 'high' : 'medium',
    title: `Verschleiertes Skript (${KIND[ext] || 'Skript'}): ${path.basename(String(label))}`,
    description: `In „${String(label).replace(/\\/g, '/')}“ stecken typische Verschleierungstricks: ${techniques.join(', ')}. Normale Skripte brauchen das nicht; Schadskripte verstecken so, was sie tun.`,
    impact: 'Wird das Skript ausgeführt, kann es Schadsoftware nachladen, Daten abgreifen oder den Rechner fernsteuern.',
    remediation: 'Skript nicht ausführen. Herkunft prüfen; bei eigenen Skripten auf Verschleierung verzichten und sie signieren.',
    evidence: decoded ? `dekodiert: ${clip(decoded)}` : '',
    location: String(label).replace(/\\/g, '/'), sourceModule: 'script-audit',
  }, 'script-audit')];
}

module.exports = { analyzeScript, scoreScript, decodePsEncoded, SCRIPT_EXT };
