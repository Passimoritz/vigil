'use strict';

// KI-Modelldateien im Pickle-Format (.pt/.pth/.ckpt/.pkl/.pickle/.joblib/.bin, auch das ZIP-basierte
// PyTorch-Format) auf gefaehrliche Importe pruefen. Beim Laden mit pickle/torch.load werden
// GLOBAL-/STACK_GLOBAL-Importe aufgeloest und per REDUCE/INST/OBJ/NEWOBJ aufgerufen – so laesst sich
// beliebiger Code (os.system, subprocess, eval …) ausfuehren. Hier wird der Opcode-Strom nur
// gelesen und ausgewertet, NIE ausgefuehrt oder entpickelt.

const zlib = require('zlib');
const AdmZip = require('adm-zip');
const { normalizeFinding } = require('./schema');

const MODEL_EXT = new Set(['.pt', '.pth', '.ckpt', '.pkl', '.pickle', '.joblib', '.bin', '.dat', '.mar', '.nemo']);
const MAX_SCAN = 32 * 1024 * 1024;   // so viel eines rohen Pickles wird gelesen
const MAX_ZIP = 512 * 1024 * 1024;   // groessere ZIP-Modelle werden nicht geoeffnet
const MAX_OPS = 2000000;

// Gefaehrliche Module (ganz) bzw. einzelne Funktionen
const BAD_MODULES = /^(os|posix|nt|subprocess|pty|commands|socket|shutil|runpy|webbrowser|ctypes|importlib|code|codeop|marshal|types|sys|platform|multiprocessing|asyncio\.subprocess|requests|urllib(\.\w+)*|httplib|http\.client|ftplib|smtplib|telnetlib|pip|setuptools|distutils|tempfile|glob|signal|threading)$/;
const BAD_BUILTINS = new Set(['eval', 'exec', 'execfile', 'compile', 'open', '__import__', 'getattr', 'setattr', 'delattr', 'globals', 'locals', 'vars', 'input', 'breakpoint', 'apply', 'file', 'reload']);
const OTHER_BAD = new Set(['pickle.loads', 'pickle.load', '_pickle.loads', 'cPickle.loads', 'dill.loads', 'numpy.load', 'torch.load', 'operator.attrgetter', 'operator.methodcaller', 'functools.partial', 'torch.serialization.load', 'joblib.load']);

function classify(mod, name) {
  const m = String(mod || '').trim();
  const n = String(name || '').trim();
  if (m === 'builtins' || m === '__builtin__' || m === '__builtins__') return BAD_BUILTINS.has(n) ? 'critical' : null;
  if (BAD_MODULES.test(m) || BAD_MODULES.test(m.split('.')[0])) return 'critical';
  if (OTHER_BAD.has(`${m}.${n}`)) return 'high';
  return null;
}

// Liest einen oder mehrere hintereinanderliegende Pickles und liefert gefundene Importe/Aufrufe.
function scanPickle(buf) {
  const res = { globals: [], calls: 0, ok: false, error: null };
  const len = Math.min(buf.length, MAX_SCAN);
  let i = 0, ops = 0;
  const strs = []; // zuletzt abgelegte Zeichenketten (fuer STACK_GLOBAL)
  const memo = new Map();
  let last = null;
  const push = (s) => { last = s; strs.push(s); if (strs.length > 64) strs.shift(); };
  const readLine = () => { const e = buf.indexOf(0x0a, i); if (e < 0 || e >= len) throw new Error('eof'); const s = buf.toString('latin1', i, e); i = e + 1; return s; };
  const need = (n) => { if (i + n > len) throw new Error('eof'); };
  const u32 = () => { need(4); const v = buf.readUInt32LE(i); i += 4; return v; };
  const u64 = () => { need(8); const v = Number(buf.readBigUInt64LE(i)); i += 8; return v; };
  const take = (n, asText) => { need(n); const s = asText ? buf.toString('utf8', i, i + n) : null; i += n; return s; };
  let pickles = 0;
  try {
    while (i < len && ops < MAX_OPS) {
      const op = buf[i++]; ops++;
      switch (op) {
        case 0x80: need(1); i += 1; break;                                     // PROTO
        case 0x95: need(8); i += 8; break;                                     // FRAME
        case 0x2e: pickles++; res.ok = true;                                   // STOP
          // weitere Pickles direkt dahinter (alte torch-Dateien: magic, protocol, sys_info, Modell)
          if (i < len && (buf[i] === 0x80 || buf[i] === 0x28 || buf[i] === 0x63 || buf[i] === 0x7d || buf[i] === 0x5d)) { strs.length = 0; memo.clear(); continue; }
          return res;
        case 0x63: case 0x69: { const mod = readLine(); const name = readLine(); res.globals.push({ mod, name, op: op === 0x63 ? 'GLOBAL' : 'INST' }); if (op === 0x69) res.calls++; push(null); break; } // GLOBAL / INST
        case 0x93: { const name = strs[strs.length - 1]; const mod = strs[strs.length - 2]; res.globals.push({ mod, name, op: 'STACK_GLOBAL' }); push(null); break; }
        case 0x52: case 0x6f: case 0x81: case 0x92: res.calls++; last = null; break; // REDUCE, OBJ, NEWOBJ, NEWOBJ_EX
        case 0x28: case 0x30: case 0x31: case 0x32: case 0x4e: case 0x51: case 0x61: case 0x62: case 0x64: case 0x7d: case 0x65:
        case 0x6c: case 0x5d: case 0x73: case 0x74: case 0x29: case 0x75: case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
        case 0x8f: case 0x90: case 0x91: case 0x97: case 0x98: last = null; break;
        case 0x94: memo.set(memo.size, last); break;                           // MEMOIZE
        case 0x46: case 0x49: case 0x4c: readLine(); last = null; break;         // FLOAT, INT, LONG
        case 0x50: readLine(); break;                                          // PERSID
        case 0x53: case 0x56: { let s = readLine(); if (op === 0x53) s = s.replace(/^['"]|['"]$/g, ''); push(s); break; } // STRING, UNICODE
        case 0x4a: need(4); i += 4; last = null; break;                        // BININT
        case 0x4b: need(1); i += 1; last = null; break;                        // BININT1
        case 0x4d: need(2); i += 2; last = null; break;                        // BININT2
        case 0x47: need(8); i += 8; last = null; break;                        // BINFLOAT
        case 0x54: case 0x58: { const n = u32(); push(take(n, true)); break; }  // BINSTRING, BINUNICODE
        case 0x55: case 0x8c: { need(1); const n = buf[i++]; push(take(n, true)); break; } // SHORT_BINSTRING, SHORT_BINUNICODE
        case 0x8d: { const n = u64(); push(take(n, true)); break; }            // BINUNICODE8
        case 0x42: { const n = u32(); take(n); last = null; break; }           // BINBYTES
        case 0x43: { need(1); const n = buf[i++]; take(n); last = null; break; } // SHORT_BINBYTES
        case 0x8e: case 0x96: { const n = u64(); take(n); last = null; break; } // BINBYTES8, BYTEARRAY8
        case 0x8a: { need(1); const n = buf[i++]; take(n); last = null; break; } // LONG1
        case 0x8b: { const n = u32(); take(n); last = null; break; }           // LONG4
        case 0x67: { const k = Number(readLine()); push(memo.get(k) ?? null); break; }       // GET
        case 0x68: { need(1); push(memo.get(buf[i++]) ?? null); break; }      // BINGET
        case 0x6a: { push(memo.get(u32()) ?? null); break; }                   // LONG_BINGET
        case 0x70: { memo.set(Number(readLine()), last); break; }              // PUT
        case 0x71: { need(1); memo.set(buf[i++], last); break; }               // BINPUT
        case 0x72: { memo.set(u32(), last); break; }                           // LONG_BINPUT
        case 0x82: need(1); i += 1; break; case 0x83: need(2); i += 2; break; case 0x84: need(4); i += 4; break; // EXT1/2/4
        default:
          // Unbekannter Opcode: kein (weiterer) Pickle – nach mindestens einem Pickle normal (Tensordaten)
          if (!pickles) res.error = `unbekannter Opcode 0x${op.toString(16)} an Position ${i - 1}`;
          return res;
      }
    }
  } catch (e) { if (!pickles) res.error = e.message; }
  return res;
}

const looksPickle = (buf) => buf.length > 2 && ((buf[0] === 0x80 && buf[1] >= 2 && buf[1] <= 5) || buf[0] === 0x28 || (buf[0] === 0x63 && /^c[\w.]+\n/.test(buf.toString('latin1', 0, 64))) || buf[0] === 0x7d || buf[0] === 0x5d);

function decompress(buf) {
  try {
    if (buf[0] === 0x1f && buf[1] === 0x8b) return zlib.gunzipSync(buf, { maxOutputLength: MAX_SCAN });
    if (buf[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(buf[1])) return zlib.inflateSync(buf, { maxOutputLength: MAX_SCAN });
    // joblib: "ZF0x" + Laenge + zlib-Daten
    if (buf[0] === 0x5a && buf[1] === 0x46) { const z = buf.indexOf(Buffer.from([0x78]), 2); if (z > 0 && z < 40) return zlib.inflateSync(buf.slice(z), { maxOutputLength: MAX_SCAN }); }
  } catch { /* nicht entpackbar */ }
  return null;
}

// Liefert [{ entry, globals, calls }] fuer alle Pickles einer Datei (roh, komprimiert oder im ZIP).
function picklesOf(buf, name) {
  const out = [];
  if (buf.length >= 4 && buf.readUInt32BE(0) === 0x504b0304) {
    if (buf.length > MAX_ZIP) return { results: out, note: 'zu groß für die ZIP-Prüfung' };
    let zip; try { zip = new AdmZip(buf); } catch { return { results: out, note: 'ZIP nicht lesbar' }; }
    for (const e of zip.getEntries()) {
      if (e.isDirectory || !/\.(pkl|pickle)$|(^|\/)data\.pkl$/i.test(e.entryName) || e.header.size > MAX_SCAN) continue;
      let data; try { data = e.getData(); } catch { continue; }
      const r = scanPickle(data);
      out.push({ entry: `${name}!/${e.entryName}`, ...r });
    }
    return { results: out };
  }
  const plain = looksPickle(buf) ? buf : decompress(buf);
  if (plain && looksPickle(plain)) out.push({ entry: name, ...scanPickle(plain) });
  return { results: out };
}

// Hauptfunktion: Puffer einer Modelldatei -> Befunde
function analyzeModelFile(buf, label) {
  const name = String(label).replace(/\\/g, '/');
  const { results } = picklesOf(buf, name);
  const findings = [];
  for (const r of results) {
    const bad = [];
    for (const g of r.globals) {
      const sev = classify(g.mod, g.name);
      if (sev) bad.push({ ...g, sev });
    }
    if (!bad.length) continue;
    const sev = bad.some((b) => b.sev === 'critical') && r.calls > 0 ? 'critical' : 'high';
    const list = [...new Set(bad.map((b) => `${b.mod}.${b.name}`))].slice(0, 6);
    findings.push(normalizeFinding({
      ruleId: 'model-pickle-dangerous-global', severity: sev, category: 'Deserialization', confidence: 'high',
      title: `Modelldatei enthält gefährliche Pickle-Importe: ${list.join(', ')}`,
      description: r.calls
        ? `Die Pickle-Daten importieren ${list.join(', ')} und rufen Funktionen auf (REDUCE/INST/OBJ). Beim Laden mit torch.load, pickle.load oder joblib.load wird dieser Code sofort ausgeführt – die Datei ist damit ein ausführbares Programm. Vigil hat die Datei nur gelesen, nicht geladen.`
        : `Die Pickle-Daten importieren ${list.join(', ')}. Beim Laden mit torch.load, pickle.load oder joblib.load wird dieser Code sofort ausgeführt – die Datei ist damit ein ausführbares Programm. Vigil hat die Datei nur gelesen, nicht geladen.`,
      impact: 'Wer die Datei lädt (Entwickler, Trainings- oder Inferenz-Server), führt den eingebauten Befehl mit seinen Rechten aus: Zugangsdaten abgreifen, Hintertür installieren, Daten verschlüsseln.',
      remediation: 'Die Datei nicht laden und die Herkunft prüfen. Modelle im safetensors-Format beziehen bzw. umwandeln, torch.load(..., weights_only=True) verwenden und Downloads nur aus vertrauenswürdigen Quellen mit Prüfsumme zulassen.',
      location: r.entry,
      evidence: bad.slice(0, 6).map((b) => `${b.op} ${b.mod} ${b.name}`).join(' · '),
      sourceModule: 'model-file-audit',
    }, 'model-file-audit'));
  }
  return findings;
}

const isModelExt = (ext) => MODEL_EXT.has(String(ext || '').toLowerCase());

module.exports = { analyzeModelFile, scanPickle, picklesOf, classify, isModelExt, MODEL_EXT, looksPickle };
