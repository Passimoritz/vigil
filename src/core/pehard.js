'use strict';

// Schutzfunktionen von Windows-Programmen (PE-Kopf, rein in JavaScript gelesen):
//  ASLR (DYNAMIC_BASE, keine entfernten Relocations), DEP (NX_COMPAT), Control Flow Guard
//  (GUARD_CF), ASLR mit hoher Entropie (HIGH_ENTROPY_VA, nur 64-Bit) und ob eine Authenticode-
//  Signatur eingebettet ist. Fehlen sie, sind Speicherfehler im Programm leichter ausnutzbar.

const path = require('path');
const { normalizeFinding } = require('./schema');

const DLL = { HIGH_ENTROPY_VA: 0x20, DYNAMIC_BASE: 0x40, FORCE_INTEGRITY: 0x80, NX_COMPAT: 0x100, NO_SEH: 0x400, GUARD_CF: 0x4000 };

function parsePe(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null;
  const pe = buf.readUInt32LE(0x3c);
  if (pe + 24 > buf.length || buf.readUInt32LE(pe) !== 0x00004550) return null;
  const coff = pe + 4;
  const machine = buf.readUInt16LE(coff), characteristics = buf.readUInt16LE(coff + 18), optSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  if (!optSize || opt + 72 > buf.length) return null;
  const magic = buf.readUInt16LE(opt);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const is64 = magic === 0x20b;
  const subsystem = buf.readUInt16LE(opt + 68), dllChars = buf.readUInt16LE(opt + 70);
  const nDirOff = opt + (is64 ? 108 : 92), dirOff = opt + (is64 ? 112 : 96);
  const nDirs = nDirOff + 4 <= buf.length ? buf.readUInt32LE(nDirOff) : 0;
  const dir = (i) => (i < nDirs && dirOff + i * 8 + 8 <= buf.length ? { va: buf.readUInt32LE(dirOff + i * 8), size: buf.readUInt32LE(dirOff + i * 8 + 4) } : { va: 0, size: 0 });
  const sec = dir(4), clr = dir(14), reloc = dir(5);
  return {
    machine, is64, subsystem, dllChars, characteristics,
    isDll: !!(characteristics & 0x2000),
    relocsStripped: !!(characteristics & 0x1),
    hasReloc: reloc.size > 0,
    isDotNet: clr.size > 0,
    signed: sec.size > 0 && sec.va > 0 && sec.va + 8 <= buf.length,
    aslr: !!(dllChars & DLL.DYNAMIC_BASE) && !(characteristics & 0x1),
    dep: !!(dllChars & DLL.NX_COMPAT),
    cfg: !!(dllChars & DLL.GUARD_CF),
    highEntropyVa: !!(dllChars & DLL.HIGH_ENTROPY_VA),
  };
}

function analyzePeHardening(buf, label) {
  const p = parsePe(buf);
  if (!p) return [];
  // Treiber/native Subsysteme und reine Ressourcen-DLLs (ohne Code) haben eigene Regeln
  if (p.subsystem === 1) return [];
  const missing = [];
  if (!p.aslr) missing.push('ASLR (zufällige Speicheradressen)');
  if (!p.dep) missing.push('DEP (Schutz vor Code in Datenbereichen)');
  if (!p.cfg && !p.isDotNet) missing.push('Control Flow Guard (CFG)');
  if (p.is64 && p.aslr && !p.highEntropyVa) missing.push('ASLR mit hoher Entropie (64-Bit)');
  if (!missing.length) return [];
  const where = String(label || 'binary').replace(/\\/g, '/');
  const severe = !p.aslr || !p.dep;
  return [normalizeFinding({
    ruleId: 'pe-hardening-missing', severity: severe ? 'medium' : 'low', category: 'Other', confidence: 'high',
    title: `Programm ohne Schutzfunktionen: ${path.basename(where)}`,
    description: `„${path.basename(where)}“ wurde ohne folgende Schutzfunktionen gebaut: ${missing.join(', ')}. ${p.signed ? 'Eine digitale Signatur ist eingebettet.' : 'Eine digitale Signatur ist nicht eingebettet.'}`,
    impact: 'Hat das Programm einen Speicherfehler (z. B. Pufferüberlauf), lässt er sich ohne diese Schutzfunktionen deutlich leichter zu einem echten Angriff ausbauen.',
    remediation: 'Für eigene Programme die Linker-Optionen /DYNAMICBASE, /NXCOMPAT, /guard:cf und (64-Bit) /HIGHENTROPYVA setzen – bei aktuellen Visual-Studio-Versionen sind sie Standard. Fremde Programme aktualisieren bzw. beim Hersteller nachfragen.',
    location: where, sourceModule: 'pe-hardening',
  }, 'pe-hardening')];
}

module.exports = { parsePe, analyzePeHardening, DLL };
