'use strict';

// Gemeinsame Bausteine fuer regelbasierte Pruefmodule: Ort/Zeile, Test-Erkennung, Befund bauen
// und eine Regel-Tabelle ueber passende Dateien laufen lassen.
//
// Regel: { id, sev, cat, re, title, desc, fix, impact?, files?: RegExp (Pfad), test?: (m, c, u) => bool,
//          unless?: RegExp (ganze Datei), max?, redact?: true (Fundstelle maskieren), conf? }

const { normalizeFinding, redactSecret } = require('../schema');

const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const fileName = (u) => base(u).split('/').pop().toLowerCase();
const extOf = (u) => (base(u).match(/\.[\w]+$/) || [''])[0].toLowerCase();
const lineOf = (text, idx) => String(text).slice(0, idx).split('\n').length;
const isTestFile = (u) => /(^|\/)(test|tests|__tests__|spec|e2e|fixtures?|mocks?|examples?)(\/|$)|\.(test|spec)\.[jt]sx?$|_test\.(py|go|rb)$/i.test(base(u));
const isText = (u) => u && u.kind !== 'binary-strings' && typeof u.content === 'string';
const oneLine = (s, n = 160) => String(s).replace(/\s+/g, ' ').trim().slice(0, n);

function mk(module, u, idx, o) {
  return normalizeFinding({
    confidence: 'medium',
    ...o,
    location: idx == null || idx < 0 ? base(u) : `${base(u)}:${lineOf(u.content || '', idx)}`,
    sourceModule: module,
    devOnly: isTestFile(u) || o.devOnly,
  }, module);
}

// Regel-Tabelle auf eine Datei anwenden.
function applyRules(module, u, rules, out) {
  const c = u.content || '';
  for (const r of rules) {
    if (r.files && !r.files.test(base(u))) continue;
    if (r.unless && r.unless.test(c)) continue;
    r.re.lastIndex = 0;
    let m, n = 0;
    while ((m = r.re.exec(c)) && n < (r.max || 5)) {
      if (m.index === r.re.lastIndex) r.re.lastIndex++;
      if (r.test && !r.test(m, c, u)) continue;
      n++;
      out.push(mk(module, u, m.index, {
        ruleId: r.id, severity: r.sev, category: r.cat, confidence: r.conf || 'medium',
        title: r.title, description: r.desc, remediation: r.fix, ...(r.impact ? { impact: r.impact } : {}),
        evidence: r.redact ? redactSecret(oneLine(m[0], 200)) : oneLine(m[0]),
      }));
      if (!r.re.global) break;
    }
  }
  return out;
}

module.exports = { base, fileName, extOf, lineOf, isTestFile, isText, oneLine, mk, applyRules };
