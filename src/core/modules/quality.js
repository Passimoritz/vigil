'use strict';

// Code-Qualitaet mit Sicherheitsbezug (niedrige Stufe bzw. Hinweis): sehr lange oder sehr
// verzweigte Funktionen sind schwer zu pruefen und verstecken Fehler; kopierte Bloecke fuehren
// dazu, dass eine Korrektur nur an einer Stelle ankommt.

const crypto = require('crypto');
const { base, mk, isText, isTestFile } = require('./rulekit');

const M = 'code-quality';
const BRACE = /\.(m?[jt]sx?|cjs|java|kt|kts|cs|go|c|cc|cpp|cxx|h|hpp|php|rs|swift|scala|dart)$/i;
const PY = /\.py$/i;
const SKIP = /\.min\.js$|(^|\/)(vendor|third[_-]?party|generated|gen)\/|\.(pb|generated|g)\.\w+$|\.d\.ts$/i;
const LONG = 150;
const COMPLEX = 30;
const DECISIONS = /\b(if|elif|for|foreach|while|case|catch|except|when)\b|&&|\|\|/g;
const CONTROL = /^\s*(}\s*)?(if|for|foreach|while|switch|catch|else|do|try|return|with|using|lock|synchronized|match|select)\b/;
const HEADER = /(\bfunction\b\s*\*?\s*[\w$]*\s*\(|\bfunc\s+(\([^)]*\)\s*)?\w+\s*\(|\bfn\s+\w+|\bfun\s+[\w.<>]+\s*\(|\bdef\s+\w+|=>\s*\{\s*$|^\s*(public|private|protected|internal|static|async|override|virtual|final|export|default|synchronized|\w[\w<>[\],\s*&:]*)\s+[\w$]+\s*\([^;]*\)\s*(:\s*[\w<>[\]|?. ]+)?\s*(throws\s+[\w., ]+)?\s*\{?\s*$|^\s*(async\s+)?[\w$]+\s*\([^;)]*\)\s*\{\s*$)/;

// Kommentare und Text-Literale durch Leerzeichen ersetzen (Zeilenumbrueche bleiben), damit
// Woerter wie "if" in Strings nicht als Verzweigung zaehlen
function codeOnly(text, py) {
  const re = py
    ? /#[^\n]*|"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g
    : /\/\*[\s\S]*?\*\/|\/\/[^\n]*|(?<=(?:[(,=:[!&|?{};]|^|\breturn)\s*)\/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+\/[gimsuy]*|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`/gm;
  return text.replace(re, (m) => (m[0] === '"' || m[0] === "'" || m[0] === '`' ? m[0] + m.slice(1, -1).replace(/[^\n]/g, ' ') + m.slice(-1) : m.replace(/[^\n]/g, ' ')));
}

// Schliessende Klammer zu text[open] finden (Strings und Kommentare werden uebersprungen)
function matchBrace(text, open) {
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    const ch = text[i];
    const nx = text[i + 1];
    if (ch === '/' && nx === '/') { i = text.indexOf('\n', i); if (i < 0) return -1; continue; }
    if (ch === '/' && nx === '*') { i = text.indexOf('*/', i + 2); if (i < 0) return -1; i++; continue; }
    if (ch === '"' || ch === "'" || ch === '`') {
      const q = ch; i++;
      while (i < text.length && text[i] !== q) { if (text[i] === '\\') i++; else if (q !== '`' && text[i] === '\n') break; i++; }
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

function functionsBrace(c) {
  const lines = c.split('\n');
  const starts = [0];
  for (let i = 0; i < lines.length; i++) starts.push(starts[i] + lines[i].length + 1);
  const out = [];
  let skipUntil = -1;
  for (let i = 0; i < lines.length; i++) {
    if (i < skipUntil) continue;
    const l = lines[i];
    if (l.length > 400 || CONTROL.test(l) || !HEADER.test(l)) continue;
    // oeffnende Klammer in dieser oder der naechsten Zeile
    let at = l.lastIndexOf('{');
    let lineOpen = i;
    if (at < 0 && i + 1 < lines.length && /^\s*\{/.test(lines[i + 1])) { at = lines[i + 1].indexOf('{'); lineOpen = i + 1; }
    if (at < 0) continue;
    const open = starts[lineOpen] + at;
    const close = matchBrace(c, open);
    if (close < 0) continue;
    const endLine = c.slice(0, close).split('\n').length - 1;
    const len = endLine - i + 1;
    if (len < 20) continue;
    const name = (l.match(/(?:function\s*\*?\s*|func\s+(?:\([^)]*\)\s*)?|fn\s+|fun\s+|def\s+)([\w$.]+)/) || l.match(/([\w$]+)\s*(?:[:=]\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)|\()/) || [])[1] || '?';
    out.push({ name, line: i + 1, len, decisions: (c.slice(open, close).match(DECISIONS) || []).length });
    if (len >= LONG) skipUntil = endLine; // innere Funktionen nicht zusaetzlich melden
  }
  return out;
}

function functionsPython(c) {
  const lines = c.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(\s*)(async\s+)?def\s+(\w+)/);
    if (!m) continue;
    const ind = m[1].length;
    let j = i + 1;
    while (j < lines.length && (/^\s*(#.*)?$/.test(lines[j]) || lines[j].match(/^\s*/)[0].length > ind)) j++;
    while (j - 1 > i && /^\s*$/.test(lines[j - 1])) j--;
    const len = j - i;
    if (len < 20) continue;
    out.push({ name: m[3], line: i + 1, len, decisions: (lines.slice(i, j).join('\n').match(DECISIONS) || []).length });
  }
  return out;
}

const NORM_SKIP = /^([{}()[\];,]+|end|else|try:|else:|finally:|\*\/|\/\*+|<\/?\w+>|pass|break;?|continue;?|return;?|\)\s*;?|\}\s*\)\s*;?)$|^(\/\/|#|\*|--|import\s|from\s+\S+\s+import|using\s|#include|package\s|require\(|const\s+\w+\s*=\s*require\(|use\s)/;

function runQuality(units) {
  const out = [];
  const seen = new Map(); // hash -> { u, line }
  let dupes = 0;
  let longCount = 0;
  for (const u of units) {
    if (!isText(u)) continue;
    const p = base(u);
    const brace = BRACE.test(p), py = PY.test(p);
    if ((!brace && !py) || SKIP.test(p)) continue;
    const c = u.content;
    if (c.length > 400 * 1024) continue;
    // Lange / verzweigte Funktionen
    const code = codeOnly(c, py);
    // Namenlose Huellen (IIFE/UMD-Wrapper um die ganze Datei) nicht als Funktion werten
    const fns = (brace ? functionsBrace(code) : functionsPython(code)).filter((f) => !['?', 'function'].includes(f.name) &&(f.len >= LONG || f.decisions >= COMPLEX));
    for (const f of fns.slice(0, 3)) {
      if (longCount >= 15) break;
      longCount++;
      const complex = f.decisions >= COMPLEX;
      out.push(mk(M, u, null, {
        ruleId: complex ? 'quality-complex-function' : 'quality-long-function', severity: 'low', category: 'Other', confidence: 'medium',
        title: complex ? `Sehr verzweigte Funktion: ${f.name} (${f.decisions} Verzweigungen)` : `Sehr lange Funktion: ${f.name} (${f.len} Zeilen)`,
        description: `Die Funktion ${f.name} hat ${f.len} Zeilen und ${f.decisions} Verzweigungen. So umfangreicher Code ist schwer zu prüfen und zu testen – Sicherheitsprüfungen und Sonderfälle werden darin leicht übersehen.`,
        remediation: 'In kleinere, einzeln testbare Funktionen aufteilen (z. B. Prüfung, Verarbeitung, Ausgabe) und tief verschachtelte Bedingungen durch frühe Rücksprünge ersetzen.',
      }));
      out[out.length - 1].location = `${p}:${f.line}`;
    }
    // Kopierte Bloecke (10 gleiche normalisierte Zeilen)
    if (isTestFile(u) || dupes >= 10) continue;
    const raw = c.split('\n');
    const norm = [];
    for (let i = 0; i < raw.length; i++) {
      const t = raw[i].trim().replace(/\s+/g, ' ');
      if (!t || t.length < 4 || NORM_SKIP.test(t)) continue;
      norm.push({ t, line: i + 1 });
    }
    const W = 10;
    for (let i = 0; i + W <= norm.length && dupes < 10; i++) {
      const win = norm.slice(i, i + W);
      const text = win.map((x) => x.t).join('\n');
      if (text.length < 250) continue;
      const h = crypto.createHash('sha1').update(text).digest('hex');
      const prev = seen.get(h);
      if (!prev) { seen.set(h, { p, line: win[0].line }); continue; }
      if (prev.p === p && win[0].line - prev.line < W * 2) continue;
      dupes++;
      out.push(mk(M, u, null, {
        ruleId: 'quality-duplicate-block', severity: 'info', category: 'Other', confidence: 'medium',
        title: 'Kopierter Code-Block',
        description: `Ab hier stehen mindestens ${W} Zeilen, die genauso schon in ${prev.p}:${prev.line} vorkommen. Wird in einer Kopie ein Fehler behoben, bleibt er in der anderen bestehen.`,
        remediation: 'Den gemeinsamen Teil in eine Funktion oder ein Modul auslagern und an beiden Stellen verwenden.',
      }));
      out[out.length - 1].location = `${p}:${win[0].line}`;
      i += W - 1;
    }
  }
  return out;
}

module.exports = { runQuality, functionsBrace, functionsPython };
