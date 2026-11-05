'use strict';

// Kleiner YAML-Leser ohne Abhaengigkeit – reicht fuer Konfigurationen wie OpenAPI-Spezifikationen
// und Regeldateien: Block-Mappings und -Listen, einfache Flow-Werte ([a, b], {a: 1}), Zeichenketten
// in Anfuehrungszeichen, mehrzeilige Texte (| und >) und Kommentare. Anker, Tags und mehrere
// Dokumente werden nicht ausgewertet (es zaehlt das erste Dokument). Nichts wird ausgefuehrt.

function stripComment(s) {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === q && s[i - 1] !== '\\') q = null; continue; }
    if (ch === '"' || ch === "'") { if (i === 0 || /[\s:[{,-]/.test(s[i - 1])) q = ch; continue; }
    if (ch === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
  }
  return s;
}

function scalar(raw) {
  const s = String(raw).trim();
  if (s === '') return null;
  if (s[0] === '"' && s.endsWith('"') && s.length >= 2) {
    try { return JSON.parse(s); } catch { return s.slice(1, -1); }
  }
  if (s[0] === "'" && s.endsWith("'") && s.length >= 2) return s.slice(1, -1).replace(/''/g, "'");
  if (s[0] === '[' || s[0] === '{') return flow(s);
  if (/^(true|True|TRUE)$/.test(s)) return true;
  if (/^(false|False|FALSE)$/.test(s)) return false;
  if (/^(null|Null|NULL|~)$/.test(s)) return null;
  if (/^[-+]?\d+$/.test(s)) return Number(s);
  if (/^[-+]?(\d+\.\d*|\.\d+)([eE][-+]?\d+)?$/.test(s)) return Number(s);
  return s.replace(/^[&*!][\w-]+\s+/, '');
}

// Flow-Schreibweise [..] / {..} (verschachtelt moeglich)
function flow(s) {
  let i = 0;
  const ws = () => { while (i < s.length && /\s/.test(s[i])) i++; };
  function value() {
    ws();
    if (s[i] === '[') { i++; const arr = []; ws(); if (s[i] === ']') { i++; return arr; }
      while (i < s.length) { arr.push(value()); ws(); if (s[i] === ',') { i++; continue; } if (s[i] === ']') { i++; break; } break; }
      return arr; }
    if (s[i] === '{') { i++; const obj = {}; ws(); if (s[i] === '}') { i++; return obj; }
      while (i < s.length) { ws(); const k = token(':,}'); ws(); let v = null; if (s[i] === ':') { i++; v = value(); } obj[String(scalar(k))] = v; ws(); if (s[i] === ',') { i++; continue; } if (s[i] === '}') { i++; break; } break; }
      return obj; }
    return scalar(token(',]}'));
  }
  function token(stops) {
    ws();
    if (s[i] === '"' || s[i] === "'") { const q = s[i]; let j = i + 1; while (j < s.length && !(s[j] === q && s[j - 1] !== '\\')) j++; const t = s.slice(i, j + 1); i = j + 1; return t; }
    let j = i; while (j < s.length && !stops.includes(s[j])) { if (s[j] === ':' && stops.includes(':') && !/\s|$/.test(s[j + 1] || '')) { j++; continue; } j++; }
    const t = s.slice(i, j); i = j; return t.trim();
  }
  try { return value(); } catch { return s; }
}

function parseYaml(text) {
  const lines = [];
  for (const rawLine of String(text || '').replace(/\r\n?/g, '\n').split('\n')) {
    if (/^(---|\.\.\.)\s*$/.test(rawLine)) { if (lines.length) break; continue; }
    lines.push(rawLine);
  }
  let p = 0;
  const indentOf = (l) => l.match(/^ */)[0].length;
  const blank = (l) => stripComment(l).trim() === '';
  function skipBlank() { while (p < lines.length && blank(lines[p])) p++; }

  function blockScalar(style, parentIndent) {
    const out = [];
    let ind = null;
    while (p < lines.length) {
      const l = lines[p];
      if (l.trim() === '') { out.push(''); p++; continue; }
      const k = indentOf(l);
      if (k <= parentIndent) break;
      if (ind == null) ind = k;
      out.push(l.slice(Math.min(ind, k)));
      p++;
    }
    while (out.length && out[out.length - 1] === '') out.pop();
    return style.startsWith('>') ? out.join(' ').replace(/ {2,}/g, ' ') : out.join('\n');
  }

  // Wert nach "key:" bzw. "- ": Inline-Wert, Blocktext oder eingerueckter Block
  function valueAfter(rest, indent) {
    const r = stripComment(rest).trim();
    if (/^[|>][-+]?\d*$/.test(r)) return blockScalar(r, indent);
    if (r !== '' && !/^[&!][\w-]+$/.test(r)) {
      // mehrzeilige Flow-Werte zusammenfuegen
      if ((r[0] === '[' || r[0] === '{') && !balanced(r)) {
        let acc = r;
        while (p < lines.length && !balanced(acc)) acc += ' ' + stripComment(lines[p++]).trim();
        return scalar(acc);
      }
      return scalar(r);
    }
    skipBlank();
    if (p >= lines.length) return null;
    const k = indentOf(lines[p]);
    const t = lines[p].trim();
    if (k > indent || (k === indent && t.startsWith('- '))) return block(k);
    return null;
  }

  function block(indent) {
    skipBlank();
    if (p >= lines.length) return null;
    const first = lines[p].slice(indent);
    if (first.startsWith('- ') || first === '-') {
      const arr = [];
      while (p < lines.length) {
        skipBlank();
        if (p >= lines.length) break;
        const l = lines[p];
        if (indentOf(l) !== indent || !(l.slice(indent).startsWith('- ') || l.slice(indent) === '-')) break;
        const rest = l.slice(indent + 1);
        const inner = rest.replace(/^ +/, '');
        const innerIndent = indent + 1 + (rest.length - inner.length);
        if (/^[^\s"'[{][^:]*:(\s|$)/.test(stripComment(inner)) || /^["'][^"']+["']\s*:(\s|$)/.test(inner)) {
          // Mapping direkt im Listeneintrag: Zeile so umschreiben, als stuende sie eingerueckt
          lines[p] = ' '.repeat(innerIndent) + inner;
          arr.push(block(innerIndent));
        } else { p++; arr.push(valueAfter(inner, indent)); }
      }
      return arr;
    }
    const obj = {};
    while (p < lines.length) {
      skipBlank();
      if (p >= lines.length) break;
      const l = lines[p];
      const k = indentOf(l);
      if (k < indent) break;
      if (k > indent) { p++; continue; } // unerwartet tief: ueberspringen
      const t = stripComment(l.slice(indent));
      const m = t.match(/^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^:]+?)\s*:(?:\s+(.*)|\s*)$/);
      if (!m || t.startsWith('- ')) break;
      p++;
      const key = String(scalar(m[1]));
      obj[key] = valueAfter(m[2] || '', indent);
    }
    return obj;
  }

  function balanced(s) {
    let d = 0, q = null;
    for (let i = 0; i < s.length; i++) { const ch = s[i]; if (q) { if (ch === q) q = null; continue; } if (ch === '"' || ch === "'") q = ch; else if (ch === '[' || ch === '{') d++; else if (ch === ']' || ch === '}') d--; }
    return d <= 0;
  }

  skipBlank();
  if (p >= lines.length) return null;
  const top = lines[p].trim();
  if ((top[0] === '{' || top[0] === '[')) return scalar(lines.slice(p).map((l) => stripComment(l).trim()).join(' '));
  return block(indentOf(lines[p]));
}

// Zeilennummer eines Schluessels/Werts grob finden (fuer Fundstellen)
function lineOfText(text, needle, from = 0) {
  const i = String(text).indexOf(needle, from);
  return i < 0 ? null : String(text).slice(0, i).split('\n').length;
}

module.exports = { parseYaml, lineOfText };
