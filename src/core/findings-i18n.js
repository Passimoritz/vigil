'use strict';

// Englische Befundtexte. Die Pruefmodule schreiben Deutsch; fuer die englische Oberflaeche und
// englische Berichte uebersetzt dieses Modul die Texte ueber das Woerterbuch in findings-en.js:
//  - feste Saetze direkt,
//  - Texte mit eingesetzten Werten ueber Vorlagen ("Datei {0} ist offen"), wobei die eingesetzten
//    Werte selbst wieder uebersetzt werden (z. B. Aufzaehlungen aus festen Teilsaetzen),
//  - sonst Satz fuer Satz.
// Unbekanntes bleibt unveraendert. Laeuft im Hauptprozess (require) und im Fenster (<script>).
(function (root, factory) {
  const api = factory(typeof module === 'object' && module.exports ? require('./findings-en') : root.VIGIL_FINDINGS_EN);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.VigilFindingsI18n = api;
})(typeof self !== 'undefined' ? self : this, (PAIRS) => {
  const norm = (s) => String(s).replace(/\s+/g, ' ').trim();
  const exact = new Map();
  const templates = [];
  const esc = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  function addTemplate(de, en, minLiteral) {
    const literal = de.replace(/\{\d+\}/g, '');
    if (literal.replace(/[\s.,:;()–-]/g, '').length < minLiteral) return; // nur Platzhalter: wuerde alles treffen
    const order = [];
    // Leerraum der Vorlage passt auf beliebigen Leerraum (auch Zeilenumbrueche im Text)
    const src = norm(de).split(/(\{\d+\})/).map((part) => {
      const m = part.match(/^\{(\d+)\}$/);
      if (m) { order.push(Number(m[1])); return '([\\s\\S]*?)'; }
      return part.split(' ').map(esc).join('\\s+');
    }).join('');
    templates.push({ re: new RegExp('^' + src + '$'), order, en, weight: literal.length });
  }
  // Bausteine, die mehrere Module gemeinsam nutzen (duerfen kurz sein)
  const EXTRA = [
    ['{0} Fundstelle: `{1}`', '{0} Location: `{1}`'], ['Fundstelle: {0}', 'Location: {0}'], ['Er {0}.', 'It {0}.'], ['auf {0}', 'on {0}'],
    ['Am schnellsten: {0}', 'Quickest: {0}'], ['(Befund: „{0}“)', '(finding: “{0}”)'], ['Möglicher Angriffsweg: {0}', 'Possible attack path: {0}'], ['Angriffsweg: {0}', 'Attack path: {0}'],
  ];
  // Kommentare in Code-Schnipseln und Patches der Loesungen ("// …", "# …")
  const CODE_COMMENTS = [
    ['in server { … } bzw. location { … }', 'in server { … } or location { … }'], ['in VirtualHost oder .htaccess (mod_headers aktiv)', 'in VirtualHost or .htaccess (mod_headers enabled)'],
    ['Node/Express – am einfachsten mit helmet: npm i helmet', 'Node/Express – easiest with helmet: npm i helmet'], ['Timer prüfen:', 'Check the timer:'],
    ['Caddy holt und erneuert Zertifikate automatisch:', 'Caddy obtains and renews certificates automatically:'], ['versteckte Dateien und SourceMaps sperren', 'block hidden files and source maps'],
    ['webpack.config.js (Produktion)', 'webpack.config.js (production)'], ['verwaisten Eintrag entfernen', 'remove the orphaned record'],
    ['shop.example.com.  CNAME  alt-shop.herokuapp.com.   <- löschen', 'shop.example.com.  CNAME  alt-shop.herokuapp.com.   <- delete'], ['nicht 403 – verrät nichts über Existenz', 'not 403 – reveals nothing about existence'],
    ['Passwörter', 'Passwords'], ['Verschlüsselung', 'Encryption'], ['oder: const safe = Object.assign(Object.create(null), src);', 'or: const safe = Object.assign(Object.create(null), src);'],
    ['Eingabe getrennt, nicht im System-Prompt', 'input kept separate, not in the system prompt'], ['Ausgabe nur als Text anzeigen', 'show output as text only'], ['statt innerHTML', 'instead of innerHTML'],
    ['Ollama nur lokal', 'Ollama local only'], ['aus der Historie entfernen', 'remove from the history'], ['statt im Code:', 'instead of in the code:'], ['aus .env / Secret-Manager', 'from .env / secret manager'],
    ['statt im Code', 'instead of in the code'], ['Produktion', 'production'], ['nur lokal', 'local only'],
  ];
  for (const [de, en] of CODE_COMMENTS) exact.set(norm(de), en);
  for (const [de, en] of [['Zwei', 'Two'], ['Drei', 'Three'], ['Vier', 'Four'], ['Fünf', 'Five'], ['Sechs', 'Six']]) exact.set(de, en);
  for (const [de, en] of EXTRA) addTemplate(de, en, 1);
  for (const [de, en] of PAIRS || []) {
    if (!de || !en || de === en) continue;
    if (!/\{\d+\}/.test(de)) exact.set(norm(de), en);
    else addTemplate(de, en, 4);
  }
  templates.sort((a, b) => b.weight - a.weight);

  // Angriffswege gibt es auch als "Möglicher Angriffsweg: …" bzw. nur mit dem Teil nach dem Doppelpunkt
  for (const [de, en] of [...exact]) {
    if (!/^Angriffsweg: /.test(de)) continue;
    exact.set('Möglicher ' + de, en.replace(/^Attack path:/, 'Possible attack path:'));
    exact.set(de.slice(13), en.replace(/^Attack path:\s*/, ''));
  }
  // Satzende: zwei Buchstaben/Ziffern vor dem Punkt, damit "z. B." nicht trennt
  const SEPS = [[/\n+/, '\n'], [/(?<=[A-Za-zÄÖÜäöüß)“"\d]{2}[.!?])\s+(?=[A-ZÄÖÜ„"(]|\d+\. )/, ' '], [/, /, ', '], [/; /, '; '], [/ · /, ' · ']];
  const cache = new Map();
  function translate(input, depth = 0) {
    if (input == null || typeof input !== 'string') return input;
    const raw = input.trim();
    const s = norm(raw);
    if (!s || !/[A-Za-zÄÖÜäöüß]/.test(s)) return input;
    if (cache.has(raw)) return withEdges(input, cache.get(raw));
    let out = exact.get(s);
    if (out == null && depth < 5) {
      for (const t of templates) {
        const m = t.re.exec(raw);
        if (!m) continue;
        const vals = {};
        t.order.forEach((n, i) => { vals[n] = translate(m[i + 1], depth + 1); });
        out = t.en.replace(/\{(\d+)\}/g, (x, n) => (vals[n] != null ? vals[n] : x));
        break;
      }
    }
    // Nummerierte Punkte ("1. …"), angehaengter Name in Klammern, "Bezeichnung: Wert"
    if (out == null && depth < 5) {
      let m = /^(\d+\.\s+)([\s\S]+)$/.exec(raw);
      if (m) { const b = translate(m[2], depth + 1); if (b !== m[2]) out = m[1] + b; }
      if (out == null && (m = /^([\s\S]*\S) \(([^()]*)\)$/.exec(raw))) { const b = translate(m[1], depth + 1), p = translate(m[2], depth + 1); if (b !== m[1] || p !== m[2]) out = `${b} (${p})`; }
      if (out == null && (m = /^([^:\n]{3,60}): (.+)$/.exec(raw))) { const b = translate(m[1], depth + 1); if (b !== m[1]) out = b + ': ' + translate(m[2], depth + 1); }
    }
    // Aufzaehlungen ("startet Programme, laedt Dateien"), Zeilen und Saetze einzeln
    if (out == null && depth < 5) {
      for (const [sep, join] of SEPS) {
        const parts = raw.split(sep);
        if (parts.length < 2) continue;
        // Laengste bekannte Folge zuerst (ein Eintrag im Woerterbuch kann mehrere Saetze umfassen)
        const tr = [];
        let changed = false;
        for (let i = 0; i < parts.length;) {
          let j = Math.min(parts.length, i + 6);
          for (; j > i + 1; j--) { const c = parts.slice(i, j).join(join).trim(); if (exact.has(norm(c)) || templates.some((t) => t.re.test(c))) break; }
          const c = parts.slice(i, j).join(join);
          const t = translate(c, depth + 1);
          if (t !== c) changed = true;
          tr.push(t);
          i = j;
        }
        if (changed) { out = tr.join(join); break; }
      }
    }
    if (out == null) out = raw;
    if (cache.size > 20000) cache.clear();
    cache.set(raw, out);
    return withEdges(input, out);
  }
  // Leerzeichen am Rand erhalten (eingesetzte Teilsaetze wie " Er startet …")
  const withEdges = (input, core) => /^\s*/.exec(input)[0] + core + /\s*$/.exec(input)[0];

  // Kommentarzeilen in Code uebersetzen: ganze Kommentarzeilen ("# …", "// …", "-- …", "; …") und
  // Kommentare am Zeilenende ("code  // …"). Code selbst bleibt unveraendert.
  const LETTERS = /[A-Za-zÄÖÜäöüß]{2}/;
  function translateCode(code) {
    if (typeof code !== 'string' || !LETTERS.test(code)) return code;
    return code.split('\n').map((line) => {
      let m = /^(\s*(?:\/\/+|#+|--|;+|\/\*+|\*|<!--)\s?)(.*?)(\s*(?:\*\/|-->)?\s*)$/.exec(line);
      if (m && m[2] && LETTERS.test(m[2]) && !/^!/.test(m[2])) { const t = translate(m[2]); return t !== m[2] ? m[1] + t + m[3] : line; }
      m = /^(.*?\S)(\s+(?:\/\/|#)\s?)([^'"`]*?)(\s*)$/.exec(line);
      if (m && LETTERS.test(m[3])) { const t = translate(m[3]); if (t !== m[3]) return m[1] + m[2] + t + m[4]; }
      return line;
    }).join('\n');
  }
  const FIELDS = ['title', 'description', 'impact', 'remediation', 'explanation', 'reachability'];
  function localizeFinding(f) {
    if (!f || typeof f !== 'object') return f;
    const o = { ...f };
    for (const k of FIELDS) if (typeof o[k] === 'string') o[k] = translate(o[k]);
    if (Array.isArray(o.steps)) o.steps = o.steps.map((x) => translate(x));
    if (o.validation && typeof o.validation.reason === 'string') o.validation = { ...o.validation, reason: translate(o.validation.reason) };
    if (Array.isArray(o.links)) o.links = o.links.map((l) => (l && typeof l.label === 'string' ? { ...l, label: translate(l.label) } : l));
    if (o.versionPatch) o.versionPatch = { ...o.versionPatch, title: translate(o.versionPatch.title), note: translate(o.versionPatch.note), command: translateCode(o.versionPatch.command), manifest: translateCode(o.versionPatch.manifest) };
    if (o.snippets && typeof o.snippets === 'object') o.snippets = Object.fromEntries(Object.entries(o.snippets).map(([k, v]) => [k, translateCode(v)]));
    if (typeof o.patch === 'string') o.patch = translateCode(o.patch);
    if (o.chain && Array.isArray(o.chain.steps)) o.chain = { ...o.chain, entry: translate(o.chain.entry), goal: translate(o.chain.goal), steps: o.chain.steps.map((st) => ({ ...st, stage: translate(st.stage), why: translate(st.why), what: translate(st.what), fix: translate(st.fix) })) };
    return o;
  }
  function localizeResult(r) {
    if (!r || typeof r !== 'object') return r;
    return { ...r, findings: (r.findings || []).map(localizeFinding), errors: Array.isArray(r.errors) ? r.errors.map((e) => translate(e)) : r.errors };
  }
  return { translate, translateCode, localizeFinding, localizeResult, size: () => exact.size + templates.length };
});
