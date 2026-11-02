'use strict';

// Datenfluesse ueber mehrere Dateien (JavaScript/TypeScript und Python).
//
// 1. Zusammenfassungen: Fuer jede Funktion wird bestimmt, welcher Parameter ungeprueft in eine
//    gefaehrliche Senke laeuft (SQL, Shell, eval, HTML, Dateipfad, Abruf fremder URLs, Weiterleitung).
// 2. Weitergabe: Ruft eine Funktion eine andere mit ihrem Parameter auf, erbt sie deren Senke
//    (Fixpunkt ueber alle Dateien, hoechstens 5 Runden).
// 3. Quellen: Aufrufstellen, die eine Eingabe von aussen (req.query, request.args …) an eine solche
//    Funktion geben. Gemeldet wird nur, wenn Quelle und Senke in VERSCHIEDENEN Dateien liegen –
//    innerhalb einer Datei finden das die Einzelregeln bzw. die KI.
// Bewusst schlank: Namen statt vollstaendiger Typ-/Modulaufloesung; Bereinigung (parseInt, escape,
// Platzhalter …) im Funktionsrumpf verhindert die Meldung.

const { normalizeFinding } = require('./schema');

const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const isJs = (u) => /\.(m?[jt]sx?|cjs)$/i.test(base(u));
const isPy = (u) => /\.py$/i.test(base(u));
const isTest = (u) => /(^|\/)(test|tests|__tests__|spec|e2e|fixtures?|mocks?)(\/|$)|\.(test|spec)\.[jt]sx?$/i.test(base(u));

const SINKS = [
  { kind: 'sql', cat: 'Injection', label: 'einen SQL-Befehl', re: (p) => new RegExp(`\\.(query|execute|raw|executemany)\\s*\\(\\s*(?:\`[^\`]*\\$\\{\\s*${p}\\b|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\\s*[+%]\\s*${p}\\b|f["'][^"']*\\{${p}\\b|${p}\\s*[,)])`, 'i'), guard: /\?\s*[,)]|\$\d|%s['"]\s*,\s*\(|:\w+\b|escape|sanitize|parseInt|Number\(|int\(/ },
  { kind: 'shell', cat: 'Injection', label: 'einen Systembefehl', re: (p) => new RegExp(`\\b(exec|execSync|spawn|spawnSync|execFile|system|popen|subprocess\\.(?:run|call|Popen|check_output)|os\\.system)\\s*\\(\\s*(?:\`[^\`]*\\$\\{\\s*${p}\\b|["'][^"']*["']\\s*\\+\\s*${p}\\b|f["'][^"']*\\{${p}\\b|${p}\\b)`), guard: /shlex\.quote|escapeShellArg|allowlist|whitelist/ },
  { kind: 'eval', cat: 'Injection', label: 'ausgeführten Code (eval)', re: (p) => new RegExp(`\\b(eval|new Function|exec)\\s*\\(\\s*${p}\\b`), guard: null },
  { kind: 'html', cat: 'XSS', label: 'die ausgelieferte Webseite', re: (p) => new RegExp(`(\\.innerHTML\\s*=\\s*${p}\\b|res\\.send\\s*\\(\\s*(?:\`[^\`]*\\$\\{\\s*${p}\\b|${p}\\b)|dangerouslySetInnerHTML=\\{\\{\\s*__html:\\s*${p}\\b|render_template_string\\s*\\(\\s*${p}\\b|Markup\\s*\\(\\s*${p}\\b)`), guard: /escape|sanitize|DOMPurify|encodeURIComponent|textContent/ },
  { kind: 'path', cat: 'PathTraversal', label: 'einen Dateipfad', re: (p) => new RegExp(`\\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|sendFile|open)\\s*\\(\\s*(?:path\\.join\\([^)]*\\b${p}\\b|${p}\\b|\`[^\`]*\\$\\{\\s*${p}\\b)`), guard: /path\.basename|startsWith\(|secure_filename|realpath/ },
  { kind: 'ssrf', cat: 'SSRF', label: 'den Abruf einer fremden Adresse (SSRF)', re: (p) => new RegExp(`\\b(fetch|axios(?:\\.get|\\.post)?|got|http\\.get|https\\.get|requests\\.(?:get|post)|urlopen)\\s*\\(\\s*(?:\`[^\`]*\\$\\{\\s*${p}\\b|${p}\\b)`), guard: /allowlist|allowedHosts|whitelist|new URL\([^)]*\)\.host(name)?\s*(===|!==|in)/ },
  { kind: 'redirect', cat: 'Config', label: 'eine Weiterleitung', re: (p) => new RegExp(`\\b(res\\.redirect|redirect)\\s*\\(\\s*${p}\\b`), guard: /startsWith\(['"]\/['"]\)|allowlist/ },
];
const SOURCE = /\b(req|request)\.(query|body|params|headers|cookies|args|form|json|values|files)\b(?:\.\w+|\[['"][^'"]+['"]\])?|\bprocess\.argv\[\d+\]|\blocation\.(search|hash)\b|\binput\(\)/;

// Funktionen mit Parametern und Rumpf finden
function functionsOf(u) {
  const c = u.content || '';
  const out = [];
  if (isJs(u)) {
    const re = /(?:function\s+(\w+)\s*\(([^)]*)\)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\s*\w*\s*)?\(([^)]*)\)\s*(?:=>)?|(?:exports|module\.exports)\.(\w+)\s*=\s*(?:async\s*)?function\s*\w*\s*\(([^)]*)\)|^\s*(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{)/gm; let m;
    while ((m = re.exec(c))) {
      const name = m[1] || m[3] || m[5] || m[7];
      if (!name || /^(if|for|while|switch|catch|function|return)$/.test(name)) continue;
      const params = (m[2] ?? m[4] ?? m[6] ?? m[8] ?? '').split(',').map((p) => p.replace(/[=:].*$/, '').replace(/[{}[\].\s]/g, '').trim()).filter((p) => /^[A-Za-z_$][\w$]*$/.test(p));
      const open = c.indexOf('{', m.index + m[0].length - 1);
      if (open < 0 || open - (m.index + m[0].length) > 40) continue;
      let d = 0, i = open;
      for (; i < c.length; i++) { if (c[i] === '{') d++; else if (c[i] === '}' && --d === 0) break; }
      out.push({ name, params, body: c.slice(open, i + 1), at: m.index });
    }
  } else if (isPy(u)) {
    const re = /^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->[^:]+)?:/gm; let m;
    while ((m = re.exec(c))) {
      const ind = m[1].length;
      const params = m[3].split(',').map((p) => p.replace(/[=:].*$/, '').replace(/^\*+/, '').trim()).filter((p) => p && p !== 'self' && p !== 'cls');
      const rest = c.slice(m.index + m[0].length).split('\n');
      const body = [];
      for (const line of rest.slice(1)) { if (line.trim() && line.match(/^[ \t]*/)[0].length <= ind) break; body.push(line); }
      out.push({ name: m[2], params, body: body.join('\n'), at: m.index });
    }
  }
  return out;
}

function analyzeTaint(units) {
  const fns = [];
  for (const u of units) if ((isJs(u) || isPy(u)) && !isTest(u)) for (const f of functionsOf(u)) fns.push({ ...f, unit: u });
  // summaries: name -> [{ param index, sink, file, chain }]
  const summary = new Map();
  const add = (name, s) => { const l = summary.get(name) || []; if (!l.some((x) => x.idx === s.idx && x.sink.kind === s.sink.kind)) { l.push(s); summary.set(name, l); return true; } return false; };
  for (const f of fns) {
    f.params.forEach((p, idx) => {
      for (const sink of SINKS) {
        const m = f.body.match(sink.re(p.replace(/\$/g, '\\$')));
        if (m && !(sink.guard && sink.guard.test(f.body))) add(f.name, { idx, sink, file: base(f.unit), line: lineOf(f.unit.content, f.unit.content.indexOf(f.body) + f.body.indexOf(m[0])), chain: [`${base(f.unit)}:${f.name}()`] });
      }
    });
  }
  // Weitergabe ueber Aufrufe: g(p) ruft f(..., p, ...) auf -> g erbt die Senke von f
  for (let round = 0; round < 5; round++) {
    let changed = false;
    for (const g of fns) {
      for (const [callee, sums] of summary) {
        if (callee === g.name) continue;
        const re = new RegExp(`\\b${callee}\\s*\\(([^)]*)\\)`, 'g'); let m;
        while ((m = re.exec(g.body))) {
          const args = m[1].split(',').map((a) => a.trim());
          for (const s of sums) {
            const arg = args[s.idx]; if (!arg) continue;
            const pi = g.params.indexOf(arg.replace(/^\.\.\./, ''));
            if (pi >= 0 && add(g.name, { ...s, idx: pi, chain: [`${base(g.unit)}:${g.name}()`, ...s.chain] })) changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }
  // Quellen: Eingabe von aussen geht an eine zusammengefasste Funktion in einer anderen Datei
  const findings = [];
  const seen = new Set();
  for (const u of units) {
    if (!(isJs(u) || isPy(u)) || isTest(u)) continue;
    const c = u.content || '';
    for (const [callee, sums] of summary) {
      const re = new RegExp(`\\b${callee}\\s*\\(([^()]*(?:\\([^()]*\\)[^()]*)*)\\)`, 'g'); let m;
      while ((m = re.exec(c))) {
        const args = m[1].split(',').map((a) => a.trim());
        for (const s of sums) {
          const arg = args[s.idx];
          if (!arg || !SOURCE.test(arg)) continue;
          if (s.file === base(u)) continue;
          const key = `${base(u)}:${callee}:${s.sink.kind}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const src = arg.match(SOURCE)[0];
          const path = [`${base(u)}:${lineOf(c, m.index)}`, ...s.chain];
          findings.push(normalizeFinding({
            ruleId: `taint-${s.sink.kind}`, severity: s.sink.kind === 'redirect' ? 'medium' : 'high', category: s.sink.cat, confidence: 'medium',
            title: `Eingabe von außen landet über mehrere Dateien in ${s.sink.label}`,
            description: `Der Wert „${src}“ wird in ${base(u)} an ${callee}() übergeben und erreicht ohne erkennbare Prüfung ${s.sink.label} in ${s.file}:${s.line}.\nWeg: ${path.join(' → ')}`,
            reachability: 'Erreichbar über die Anfrage, die diesen Programmteil aufruft. Die Prüfung arbeitet mit Funktionsnamen und kann bei gleichnamigen Funktionen danebenliegen.',
            impact: { sql: 'Wer den Wert steuert, kann den SQL-Befehl verändern und Daten lesen, ändern oder löschen.', shell: 'Wer den Wert steuert, kann eigene Befehle auf dem Server ausführen.', eval: 'Wer den Wert steuert, kann eigenen Programmcode ausführen.', html: 'Wer den Wert steuert, kann Skripte in die Seite einschleusen und z. B. Sitzungen übernehmen.', path: 'Wer den Wert steuert, kann mit ../ beliebige Dateien des Servers lesen oder überschreiben.', ssrf: 'Wer den Wert steuert, lässt den Server interne Dienste oder Cloud-Zugangsdaten abrufen.', redirect: 'Besucher können auf fremde Seiten umgeleitet werden – beliebt für Phishing.' }[s.sink.kind],
            remediation: { sql: 'Platzhalter (Prepared Statements) statt zusammengesetztem SQL verwenden.', shell: 'Programm ohne Shell und mit festen Argumenten starten; Eingaben gegen eine Liste erlaubter Werte prüfen.', eval: 'Auf eval verzichten; Daten mit JSON.parse oder einem festen Regelwerk verarbeiten.', html: 'Werte beim Ausgeben maskieren (Template-Engine mit Auto-Escape, textContent statt innerHTML).', path: 'Nur den Dateinamen verwenden (path.basename) und prüfen, dass der Pfad im erlaubten Ordner bleibt.', ssrf: 'Nur Adressen aus einer festen Liste erlauben; interne Adressen sperren.', redirect: 'Nur relative Pfade oder Ziele aus einer festen Liste erlauben.' }[s.sink.kind],
            location: `${s.file}:${s.line}`, evidence: path.join(' → ').slice(0, 480), sourceModule: 'taint-flow', taint: path,
          }, 'taint-flow'));
        }
      }
    }
  }
  return findings;
}

module.exports = { analyzeTaint, functionsOf };
