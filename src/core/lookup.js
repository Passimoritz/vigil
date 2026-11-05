'use strict';

// "KI darf nachschlagen": Werkzeuge, mit denen die KI waehrend der Analyse weitere Dateien
// bzw. Funktionsdefinitionen anfordern kann. Gelesen wird NUR aus den bereits eingelesenen
// Units (kein Zugriff auf beliebige Pfade), Ausgaben sind gekuerzt; vor dem Versand an eine
// Cloud-KI wird geschwaerzt (Aufrufer uebergibt redact).

const MAX_FILE_CHARS = 8000;
const MAX_DEF_LINES = 40;

const TOOLS = [
  {
    name: 'read_file',
    description: 'Liefert den Inhalt einer weiteren Datei des geprueften Projekts (gekuerzt). Nutze das, wenn eine importierte/aufgerufene Datei fuer die Bewertung noetig ist.',
    parameters: { type: 'object', properties: { path: { type: 'string', description: 'Dateipfad wie in den UNIT-Ueberschriften oder Import-Pfad' } }, required: ['path'] },
  },
  {
    name: 'find_definition',
    description: 'Sucht die Definition einer Funktion, Methode oder Klasse im Projekt und liefert den Code-Ausschnitt.',
    parameters: { type: 'object', properties: { name: { type: 'string', description: 'Name der Funktion/Methode/Klasse' } }, required: ['name'] },
  },
];

const norm = (p) => String(p || '').replace(/\\/g, '/').replace(/^\.?\//, '').toLowerCase();

function findUnitByPath(units, p) {
  const want = norm(p).replace(/\.(js|ts|mjs|cjs|jsx|tsx|py)$/, '');
  if (!want) return null;
  const score = (u) => {
    const l = norm(u.label);
    const ls = l.replace(/\.(js|ts|mjs|cjs|jsx|tsx|py)$/, '');
    if (l === norm(p) || ls === want) return 3;
    if (ls.endsWith('/' + want) || want.endsWith('/' + ls)) return 2;
    if (ls.split('/').pop() === want.split('/').pop()) return 1;
    return 0;
  };
  let best = null, bs = 0;
  for (const u of units) { const s = score(u); if (s > bs) { best = u; bs = s; } }
  return best;
}

const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function defPatterns(name) {
  const n = reEsc(name);
  return [
    new RegExp(`\\b(?:async\\s+)?function\\s*\\*?\\s*${n}\\s*\\(`),
    new RegExp(`\\b(?:const|let|var)\\s+${n}\\s*=\\s*(?:async\\s*)?(?:function\\b|\\(|[\\w$]+\\s*=>)`),
    new RegExp(`^\\s*(?:export\\s+)?(?:default\\s+)?class\\s+${n}\\b`),
    new RegExp(`^\\s*(?:async\\s+)?def\\s+${n}\\s*\\(`),
    new RegExp(`^\\s*func\\s+(?:\\([^)]*\\)\\s*)?${n}\\s*\\(`),
    new RegExp(`^\\s*(?:pub\\s+)?fn\\s+${n}\\s*[<(]`),
    new RegExp(`^\\s*(?:public|private|protected|internal|static|\\s)+[\\w<>\\[\\],\\s]+\\s${n}\\s*\\(`),
    new RegExp(`^\\s*(?:static\\s+)?(?:async\\s+)?${n}\\s*\\([^)]*\\)\\s*\\{`),
    new RegExp(`\\b${n}\\s*:\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*=>)`),
  ];
}

function findDefinitions(units, name, max = 3) {
  const n = String(name || '').trim();
  if (!/^[\w$.]{1,80}$/.test(n)) return [];
  const simple = n.split('.').pop();
  const pats = defPatterns(simple);
  const hits = [];
  for (const u of units) {
    const lines = String(u.content || '').split(/\r?\n/);
    for (let i = 0; i < lines.length && hits.length < max; i++) {
      if (!pats.some((re) => re.test(lines[i]))) continue;
      const from = i + 1;
      const to = Math.min(lines.length, i + MAX_DEF_LINES);
      hits.push({ label: u.label, from, to, text: lines.slice(i, to).map((l, k) => `${String(from + k).padStart(5)}  ${l}`).join('\n') });
    }
    if (hits.length >= max) break;
  }
  return hits;
}

// Liefert { tools, run(name, args) }. redact: (text) => text (Schwaerzen fuer Cloud-Anbieter).
function makeLookupTools(units, { redact = (t) => t } = {}) {
  const seen = new Set();
  const run = async (name, args = {}) => {
    if (name === 'read_file') {
      const u = findUnitByPath(units, args.path);
      if (!u) return `Datei "${String(args.path || '').slice(0, 200)}" ist nicht Teil des geprueften Materials.`;
      if (seen.has('f:' + u.label)) return `Datei ${u.label} wurde bereits geliefert.`;
      seen.add('f:' + u.label);
      let c = String(u.content || '');
      if (c.length > MAX_FILE_CHARS) c = c.slice(0, MAX_FILE_CHARS) + '\n/* ... [gekuerzt] ... */';
      return redact(`### UNIT: ${u.label}\n${c}`);
    }
    if (name === 'find_definition') {
      const hits = findDefinitions(units, args.name);
      if (!hits.length) return `Keine Definition von "${String(args.name || '').slice(0, 80)}" im geprueften Material gefunden.`;
      return redact(hits.map((h) => `### ${h.label} Zeilen ${h.from}-${h.to}\n${h.text}`).join('\n\n'));
    }
    return `Unbekanntes Werkzeug: ${String(name).slice(0, 40)}`;
  };
  return { tools: TOOLS, run };
}

module.exports = { makeLookupTools, findDefinitions, findUnitByPath, TOOLS };
