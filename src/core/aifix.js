'use strict';

// KI-Hilfen auf Knopfdruck (nichts davon aendert Dateien – Vigil SCHLAEGT nur vor):
//  - generatePatch:  konkreter Fix als unified diff fuer die betroffene Datei
//  - explainFinding: Erklaerung je Stufe (Laie / Entwickler / Experte), zwischengespeichert
//  - summarizeRun:   ein Absatz in Alltagssprache ueber den ganzen Lauf (KI oder Regeln)
//  - threatModel:    STRIDE-Bedrohungsmodell des Projekts (KI, sonst aus den Befunden abgeleitet)
// Vor jedem Versand an eine Cloud-KI wird geschwaerzt (harness.redactForCloud).

const crypto = require('crypto');
const providers = require('./providers'); // als Modul, damit Tests den Aufruf ersetzen koennen
const { shouldRedact, redactForCloud } = require('./harness');
const { estimateCost } = require('./cost');

const en = (config) => !config || config.lang !== 'de';
const langLine = (config) => (en(config) ? 'Answer in English.' : 'Antworte auf Deutsch.');
const sha = (s) => crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');

function parseJsonObject(text) {
  const t = String(text || '').replace(/^\s*```(?:json)?\s*|\s*```\s*$/g, '').trim();
  try { return JSON.parse(t); } catch { /* weiter */ }
  const a = t.indexOf('{'), b = t.lastIndexOf('}');
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch { /* egal */ } }
  return null;
}

// Ein KI-Aufruf mit Schwaerzen und Kosten. Liefert { text, usage, cost, redacted }.
async function aiCall(config, { system, user, json = true, kind, maxTokens }) {
  let u = user, redacted = 0;
  if (shouldRedact(config)) { const r = redactForCloud(u, config); u = r.text; redacted = r.count; }
  const res = await providers.callProvider({ ...config, ...(maxTokens ? { maxTokens } : {}) }, { system, user: u, json, kind });
  const usage = res.usage || {};
  const c = estimateCost({ provider: config.provider, model: config.model, baseUrl: config.baseUrl, inputTokens: usage.inputTokens || 0, outputTokens: usage.outputTokens || 0, cachedTokens: usage.cachedTokens || 0 });
  return { text: String(res.text || ''), usage, cost: { usd: c.usd || 0, priced: c.priced, local: c.local, inputTokens: c.inputTokens, outputTokens: c.outputTokens }, redacted };
}

const factsOf = (f) => [
  `Titel: ${f.title || ''}`, `Schwere: ${f.severity || ''}`, `Ort: ${f.location || ''}`, `Kategorie: ${f.category || ''}`,
  f.cwe && `CWE: ${f.cwe}`, f.description && `Beschreibung: ${f.description}`, f.impact && `Auswirkung: ${f.impact}`,
  f.reachability && `Erreichbarkeit: ${f.reachability}`, f.remediation && `Behebung: ${f.remediation}`,
].filter(Boolean).map((x) => String(x).slice(0, 1500)).join('\n');

// code: { file, from, line, lines: [...] } (aus dem Main-Prozess, nur aus gepruefen Ordnern)
const numbered = (code) => code.lines.map((l, i) => `${String(code.from + i).padStart(5)}${code.from + i === code.line ? ' >' : '  '} ${l}`).join('\n');

// --- 1. Fix als unified diff ------------------------------------------------
const PATCH_PROMPT = `Du bist ein erfahrener, defensiver Security-Engineer. Schreibe fuer GENAU den genannten Befund einen minimalen, konkreten Fix als unified diff (Format wie "git diff") fuer die betroffene Datei.
Regeln:
- Kopf: "--- a/<datei>" und "+++ b/<datei>" mit dem mitgelieferten Dateipfad, danach Hunks mit "@@ -<start>,<anzahl> +<start>,<anzahl> @@".
- Kontext- und entfernte Zeilen EXAKT aus dem mitgelieferten Code uebernehmen (ohne Zeilennummern, gleiche Einrueckung). Nur aendern, was fuer den Fix noetig ist.
- Nichts erfinden, was nicht im Ausschnitt steht. Braucht der Fix Aenderungen an anderen Dateien (z. B. neue Abhaengigkeit), nenne das in "notes" statt sie zu raten.
- Keine Angriffs-Payloads, keine Testdaten mit echten Zugangsdaten.
- Steht kein Code zur Verfuegung oder ist der Befund nicht per Code-Aenderung behebbar (z. B. Server-Konfiguration), liefere "diff": "" und erklaere in "notes", was zu tun ist.
Antworte AUSSCHLIESSLICH mit JSON: {"summary": string, "diff": string, "notes": string, "confidence": "high"|"medium"|"low"}`;

function extractDiff(text) {
  const j = parseJsonObject(text);
  if (j && typeof j.diff === 'string') return { summary: String(j.summary || ''), diff: j.diff, notes: String(j.notes || ''), confidence: ['high', 'medium', 'low'].includes(j.confidence) ? j.confidence : 'medium' };
  const m = String(text || '').match(/```(?:diff|patch)?\s*\n([\s\S]*?)```/);
  if (m && /^@@/m.test(m[1])) return { summary: '', diff: m[1], notes: '', confidence: 'low' };
  return { summary: '', diff: '', notes: String(text || '').slice(0, 2000), confidence: 'low' };
}

// Diff aufraeumen: CRLF, Zeilennummern-Reste, fehlender Kopf.
function normalizeDiff(diff, file) {
  let d = String(diff || '').replace(/\r\n?/g, '\n').replace(/^\s*```(?:diff|patch)?\s*\n|\n?```\s*$/g, '');
  if (!/^@@/m.test(d)) return '';
  if (!/^--- /m.test(d)) d = `--- a/${file}\n+++ b/${file}\n` + d.replace(/^\n+/, '');
  return d.replace(/\n*$/, '\n');
}

// Passt der Diff zum Original? Jeder Hunk: Kontext- und "-"-Zeilen muessen in dieser Reihenfolge
// im Code vorkommen (Leerzeichen am Rand egal). Ergebnis ist ein Hinweis, kein Anwenden.
function checkDiff(diff, code) {
  if (!code || !Array.isArray(code.lines)) return { checked: false, applies: null, hunks: 0 };
  const src = code.lines.map((l) => l.trim());
  const hunks = String(diff || '').split(/^@@[^\n]*@@[^\n]*$/m).slice(1);
  let ok = 0;
  for (const h of hunks) {
    const want = h.split('\n').filter((l) => /^[ -]/.test(l) && !/^--- /.test(l)).map((l) => l.slice(1).trim()).filter(Boolean);
    let pos = 0, hit = true;
    for (const w of want) { const i = src.indexOf(w, pos); if (i < 0) { hit = false; break; } pos = i + 1; }
    if (hit) ok++;
  }
  return { checked: true, applies: hunks.length > 0 && ok === hunks.length, hunks: hunks.length, matched: ok };
}

const diffStats = (d) => ({ added: (d.match(/^\+(?!\+\+ )/gm) || []).length, removed: (d.match(/^-(?!-- )/gm) || []).length });

async function generatePatch({ finding = {}, code = null, config }) {
  const file = code ? code.file : String(finding.location || '').replace(/:\d+(:\d+)?$/, '');
  const user = `## Befund\n${factsOf(finding)}\n\n` + (code
    ? `## Datei\n${code.file}\n\n## Code (Zeilennummern links, ">" = gemeldete Zeile ${code.line})\n\`\`\`\n${numbered(code)}\n\`\`\`\n`
    : '## Code\n(nicht verfuegbar)\n') + `\n${langLine(config)} (summary/notes)`;
  const r = await aiCall(config, { system: PATCH_PROMPT, user, json: true, kind: 'patch', maxTokens: 2500 });
  const x = extractDiff(r.text);
  const diff = normalizeDiff(x.diff, file);
  return { ok: true, diff, summary: x.summary, notes: x.notes, confidence: x.confidence, check: diff ? checkDiff(diff, code) : { checked: false, applies: null, hunks: 0 }, stats: diffStats(diff), withCode: !!code, redacted: r.redacted, model: config.model, cost: r.cost, usage: r.usage };
}

// --- 2. Erklaerung je Stufe ---------------------------------------------------
const LEVELS = {
  lay: 'fuer einen Laien ohne Programmierkenntnisse (z. B. Geschaeftsfuehrung): Alltagsvergleich, was konkret passieren kann, wie dringend – keine Fachbegriffe, kein Code.',
  dev: 'fuer eine Entwicklerin: Ursache, wie es ausgenutzt wird (Ablauf, ohne Payload), wie man es richtig macht (kurzes Beispiel), wie man den Fix testet.',
  expert: 'fuer einen Security-Experten: Einordnung (CWE/OWASP), Voraussetzungen, Schwere-Einschaetzung, Fallstricke naiver Fixes, Defense in Depth. Knapp und praezise.',
};
// Feste Abschnitte je Stufe: die KI fuellt nur die Inhalte, Ueberschriften und Reihenfolge kommen von uns.
// So sieht jede Erklaerung gleich aus und das Modell kann die Frage nicht einfach wiederholen.
const SECTIONS = {
  lay: [['what', 'Was ist los?', '1-2 Saetze in Alltagssprache'], ['compare', 'Vergleich aus dem Alltag', '1 Satz'], ['risk', 'Was kann passieren?', '1-3 Stichpunkte'], ['urgency', 'Wie dringend?', '1 Satz: sofort / bald / bei Gelegenheit, mit Grund'], ['todo', 'Was ist zu tun?', '1-3 Stichpunkte, was man der IT sagt']],
  dev: [['cause', 'Ursache', '1-3 Stichpunkte'], ['flow', 'So wird es ausgenutzt', '2-4 Schritte als Ablauf, ohne Payload'], ['fix', 'So machst du es richtig', '2-4 Stichpunkte'], ['test', 'So testest du den Fix', '1-3 Stichpunkte']],
  expert: [['class', 'Einordnung', 'CWE und OWASP-Kategorie mit Namen, 1-2 Stichpunkte'], ['preconditions', 'Voraussetzungen', '1-4 Stichpunkte: was ein Angreifer braucht'], ['severity', 'Schwere-Einschätzung', '1-3 Stichpunkte in Worten (Angriffsweg, noetige Rechte, Nutzer-Interaktion, Folgen). Erfinde KEINEN CVSS-Vektor oder Score; nur wenn unter "Befund" ein CVSS steht, darfst du ihn nennen.'], ['pitfalls', 'Fallstricke bei naiven Fixes', '1-3 Stichpunkte'], ['defense', 'Defense in Depth', '1-3 Stichpunkte']],
};
const sectionSpec = (level) => SECTIONS[level].map(([k, , hint]) => `"${k}": [${hint}]`).join(',\n  ');
const EXPLAIN_PROMPT = `Du bist ein defensiver Sicherheitsberater und erklaerst EINEN Befund aus der Sicherheitspruefung des eigenen Projekts des Nutzers.
- Antworte AUSSCHLIESSLICH mit einem JSON-Objekt im verlangten Format. Kein Text davor oder danach.
- Wiederhole NICHT die Angaben zum Befund (Titel, Schwere, Ort …) – der Nutzer sieht sie bereits.
- Jeder Stichpunkt ist ein kurzer, vollstaendiger Satz. In Texten sind **fett** und \`Code\` erlaubt, sonst kein Markdown.
- Bleib bei dem, was aus den Angaben folgt; erfinde keine Details ueber das Projekt.
- Keine einsatzfertigen Angriffs-Payloads oder Schritt-fuer-Schritt-Anleitungen. Schwerpunkt: verstehen und beheben.`;

function explainKey(finding, level, config) {
  return 'explain:' + sha(['v2', level, en(config) ? 'en' : 'de', config.provider, config.model, finding.id || '', finding.title || '', finding.location || '', String(finding.description || '').slice(0, 500), config.aiFocus || ''].join('\u0000'));
}

// Vom Modell wiederholte Befund-Angaben am Anfang entfernen ("Befund", "Titel: …", "Erklärung für …")
const ECHO = /^\s*(?:#+\s*)?(?:\*\*)?(?:Befund|Finding|Aufgabe|Task|Titel|Title|Schwere|Severity|Ort|Location|Kategorie|Category|CWE|Beschreibung|Description|Auswirkung|Impact|Erreichbarkeit|Reachability|Behebung|Remediation|Erkl(?:ä|ae)r(?:e|ung)[^\n]{0,80}(?:Laie|Entwickler|Experte|Security)[^\n]*|Explanation for[^\n]*)(?:\*\*)?\s*(?::[^\n]*)?$/i;
function stripEcho(text) {
  const lines = String(text || '').replace(/\r/g, '').split('\n');
  let i = 0;
  while (i < lines.length && (ECHO.test(lines[i]) || !lines[i].trim())) i++;
  return lines.slice(i).join('\n').trim();
}

// JSON-Antwort -> { summary, sections: [{ key, title, points[] }], code: { lang, text } | null }
function normalizeExplanation(j, level) {
  if (!j || typeof j !== 'object') return null;
  const src = j.sections && typeof j.sections === 'object' && !Array.isArray(j.sections) ? j.sections : j;
  const pts = (v) => (Array.isArray(v) ? v : typeof v === 'string' ? v.split(/\n+/) : [])
    .map((x) => String(typeof x === 'object' && x ? (x.text || x.point || Object.values(x).join(' ')) : x).replace(/^\s*(?:[-*•]|\d+[.)])\s+/, '').trim())
    .filter(Boolean).slice(0, 6).map((x) => x.slice(0, 600));
  const sections = SECTIONS[level].map(([key, title]) => ({ key, title, points: pts(src[key]) })).filter((s) => s.points.length);
  if (!sections.length) return null;
  const c = j.code || src.code;
  const ctext = c ? (typeof c === 'string' ? c : String(c.text || c.code || '')).replace(/^```[\w+.-]*\n?|\n?```$/g, '').trim() : '';
  const code = ctext ? { lang: String((c && c.lang) || '').slice(0, 20), text: ctext.slice(0, 2500) } : null;
  return { summary: String(j.summary || '').trim().slice(0, 400), sections, code };
}
// Strukturierte Erklaerung als Text (Fallback-Anzeige, Export, alte Aufrufer)
function explanationText(s) {
  return [s.summary, ...s.sections.map((x) => `**${x.title}**\n${x.points.map((p) => `- ${p}`).join('\n')}`), s.code ? '```' + (s.code.lang || '') + '\n' + s.code.text + '\n```' : ''].filter(Boolean).join('\n\n');
}

async function explainFinding({ finding = {}, level = 'dev', code = null, config, cache = null, refresh = false }) {
  if (!LEVELS[level]) level = 'dev';
  const key = explainKey(finding, level, config);
  if (cache && !refresh) {
    const hit = cache.get(key);
    if (hit && typeof hit.text === 'string') return { ok: true, level, text: hit.text, structured: hit.structured || null, model: hit.model, cached: true };
  }
  const wantsCode = level === 'dev';
  const format = `{\n  "summary": "ein Satz: das Wichtigste in Kuerze",\n  "sections": {\n  ${sectionSpec(level)}\n  }${wantsCode ? ',\n  "code": {"lang": "z. B. js, nginx, apache, http", "text": "kurzes Beispiel fuer die richtige Loesung (Code oder Konfiguration), hoechstens 15 Zeilen"}' : ''}\n}`;
  const user = `## Befund\n${factsOf(finding)}${finding.cvss ? `\nCVSS: ${finding.cvss}` : ''}\n\n${code ? '## Code\n```\n' + numbered(code) + '\n```\n\n' : ''}## Aufgabe\nErklaere den Befund ${LEVELS[level]}\nAntwortformat (JSON, Werte in [] sind Listen von Stichpunkten):\n${format}\n${langLine(config)}`;
  const r = await aiCall(config, { system: EXPLAIN_PROMPT, user, json: true, kind: 'explain', maxTokens: 1200 });
  const raw = String(r.text || '').trim();
  const structured = normalizeExplanation(parseJsonObject(raw), level);
  let text;
  if (structured) text = explanationText(structured);
  else {
    // Kein brauchbares JSON: Freitext ohne wiederholte Befund-Angaben
    const j = /^\s*\{/.test(raw) ? parseJsonObject(raw) : null;
    text = stripEcho(j ? String(j.answer || j.explanation || j.text || Object.values(j).find((v) => typeof v === 'string') || raw) : raw);
  }
  if (cache && text) { cache.set(key, { text, structured, model: config.model }); if (typeof cache.flush === 'function') cache.flush(); }
  return { ok: true, level, text, structured, model: config.model, cached: false, cost: r.cost, usage: r.usage };
}

// --- 3. Zusammenfassung des Laufs --------------------------------------------
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_DE = { critical: 'kritisch', high: 'hoch', medium: 'mittel', low: 'niedrig', info: 'Hinweis' };
const openOf = (result) => (result.findings || []).filter((f) => !f.suppressed && !['FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED'].includes(f.status));
function titleIn(f, config) {
  const t = String(f.title || '').replace(/^(gitleaks|trufflehog|trivy|grype|semgrep|bandit|checkov|retire\.js|hadolint|osv-scanner|nuclei|binary)\s*:\s*/i, '');
  if (!en(config)) return t;
  try { return require('./findings-i18n').translate(t); } catch { return t; }
}

// Regelbasierter Absatz – immer verfuegbar, ohne KI.
function ruleSummary(result, config = {}) {
  const open = openOf(result);
  const c = Object.fromEntries(SEVS.map((s) => [s, open.filter((f) => f.severity === s).length]));
  const meta = result.meta || {};
  const files = meta.units || 0;
  const unverified = open.filter((f) => f.assurance === 'unverified').length;
  const toxic = open.filter((f) => /^toxic-/.test(f.ruleId || '')).length;
  const kev = open.filter((f) => f.inCisaKev).length;
  const top = open.find((f) => f.severity === 'critical') || open.find((f) => f.severity === 'high') || open[0];
  const step = top && ((Array.isArray(top.steps) && top.steps[0]) || top.remediation);
  const E = en(config);
  const parts = [];
  const sevList = SEVS.filter((s) => c[s] && s !== 'info').map((s) => `${c[s]} ${E ? s : SEV_DE[s]}`).join(', ');
  if (!open.length) {
    parts.push(E ? `Vigil checked ${files ? files + ' file(s)' : 'the targets'} and found no open findings in this run.` : `Vigil hat ${files ? files + ' Datei(en)' : 'die Ziele'} geprüft und in diesem Lauf keine offenen Befunde gefunden.`);
    parts.push(E ? 'That is a good sign, but not a guarantee – keep checking regularly, especially after changes.' : 'Das ist ein gutes Zeichen, aber keine Garantie – prüfe regelmäßig weiter, besonders nach Änderungen.');
  } else {
    parts.push(E
      ? `Vigil checked ${files ? files + ' file(s)' : 'the targets'} and found ${open.length} open finding(s)${sevList ? ` (${sevList})` : ''}.`
      : `Vigil hat ${files ? files + ' Datei(en)' : 'die Ziele'} geprüft und ${open.length} offene(n) Befund(e) gefunden${sevList ? ` (${sevList})` : ''}.`);
    if (toxic) parts.push(E ? `${toxic} attack path(s) combine several weaknesses into a complete route for an attacker – fixing one link breaks it.` : `${toxic} Angriffsweg(e) verbinden mehrere Schwächen zu einem kompletten Weg für Angreifer – schon eine Behebung unterbricht ihn.`);
    if (kev) parts.push(E ? `${kev} affected package(s) contain vulnerabilities that are actively exploited in the wild.` : `${kev} betroffene(s) Paket(e) enthalten Lücken, die bereits aktiv ausgenutzt werden.`);
    if (top) parts.push(E ? `Most urgent: “${titleIn(top, config)}”${step ? ` – ${titleIn({ title: step }, config).replace(/\.$/, '')}` : ''}.` : `Am dringendsten: „${titleIn(top, config)}“${step ? ` – ${String(step).replace(/\.$/, '')}` : ''}.`);
    if (unverified) parts.push(E ? `${unverified} finding(s) were only reported by the AI and are unconfirmed – please check them yourself.` : `${unverified} Befund(e) hat nur die KI gemeldet, sie sind unbestätigt – bitte selbst prüfen.`);
  }
  return parts.join(' ');
}

const SUMMARY_PROMPT = `Du fasst das Ergebnis einer defensiven Sicherheitspruefung des eigenen Projekts in EINEM Absatz in Alltagssprache zusammen (hoechstens 110 Woerter), fuer Menschen ohne Security-Wissen.
- Inhalt: Gesamteindruck, die 1-3 wichtigsten Risiken in einfachen Worten, womit man anfangen sollte. Unbestaetigte KI-Funde als solche benennen.
- Kein Markdown, keine Aufzaehlung, keine Ueberschrift, keine Angriffsanleitungen, keine erfundenen Zahlen – nur die mitgelieferten Daten.`;

async function summarizeRun(result, config = {}) {
  const rule = ruleSummary(result, config);
  const meta = result.meta || {};
  const useAi = config.aiRunSummary !== false && config.provider && meta.batches > 0;
  if (!useAi) return { text: rule, source: 'rules' };
  const open = openOf(result);
  const data = {
    files: meta.units || 0, open: open.length,
    counts: Object.fromEntries(SEVS.map((s) => [s, open.filter((f) => f.severity === s).length])),
    attackPaths: open.filter((f) => /^toxic-/.test(f.ruleId || '')).length,
    activelyExploited: open.filter((f) => f.inCisaKev).length,
    unconfirmedAi: open.filter((f) => f.assurance === 'unverified').length,
    top: open.slice(0, 8).map((f) => ({ severity: f.severity, title: titleIn(f, config), category: f.category, confirmed: f.assurance !== 'unverified' })),
  };
  try {
    const r = await aiCall(config, { system: SUMMARY_PROMPT, user: `## Daten des Laufs (JSON)\n${JSON.stringify(data)}\n\n${langLine(config)}`, json: false, kind: 'summary', maxTokens: 400 });
    let text = r.text.replace(/\s+/g, ' ').trim();
    const j = /^\{/.test(text) ? parseJsonObject(text) : null;
    if (j) text = String(j.summary || j.text || Object.values(j).find((v) => typeof v === 'string') || '');
    if (text.length < 40) return { text: rule, source: 'rules' };
    return { text: text.slice(0, 1200), source: 'ai', model: config.model, cost: r.cost, usage: r.usage };
  } catch (e) { return { text: rule, source: 'rules', error: e.message }; }
}

// --- 4. STRIDE-Bedrohungsmodell ----------------------------------------------
const STRIDE = {
  S: { de: 'Identitätsvortäuschung (Spoofing)', en: 'Spoofing' },
  T: { de: 'Manipulation (Tampering)', en: 'Tampering' },
  R: { de: 'Abstreitbarkeit (Repudiation)', en: 'Repudiation' },
  I: { de: 'Informationspreisgabe (Information disclosure)', en: 'Information disclosure' },
  D: { de: 'Dienstverweigerung (Denial of service)', en: 'Denial of service' },
  E: { de: 'Rechteausweitung (Elevation of privilege)', en: 'Elevation of privilege' },
};
const CAT_STRIDE = { Auth: 'S', Injection: 'T', XSS: 'T', PathTraversal: 'T', Deserialization: 'T', SSRF: 'T', Logging: 'R', Secrets: 'I', Crypto: 'I', Transport: 'I', Config: 'I', DoS: 'D', AccessControl: 'E', Dependencies: 'T' };
const LEVEL = ['high', 'medium', 'low'];

const THREAT_PROMPT = `Du bist ein defensiver Security-Architekt und erstellst ein STRIDE-Bedrohungsmodell fuer das eigene Projekt des Nutzers.
Grundlage sind NUR die mitgelieferten Angaben (Dateiliste, Pakete, Ziele, gefundene Befunde). Leite die Architektur vorsichtig ab und kennzeichne Annahmen.
Je STRIDE-Kategorie (S, T, R, I, D, E) 1-3 konkrete, projektbezogene Bedrohungen mit betroffenem Asset, Wahrscheinlichkeit, Auswirkung und konkreten Gegenmassnahmen. Verweise auf passende Befunde ueber deren Nummer. Keine Angriffsanleitungen.
Antworte AUSSCHLIESSLICH mit JSON: {"summary": string, "assumptions": [string], "assets": [string], "entryPoints": [string], "threats": [{"stride": "S"|"T"|"R"|"I"|"D"|"E", "title": string, "asset": string, "description": string, "likelihood": "high"|"medium"|"low", "impact": "high"|"medium"|"low", "mitigations": [string], "findings": [number]}]}`;

const strList = (a, n = 12, len = 300) => (Array.isArray(a) ? a : []).map((x) => String(x || '').trim().slice(0, len)).filter(Boolean).slice(0, n);
function normalizeThreatModel(j, list, config, source) {
  const threats = (Array.isArray(j && j.threats) ? j.threats : []).map((t) => {
    const s = String(t.stride || '').trim().charAt(0).toUpperCase();
    if (!STRIDE[s]) return null;
    const idx = (Array.isArray(t.findings) ? t.findings : []).map(Number).filter((n) => Number.isInteger(n) && n >= 1 && n <= list.length);
    return {
      stride: s, category: STRIDE[s][en(config) ? 'en' : 'de'],
      title: String(t.title || '').slice(0, 200), asset: String(t.asset || '').slice(0, 200), description: String(t.description || '').slice(0, 1200),
      likelihood: LEVEL.includes(t.likelihood) ? t.likelihood : 'medium', impact: LEVEL.includes(t.impact) ? t.impact : 'medium',
      mitigations: strList(t.mitigations, 6, 400),
      findings: [...new Set(idx)].slice(0, 8).map((n) => ({ n, title: titleIn(list[n - 1], config), severity: list[n - 1].severity, id: list[n - 1].id || null })),
    };
  }).filter((t) => t && t.title).slice(0, 24);
  threats.sort((a, b) => 'STRIDE'.indexOf(a.stride) - 'STRIDE'.indexOf(b.stride));
  return { version: 1, at: new Date().toISOString(), source, summary: String((j && j.summary) || '').slice(0, 1500), assumptions: strList(j && j.assumptions, 8), assets: strList(j && j.assets), entryPoints: strList(j && j.entryPoints), threats, ...(source === 'ai' ? { model: config.model } : {}) };
}

// Ohne KI: Befunde ihrer STRIDE-Kategorie zuordnen (Kategorie -> Bedrohungsklasse)
function ruleThreatModel(result, config = {}) {
  const list = openOf(result).slice(0, 60);
  const E = en(config);
  const groups = {};
  list.forEach((f, i) => { const s = CAT_STRIDE[f.category]; if (s) (groups[s] = groups[s] || []).push(i + 1); });
  const rank = (ns) => (ns.some((n) => ['critical', 'high'].includes(list[n - 1].severity)) ? 'high' : ns.some((n) => list[n - 1].severity === 'medium') ? 'medium' : 'low');
  const j = {
    summary: E ? 'Derived from the findings of this run without AI – each finding is assigned to its STRIDE threat class. Configure an AI for a project-specific model.' : 'Ohne KI aus den Befunden dieses Laufs abgeleitet – jeder Befund ist seiner STRIDE-Bedrohungsklasse zugeordnet. Mit KI entsteht ein projektbezogenes Modell.',
    threats: Object.entries(groups).map(([s, ns]) => ({
      stride: s, title: `${STRIDE[s][E ? 'en' : 'de']}: ${ns.length} ${E ? 'finding(s)' : 'Befund(e)'}`, asset: '',
      description: ns.slice(0, 3).map((n) => titleIn(list[n - 1], config)).join('; '),
      likelihood: rank(ns), impact: rank(ns),
      mitigations: [...new Set(ns.map((n) => (Array.isArray(list[n - 1].steps) && list[n - 1].steps[0]) || list[n - 1].remediation).filter(Boolean))].slice(0, 3),
      findings: ns.slice(0, 8),
    })),
  };
  return normalizeThreatModel(j, list, config, 'rules');
}

async function threatModel({ result = {}, targets = [], config }) {
  const list = openOf(result).slice(0, 60);
  if (!config || !config.provider) return ruleThreatModel(result, config);
  const meta = result.meta || {};
  const files = (meta.files || []).slice(0, 250);
  const pkgs = (meta.sbom || []).slice(0, 60).map((p) => `${p.ecosystem}:${p.name}@${p.version}`);
  const user = [
    `## Ziele\n${(targets || []).map((t) => (typeof t === 'string' ? t : t.value)).filter(Boolean).slice(0, 10).join('\n') || '(unbekannt)'}`,
    `## Dateien (${files.length}${(meta.files || []).length > files.length ? ' von ' + meta.files.length : ''})\n${files.join('\n') || '(keine Dateiliste)'}`,
    `## Pakete\n${pkgs.join(', ') || '(keine)'}`,
    `## Befunde (Nummer. Schwere | Kategorie | Titel | Ort)\n${list.map((f, i) => `${i + 1}. ${f.severity} | ${f.category} | ${titleIn(f, config)} | ${f.location || '-'}`).join('\n') || '(keine offenen Befunde)'}`,
    langLine(config),
  ].join('\n\n');
  let r;
  try { r = await aiCall(config, { system: THREAT_PROMPT, user, json: true, kind: 'threat', maxTokens: 4000 }); }
  catch (e) { const fb = ruleThreatModel(result, config); fb.error = `KI nicht erreichbar (${String(e.message).slice(0, 160)}) – aus den Befunden abgeleitet.`; return fb; }
  const tm = normalizeThreatModel(parseJsonObject(r.text) || {}, list, config, 'ai');
  if (!tm.threats.length) { const fb = ruleThreatModel(result, config); fb.error = 'KI-Antwort enthielt kein verwertbares Bedrohungsmodell.'; return fb; }
  tm.cost = r.cost; tm.usage = r.usage;
  return tm;
}

module.exports = { generatePatch, explainFinding, normalizeExplanation, explanationText, stripEcho, SECTIONS, summarizeRun, ruleSummary, threatModel, ruleThreatModel, normalizeThreatModel, checkDiff, normalizeDiff, extractDiff, aiCall, LEVELS, STRIDE, explainKey };
