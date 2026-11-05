'use strict';

// Vulnerability-Harness: alles, was KI-Befunde belastbar macht.
//  - Schwaerzen: Secrets verlassen den Rechner nicht, wenn ein externer KI-Anbieter genutzt wird.
//  - Code-Slices: gezielte Ausschnitte um einen Befund statt ganzer Dateien.
//  - Validierung: ein eigener KI-Schritt versucht, jeden reinen KI-Befund zu WIDERLEGEN.
//  - Belege & Kontext: deterministisch bestaetigt / KI-verifiziert / unbestaetigt, Exposition.

const providers = require('./providers'); // als Modul, damit Tests den Aufruf ersetzen koennen
const { SECRET_RULES } = require('./prescan');
const { isLocalProvider } = require('./cost');
const { splitLoc } = require('./schema');

// --- Schwaerzen ----------------------------------------------------------
function redactSecrets(text) {
  let out = String(text || '');
  let count = 0;
  for (const rule of SECRET_RULES) {
    out = out.replace(new RegExp(rule.re.source, rule.re.flags), (m) => {
      count++;
      return `${m.slice(0, 4)}«geschwaerzt: ${rule.name}»`;
    });
  }
  return { text: out, count };
}

// --- Strenger Datenschutz-Modus ("privmode") --------------------------------
// Zusaetzlich zu Secrets: Firmennamen (eigene Liste), interne Hostnamen und private IPs,
// E-Mail-Adressen und Personennamen (einfache Heuristik: Autor-/Copyright-/Signatur-Zeilen).
// Gleiche Werte bekommen im selben Text denselben Platzhalter, damit der Code lesbar bleibt.
const INTERNAL_TLD = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:internal|intern|corp|local|lan|intranet|localdomain|home\.arpa|private|priv)\b/gi;
const PRIVATE_IP = /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;
const NAME = "[A-ZÄÖÜ][a-zäöüßéèáàóòíìñç'-]+(?:[ \\t]+(?:von|van|de|der|zu|di|da|le)\\b)?(?:[ \\t]+[A-ZÄÖÜ][a-zäöüßéèáàóòíìñç'-]+){1,2}";
const PERSON_LINES = [
  new RegExp(`(@author\\s+|\\bAuthor(?:s)?\\s*[:=]\\s*["']?|\\bAutor(?:in)?\\s*[:=]\\s*["']?|\\bMaintainer\\s*[:=]\\s*["']?|\\bCreated by\\s+|\\bErstellt von\\s+|\\bWritten by\\s+|\\bSigned-off-by:\\s*|\\bCo-authored-by:\\s*|\\bContact\\s*[:=]\\s*["']?|\\bKontakt\\s*[:=]\\s*["']?)(${NAME})`, 'g'),
  new RegExp(`(\\b(?:[Cc]opyright|COPYRIGHT)[ \\t]*(?:\\(c\\)|©)?\\s*(?:\\d{4}(?:\\s*[-–]\\s*\\d{4})?,?\\s*)?)(${NAME})`, 'g'),
  new RegExp(`("(?:author|maintainer|name)"\\s*:\\s*")(${NAME})(?=\\s*[<"(])`, 'g'),
];
const listOf = (v) => (Array.isArray(v) ? v : String(v || '').split(/[\n,;]+/)).map((x) => String(x).trim()).filter((x) => x.length >= 2).slice(0, 200);
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function redactPrivate(text, opts = {}) {
  let out = String(text || '');
  let count = 0;
  const maps = {};
  const ph = (kind, val) => {
    const m = maps[kind] || (maps[kind] = new Map());
    const k = val.toLowerCase();
    if (!m.has(k)) m.set(k, `«${kind}-${m.size + 1}»`);
    count++;
    return m.get(k);
  };
  // 1. Firmen- und Projektnamen aus der eigenen Liste (laengste zuerst)
  for (const term of listOf(opts.terms).sort((a, b) => b.length - a.length)) {
    out = out.replace(new RegExp(`(^|[^\\p{L}\\p{N}_])(${reEsc(term)})(?=$|[^\\p{L}\\p{N}_])`, 'giu'), (_m, pre, t) => pre + ph('firma', t));
  }
  // 2. E-Mail-Adressen (vor den Hostnamen, sonst wird nur die Domain ersetzt)
  out = out.replace(EMAIL, (m) => ph('email', m));
  // 3. Eigene interne Domains, interne Endungen und private IP-Adressen
  for (const d of listOf(opts.hosts).map((x) => x.replace(/^\*?\./, '').toLowerCase())) {
    out = out.replace(new RegExp(`\\b(?:[a-z0-9-]+\\.)*${reEsc(d)}\\b`, 'gi'), (m) => ph('host', m));
  }
  out = out.replace(INTERNAL_TLD, (m) => ph('host', m));
  out = out.replace(PRIVATE_IP, (m) => ph('ip', m));
  // 4. Personennamen in typischen Autor-/Copyright-/Signaturzeilen
  for (const re of PERSON_LINES) out = out.replace(re, (_m, pre, name) => pre + ph('person', name));
  return { text: out, count };
}

// Alles, was vor dem Versand an eine Cloud-KI geschwaerzt werden muss – EIN Einstieg fuer alle Aufrufer.
function redactForCloud(text, config = {}) {
  let out = String(text || '');
  let count = 0;
  if (config.redactSecrets !== false) { const r = redactSecrets(out); out = r.text; count += r.count; }
  if (config.privacyMode) { const r = redactPrivate(out, { terms: config.privacyTerms, hosts: config.privacyHosts }); out = r.text; count += r.count; }
  return { text: out, count };
}

// Nur fuer externe Anbieter schwaerzen; lokale Modelle sehen den Originalcode.
function shouldRedact(config) {
  return (config.redactSecrets !== false || !!config.privacyMode) && !isLocalProvider(config.provider, config.baseUrl);
}

// --- Code-Slices ---------------------------------------------------------
function findUnit(units, location) {
  const { file } = splitLoc(location);
  if (!file) return null;
  const base = file.split('/').pop();
  return units.find((u) => {
    const l = splitLoc(u.label || u.path).file;
    return l && (l === file || l.endsWith('/' + file) || file.endsWith('/' + l) || l.split('/').pop() === base);
  }) || null;
}

// Ausschnitt mit Zeilennummern um die gemeldete Zeile (ohne Zeile: Dateianfang).
function extractSlice(units, location, radius = 25) {
  const unit = findUnit(units, location);
  if (!unit || !unit.content) return null;
  const lines = unit.content.split(/\r?\n/);
  const { line } = splitLoc(location);
  const center = line && line <= lines.length ? line : Math.min(radius, lines.length);
  const from = Math.max(1, center - radius);
  const to = Math.min(lines.length, center + radius);
  const body = lines.slice(from - 1, to).map((l, i) => `${String(from + i).padStart(5)}${from + i === line ? ' >' : '  '} ${l}`).join('\n');
  return { label: unit.label, from, to, text: body, unit };
}

// --- Validierung (KI versucht zu widerlegen) -----------------------------
const VALIDATOR_PROMPT = `Du bist ein skeptischer, defensiver Security-Reviewer. Ein anderer Auditor hat Befunde gemeldet. Deine Aufgabe ist es, jeden Befund anhand des mitgelieferten Code-Ausschnitts zu WIDERLEGEN.

Pruefe pro Befund:
- Existiert die beschriebene Stelle im Ausschnitt ueberhaupt (Datei/Zeile/Funktion)?
- Erreichen unvertraute Daten (Quelle) die gefaehrliche Senke wirklich, oder gibt es Validierung, Parametrisierung, Escaping, Typpruefung oder eine Rechtepruefung davor?
- Ist der Code ueberhaupt erreichbar (kein toter Code, kein Test, kein Beispiel)?
Urteile streng: "confirmed" nur, wenn der Ausschnitt den Fehler klar belegt; "refuted", wenn er klar widerlegt ist oder die Stelle nicht existiert; sonst "uncertain".
Gib KEINE Angriffs-Payloads aus.

Antworte AUSSCHLIESSLICH mit JSON: {"verdicts":[{"id": number, "verdict": "confirmed"|"refuted"|"uncertain", "reason": string}]}`;

function parseVerdicts(text) {
  const t = String(text || '').replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
  const s = t.indexOf('{'), e = t.lastIndexOf('}');
  if (s < 0 || e < s) return [];
  try {
    const d = JSON.parse(t.slice(s, e + 1));
    return Array.isArray(d.verdicts) ? d.verdicts : [];
  } catch { return []; }
}

const isAiOnly = (f) => (f.sources || [f.source]).every((s) => s === 'ai');
const VALIDATE_BATCH = 6;
const MAX_VALIDATE = 60;

// Liefert { findings, refuted, usage, errors }. Widerlegte Befunde fallen heraus.
async function validateFindings({ findings, units, config, onProgress = () => {} }) {
  const errors = [];
  const refuted = [];
  const usage = { inputTokens: 0, outputTokens: 0 };
  const candidates = findings.filter((f) => isAiOnly(f) && f.severity !== 'info').slice(0, MAX_VALIDATE);
  if (!candidates.length || config.aiValidation === false) return { findings, refuted, usage, errors };

  const redact = shouldRedact(config);
  const verdictOf = new Map();
  const batches = [];
  for (let i = 0; i < candidates.length; i += VALIDATE_BATCH) batches.push(candidates.slice(i, i + VALIDATE_BATCH));

  onProgress({ phase: 'validate', message: `Gegenprüfung: ${candidates.length} KI-Befund(e) werden auf Widerlegbarkeit geprüft …`, total: batches.length, done: 0 });
  for (let b = 0; b < batches.length; b++) {
    if (config.signal && config.signal.aborted) break;
    const items = batches[b].map((f, i) => {
      const slice = extractSlice(units, f.location);
      const code = slice ? `Ausschnitt ${slice.label} Zeilen ${slice.from}-${slice.to} (">" = gemeldete Zeile):\n\`\`\`\n${slice.text}\n\`\`\`` : 'Kein Code-Ausschnitt verfuegbar (Ort nicht auffindbar).';
      return `### Befund ${i}\nTitel: ${f.title}\nOrt: ${f.location || '-'}\nKategorie: ${f.category}\nBehauptung: ${f.description}\n${code}`;
    });
    let user = `Pruefe die folgenden ${items.length} Befunde. Nutze als id die Nummer hinter "Befund".\n\n${items.join('\n\n')}`;
    if (redact) user = redactForCloud(user, config).text;
    try {
      const { text, usage: u } = await providers.callProvider({ ...config, temperature: 0 }, { system: VALIDATOR_PROMPT, user, kind: 'validate' });
      if (u) { usage.inputTokens += u.inputTokens || 0; usage.outputTokens += u.outputTokens || 0; }
      for (const v of parseVerdicts(text)) {
        const f = batches[b][Number(v.id)];
        if (f && ['confirmed', 'refuted', 'uncertain'].includes(v.verdict)) verdictOf.set(f, { verdict: v.verdict, reason: String(v.reason || '').trim() });
      }
    } catch (e) {
      if ((config.signal && config.signal.aborted) || e.name === 'AbortError') break;
      errors.push(`Gegenprüfung Block ${b + 1}: ${e.message}`);
    }
    onProgress({ phase: 'validate', message: `Gegenprüfung ${b + 1}/${batches.length}`, total: batches.length, done: b + 1 });
  }

  const kept = [];
  for (const f of findings) {
    const v = verdictOf.get(f);
    if (!v) { kept.push(f); continue; }
    if (v.verdict === 'refuted') { refuted.push({ ...f, validation: v }); continue; }
    kept.push({
      ...f,
      validation: v,
      confidence: v.verdict === 'confirmed' ? (f.confidence === 'low' ? 'medium' : f.confidence) : 'low',
    });
  }
  return { findings: kept, refuted, usage, errors };
}

// --- KI-Gegencheck fuer Regel-Befunde ------------------------------------
// Regeln sind schnell, aber stur: Eine Weiterleitung, eine eigene Schutz-Registrierung oder ein Testordner
// sieht fuer sie aus wie ein Problem. Die KI liest jeden Regel-Befund (ab "mittel") samt Beleg und den
// Hinweisen des Laufs und sagt, ob er plausibel ist. Regel-Befunde werden NIE geloescht – ein Zweifel
// senkt nur die Schwere um eine Stufe und die Verlaesslichkeit auf "niedrig", mit Begruendung.
const REVIEW_PROMPT = `Du bist ein erfahrener, nuechterner Security-Reviewer. Ein regelbasierter Scanner hat Befunde gemeldet. Regeln liegen oft daneben, weil ihnen Zusammenhang fehlt (z. B. eine aehnliche Domain, die in Wahrheit dem Betreiber selbst gehoert und auf seine Seite weiterleitet; ein Test- oder Beispielordner; ein Wert, der nur so aussieht wie ein Geheimnis).

Pruefe jeden Befund anhand von Titel, Beschreibung, Beleg, Ort und den Hinweisen des Laufs:
- "plausible": der Beleg stuetzt den Befund, ein Mensch sollte ihn sich ansehen.
- "doubtful": der Beleg oder die Hinweise sprechen klar dagegen, oder der Befund ist fuer den beschriebenen Fall offensichtlich harmlos.
- "uncertain": aus den Angaben nicht zu entscheiden.
Erfinde keine Fakten, die nicht in den Angaben stehen. Begruende in einem kurzen Satz in einfacher Sprache. Gib KEINE Angriffs-Payloads aus.

Antworte AUSSCHLIESSLICH mit JSON: {"verdicts":[{"id": number, "verdict": "plausible"|"doubtful"|"uncertain", "reason": string}]}`;
const SEV_DOWN = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
const REVIEW_BATCH = 8;
const MAX_REVIEW = 40;

// Liefert { findings, usage, errors, reviewed, doubted }.
async function reviewRuleFindings({ findings, notes = [], config, onProgress = () => {} }) {
  const errors = [];
  const usage = { inputTokens: 0, outputTokens: 0 };
  const none = { findings, usage, errors, reviewed: 0, doubted: 0 };
  if (config.aiReview === false || config.aiValidation === false || !config.provider || !config.model) return none;
  const candidates = findings.filter((f) => !isAiOnly(f) && !f.validation && ['critical', 'high', 'medium'].includes(f.severity)).slice(0, MAX_REVIEW);
  if (!candidates.length) return none;
  const redact = shouldRedact(config);
  const lang = config.lang === 'de' ? 'Schreibe die Begruendung auf Deutsch.' : 'Write the reason in English.';
  const context = notes.filter(Boolean).slice(0, 40).map((n) => `- ${String(n).slice(0, 400)}`).join('\n');
  const verdictOf = new Map();
  const batches = [];
  for (let i = 0; i < candidates.length; i += REVIEW_BATCH) batches.push(candidates.slice(i, i + REVIEW_BATCH));
  onProgress({ phase: 'validate', message: `KI-Gegencheck: ${candidates.length} Regel-Befund(e) werden auf Fehlalarme geprüft …`, total: batches.length, done: 0 });
  for (let b = 0; b < batches.length; b++) {
    if (config.signal && config.signal.aborted) break;
    const items = batches[b].map((f, i) => `### Befund ${i}\nTitel: ${f.title}\nSchwere: ${f.severity}\nErkannt durch: ${f.source || '-'} (${f.ruleId || '-'})\nOrt: ${f.location || '-'}\nBeschreibung: ${f.description || '-'}\nBeleg: ${String(f.evidence || '-').slice(0, 600)}`);
    let user = `Hinweise des Laufs (Zusammenhang):\n${context || '- keine'}\n\nPruefe die folgenden ${items.length} Befunde. Nutze als id die Nummer hinter "Befund". ${lang}\n\n${items.join('\n\n')}`;
    if (redact) user = redactForCloud(user, config).text;
    try {
      const { text, usage: u } = await providers.callProvider({ ...config, temperature: 0 }, { system: REVIEW_PROMPT, user, kind: 'validate' });
      if (u) { usage.inputTokens += u.inputTokens || 0; usage.outputTokens += u.outputTokens || 0; }
      for (const v of parseVerdicts(text)) {
        const f = batches[b][Number(v.id)];
        if (f && ['plausible', 'doubtful', 'uncertain'].includes(v.verdict)) verdictOf.set(f, { verdict: v.verdict, reason: String(v.reason || '').trim().slice(0, 500) });
      }
    } catch (e) {
      if ((config.signal && config.signal.aborted) || e.name === 'AbortError') break;
      errors.push(`KI-Gegencheck: ${e.message}`);
      break; // KI nicht erreichbar -> nicht fuer jeden Block erneut versuchen
    }
    onProgress({ phase: 'validate', message: `KI-Gegencheck ${b + 1}/${batches.length}`, total: batches.length, done: b + 1 });
  }
  let doubted = 0;
  const out = findings.map((f) => {
    const v = verdictOf.get(f);
    if (!v) return f;
    const review = { verdict: v.verdict === 'plausible' ? 'confirmed' : v.verdict === 'doubtful' ? 'doubted' : 'uncertain', reason: v.reason, by: 'ai-review' };
    if (v.verdict !== 'doubtful') return { ...f, validation: review };
    doubted++;
    return { ...f, validation: review, severityOriginal: f.severity, severity: SEV_DOWN[f.severity] || f.severity, confidence: 'low' };
  });
  if (doubted) errors.push(`KI-Gegencheck: ${doubted} Regel-Befund(e) als wahrscheinlicher Fehlalarm herabgestuft (nicht gelöscht).`);
  return { findings: out, usage, errors, reviewed: verdictOf.size, doubted };
}

// --- Belege & Kontext ----------------------------------------------------
const EXPOSED_PATH = /(^|\/)(routes?|controllers?|api|handlers?|endpoints?|views?|server|resolvers?|webhooks?)(\/|\.|$)/i;
const EXPOSED_CODE = /\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(|@(?:app|bp|router)\.(?:route|get|post)|@(?:Get|Post|Put|Delete|Request)Mapping|\[Http(?:Get|Post|Put|Delete)\]|createServer\s*\(|ipcMain\.handle/;
const SENSITIVE = /\b(?:password|passwort|passwd|credit.?card|iban|payment|zahlung|ssn|token|session|secret|private.?key|invoice|rechnung|email)\b/i;

// Beleg-Status ("assurance"): wie gut ist ein Befund abgesichert? Getrennt vom Feld `evidence` (Ausschnitt).
function assuranceOf(f) {
  const srcs = f.sources || [f.source];
  if (srcs.some((s) => s !== 'ai')) return srcs.length > 1 ? 'confirmed-multi' : 'deterministic';
  if (f.validation && f.validation.verdict === 'confirmed') return 'ai-verified';
  return 'unverified';
}

function contextOf(f, units) {
  const tags = [];
  if (/^https?:\/\//i.test(f.location || '') || ['webscan', 'nmap', 'nuclei'].includes(f.source)) tags.push('internet-exposed');
  else {
    const unit = findUnit(units, f.location);
    const { file } = splitLoc(f.location);
    if (EXPOSED_PATH.test(file) || (unit && EXPOSED_CODE.test(unit.content || ''))) tags.push('request-handler');
    const slice = extractSlice(units, f.location, 12);
    if (SENSITIVE.test(`${f.title} ${f.description} ${slice ? slice.text : ''}`)) tags.push('sensitive-data');
  }
  if (f.category === 'Dependencies') tags.push('supply-chain');
  return tags;
}

function enrich(findings, units = []) {
  return findings.map((f) => ({ ...f, assurance: assuranceOf(f), context: contextOf(f, units) }));
}

module.exports = { redactSecrets, redactPrivate, redactForCloud, shouldRedact, extractSlice, validateFindings, reviewRuleFindings, enrich, assuranceOf, parseVerdicts, VALIDATOR_PROMPT, REVIEW_PROMPT };
