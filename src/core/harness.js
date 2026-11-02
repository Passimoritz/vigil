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

// Nur fuer externe Anbieter schwaerzen; lokale Modelle sehen den Originalcode.
function shouldRedact(config) {
  return config.redactSecrets !== false && !isLocalProvider(config.provider, config.baseUrl);
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
    if (redact) user = redactSecrets(user).text;
    try {
      const { text, usage: u } = await providers.callProvider({ ...config, temperature: 0 }, { system: VALIDATOR_PROMPT, user });
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

module.exports = { redactSecrets, shouldRedact, extractSlice, validateFindings, enrich, assuranceOf, parseVerdicts, VALIDATOR_PROMPT };
