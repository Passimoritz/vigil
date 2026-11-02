'use strict';

// Orchestrierung: Units + Fakten -> KI-Prompts -> geparste, normalisierte Befunde.

const { callProvider } = require('./providers');
const { normalizeFinding, sortFindings, summarize, dedupeFindings } = require('./schema');
const { estimateCost, approxTokens } = require('./cost');
const { redactSecrets, shouldRedact, validateFindings, enrich } = require('./harness');

const SYSTEM_PROMPT = `Du bist ein erfahrener, defensiver Security-Code-Auditor. Der Nutzer prueft ausschliesslich eigene oder ausdruecklich freigegebene Artefakte. Dein Ziel: Schwachstellen FINDEN, einordnen und BEHEBEN helfen.

Arbeitsweise:
- Denke in DATENFLUESSEN: Woher kommen unvertraute Eingaben/Daten (Quellen: HTTP-Request, Parameter, Header, Datei, Umgebung, Netzwerk, DB, Nutzereingabe) und wo landen sie (Senken: DB-Query, Shell/Prozess, Dateipfad, HTML/DOM, Template, Deserialisierung, Redirect, Antwort). Eine Luecke entsteht, wenn unvertraute Daten eine Senke ohne passende Pruefung/Kodierung/Parametrisierung erreichen. Folge diesen Pfaden durch den Code.
- Achte besonders auf das, was einfache Mustererkennung NICHT sieht:
  * Fehlerhafte Autorisierung: fehlende Rechtepruefung, IDOR (Zugriff auf fremde Objekte ueber manipulierbare IDs), fehlende Mandanten-/Ownership-Pruefung.
  * Authentifizierungs-Bypaesse, kaputte Session-/Token-/Passwort-Reset-Logik, vertrauensselige Checks.
  * Race Conditions / TOCTOU (Pruefen-und-dann-Handeln ohne Sperre), nebenlaeufige Zustandsfehler.
  * Business-Logik: manipulierbare Preise/Mengen/Status, Negativ-/Ueberlaufwerte, fehlende Limits, Reihenfolge-/Workflow-Umgehung, Rabatt-/Gutschein-Missbrauch.
  * Fail-open-Fehlerpfade (bei Fehler wird Zugriff gewaehrt), unsichere Defaults, fehlende Eingabevalidierung, Mass Assignment.
- Pruefe zusaetzlich die ueblichen Klassen: Injection (SQL/NoSQL/Command/LDAP/Template), XSS, SSRF, Path Traversal, unsichere Deserialisierung, Krypto-Fehler (schwache Verfahren, feste Schluessel/IV, schlechte Zufallsquelle), Secrets im Code, unsichere Konfiguration, Information Disclosure (Fehler/Stacktraces/Debug), unsicheres Logging.
- Bewerte Schweregrad und (falls moeglich) CVSS (0-10). Erklaere Erreichbarkeit KONZEPTIONELL (welcher Eingang, welche Voraussetzungen, wie realistisch), damit priorisiert werden kann - gib KEINE einsatzfertigen Angriffs-Payloads und keine Schritt-fuer-Schritt-Anleitungen gegen fremde Systeme.
- Schwerpunkt auf konkrete Behebung (remediation) und, wo moeglich, einen konkreten Patch.
- Formuliere jeden Befund als pruefbare Hypothese: nenne in der description konkret die Quelle (woher kommen die Daten) und die Senke (wo werden sie gefaehrlich), damit ein zweiter Pruefer ihn am Code-Ausschnitt bestaetigen oder widerlegen kann.
- Qualitaet vor Menge: Melde echte, plausible Befunde mit konkretem Bezug (Datei:Zeile, betroffene Funktion/Variable). Bei Unsicherheit niedrigere confidence und benenne, was noch zu pruefen ist. Keine erfundenen Zeilennummern, keine generischen "koennte unsicher sein"-Floskeln. Die mitgelieferten statischen Fakten sind nur HINWEISE - verlass dich nicht darauf und wiederhole nicht bloss Offensichtliches, sondern ergaenze echten Kontext/Erreichbarkeit oder finde, was dort fehlt.

Antworte AUSSCHLIESSLICH mit gueltigem JSON in genau dieser Form:
{"findings":[{
  "title": string,
  "severity": "critical"|"high"|"medium"|"low"|"info",
  "cvss": number|null,
  "category": "Injection"|"XSS"|"Deserialization"|"Secrets"|"Crypto"|"Auth"|"AccessControl"|"SSRF"|"PathTraversal"|"Config"|"Dependencies"|"DoS"|"Logging"|"Transport"|"Other",
  "location": string,
  "description": string,
  "reachability": string,
  "impact": string,
  "remediation": string,
  "patch": string,
  "confidence": "high"|"medium"|"low"
}]}
Wenn du nichts findest: {"findings":[]}. Kein Text ausserhalb des JSON.`;

const DEFAULT_CHAR_BUDGET = 45000;
const MAX_UNIT_CHARS = 24000;

function clipUnit(u) {
  let c = u.content || '';
  if (c.length > MAX_UNIT_CHARS) c = c.slice(0, MAX_UNIT_CHARS) + '\n/* ... [gekuerzt] ... */';
  const note = u.meta?.note ? ` (${u.meta.note})` : '';
  return `### UNIT: ${u.label} [${u.kind}/${u.language}]${note}\n\`\`\`${u.language === 'text' ? '' : u.language}\n${c}\n\`\`\`\n`;
}

function batchUnits(units, budget) {
  const batches = [];
  let cur = [];
  let size = 0;
  for (const u of units) {
    const text = clipUnit(u);
    if (cur.length && size + text.length > budget) {
      batches.push(cur);
      cur = [];
      size = 0;
    }
    cur.push(text);
    size += text.length;
  }
  if (cur.length) batches.push(cur);
  return batches;
}

// Robustes JSON-Parsing: Objekt mit findings, bare Array, oder in Fences/Text eingebettet.
function parseFindings(text) {
  if (!text) return [];
  let t = text.trim();
  t = t.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  const tryParse = (s) => { try { return JSON.parse(s); } catch { return undefined; } };
  let data = tryParse(t);

  if (data === undefined) {
    // Erstes { ... } oder [ ... ] herausschneiden.
    const objStart = t.indexOf('{');
    const arrStart = t.indexOf('[');
    let start = -1, open = '{', close = '}';
    if (arrStart !== -1 && (objStart === -1 || arrStart < objStart)) { start = arrStart; open = '['; close = ']'; }
    else if (objStart !== -1) { start = objStart; }
    if (start !== -1) {
      let depth = 0;
      for (let i = start; i < t.length; i++) {
        if (t[i] === open) depth++;
        else if (t[i] === close) { depth--; if (depth === 0) { data = tryParse(t.slice(start, i + 1)); break; } }
      }
    }
  }

  if (!data) return [];
  const arr = Array.isArray(data) ? data : (Array.isArray(data.findings) ? data.findings : []);
  return arr;
}

// Fokus-Durchgaenge fuer den gruendlichen Modus (je ein KI-Durchgang pro Schwerpunkt).
const FOCI = [
  { key: 'access', label: 'Zugriff & Identitaet', hint: 'Authentifizierung, Autorisierung, IDOR/Objektzugriff ueber fremde IDs, fehlende Rechte-/Ownership-Pruefung, Session-/Token-/Passwort-Reset-Logik.' },
  { key: 'injection', label: 'Eingaben & Injection', hint: 'SQL/NoSQL/Command/LDAP/Template-Injection, XSS, SSRF, Path Traversal, unsichere Deserialisierung, fehlende Eingabevalidierung/Sanitisierung.' },
  { key: 'crypto', label: 'Krypto & Secrets', hint: 'schwache/falsch genutzte Kryptografie, feste Schluessel/IV, schwache Zufallsquellen, hartkodierte Secrets, unsichere TLS-/Passwort-Speicherung.' },
  { key: 'logic', label: 'Logik & Nebenlaeufigkeit', hint: 'Business-Logik-Fehler (Preis/Menge/Status/Negativwerte), Race Conditions/TOCTOU, Fail-open-Fehlerpfade, fehlende Limits/Rate-Limiting, Workflow-Umgehung.' },
  { key: 'config', label: 'Konfiguration & Abhaengigkeiten', hint: 'unsichere Konfiguration/Defaults, fehlende Sicherheits-Header, Information Disclosure/Logging, veraltete/anfaellige Abhaengigkeiten, Infrastruktur (Docker/K8s/CI).' },
];

// Haupteinstieg.
// opts: { units, facts, prescanFindings, config, onProgress, charBudget }
async function analyze(opts) {
  const { units = [], facts = '', prescanFindings = [], config, onProgress = () => {} } = opts;
  const budget = opts.charBudget || DEFAULT_CHAR_BUDGET;
  const errors = [];
  const aiFindings = [];

  const depth = config.analysisDepth === 'thorough' ? 'thorough' : 'standard';
  const passes = depth === 'thorough' ? FOCI : [{ key: 'all', label: 'Rundum', hint: '' }];
  const batches = batchUnits(units, budget);
  const total = batches.length * passes.length;
  let done = 0;
  const factBlock = facts ? `## Statische Vorab-Fakten (Heuristik; verifizieren):\n${facts.slice(0, 8000)}\n\n` : '';

  // Kosten/Token mitfuehren (nur bei nicht-lokalen Anbietern in der UI sichtbar).
  // Erst eine grobe Vorab-Schaetzung, dann waehrend des Laufs die echten Werte.
  const costCfg = { provider: config.provider, model: config.model, baseUrl: config.baseUrl };
  let usedIn = 0, usedOut = 0;
  const costOf = (inTok, outTok, estimate) => {
    const c = estimateCost({ ...costCfg, inputTokens: inTok, outputTokens: outTok });
    return { inputTokens: c.inputTokens, outputTokens: c.outputTokens, usd: c.usd, priced: c.priced, local: c.local, estimate: !!estimate };
  };
  let estInChars = 0;
  for (let i = 0; i < batches.length; i++) estInChars += SYSTEM_PROMPT.length + factBlock.length + 400 + batches[i].join('\n').length;
  const estCost = costOf(approxTokens(estInChars) * passes.length, 700 * total, true);

  onProgress({ phase: 'analyze', message: `KI-Analyse (${depth === 'thorough' ? 'gruendlich, ' + passes.length + ' Durchgaenge' : 'standard'}) in ${batches.length} Block/Bloecken`, total, done, cost: estCost });

  const redact = shouldRedact(config);
  let redactedCount = 0;
  let aborted = false;
  for (let i = 0; i < batches.length && !aborted; i++) {
    for (const pass of passes) {
      if (config.signal && config.signal.aborted) { aborted = true; break; }
      const focusLine = pass.hint ? `\nSCHWERPUNKT dieses Durchgangs: ${pass.hint} Melde auch andere klare Funde, aber grabe bei diesem Schwerpunkt besonders tief.\n` : '';
      const user =
        `Pruefe die folgenden Artefakte auf Sicherheitsluecken und gib Befunde als JSON zurueck. ` +
        `Suche aktiv auch nach Logik-, Autorisierungs- (IDOR/fehlende Rechtepruefung), Auth-Bypass- und Race-Condition-Fehlern, die reine Mustererkennung nicht findet - folge dabei den Datenfluessen von Eingaben zu gefaehrlichen Senken.` +
        focusLine + `\n\n` +
        factBlock +
        `## Zu pruefende Artefakte (Block ${i + 1}/${batches.length}):\n` +
        batches[i].join('\n');
      // Externe Anbieter bekommen Secrets nur geschwaerzt zu sehen.
      let prompt = user;
      if (redact) { const r = redactSecrets(user); prompt = r.text; if (pass === passes[0]) redactedCount += r.count; }
      try {
        const { text, usage } = await callProvider(config, { system: SYSTEM_PROMPT, user: prompt });
        if (usage) { usedIn += usage.inputTokens || 0; usedOut += usage.outputTokens || 0; }
        const raw = parseFindings(text);
        for (const r of raw) aiFindings.push(normalizeFinding(r, 'ai'));
        done++;
        onProgress({ phase: 'analyze', message: `Block ${i + 1}/${batches.length} · ${pass.label}: ${raw.length} Befund(e)`, total, done, cost: costOf(usedIn, usedOut, false) });
      } catch (e) {
        done++;
        if ((config.signal && config.signal.aborted) || e.name === 'AbortError') { aborted = true; break; }
        errors.push(`Block ${i + 1} (${pass.label}): ${e.message}`);
        onProgress({ phase: 'analyze', message: `Block ${i + 1} (${pass.label}) fehlgeschlagen: ${e.message}`, total, done, error: true });
      }
    }
  }
  if (aborted) errors.push('KI-Analyse abgebrochen - Teilergebnis angezeigt.');

  if (redactedCount) errors.push(`Datenschutz: ${redactedCount} Secret(s) vor dem Versand an den externen KI-Anbieter geschwaerzt.`);

  // Zweite Stufe: reine KI-Befunde am Code-Ausschnitt gegenpruefen; widerlegte fallen heraus.
  let merged = dedupeFindings([...prescanFindings, ...aiFindings]);
  let refuted = [];
  if (!aborted) {
    const v = await validateFindings({ findings: merged, units, config, onProgress });
    merged = v.findings; refuted = v.refuted;
    usedIn += v.usage.inputTokens; usedOut += v.usage.outputTokens;
    errors.push(...v.errors);
    if (refuted.length) errors.push(`Gegenprüfung: ${refuted.length} KI-Befund(e) widerlegt und verworfen – ${refuted.slice(0, 5).map((f) => f.title).join('; ')}${refuted.length > 5 ? ' …' : ''}`);
  }
  const all = sortFindings(enrich(merged, units));
  return {
    findings: all,
    summary: summarize(all),
    errors,
    meta: { batches: batches.length, passes: passes.length, depth, units: units.length, provider: config.provider, model: config.model, at: new Date().toISOString(), usage: costOf(usedIn, usedOut, false), redacted: redactedCount, refuted: refuted.length },
  };
}

// Vorab-Schaetzung ohne KI-Aufruf: gleiche Blockbildung wie analyze(), daraus Tokens, Kosten, Dauer.
function estimateRun({ units = [], facts = '', config = {}, charBudget }) {
  const depth = config.analysisDepth === 'thorough' ? 'thorough' : 'standard';
  const passes = depth === 'thorough' ? FOCI.length : 1;
  const batches = batchUnits(units, charBudget || DEFAULT_CHAR_BUDGET);
  const factLen = facts ? Math.min(8000, facts.length) + 60 : 0;
  let chars = 0;
  for (const b of batches) chars += SYSTEM_PROMPT.length + factLen + 400 + b.join('\n').length;
  const calls = batches.length * passes;
  let inputTokens = approxTokens(chars) * passes;
  let outputTokens = 700 * calls;
  // Gegenpruefung: grob ein Zusatzaufruf je ~6 KI-Befunde, typischerweise 10–15 % mehr
  if (config.aiValidation !== false && calls) { inputTokens = Math.round(inputTokens * 1.12); outputTokens = Math.round(outputTokens * 1.15); }
  const c = estimateCost({ provider: config.provider, model: config.model, baseUrl: config.baseUrl, inputTokens, outputTokens });
  // Dauer: lokal ~35 s je Aufruf (Mittelklasse-GPU/CPU), Cloud ~10 s
  const perCall = c.local ? 35 : 10;
  return { units: units.length, batches: batches.length, passes, calls, inputTokens: c.inputTokens, outputTokens: c.outputTokens, usd: c.usd, priced: c.priced, local: c.local, seconds: calls * perCall, depth };
}

module.exports = { analyze, parseFindings, estimateRun, SYSTEM_PROMPT };
