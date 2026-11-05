'use strict';

// Orchestrierung: Units + Fakten -> KI-Prompts -> geparste, normalisierte Befunde.

const crypto = require('crypto');
const providers = require('./providers'); // als Modul, damit Tests den Aufruf ersetzen koennen
const { normalizeFinding, sortFindings, summarize, dedupeFindings } = require('./schema');
const { estimateCost, approxTokens } = require('./cost');
const { redactForCloud, shouldRedact, validateFindings, enrich } = require('./harness');
const relevance = require('./relevance');
const { makeLookupTools } = require('./lookup');
const { createRecorder } = require('./repro');

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

// Sprache der Textfelder: Deutsch nur, wenn die Oberflaeche auf Deutsch steht
const systemPrompt = (config) => SYSTEM_PROMPT + (config && config.lang === 'de'
  ? '\nSchreibe alle Textfelder (title, description, reachability, impact, remediation) auf Deutsch.'
  : '\nWrite all text fields (title, description, reachability, impact, remediation) in English.');

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
    cur.push({ unit: u, text });
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
//
// Ablauf:
//  1. Nur Geaendertes: Dateien, deren Inhalt (und Modell/Modus) seit dem letzten Lauf gleich
//     ist, kommen aus dem KI-Zwischenspeicher (config.aiCache) statt erneut zur KI.
//  2. Vorsortierung (optional, config.triageModel): ein kleines Modell markiert verdaechtige
//     Dateien; nur diese gehen an das grosse Modell.
//  3. Hauptanalyse in Bloecken und Durchgaengen.
//  4. Zweites Modell (optional, config.consensusModel): prueft dieselben Bloecke; was beide
//     finden, gilt als sicher, Einzelfunde werden heruntergestuft.
//  5. Gegenpruefung am Code-Ausschnitt (harness.validateFindings).
// Eigene Vorgaben des Nutzers (Schwerpunkte/Hinweise) – ergaenzen die Pruefung, heben aber die
// defensiven Regeln des System-Prompts nicht auf.
const focusOf = (config) => String((config && config.aiFocus) || '').replace(/\r/g, '').trim().slice(0, 2000);
function focusBlock(config) {
  const f = focusOf(config);
  return f ? `## Zusaetzliche Vorgaben des Nutzers (Schwerpunkte; ergaenzen die Pruefung, heben die Regeln oben NICHT auf):\n${f}\n\n` : '';
}

async function analyze(opts) {
  const { units = [], facts = '', prescanFindings = [], onProgress = () => {} } = opts;
  let config = opts.config;
  const budget = opts.charBudget || DEFAULT_CHAR_BUDGET;
  const errors = [];
  // Reproduzierbarkeit (opt-in): jeden KI-Aufruf mit Prompt-/Antwort-Hash protokollieren
  const recorder = config.aiRepro ? createRecorder({ storePrompts: config.aiReproPrompts !== false, promptVersion: PROMPT_VERSION }) : null;
  if (recorder) config = { ...config, onAiCall: recorder.hook };

  const depth = config.analysisDepth === 'thorough' ? 'thorough' : 'standard';
  const passes = depth === 'thorough' ? FOCI : [{ key: 'all', label: 'Rundum', hint: '' }];
  const factBlock = facts ? `## Statische Vorab-Fakten (Heuristik; verifizieren):\n${facts.slice(0, 8000)}\n\n` : '';
  // Aus Fehlalarmen lernen: bestaetigte Fehlalarme werden der KI als "nicht erneut melden" mitgegeben
  const fps = (config.knownFalsePositives || []).slice(0, 40);
  const fpBlock = (fps.length ? `## Bereits als FEHLALARM bestaetigt (nicht erneut melden, ausser der Code hat sich dort wesentlich geaendert):\n${fps.map((f) => `- ${f.title} @ ${f.location}`).join('\n')}\n\n` : '') + focusBlock(config);

  const costCfg = { provider: config.provider, model: config.model, baseUrl: config.baseUrl };
  const used = { in: 0, out: 0, cached: 0, written: 0 };
  const addUsage = (u) => { if (!u) return; used.in += u.inputTokens || 0; used.out += u.outputTokens || 0; used.cached += u.cachedTokens || 0; used.written += u.cacheWriteTokens || 0; };
  const costOf = (inTok, outTok, estimate, cached = 0, written = 0) => {
    const c = estimateCost({ ...costCfg, inputTokens: inTok, outputTokens: outTok, cachedTokens: cached, cacheWriteTokens: written });
    return { inputTokens: c.inputTokens, outputTokens: c.outputTokens, usd: c.usd, savedUsd: c.savedUsd || 0, cachedTokens: c.cachedTokens || 0, priced: c.priced, local: c.local, estimate: !!estimate };
  };
  const liveCost = () => costOf(used.in, used.out, false, used.cached, used.written);

  // 1. Nur Geaendertes neu pruefen
  const cache = config.incremental !== false && config.aiCache ? config.aiCache : null;
  const cachedFindings = [];
  let fresh = units;
  let fromCache = 0;
  if (cache) {
    fresh = [];
    for (const u of units) {
      const hit = cache.get(unitKey(u, config, depth));
      if (Array.isArray(hit)) { fromCache++; for (const f of hit) cachedFindings.push(normalizeFinding(f, 'ai')); }
      else fresh.push(u);
    }
  }

  const aborted = () => !!(config.signal && config.signal.aborted);
  const redact = shouldRedact(config);
  let redactedCount = 0;
  const progress = { total: 0, done: 0 };

  // 2. Vorsortierung durch ein kleines Modell
  let skippedByTriage = [];
  if (config.triageModel && fresh.length > 1 && !aborted()) {
    const r = await triage(fresh, { ...config, model: config.triageModel }, { redact: redact ? (t) => redactForCloud(t, config).text : null, addUsage, onProgress, signal: config.signal });
    if (r.ok) { skippedByTriage = fresh.filter((u) => !r.keep.has(u.label)); fresh = fresh.filter((u) => r.keep.has(u.label)); }
    else errors.push(`Vorsortierung übersprungen: ${r.error}`);
  }

  // Grosse Projekte: riskanteste Dateien zuerst; optional nur die wichtigsten N Dateien (Budget)
  let skippedByBudget = [];
  let ranked = false;
  if (config.rankFiles !== false && fresh.length > 1 && !aborted()) {
    let emb = null;
    if (config.embedModel) {
      onProgress({ phase: 'analyze', message: `Ordne ${fresh.length} Dateien nach Relevanz (lokale Embeddings: ${config.embedModel}) …` });
      emb = await relevance.embedScores(fresh, { baseUrl: config.embedBaseUrl || 'http://localhost:11434', model: config.embedModel, signal: config.signal });
      if (!emb) errors.push(`Relevanz: lokale Embeddings (${config.embedModel}) nicht verfügbar – nur Heuristik genutzt.`);
    }
    const order = relevance.rankUnits(fresh, { keywords: relevance.focusKeywords(focusOf(config)), embedScores: emb });
    ranked = true;
    const maxFiles = Math.max(0, Math.floor(Number(config.aiFileBudget) || 0));
    if (maxFiles && fresh.length > maxFiles) {
      const sel = relevance.selectByBudget(order, { maxFiles });
      fresh = sel.keep; skippedByBudget = sel.skipped;
      errors.push(`Budget: nur die ${fresh.length} relevantesten von ${fresh.length + skippedByBudget.length} Dateien gingen an die KI – ${skippedByBudget.length} weniger relevante übersprungen (z. B. ${skippedByBudget.slice(0, 3).map((u) => u.label).join(', ')}).`);
    } else fresh = order.map((r) => r.u);
  }

  // "KI darf nachschlagen": Werkzeuge ueber die eingelesenen Units (begrenzt je Block)
  const lookupOn = !!config.aiLookup && providers.supportsTools(config.provider);
  if (config.aiLookup && !lookupOn) errors.push(`Nachschlagen: ${config.provider} unterstützt keine Werkzeug-Aufrufe – normale Analyse ohne Nachschlagen.`);
  const lookupMax = Math.min(10, Math.max(1, Math.floor(Number(config.aiLookupMax) || 4)));
  const lookupTools = lookupOn ? makeLookupTools(units, { redact: (t) => (redact ? redactForCloud(t, config).text : t) }) : null;
  let lookupsUsed = 0;
  let lookupFallback = false;

  const batches = batchUnits(fresh, budget);
  const models = [config.model, ...(config.consensusModel && config.consensusModel !== config.model ? [config.consensusModel] : [])];
  progress.total = batches.length * passes.length * models.length;
  let estInChars = 0;
  for (const b of batches) estInChars += SYSTEM_PROMPT.length + factBlock.length + fpBlock.length + 400 + b.map((x) => x.text).join('\n').length;
  const estCost = costOf(approxTokens(estInChars) * passes.length * models.length, 700 * progress.total, true);
  const cacheNote = fromCache ? ` – ${fromCache} unveränderte ${fromCache === 1 ? 'Datei' : 'Dateien'} aus dem Zwischenspeicher` : '';
  onProgress({ phase: 'analyze', message: fresh.length
    ? `KI-Analyse (${depth === 'thorough' ? 'gründlich, ' + passes.length + ' Durchgänge' : 'standard'}${models.length > 1 ? ', zwei Modelle' : ''}) in ${batches.length} ${batches.length === 1 ? 'Block' : 'Blöcken'}${cacheNote}`
    : `Keine geänderten Dateien – ${fromCache} KI-Ergebnis(se) aus dem Zwischenspeicher`, total: progress.total, done: 0, cost: estCost });

  // 3./4. Durchgaenge je Modell
  let aborts = false;
  const perModel = [];
  for (const model of models) {
    const cfgM = { ...config, model };
    const found = [];
    const batchOk = batches.map(() => true);
    for (let i = 0; i < batches.length && !aborts; i++) {
      for (const pass of passes) {
        if (aborted()) { aborts = true; break; }
        const focusLine = pass.hint ? `\nSCHWERPUNKT dieses Durchgangs: ${pass.hint} Melde auch andere klare Funde, aber grabe bei diesem Schwerpunkt besonders tief.\n` : '';
        // Gleichbleibender Anfang (wird beim Anbieter zwischengespeichert) + wechselnder Block
        let prefix =
          `Pruefe die folgenden Artefakte auf Sicherheitsluecken und gib Befunde als JSON zurueck. ` +
          `Suche aktiv auch nach Logik-, Autorisierungs- (IDOR/fehlende Rechtepruefung), Auth-Bypass- und Race-Condition-Fehlern, die reine Mustererkennung nicht findet - folge dabei den Datenfluessen von Eingaben zu gefaehrlichen Senken.` +
          focusLine + `\n\n` + factBlock + fpBlock;
        let user = `## Zu pruefende Artefakte (Block ${i + 1}/${batches.length}):\n` + batches[i].map((x) => x.text).join('\n');
        if (redact) {
          const a = redactForCloud(prefix, config); const b = redactForCloud(user, config);
          prefix = a.text; user = b.text;
          if (pass === passes[0] && model === models[0]) redactedCount += a.count + b.count;
        }
        const tag = models.length > 1 ? ` · ${model}` : '';
        try {
          let res;
          if (lookupTools && !lookupFallback) {
            try {
              res = await providers.callProviderTools(cfgM, { system: systemPrompt(config) + LOOKUP_HINT, prefix, user, tools: lookupTools.tools, runTool: lookupTools.run, maxCalls: lookupMax, kind: 'analyze' });
              lookupsUsed += res.lookups || 0;
            } catch (e) {
              if (aborted() || e.name === 'AbortError' || !(e.code === 'NO_TOOLS' || /HTTP 4\d\d.*(tool|function)/i.test(e.message))) throw e;
              lookupFallback = true;
              errors.push(`Nachschlagen: ${model} unterstützt keine Werkzeug-Aufrufe (${e.message.slice(0, 120)}) – normale Analyse ohne Nachschlagen.`);
            }
          }
          if (!res) res = await providers.callProvider(cfgM, { system: systemPrompt(config), prefix, user, kind: 'analyze' });
          const { text, usage } = res;
          addUsage(usage);
          const raw = parseFindings(text);
          for (const r of raw) { const f = normalizeFinding(r, 'ai'); f._batch = i; found.push(f); }
          progress.done++;
          onProgress({ phase: 'analyze', message: `Block ${i + 1}/${batches.length} · ${pass.label}${tag}: ${raw.length} Befund(e)`, total: progress.total, done: progress.done, cost: liveCost() });
        } catch (e) {
          progress.done++;
          batchOk[i] = false;
          if (aborted() || e.name === 'AbortError') { aborts = true; break; }
          errors.push(`Block ${i + 1} (${pass.label}${tag}): ${e.message}`);
          onProgress({ phase: 'analyze', message: `Block ${i + 1} (${pass.label}${tag}) fehlgeschlagen: ${e.message}`, total: progress.total, done: progress.done, error: true });
        }
      }
    }
    perModel.push({ model, found, batchOk });
    if (aborts) break;
  }
  if (aborts) errors.push('KI-Analyse abgebrochen - Teilergebnis angezeigt.');
  if (redactedCount) errors.push(`Datenschutz: ${redactedCount} Secret(s) vor dem Versand an den externen KI-Anbieter geschwaerzt.`);

  let aiFindings = perModel.length > 1 ? consensus(perModel[0].found, perModel[1].found, perModel.map((p) => p.model)) : (perModel[0] ? perModel[0].found : []);

  // Ergebnisse je Datei zwischenspeichern (nur vollstaendig gelaufene Bloecke)
  if (cache && !aborts) {
    const okAll = (i) => perModel.every((p) => p.batchOk[i]);
    batches.forEach((b, i) => {
      if (!okAll(i)) return;
      const byUnit = attribute(aiFindings.filter((f) => f._batch === i), b.map((x) => x.unit));
      for (const x of b) cache.set(unitKey(x.unit, config, depth), byUnit.get(x.unit.label) || []);
    });
    for (const u of skippedByTriage) cache.set(unitKey(u, config, depth), []);
  }
  for (const f of aiFindings) delete f._batch;
  aiFindings = [...cachedFindings, ...aiFindings];

  // 5. Gegenpruefung: reine KI-Befunde am Code-Ausschnitt; widerlegte fallen heraus.
  let merged = dedupeFindings([...prescanFindings, ...aiFindings]);
  let refuted = [];
  if (!aborts) {
    const v = await validateFindings({ findings: merged, units, config, onProgress });
    merged = v.findings; refuted = v.refuted;
    addUsage(v.usage);
    errors.push(...v.errors);
    if (refuted.length) errors.push(`Gegenprüfung: ${refuted.length} KI-Befund(e) widerlegt und verworfen – ${refuted.slice(0, 5).map((f) => f.title).join('; ')}${refuted.length > 5 ? ' …' : ''}`);
  }
  if (cache && typeof cache.flush === 'function') cache.flush();
  const all = sortFindings(enrich(merged, units));
  return {
    findings: all,
    summary: summarize(all),
    errors,
    meta: { batches: batches.length, passes: passes.length, depth, units: units.length, provider: config.provider, model: config.model, consensusModel: models[1] || null, triageModel: config.triageModel || null, at: new Date().toISOString(), usage: liveCost(), redacted: redactedCount, refuted: refuted.length, fromCache, skippedByTriage: skippedByTriage.length,
      skippedByBudget: skippedByBudget.length, ranked, lookups: lookupOn && !lookupFallback ? lookupsUsed : null, focus: focusOf(config) ? true : undefined, privacyMode: !!config.privacyMode && redact,
      files: units.map((u) => u.label).slice(0, 500), ...(recorder ? { repro: recorder.dump() } : {}) },
  };
}

// --- Hilfen fuer Zwischenspeicher, Vorsortierung, Konsens -------------------------
const PROMPT_VERSION = 'v3';
// Hinweis fuer den Nachschlage-Modus (nur wenn Werkzeuge mitgeschickt werden)
const LOOKUP_HINT = '\nDu darfst mit den Werkzeugen read_file und find_definition gezielt weitere Dateien bzw. Funktionsdefinitionen aus dem geprueften Projekt anfordern, wenn das fuer die Bewertung eines Datenflusses noetig ist (sparsam, nur wenn wirklich noetig). Die Antwort bleibt das JSON-Format oben.';
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function unitKey(u, cfg, depth) {
  return sha([PROMPT_VERSION, cfg.provider, cfg.model, cfg.consensusModel || '', depth, cfg.lang === 'de' ? 'de' : 'en', focusOf(cfg), cfg.aiLookup ? 'lookup' : '', u.label, u.content || ''].join('\u0000'));
}
const fileOf = (loc) => String(loc || '').replace(/\\/g, '/').replace(/(:\d+)+$/, '').trim().toLowerCase();
// Befunde den Dateien eines Blocks zuordnen (ueber den Dateiteil des Orts)
function attribute(findings, units) {
  const map = new Map();
  for (const f of findings) {
    const file = fileOf(f.location);
    const u = units.find((x) => { const l = String(x.label).replace(/\\/g, '/').toLowerCase(); return file === l || file.endsWith('/' + l) || l.endsWith('/' + file) || (file && l.endsWith(file)); });
    if (!u) continue;
    if (!map.has(u.label)) map.set(u.label, []);
    const copy = { ...f }; delete copy._batch;
    map.get(u.label).push(copy);
  }
  return map;
}

const TRIAGE_PROMPT = `Du sortierst Quelltext-Dateien fuer eine Sicherheitspruefung vor. Markiere jede Datei, die moeglicherweise sicherheitsrelevanten Code enthaelt: Eingaben von aussen, Datenbank, Dateien, Shell, Netzwerk, Anmeldung, Rechte, Krypto, Geheimnisse, Templates/HTML, Deserialisierung, Konfiguration. Im Zweifel markieren. Unauffaellig sind z. B. reine Typdefinitionen, Styles, Konstanten, Tests ohne Logik.
Antworte NUR mit JSON: {"suspicious":["<UNIT-Name>", ...]}`;
async function triage(units, cfg, { redact, addUsage, onProgress, signal }) {
  const batches = batchUnits(units, 60000);
  const keep = new Set();
  for (let i = 0; i < batches.length; i++) {
    if (signal && signal.aborted) return { ok: false, error: 'abgebrochen' };
    onProgress({ phase: 'analyze', message: `Vorsortierung mit ${cfg.model}: Block ${i + 1}/${batches.length} …` });
    let user = batches[i].map((x) => x.text).join('\n');
    if (redact) user = redact(user);
    try {
      const { text, usage } = await providers.callProvider(cfg, { system: TRIAGE_PROMPT, user, kind: 'triage' });
      addUsage(usage);
      const j = parseJsonObject(text);
      if (!j || !Array.isArray(j.suspicious)) { batches[i].forEach((x) => keep.add(x.unit.label)); continue; }
      const names = j.suspicious.map((s) => String(s).toLowerCase()).filter(Boolean);
      for (const x of batches[i]) { const l = x.unit.label.toLowerCase(); if (names.some((n) => l.includes(n) || n.includes(l))) keep.add(x.unit.label); }
    } catch (e) { return { ok: false, error: e.message }; }
  }
  return { ok: true, keep };
}
function parseJsonObject(text) {
  const t = String(text || '').replace(/^```(?:json)?\s*|\s*```$/g, '').trim();
  try { return JSON.parse(t); } catch { /* weiter */ }
  const a = t.indexOf('{'), b = t.lastIndexOf('}');
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch { /* egal */ } }
  return null;
}

const CONF_DOWN = { high: 'medium', medium: 'low', low: 'low' };
const lineNo = (loc) => { const m = String(loc || '').match(/:(\d+)(?::\d+)?$/); return m ? Number(m[1]) : null; };
function sameIssue(a, b) {
  if (fileOf(a.location) !== fileOf(b.location)) return false;
  const la = lineNo(a.location), lb = lineNo(b.location);
  if (la != null && lb != null) return Math.abs(la - lb) <= 5;
  return a.category === b.category;
}
// Zwei Modelle: Treffer beider -> sicher; Einzelfunde -> eine Stufe weniger Vertrauen
function consensus(a, b, models) {
  const usedB = new Set();
  const out = [];
  for (const f of a) {
    const j = b.findIndex((g, k) => !usedB.has(k) && sameIssue(f, g));
    if (j >= 0) { usedB.add(j); out.push({ ...f, confidence: 'high', consensus: 'both' }); }
    else out.push({ ...f, confidence: CONF_DOWN[f.confidence] || 'low', consensus: `only:${models[0]}` });
  }
  b.forEach((g, k) => { if (!usedB.has(k)) out.push({ ...g, confidence: CONF_DOWN[g.confidence] || 'low', consensus: `only:${models[1]}` }); });
  return out;
}

// Vorab-Schaetzung ohne KI-Aufruf: gleiche Blockbildung wie analyze(), daraus Tokens, Kosten, Dauer.
function estimateRun({ units = [], facts = '', config = {}, charBudget }) {
  const depth = config.analysisDepth === 'thorough' ? 'thorough' : 'standard';
  const passes = depth === 'thorough' ? FOCI.length : 1;
  const maxFiles = Math.max(0, Math.floor(Number(config.aiFileBudget) || 0));
  if (maxFiles && units.length > maxFiles) units = relevance.selectByBudget(relevance.rankUnits(units), { maxFiles }).keep;
  const batches = batchUnits(units, charBudget || DEFAULT_CHAR_BUDGET);
  const factLen = facts ? Math.min(8000, facts.length) + 60 : 0;
  let chars = 0;
  for (const b of batches) chars += SYSTEM_PROMPT.length + factLen + 400 + b.map((x) => x.text).join('\n').length;
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

module.exports = { analyze, parseFindings, estimateRun, consensus, attribute, unitKey, focusBlock, SYSTEM_PROMPT, PROMPT_VERSION };
