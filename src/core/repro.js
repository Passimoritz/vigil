'use strict';

// Reproduzierbarkeit (opt-in, config.aiRepro): je KI-Aufruf eines Laufs werden Anbieter, Modell,
// Parameter, SHA-256 von Prompt und Antwort sowie der TATSAECHLICH gesendete (bereits
// geschwaerzte) Prompt gespeichert. Liegt nur lokal im Verlauf; ab einer Gesamtgroesse werden
// nur noch Hashes gespeichert.

const crypto = require('crypto');
const sha = (s) => crypto.createHash('sha256').update(String(s || ''), 'utf8').digest('hex');

function createRecorder({ storePrompts = true, maxChars = 1500000, promptVersion = '' } = {}) {
  const calls = [];
  let stored = 0;
  let truncated = false;
  const hook = (ev) => {
    const prompt = `${ev.system}\n\u0000${ev.prefix}\n\u0000${ev.user}`;
    const entry = {
      n: calls.length + 1,
      at: new Date().toISOString(),
      kind: ev.kind || 'analyze',
      provider: ev.provider,
      model: ev.model,
      params: { temperature: ev.temperature, maxTokens: ev.maxTokens, json: ev.json },
      systemSha256: sha(ev.system),
      promptSha256: sha(prompt),
      responseSha256: sha(ev.text),
      promptChars: prompt.length,
      responseChars: String(ev.text || '').length,
      usage: ev.usage ? { inputTokens: ev.usage.inputTokens || 0, outputTokens: ev.usage.outputTokens || 0 } : null,
      ...(ev.lookups ? { lookups: ev.lookups } : {}),
    };
    const size = prompt.length + String(ev.text || '').length;
    if (storePrompts && stored + size <= maxChars) {
      entry.prompt = { system: ev.system, prefix: ev.prefix, user: ev.user };
      entry.response = ev.text;
      stored += size;
    } else if (storePrompts) truncated = true;
    calls.push(entry);
  };
  const dump = () => ({ version: 1, promptVersion, recordedAt: new Date().toISOString(), calls: calls.length, truncated, entries: calls });
  return { hook, dump, calls };
}

// Pruefen, ob gespeicherte Prompts/Antworten zu ihren Hashes passen (Integritaet des Protokolls)
function verifyLog(log) {
  const bad = [];
  for (const e of (log && log.entries) || []) {
    if (!e.prompt) continue;
    const prompt = `${e.prompt.system}\n\u0000${e.prompt.prefix}\n\u0000${e.prompt.user}`;
    if (sha(prompt) !== e.promptSha256 || sha(e.response) !== e.responseSha256) bad.push(e.n);
  }
  return { ok: !bad.length, bad };
}

module.exports = { createRecorder, verifyLog, sha };
