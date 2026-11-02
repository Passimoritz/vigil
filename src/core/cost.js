'use strict';

// Grobe Kosten-/Token-Schaetzung fuer nicht-lokale KI-Anbieter.
// Preise in US-Dollar je 1 Mio. Tokens (Stand 2026-10, nur Orientierung -
// Tarife aendern sich). Lokale Modelle (Ollama, lokaler OpenAI-kompatibler
// Dienst) sind kostenlos; dort zeigen wir keine $-Schaetzung.

// Reihenfolge pro Anbieter: spezifischere Muster zuerst (sie gewinnen).
const PRICING = {
  anthropic: [
    { re: /opus-5-5/i, in: 4, out: 20 },
    { re: /opus-5/i, in: 5, out: 25 },
    { re: /opus-4/i, in: 5, out: 25 },
    { re: /sonnet-5/i, in: 2, out: 10 },
    { re: /sonnet-4/i, in: 3, out: 15 },
    { re: /haiku-5/i, in: 0.10, out: 0.50 },
    { re: /haiku-4/i, in: 1, out: 5 },
    { re: /(fable|mythos)/i, in: 10, out: 50 },
  ],
  openai: [
    { re: /gpt-4\.1-nano/i, in: 0.10, out: 0.40 },
    { re: /gpt-4\.1-mini/i, in: 0.40, out: 1.60 },
    { re: /gpt-4\.1/i, in: 2, out: 8 },
    { re: /4o-mini/i, in: 0.15, out: 0.60 },
    { re: /gpt-4o/i, in: 2.50, out: 10 },
    { re: /(o3-mini|o4-mini)/i, in: 1.10, out: 4.40 },
    { re: /gpt-3\.5/i, in: 0.50, out: 1.50 },
  ],
  gemini: [
    { re: /(2\.5-pro|1\.5-pro)/i, in: 1.25, out: 10 },
    { re: /(2\.0-flash-lite|1\.5-flash-8b)/i, in: 0.075, out: 0.30 },
    { re: /flash/i, in: 0.10, out: 0.40 },
  ],
};

// Sieht die Basis-URL nach einem lokalen Ziel aus? (localhost/127.0.0.1/::1/*.local)
function looksLocalUrl(baseUrl) {
  const s = String(baseUrl || '');
  if (!s) return false;
  let host;
  try { host = new URL(s).hostname; } catch { host = s; }
  host = String(host).replace(/^\[|\]$/g, '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1'
    || /\.localhost$/.test(host) || /\.local$/.test(host);
}

// Laeuft der Anbieter lokal (kostenlos)? Ollama immer; OpenAI-kompatibel nur
// mit lokaler Basis-URL (z. B. LM Studio) - ein Cloud-compat-Dienst nicht.
function isLocalProvider(provider, baseUrl) {
  if (provider === 'ollama') return true;
  if (provider === 'compat') return looksLocalUrl(baseUrl);
  return false;
}

// Tarif fuer provider+model finden (oder null, wenn unbekannt).
function priceFor(provider, model) {
  const list = PRICING[provider];
  if (!list) return null;
  const m = String(model || '');
  for (const p of list) if (p.re.test(m)) return { in: p.in, out: p.out };
  return null;
}

// grobe Token-Schaetzung aus Zeichen (ca. 4 Zeichen je Token).
function approxTokens(chars) {
  return Math.max(0, Math.ceil((Number(chars) || 0) / 4));
}

// Kosten fuer eine (geschaetzte oder tatsaechliche) Token-Menge berechnen.
// Rueckgabe: { local, priced, usd, inputTokens, outputTokens, rate }
// Zwischengespeicherte Eingangs-Tokens kosten nur einen Bruchteil (Anteil des normalen Preises).
const CACHE_READ_FACTOR = { anthropic: 0.1, openai: 0.25, gemini: 0.25 };
const CACHE_WRITE_FACTOR = { anthropic: 1.25 };

function estimateCost({ provider, model, baseUrl, inputTokens = 0, outputTokens = 0, cachedTokens = 0, cacheWriteTokens = 0 } = {}) {
  const inTok = Math.max(0, Math.round(inputTokens) || 0);
  const outTok = Math.max(0, Math.round(outputTokens) || 0);
  if (isLocalProvider(provider, baseUrl)) {
    return { local: true, priced: false, usd: 0, inputTokens: inTok, outputTokens: outTok, rate: null };
  }
  const rate = priceFor(provider, model);
  if (!rate) {
    return { local: false, priced: false, usd: 0, inputTokens: inTok, outputTokens: outTok, rate: null };
  }
  const cached = Math.min(inTok, Math.max(0, cachedTokens || 0));
  const written = Math.min(inTok - cached, Math.max(0, cacheWriteTokens || 0));
  const plain = inTok - cached - written;
  const usd = ((plain + cached * (CACHE_READ_FACTOR[provider] ?? 1) + written * (CACHE_WRITE_FACTOR[provider] ?? 1)) / 1e6) * rate.in + (outTok / 1e6) * rate.out;
  const fullUsd = (inTok / 1e6) * rate.in + (outTok / 1e6) * rate.out;
  return { local: false, priced: true, usd, savedUsd: Math.max(0, fullUsd - usd), cachedTokens: cached, inputTokens: inTok, outputTokens: outTok, rate };
}

module.exports = { PRICING, isLocalProvider, looksLocalUrl, priceFor, approxTokens, estimateCost };
