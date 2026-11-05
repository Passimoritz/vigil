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
  mistral: [
    { re: /codestral/i, in: 0.30, out: 0.90 },
    { re: /(mistral-large|pixtral-large)/i, in: 2, out: 6 },
    { re: /mistral-medium/i, in: 0.40, out: 2 },
    { re: /(mistral-small|ministral|devstral)/i, in: 0.10, out: 0.30 },
  ],
  deepseek: [
    { re: /reasoner/i, in: 0.55, out: 2.19 },
    { re: /deepseek/i, in: 0.27, out: 1.10 },
  ],
  groq: [
    { re: /(70b|versatile)/i, in: 0.59, out: 0.79 },
    { re: /(8b|instant)/i, in: 0.05, out: 0.08 },
    { re: /gpt-oss-120b/i, in: 0.15, out: 0.75 },
    { re: /gpt-oss/i, in: 0.10, out: 0.50 },
    { re: /qwen/i, in: 0.29, out: 0.59 },
  ],
  bedrock: [
    { re: /nova-pro/i, in: 0.80, out: 3.20 },
    { re: /nova-lite/i, in: 0.06, out: 0.24 },
    { re: /nova-micro/i, in: 0.035, out: 0.14 },
    { re: /llama3-[13]-70b/i, in: 0.72, out: 0.72 },
    { re: /mistral-large/i, in: 2, out: 6 },
  ],
};

// Anbieter, die Modelle anderer Hersteller weiterreichen, rechnen mit deren Tarif:
// Azure = OpenAI, Vertex = Gemini, OpenRouter "hersteller/modell", Bedrock "…anthropic.claude-…".
const VENDOR = { openai: 'openai', anthropic: 'anthropic', google: 'gemini', mistralai: 'mistral', deepseek: 'deepseek' };
function delegated(provider, model) {
  const m = String(model || '');
  if (provider === 'azure') return ['openai', m];
  if (provider === 'vertex') return ['gemini', m];
  if (provider === 'openrouter') { const [v, ...rest] = m.split('/'); return VENDOR[v] ? [VENDOR[v], v === 'anthropic' ? rest.join('/').replace(/\./g, '-') : rest.join('/')] : null; }
  if (provider === 'bedrock' && /anthropic\./i.test(m)) return ['anthropic', m.replace(/\./g, '-')];
  return null;
}

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
  const d = delegated(provider, model);
  if (d) { const r = priceFor(d[0], d[1]); if (r) return r; }
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
const CACHE_READ_FACTOR = { anthropic: 0.1, openai: 0.25, gemini: 0.25, azure: 0.25, vertex: 0.25, deepseek: 0.1, bedrock: 0.1 };
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
