'use strict';

// Einheitliche Schnittstelle zu lokalen und externen KI-Anbietern.
// Jeder Aufruf: callProvider(config, { system, user }) -> { text }
// config = { provider, model, apiKey, baseUrl, temperature, maxTokens }

const PROVIDERS = {
  ollama: {
    label: 'Lokal (Ollama)',
    needsKey: false,
    defaultBaseUrl: 'http://localhost:11434',
    defaultModel: 'qwen2.5-coder',
  },
  anthropic: {
    label: 'Claude (Anthropic)',
    needsKey: true,
    defaultBaseUrl: 'https://api.anthropic.com',
    defaultModel: 'claude-sonnet-5-5',
  },
  openai: {
    label: 'OpenAI (ChatGPT)',
    needsKey: true,
    defaultBaseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4.1-mini',
  },
  gemini: {
    label: 'Gemini (Google)',
    needsKey: true,
    defaultBaseUrl: 'https://generativelanguage.googleapis.com/v1beta',
    defaultModel: 'gemini-2.0-flash',
  },
  compat: {
    label: 'OpenAI-kompatibel (Mistral/DeepSeek/Groq/LM Studio …)',
    needsKey: false, // manche lokalen brauchen keinen Key
    defaultBaseUrl: '',
    defaultModel: '',
  },
};

// Netzwerk-/Timeout-Fehler in eine verstaendliche Meldung uebersetzen
// (Ollama laeuft lokal und ist die haeufigste Fehlerquelle).
function friendlyNetError(provider, msg) {
  const m = String(msg == null ? '' : msg);
  if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ECONNRESET|socket hang up|fetch failed|Failed to fetch|network|getaddrinfo/i.test(m)) {
    if (provider === 'ollama') {
      return 'Ollama antwortet nicht. Läuft die Ollama-App? Starte sie bzw. „ollama serve". '
        + 'Noch nicht installiert? Kostenlos unter https://ollama.com (Standard-Adresse: http://localhost:11434).';
    }
    return 'Keine Verbindung zum Anbieter. Internetverbindung und Basis-URL prüfen.';
  }
  if (/AbortError|The operation was aborted|aborted|timed out|timeout/i.test(m)) {
    if (provider === 'ollama') {
      return 'Ollama hat zu lange gebraucht (Zeitüberschreitung). Beim ersten Mal lädt das Modell evtl. noch – '
        + 'kurz warten und erneut versuchen.';
    }
    return 'Zeitüberschreitung bei der Anfrage an den Anbieter.';
  }
  if (provider === 'ollama' && /\b404\b|not found|try pulling/i.test(m)) {
    return 'Dieses Modell ist in Ollama nicht installiert. Lade es mit „ollama pull <Modellname>" '
      + 'oder wähle in den Einstellungen ein vorhandenes Modell.';
  }
  return m;
}

// Transport-Schutz: lokale Adressen duerfen HTTP nutzen (Ollama/LM Studio),
// an externe Dienste gehen Prompts/Code/Schluessel NUR verschluesselt (HTTPS) raus.
function isLocalHost(h) {
  const host = String(h || '').replace(/^\[|\]$/g, '').toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1'
    || /\.localhost$/.test(host) || /\.local$/.test(host);
}
function assertSecureTransport(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return; }
  if (u.protocol === 'http:' && !isLocalHost(u.hostname)) {
    throw new Error(
      `Abgebrochen zum Schutz deiner Daten: unverschlüsselte Verbindung (HTTP) zu „${u.hostname}". `
      + 'Deine Anfragen (und ggf. der Schlüssel) würden im Klartext übertragen. '
      + 'Bitte eine https://-Adresse verwenden – nur lokale Ziele (localhost) dürfen HTTP nutzen.'
    );
  }
}

async function withTimeout(ms, fn, extSignal) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  const signal = extSignal ? AbortSignal.any([ctrl.signal, extSignal]) : ctrl.signal;
  try { return await fn(signal); }
  finally { clearTimeout(t); }
}

async function httpJson(url, options, timeoutMs = 120000, extSignal) {
  assertSecureTransport(url);
  const res = await withTimeout(timeoutMs, (signal) => fetch(url, { ...options, signal }), extSignal);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  if (!res.ok) {
    const msg = (json && (json.error?.message || json.error || json.message)) || text.slice(0, 400);
    throw new Error(`HTTP ${res.status}: ${msg}`);
  }
  return json;
}

// --- Ollama -------------------------------------------------------------
async function callOllama(cfg, { system, user }) {
  const base = (cfg.baseUrl || PROVIDERS.ollama.defaultBaseUrl).replace(/\/$/, '');
  let json;
  try {
    json = await httpJson(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.model || PROVIDERS.ollama.defaultModel,
        stream: false,
        format: 'json',
        options: { temperature: cfg.temperature ?? 0.1 },
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
      }),
    }, 120000, cfg.signal);
  } catch (e) {
    throw new Error(friendlyNetError('ollama', e.message));
  }
  return {
    text: json?.message?.content || '',
    usage: { inputTokens: json?.prompt_eval_count || 0, outputTokens: json?.eval_count || 0 },
  };
}

// --- Anthropic / Claude -------------------------------------------------
async function callAnthropic(cfg, { system, user }) {
  const base = (cfg.baseUrl || PROVIDERS.anthropic.defaultBaseUrl).replace(/\/$/, '');
  const json = await httpJson(`${base}/v1/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': cfg.apiKey || '',
      'anthropic-version': '2023-06-01',
    },
    // Hinweis: temperature wird bewusst NICHT gesendet - neuere Claude-Modelle
    // (5.x) lehnen den Parameter ab ("temperature is deprecated for this model").
    body: JSON.stringify({
      model: cfg.model || PROVIDERS.anthropic.defaultModel,
      max_tokens: cfg.maxTokens || 4096,
      system,
      messages: [{ role: 'user', content: user }],
    }),
  }, 120000, cfg.signal);
  const text = Array.isArray(json?.content)
    ? json.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n')
    : '';
  const u = json?.usage || {};
  return {
    text,
    usage: {
      inputTokens: (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0),
      outputTokens: u.output_tokens || 0,
    },
  };
}

// --- OpenAI (und kompatibel) -------------------------------------------
async function callOpenAICompatible(cfg, { system, user }, fallbackBase) {
  const base = (cfg.baseUrl || fallbackBase || '').replace(/\/$/, '');
  if (!base) throw new Error('Keine Basis-URL fuer den OpenAI-kompatiblen Anbieter gesetzt.');
  const headers = { 'Content-Type': 'application/json' };
  if (cfg.apiKey) headers.Authorization = `Bearer ${cfg.apiKey}`;
  const json = await httpJson(`${base}/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: cfg.model,
      temperature: cfg.temperature ?? 0.1,
      max_tokens: cfg.maxTokens || 4096,
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
      response_format: { type: 'json_object' },
    }),
  }, 120000, cfg.signal);
  const u = json?.usage || {};
  return {
    text: json?.choices?.[0]?.message?.content || '',
    usage: { inputTokens: u.prompt_tokens || 0, outputTokens: u.completion_tokens || 0 },
  };
}

// --- Gemini -------------------------------------------------------------
async function callGemini(cfg, { system, user }) {
  const base = (cfg.baseUrl || PROVIDERS.gemini.defaultBaseUrl).replace(/\/$/, '');
  const model = cfg.model || PROVIDERS.gemini.defaultModel;
  // Schluessel als Header statt in der URL (landet sonst in Logs/Proxies/History).
  const url = `${base}/models/${model}:generateContent`;
  const json = await httpJson(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': cfg.apiKey || '' },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: 'user', parts: [{ text: user }] }],
      generationConfig: {
        temperature: cfg.temperature ?? 0.1,
        maxOutputTokens: cfg.maxTokens || 4096,
        responseMimeType: 'application/json',
      },
    }),
  }, 120000, cfg.signal);
  const text = (json?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('\n');
  const u = json?.usageMetadata || {};
  return {
    text,
    usage: { inputTokens: u.promptTokenCount || 0, outputTokens: u.candidatesTokenCount || 0 },
  };
}

async function callProvider(cfg, messages) {
  switch (cfg.provider) {
    case 'ollama': return callOllama(cfg, messages);
    case 'anthropic': return callAnthropic(cfg, messages);
    case 'openai': return callOpenAICompatible(cfg, messages, PROVIDERS.openai.defaultBaseUrl);
    case 'compat': return callOpenAICompatible(cfg, messages, null);
    case 'gemini': return callGemini(cfg, messages);
    default: throw new Error(`Unbekannter Anbieter: ${cfg.provider}`);
  }
}

// Verfuegbare Modelle beim Anbieter abfragen (fuer die Auswahl in der UI).
async function httpGetJson(url, headers, timeoutMs = 20000) {
  assertSecureTransport(url);
  const res = await withTimeout(timeoutMs, (signal) => fetch(url, { headers, signal }));
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = null; }
  if (!res.ok) {
    const msg = (json && (json.error?.message || json.error || json.message)) || text.slice(0, 300);
    throw new Error(`HTTP ${res.status}: ${msg}`);
  }
  return json;
}

async function fetchModels(cfg) {
  try {
    let models = [];
    if (cfg.provider === 'ollama') {
      const base = (cfg.baseUrl || PROVIDERS.ollama.defaultBaseUrl).replace(/\/$/, '');
      const j = await httpGetJson(`${base}/api/tags`, {});
      models = (j.models || []).map((m) => m.name);
    } else if (cfg.provider === 'anthropic') {
      const base = (cfg.baseUrl || PROVIDERS.anthropic.defaultBaseUrl).replace(/\/$/, '');
      const j = await httpGetJson(`${base}/v1/models?limit=100`, { 'x-api-key': cfg.apiKey || '', 'anthropic-version': '2023-06-01' });
      models = (j.data || []).map((m) => m.id);
    } else if (cfg.provider === 'gemini') {
      const base = (cfg.baseUrl || PROVIDERS.gemini.defaultBaseUrl).replace(/\/$/, '');
      // Schluessel als Header statt in der URL.
      const j = await httpGetJson(`${base}/models?pageSize=100`, { 'x-goog-api-key': cfg.apiKey || '' });
      models = (j.models || [])
        .filter((m) => (m.supportedGenerationMethods || []).includes('generateContent'))
        .map((m) => (m.name || '').replace(/^models\//, ''));
    } else { // openai / compat
      const base = (cfg.baseUrl || PROVIDERS.openai.defaultBaseUrl).replace(/\/$/, '');
      const headers = {};
      if (cfg.apiKey) headers.Authorization = `Bearer ${cfg.apiKey}`;
      const j = await httpGetJson(`${base}/models`, headers);
      models = (j.data || []).map((m) => m.id);
    }
    models = [...new Set(models)].filter(Boolean).sort();
    return { ok: true, models };
  } catch (e) {
    return { ok: false, error: friendlyNetError(cfg.provider, e.message), models: [] };
  }
}

// Kurzer Verbindungstest (billig).
async function pingProvider(cfg) {
  try {
    const res = await callProvider(
      { ...cfg, maxTokens: 50, temperature: 0 },
      { system: 'Antworte ausschliesslich mit dem JSON {"ok":true}.', user: 'ping' }
    );
    return { ok: true, sample: (res.text || '').slice(0, 120) };
  } catch (e) {
    throw new Error(friendlyNetError(cfg.provider, e.message));
  }
}

module.exports = { PROVIDERS, callProvider, pingProvider, fetchModels };
