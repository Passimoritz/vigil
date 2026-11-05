'use strict';

// Einheitliche Schnittstelle zu lokalen und externen KI-Anbietern.
// Jeder Aufruf: callProvider(config, { system, user }) -> { text }
// config = { provider, model, apiKey, baseUrl, temperature, maxTokens }

const crypto = require('crypto');

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
    label: 'OpenAI-kompatibel (LM Studio, vLLM, eigener Dienst …)',
    needsKey: false, // manche lokalen brauchen keinen Key
    defaultBaseUrl: '',
    defaultModel: '',
  },
  // Weitere Cloud-Anbieter. Die meisten sprechen das OpenAI-Format (chat/completions).
  mistral: { label: 'Mistral AI', needsKey: true, defaultBaseUrl: 'https://api.mistral.ai/v1', defaultModel: 'codestral-latest', openaiCompatible: true },
  deepseek: { label: 'DeepSeek', needsKey: true, defaultBaseUrl: 'https://api.deepseek.com/v1', defaultModel: 'deepseek-chat', openaiCompatible: true },
  groq: { label: 'Groq', needsKey: true, defaultBaseUrl: 'https://api.groq.com/openai/v1', defaultModel: 'llama-3.3-70b-versatile', openaiCompatible: true },
  openrouter: { label: 'OpenRouter', needsKey: true, defaultBaseUrl: 'https://openrouter.ai/api/v1', defaultModel: 'openai/gpt-4.1-mini', openaiCompatible: true },
  // Azure: Basis-URL = https://<ressource>.openai.azure.com, Modell = Name des Deployments
  azure: { label: 'Azure OpenAI', needsKey: true, needsBaseUrl: true, defaultBaseUrl: '', defaultModel: '', openaiCompatible: true },
  // Bedrock: Schluessel = Bedrock-API-Key (Bearer) ODER "ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]" (SigV4)
  bedrock: { label: 'AWS Bedrock', needsKey: true, defaultBaseUrl: 'https://bedrock-runtime.us-east-1.amazonaws.com', defaultModel: 'amazon.nova-pro-v1:0' },
  // Vertex: Basis-URL = https://<region>-aiplatform.googleapis.com/v1/projects/<projekt>/locations/<region>
  // Schluessel = OAuth-Zugriffstoken; leer = "gcloud auth print-access-token"
  vertex: { label: 'Google Vertex AI', needsKey: false, needsBaseUrl: true, defaultBaseUrl: '', defaultModel: 'gemini-2.0-flash' },
};

// Anbieter, die Werkzeug-Aufrufe ("KI darf nachschlagen") unterstuetzen
const TOOL_PROVIDERS = new Set(['anthropic', 'openai', 'compat', 'ollama', 'gemini', 'vertex', 'mistral', 'deepseek', 'groq', 'openrouter', 'azure']);
const supportsTools = (provider) => TOOL_PROVIDERS.has(provider);

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
async function callOllama(cfg, { system, user, prefix, json: jsonMode = true }) {
  const base = (cfg.baseUrl || PROVIDERS.ollama.defaultBaseUrl).replace(/\/$/, '');
  let json;
  try {
    json = await httpJson(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.model || PROVIDERS.ollama.defaultModel,
        stream: false,
        ...(jsonMode ? { format: 'json' } : {}),
        options: { temperature: cfg.temperature ?? 0.1 },
        // Modell zwischen den Bloecken im Speicher halten (sonst Neuladen je Aufruf)
        keep_alive: '20m',
        messages: [{ role: 'system', content: system }, { role: 'user', content: prefix ? prefix + user : user }],
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
async function callAnthropic(cfg, { system, user, prefix }) {
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
      // Prompt-Caching: System-Prompt und gleichbleibender Anfang (Anweisung + Fakten) werden
      // beim Anbieter zwischengespeichert und bei Folgeaufrufen zum Bruchteil abgerechnet.
      system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
      messages: [{ role: 'user', content: prefix
        ? [{ type: 'text', text: prefix, cache_control: { type: 'ephemeral' } }, { type: 'text', text: user }]
        : [{ type: 'text', text: user }] }],
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
      cachedTokens: u.cache_read_input_tokens || 0,
      cacheWriteTokens: u.cache_creation_input_tokens || 0,
    },
  };
}

// --- OpenAI (und kompatibel) -------------------------------------------
// Ziel-URL und Kopfzeilen fuer alle Anbieter im OpenAI-Format (OpenAI, compat, Mistral,
// DeepSeek, Groq, OpenRouter, Azure).
function openaiTarget(cfg, fallbackBase) {
  const base = (cfg.baseUrl || fallbackBase || '').replace(/\/$/, '');
  if (!base) throw new Error(cfg.provider === 'azure'
    ? 'Für Azure OpenAI die Basis-URL eintragen (https://<ressource>.openai.azure.com) und als Modell den Deployment-Namen.'
    : 'Keine Basis-URL fuer den OpenAI-kompatiblen Anbieter gesetzt.');
  const headers = { 'Content-Type': 'application/json' };
  if (cfg.provider === 'azure') {
    if (cfg.apiKey) headers['api-key'] = cfg.apiKey;
    const ver = cfg.apiVersion || '2024-10-21';
    const root = /\/deployments\/[^/]+$/.test(base) ? base : `${base.replace(/\/openai$/, '')}/openai/deployments/${encodeURIComponent(cfg.model || '')}`;
    return { url: `${root}/chat/completions?api-version=${encodeURIComponent(ver)}`, headers };
  }
  if (cfg.apiKey) headers.Authorization = `Bearer ${cfg.apiKey}`;
  if (cfg.provider === 'openrouter') { headers['HTTP-Referer'] = 'https://github.com/Passimoritz/vigil'; headers['X-Title'] = 'Vigil'; }
  return { url: `${base}/chat/completions`, headers };
}
const openaiUsage = (u = {}) => ({ inputTokens: u.prompt_tokens || 0, outputTokens: u.completion_tokens || 0, cachedTokens: (u.prompt_tokens_details && u.prompt_tokens_details.cached_tokens) || 0 });

async function callOpenAICompatible(cfg, { system, user, prefix, json: jsonMode = true }, fallbackBase) {
  const { url, headers } = openaiTarget(cfg, fallbackBase);
  const json = await httpJson(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      ...(cfg.provider === 'azure' ? {} : { model: cfg.model }),
      temperature: cfg.temperature ?? 0.1,
      max_tokens: cfg.maxTokens || 4096,
      messages: [{ role: 'system', content: system }, { role: 'user', content: prefix ? prefix + user : user }],
      ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
    }),
  }, 120000, cfg.signal);
  return { text: json?.choices?.[0]?.message?.content || '', usage: openaiUsage(json?.usage) };
}

// --- Gemini / Vertex ------------------------------------------------------
// Vertex AI nutzt dasselbe Anfrageformat wie Gemini, aber mit OAuth-Zugriffstoken.
let vertexToken = { value: '', until: 0 };
function gcloudToken() {
  const { execFile } = require('child_process');
  const win = process.platform === 'win32';
  return new Promise((resolve, reject) => {
    // feste Argumente, keine Nutzereingaben in der Kommandozeile
    execFile(win ? 'gcloud.cmd' : 'gcloud', ['auth', 'print-access-token'], { timeout: 20000, windowsHide: true, shell: win }, (err, out) => {
      if (err) return reject(new Error('Kein Vertex-Zugriffstoken: Token als Schlüssel eintragen oder Google Cloud CLI anmelden („gcloud auth login“).'));
      resolve(String(out || '').trim());
    });
  });
}
async function geminiTarget(cfg) {
  const model = cfg.model || PROVIDERS[cfg.provider === 'vertex' ? 'vertex' : 'gemini'].defaultModel;
  if (cfg.provider === 'vertex') {
    const base = String(cfg.baseUrl || '').replace(/\/$/, '');
    if (!/^https:\/\/[\w.-]*aiplatform\.googleapis\.com\/v1\w*\/projects\/[^/]+\/locations\/[^/]+$/.test(base)) {
      throw new Error('Für Vertex AI die Basis-URL eintragen: https://<region>-aiplatform.googleapis.com/v1/projects/<projekt>/locations/<region>');
    }
    let token = cfg.apiKey || process.env.VERTEX_ACCESS_TOKEN || '';
    if (!token) {
      if (vertexToken.value && vertexToken.until > Date.now()) token = vertexToken.value;
      else { token = await gcloudToken(); vertexToken = { value: token, until: Date.now() + 45 * 60 * 1000 }; }
    }
    return { url: `${base}/publishers/google/models/${encodeURIComponent(model)}:generateContent`, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` } };
  }
  const base = (cfg.baseUrl || PROVIDERS.gemini.defaultBaseUrl).replace(/\/$/, '');
  // Schluessel als Header statt in der URL (landet sonst in Logs/Proxies/History).
  return { url: `${base}/models/${model}:generateContent`, headers: { 'Content-Type': 'application/json', 'x-goog-api-key': cfg.apiKey || '' } };
}
const geminiUsage = (u = {}) => ({ inputTokens: u.promptTokenCount || 0, outputTokens: u.candidatesTokenCount || 0, cachedTokens: u.cachedContentTokenCount || 0 });

async function callGemini(cfg, { system, user, prefix, json: jsonMode = true }) {
  const { url, headers } = await geminiTarget(cfg);
  const json = await httpJson(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ role: 'user', parts: [{ text: prefix ? prefix + user : user }] }],
      generationConfig: {
        temperature: cfg.temperature ?? 0.1,
        maxOutputTokens: cfg.maxTokens || 4096,
        ...(jsonMode ? { responseMimeType: 'application/json' } : {}),
      },
    }),
  }, 120000, cfg.signal);
  const text = (json?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('\n');
  return { text, usage: geminiUsage(json?.usageMetadata) };
}

// --- AWS Bedrock (Converse-API) -------------------------------------------
// Anmeldung: Bedrock-API-Key als Bearer-Token oder klassische Zugangsschluessel mit SigV4-Signatur.
const hmac = (key, s) => crypto.createHmac('sha256', key).update(s, 'utf8').digest();
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
function sigv4Key(secret, dateStamp, region, service) {
  return hmac(hmac(hmac(hmac('AWS4' + secret, dateStamp), region), service), 'aws4_request');
}
// Signiert eine Anfrage (AWS Signature Version 4). path ist bereits URL-kodiert.
function sigv4Headers({ method = 'POST', host, path, region, service = 'bedrock', body = '', accessKeyId, secretAccessKey, sessionToken, now = new Date() }) {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256hex(body);
  const h = { 'content-type': 'application/json', host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  if (sessionToken) h['x-amz-security-token'] = sessionToken;
  const keys = Object.keys(h).sort();
  const signedHeaders = keys.join(';');
  const canonicalHeaders = keys.map((k) => `${k}:${String(h[k]).trim()}\n`).join('');
  // Nicht-S3-Dienste: jedes Pfadsegment wird fuer die Signatur ein zweites Mal kodiert
  const canonicalUri = path.split('/').map((seg) => encodeURIComponent(seg)).join('/');
  const canonicalRequest = [method, canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const signature = crypto.createHmac('sha256', sigv4Key(secretAccessKey, dateStamp, region, service)).update(toSign, 'utf8').digest('hex');
  const out = { ...h, authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
  delete out.host; // setzt fetch selbst (identisch)
  return out;
}
function bedrockCreds(cfg) {
  const key = String(cfg.apiKey || '').trim();
  const parts = key.split(':');
  if (parts.length >= 2 && /^(AKIA|ASIA)[A-Z0-9]{12,}$/.test(parts[0])) return { accessKeyId: parts[0], secretAccessKey: parts[1], sessionToken: parts[2] || process.env.AWS_SESSION_TOKEN || '' };
  if (key) return { bearer: key };
  if (process.env.AWS_BEARER_TOKEN_BEDROCK) return { bearer: process.env.AWS_BEARER_TOKEN_BEDROCK };
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) return { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, sessionToken: process.env.AWS_SESSION_TOKEN || '' };
  throw new Error('Für AWS Bedrock einen Bedrock-API-Schlüssel oder „ACCESS_KEY_ID:SECRET_ACCESS_KEY“ eintragen.');
}
async function callBedrock(cfg, { system, user, prefix }) {
  const base = (cfg.baseUrl || PROVIDERS.bedrock.defaultBaseUrl).replace(/\/$/, '');
  const u = new URL(base);
  const region = (u.hostname.match(/^bedrock-runtime(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com$/) || [])[1] || process.env.AWS_REGION || 'us-east-1';
  const path = `/model/${encodeURIComponent(cfg.model || PROVIDERS.bedrock.defaultModel)}/converse`;
  const body = JSON.stringify({
    system: [{ text: system }],
    messages: [{ role: 'user', content: [{ text: prefix ? prefix + user : user }] }],
    inferenceConfig: { maxTokens: cfg.maxTokens || 4096, temperature: cfg.temperature ?? 0.1 },
  });
  const cr = bedrockCreds(cfg);
  const headers = cr.bearer ? { 'Content-Type': 'application/json', Authorization: `Bearer ${cr.bearer}` }
    : sigv4Headers({ host: u.host, path, region, body, ...cr });
  const json = await httpJson(`${u.origin}${path}`, { method: 'POST', headers, body }, 120000, cfg.signal);
  const text = (json?.output?.message?.content || []).map((c) => c.text || '').join('\n');
  const us = json?.usage || {};
  return { text, usage: { inputTokens: us.inputTokens || 0, outputTokens: us.outputTokens || 0, cachedTokens: us.cacheReadInputTokens || 0 } };
}

// --- Verteiler ------------------------------------------------------------
function dispatch(cfg, messages) {
  const p = PROVIDERS[cfg.provider];
  switch (cfg.provider) {
    case 'ollama': return callOllama(cfg, messages);
    case 'anthropic': return callAnthropic(cfg, messages);
    case 'openai': return callOpenAICompatible(cfg, messages, PROVIDERS.openai.defaultBaseUrl);
    case 'compat': return callOpenAICompatible(cfg, messages, null);
    case 'gemini': case 'vertex': return callGemini(cfg, messages);
    case 'bedrock': return callBedrock(cfg, messages);
    default:
      if (p && p.openaiCompatible) return callOpenAICompatible(cfg, messages, p.defaultBaseUrl);
      throw new Error(`Unbekannter Anbieter: ${cfg.provider}`);
  }
}

// Optionaler Mitschnitt (Reproduzierbarkeit): cfg.onAiCall erhaelt Prompt, Parameter und Antwort.
function notify(cfg, messages, res, extra) {
  if (typeof cfg.onAiCall !== 'function') return;
  try {
    cfg.onAiCall({ kind: messages.kind || '', provider: cfg.provider, model: cfg.model, temperature: cfg.temperature ?? null, maxTokens: cfg.maxTokens || null, json: messages.json !== false, system: messages.system || '', prefix: messages.prefix || '', user: messages.user || '', text: (res && res.text) || '', usage: (res && res.usage) || null, ...(extra || {}) });
  } catch { /* Mitschnitt darf nie den Lauf stoeren */ }
}

async function callProvider(cfg, messages) {
  const res = await dispatch(cfg, messages);
  notify(cfg, messages, res);
  return res;
}

// --- Werkzeug-Aufrufe ("KI darf nachschlagen") -----------------------------
// tools: [{ name, description, parameters: JSON-Schema }]; runTool(name, args) -> Text.
// Hoechstens maxCalls Abfragen; danach muss das Modell ohne weitere Abfragen antworten.
// Anbieter ohne Werkzeug-Unterstuetzung: Fehler mit code 'NO_TOOLS' (Aufrufer faellt zurueck).
async function callProviderTools(cfg, messages) {
  const { system, user, prefix, tools = [], runTool, maxCalls = 4 } = messages;
  if (!supportsTools(cfg.provider)) { const e = new Error('Anbieter unterstützt keine Werkzeug-Aufrufe.'); e.code = 'NO_TOOLS'; throw e; }
  const adapter = await toolAdapter(cfg, { system, user: prefix ? prefix + user : user, prefix, plainUser: user, tools });
  const usage = { inputTokens: 0, outputTokens: 0, cachedTokens: 0, cacheWriteTokens: 0 };
  const log = [];
  let used = 0;
  for (let round = 0; round < maxCalls + 3; round++) {
    const final = used >= maxCalls;
    const json = await adapter.send(final);
    const r = adapter.parse(json);
    for (const k of Object.keys(usage)) usage[k] += (r.usage && r.usage[k]) || 0;
    if (!r.calls.length || final) {
      const res = { text: r.text, usage, lookups: used, lookupLog: log };
      notify(cfg, messages, res, { lookups: used });
      return res;
    }
    const results = [];
    for (const c of r.calls) {
      let output;
      if (used >= maxCalls) output = 'Limit für Nachschlagen erreicht – antworte jetzt ohne weitere Abfragen mit dem JSON-Ergebnis.';
      else {
        used++;
        try { output = String(await runTool(c.name, c.args || {}) || ''); } catch (e) { output = 'Fehler: ' + e.message; }
        log.push({ name: c.name, args: c.args || {}, chars: output.length });
      }
      results.push({ ...c, output });
    }
    adapter.push(json, results);
  }
  const res = { text: '', usage, lookups: used, lookupLog: log };
  notify(cfg, messages, res, { lookups: used });
  return res;
}

// Je Anbieter: Anfrage senden, Antwort lesen, Werkzeug-Ergebnisse anhaengen.
async function toolAdapter(cfg, { system, user, prefix, plainUser, tools }) {
  const temp = cfg.temperature ?? 0.1;
  const maxTok = cfg.maxTokens || 4096;
  const P = cfg.provider;
  if (P === 'anthropic') {
    const base = (cfg.baseUrl || PROVIDERS.anthropic.defaultBaseUrl).replace(/\/$/, '');
    const msgs = [{ role: 'user', content: prefix ? [{ type: 'text', text: prefix, cache_control: { type: 'ephemeral' } }, { type: 'text', text: plainUser }] : [{ type: 'text', text: plainUser }] }];
    const defs = tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters }));
    return {
      send: (final) => httpJson(`${base}/v1/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': cfg.apiKey || '', 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: cfg.model || PROVIDERS.anthropic.defaultModel, max_tokens: maxTok, system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }], tools: defs, tool_choice: final ? { type: 'none' } : { type: 'auto' }, messages: msgs }),
      }, 120000, cfg.signal),
      parse: (j) => {
        const content = Array.isArray(j?.content) ? j.content : [];
        const u = j?.usage || {};
        return {
          text: content.filter((b) => b.type === 'text').map((b) => b.text).join('\n'),
          calls: content.filter((b) => b.type === 'tool_use').map((b) => ({ id: b.id, name: b.name, args: b.input })),
          usage: { inputTokens: (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0), outputTokens: u.output_tokens || 0, cachedTokens: u.cache_read_input_tokens || 0, cacheWriteTokens: u.cache_creation_input_tokens || 0 },
        };
      },
      push: (j, results) => {
        msgs.push({ role: 'assistant', content: j.content });
        msgs.push({ role: 'user', content: results.map((r) => ({ type: 'tool_result', tool_use_id: r.id, content: r.output })) });
      },
    };
  }
  if (P === 'ollama') {
    const base = (cfg.baseUrl || PROVIDERS.ollama.defaultBaseUrl).replace(/\/$/, '');
    const msgs = [{ role: 'system', content: system }, { role: 'user', content: user }];
    const defs = tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.parameters } }));
    return {
      send: async (final) => {
        try {
          return await httpJson(`${base}/api/chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: cfg.model || PROVIDERS.ollama.defaultModel, stream: false, options: { temperature: temp }, keep_alive: '20m', messages: msgs, ...(final ? {} : { tools: defs }) }) }, 120000, cfg.signal);
        } catch (e) {
          if (/does not support tools/i.test(e.message)) { const x = new Error(e.message); x.code = 'NO_TOOLS'; throw x; }
          throw new Error(friendlyNetError('ollama', e.message));
        }
      },
      parse: (j) => ({
        text: j?.message?.content || '',
        calls: (j?.message?.tool_calls || []).map((c, i) => ({ id: String(i), name: c.function && c.function.name, args: typeof (c.function && c.function.arguments) === 'string' ? safeJson(c.function.arguments) : (c.function && c.function.arguments) || {} })),
        usage: { inputTokens: j?.prompt_eval_count || 0, outputTokens: j?.eval_count || 0 },
      }),
      push: (j, results) => {
        msgs.push(j.message);
        for (const r of results) msgs.push({ role: 'tool', tool_name: r.name, content: r.output });
      },
    };
  }
  if (P === 'gemini' || P === 'vertex') {
    const { url, headers } = await geminiTarget(cfg);
    const contents = [{ role: 'user', parts: [{ text: user }] }];
    const decl = [{ functionDeclarations: tools.map((t) => ({ name: t.name, description: t.description, parameters: t.parameters })) }];
    return {
      send: (final) => httpJson(url, { method: 'POST', headers, body: JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents, tools: decl, toolConfig: { functionCallingConfig: { mode: final ? 'NONE' : 'AUTO' } }, generationConfig: { temperature: temp, maxOutputTokens: maxTok } }) }, 120000, cfg.signal),
      parse: (j) => {
        const parts = j?.candidates?.[0]?.content?.parts || [];
        return { text: parts.map((p) => p.text || '').join('\n'), calls: parts.filter((p) => p.functionCall).map((p, i) => ({ id: String(i), name: p.functionCall.name, args: p.functionCall.args || {} })), usage: geminiUsage(j?.usageMetadata) };
      },
      push: (j, results) => {
        contents.push(j.candidates[0].content);
        contents.push({ role: 'user', parts: results.map((r) => ({ functionResponse: { name: r.name, response: { content: r.output } } })) });
      },
    };
  }
  // OpenAI-Format (OpenAI, compat, Mistral, DeepSeek, Groq, OpenRouter, Azure)
  const p = PROVIDERS[P] || {};
  const { url, headers } = openaiTarget(cfg, P === 'compat' ? null : p.defaultBaseUrl);
  const msgs = [{ role: 'system', content: system }, { role: 'user', content: user }];
  const defs = tools.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.parameters } }));
  return {
    send: (final) => httpJson(url, { method: 'POST', headers, body: JSON.stringify({ ...(P === 'azure' ? {} : { model: cfg.model }), temperature: temp, max_tokens: maxTok, messages: msgs, tools: defs, tool_choice: final ? 'none' : 'auto' }) }, 120000, cfg.signal),
    parse: (j) => {
      const m = j?.choices?.[0]?.message || {};
      return { text: m.content || '', calls: (m.tool_calls || []).map((c) => ({ id: c.id, name: c.function && c.function.name, args: safeJson(c.function && c.function.arguments) })), usage: openaiUsage(j?.usage) };
    },
    push: (j, results) => {
      const m = j.choices[0].message;
      msgs.push({ role: 'assistant', content: m.content || null, tool_calls: m.tool_calls });
      for (const r of results) msgs.push({ role: 'tool', tool_call_id: r.id, content: r.output });
    },
  };
}
function safeJson(s) { if (s && typeof s === 'object') return s; try { return JSON.parse(String(s || '{}')); } catch { return {}; } }

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

const STATIC_MODELS = {
  bedrock: ['amazon.nova-pro-v1:0', 'amazon.nova-lite-v1:0', 'amazon.nova-micro-v1:0', 'meta.llama3-3-70b-instruct-v1:0', 'mistral.mistral-large-2407-v1:0'],
  vertex: ['gemini-2.0-flash', 'gemini-2.0-flash-lite', 'gemini-2.5-pro', 'gemini-2.5-flash'],
};

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
    } else if (cfg.provider === 'azure') {
      // Azure: Modelle sind eigene Deployments – Name von Hand eintragen
      return { ok: false, error: 'Azure OpenAI: den Namen deines Deployments über „Anderes Modell eingeben“ eintragen.', models: [] };
    } else if (STATIC_MODELS[cfg.provider]) {
      // Bedrock/Vertex: die Modell-Liste braucht eigene Verwaltungs-APIs – gaengige Modelle vorschlagen
      models = STATIC_MODELS[cfg.provider];
    } else { // openai / compat / Mistral / DeepSeek / Groq / OpenRouter
      const base = (cfg.baseUrl || (PROVIDERS[cfg.provider] || {}).defaultBaseUrl || PROVIDERS.openai.defaultBaseUrl).replace(/\/$/, '');
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

module.exports = { PROVIDERS, callProvider, callProviderTools, supportsTools, pingProvider, fetchModels, sigv4Headers, sigv4Key, openaiTarget };
