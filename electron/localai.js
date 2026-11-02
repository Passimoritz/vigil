'use strict';

// Sucht bereits laufende lokale KI-Server auf diesem Rechner (nur 127.0.0.1, nur lesend):
// Ollama und alle gaengigen OpenAI-kompatiblen Server. Nichts wird gestartet oder installiert.

const { fetch, Agent } = require('undici');

const DIRECT = new Agent();
const KNOWN = [
  { id: 'ollama', name: 'Ollama', port: 11434, kind: 'ollama' },
  { id: 'lmstudio', name: 'LM Studio', port: 1234, kind: 'openai' },
  { id: 'jan', name: 'Jan', port: 1337, kind: 'openai' },
  { id: 'gpt4all', name: 'GPT4All', port: 4891, kind: 'openai' },
  { id: 'textgen', name: 'text-generation-webui', port: 5000, kind: 'openai' },
  { id: 'kobold', name: 'KoboldCpp', port: 5001, kind: 'openai' },
  { id: 'vllm', name: 'vLLM', port: 8000, kind: 'openai' },
  { id: 'llamacpp', name: 'llama.cpp / LocalAI', port: 8080, kind: 'openai' },
];

async function getJson(url, ms = 1500) {
  const res = await fetch(url, { dispatcher: DIRECT, signal: AbortSignal.timeout(ms) });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return res.json();
}

async function probe(k) {
  const base = `http://127.0.0.1:${k.port}`;
  try {
    if (k.kind === 'ollama') {
      const j = await getJson(base + '/api/tags');
      return { ...k, baseUrl: base, models: (j.models || []).map((m) => m.name) };
    }
    const j = await getJson(base + '/v1/models');
    const models = (j.data || j.models || []).map((m) => m.id || m.name).filter(Boolean);
    return { ...k, baseUrl: base + '/v1', models };
  } catch { return null; }
}

// Alle bekannten Ports parallel pruefen (je max. 1,5 s); nur antwortende Server zurueckgeben.
async function detectLocalAi() {
  const found = (await Promise.all(KNOWN.map(probe))).filter(Boolean);
  return found;
}

module.exports = { detectLocalAi, KNOWN };
