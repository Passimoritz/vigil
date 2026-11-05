'use strict';

// Trefferquote messen: prueft das absichtlich unsichere Uebungsprojekt und vergleicht mit
// bench/expected.json.
//
//   npm run bench                               nur Regeln/Module (ohne KI, ohne Internet)
//   npm run bench -- ollama qwen2.5-coder:14b   zusaetzlich mit diesem KI-Modell
//   npm run bench -- anthropic claude-sonnet-5  (API-Schluessel aus .env)
//
// Ergebnis: Tabelle in der Konsole und bench/results/<anbieter>-<modell>-<datum>.json.

const fs = require('fs');
const path = require('path');
try { require('dotenv').config({ path: path.join(__dirname, '..', '.env') }); } catch { /* optional */ }
const { runAudit, PROVIDERS } = require('../src/core');
const { scoreBench } = require('../src/core/bench');

const ENV = { anthropic: 'ANTHROPIC_API_KEY', openai: 'OPENAI_API_KEY', gemini: 'GEMINI_API_KEY', compat: 'OPENAI_COMPAT_API_KEY' };

(async () => {
  const [provider, model] = process.argv.slice(2);
  const root = path.join(__dirname, '..', 'bench');
  const expected = JSON.parse(fs.readFileSync(path.join(root, 'expected.json'), 'utf8'));
  const target = { type: 'path', value: path.join(root, expected.project) };
  const config = {
    provider: provider || 'none', model: model || (provider && PROVIDERS[provider] ? PROVIDERS[provider].defaultModel : ''),
    apiKey: provider ? process.env[ENV[provider]] || '' : '', baseUrl: provider && PROVIDERS[provider] ? PROVIDERS[provider].defaultBaseUrl : '',
    analysisDepth: 'standard', aiValidation: !!provider, cveLookup: false, gitHistory: false, incremental: false, redactSecrets: true,
  };
  const t0 = Date.now();
  let result;
  if (provider) result = (await runAudit([target], config, (p) => process.stderr.write(`\r${p.phase}: ${String(p.message || '').slice(0, 70).padEnd(70)}`))).result;
  else {
    // Ohne KI: nur Vorpruefung und Module (analyze wird nicht aufgerufen)
    const { ingestTargets } = require('../src/core/ingest');
    const { prescan } = require('../src/core/prescan');
    const { runStaticModules } = require('../src/core/modules/static');
    const { dedupeFindings } = require('../src/core/schema');
    const ing = await ingestTargets([target]);
    const pre = prescan(ing.units, {});
    result = { findings: dedupeFindings([...pre.findings, ...runStaticModules(ing.units).findings]) };
  }
  process.stderr.write('\n');
  const s = scoreBench(result.findings, expected);
  const pct = (x) => `${Math.round(x * 100)} %`;
  console.log(`\nVigil-Trefferquote · ${provider ? `${provider} / ${config.model}` : 'nur Regeln (ohne KI)'} · ${Math.round((Date.now() - t0) / 1000)} s\n`);
  for (const h of s.hits) console.log(`  ${h.found ? '✔' : '✘'}  ${h.label}${h.found ? `  (${h.by.join(', ')})` : ''}`);
  console.log(`\n  Gefunden:     ${s.found} von ${s.total} (${pct(s.recall)})`);
  console.log(`  Genauigkeit:  ${pct(s.precision)} – ${s.extra.length} Befund(e) ohne erwartete Lücke`);
  const out = path.join(root, 'results');
  fs.mkdirSync(out, { recursive: true });
  const name = `${provider || 'regeln'}-${String(config.model || 'ohne-ki').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.json`;
  fs.writeFileSync(path.join(out, name), JSON.stringify({ at: new Date().toISOString(), provider: provider || null, model: config.model || null, ...s }, null, 2));
  console.log(`\n  Gespeichert: bench/results/${name}`);
  // Regeln ohne KI muessen die Mindestwerte aus expected.json halten (CI-tauglich, Exit-Code 1)
  if (!provider && (s.recall < (expected.minRecall || 0) || s.precision < (expected.minPrecision || 0))) {
    console.error(`\n  FAIL: below minimum (recall ${pct(expected.minRecall || 0)}, precision ${pct(expected.minPrecision || 0)})`);
    process.exit(1);
  }
})().catch((e) => { console.error(e); process.exit(1); });
