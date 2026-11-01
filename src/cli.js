'use strict';

// Kleine CLI zum Testen des Kerns ohne GUI.
// Beispiel:
//   node src/cli.js --provider ollama --model qwen2.5-coder ./mein-ordner ./app.jar
//   node src/cli.js --provider anthropic --model claude-sonnet-4-5 --out report.html ./src

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { runAudit, report, atOrAbove } = require('./core');

function parseArgs(argv) {
  const opts = { targets: [], provider: 'ollama', model: '', out: '', baseUrl: '', authorize: false, cveLookup: true, deep: false, validate: true, redact: true, failOn: '', format: '' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--provider') opts.provider = argv[++i];
    else if (a === '--model') opts.model = argv[++i];
    else if (a === '--base-url') opts.baseUrl = argv[++i];
    else if (a === '--out') opts.out = argv[++i];
    else if (a === '--url') opts.targets.push({ type: 'url', value: argv[++i], authorized: true }); // explizit auf der Kommandozeile = freigegeben
    else if (a === '--image') opts.targets.push({ type: 'image', value: argv[++i] });
    else if (a === '--endpoint') opts.targets.push({ type: 'endpoint', value: argv[++i], authorized: true });
    else if (a === '--authorize') opts.authorize = true;
    else if (a === '--no-cve') opts.cveLookup = false;
    else if (a === '--deep') opts.deep = true;
    else if (a === '--no-validate') opts.validate = false;
    else if (a === '--no-redact') opts.redact = false;
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a === '--format') opts.format = argv[++i];
    else opts.targets.push({ type: 'path', value: path.resolve(a) });
  }
  return opts;
}

function keyFor(provider) {
  return {
    anthropic: process.env.ANTHROPIC_API_KEY,
    openai: process.env.OPENAI_API_KEY,
    gemini: process.env.GEMINI_API_KEY,
    compat: process.env.OPENAI_COMPAT_API_KEY,
  }[provider] || '';
}

(async () => {
  const o = parseArgs(process.argv.slice(2));
  if (!o.targets.length) {
    console.error('Nutzung: node src/cli.js [--provider ollama|anthropic|openai|gemini|compat] [--model …] [--out report.html] <pfad|--url URL|--endpoint HOST> …');
    process.exit(1);
  }
  const config = {
    provider: o.provider,
    model: o.model,
    apiKey: keyFor(o.provider),
    baseUrl: o.baseUrl || (o.provider === 'compat' ? process.env.OPENAI_COMPAT_BASE_URL : o.provider === 'ollama' ? process.env.OLLAMA_BASE_URL : ''),
    temperature: 0.1,
    maxTokens: 4096,
    cveLookup: o.cveLookup,
    analysisDepth: o.deep ? 'thorough' : 'standard',
    aiValidation: o.validate,
    redactSecrets: o.redact,
  };

  const { result } = await runAudit(o.targets, config, (p) => {
    const d = p.total ? ` [${p.done}/${p.total}]` : '';
    console.log(`· ${p.phase}${d}: ${p.message}`);
  });

  console.log(`\nBefunde: ${result.summary.total}  (crit ${result.summary.counts.critical}, high ${result.summary.counts.high}, med ${result.summary.counts.medium}, low ${result.summary.counts.low}, info ${result.summary.counts.info})`);
  for (const f of result.findings.slice(0, 50)) {
    console.log(`  [${f.severity}] ${f.title}  ${f.location ? '(' + f.location + ')' : ''}`);
  }
  if (result.errors?.length) console.log('\nHinweise:\n  ' + result.errors.join('\n  '));

  if (o.out) {
    const fmt = o.format
      || (o.out.endsWith('.md') ? 'md' : o.out.endsWith('.sarif') ? 'sarif' : o.out.endsWith('.json') ? 'json' : 'html');
    const out = fmt === 'md' ? report.toMarkdown(result)
      : fmt === 'sarif' ? report.toSarif(result)
        : fmt === 'json' ? JSON.stringify(result, null, 2)
          : report.toHtml(result);
    fs.writeFileSync(o.out, out, 'utf8');
    console.log(`\nReport (${fmt}) geschrieben: ${o.out}`);
  }

  // --fail-on <severity>: Exit-Code 2, wenn Befunde mit diesem Schweregrad oder hoeher existieren (fuer CI).
  if (o.failOn) {
    const n = atOrAbove(result.summary.counts, o.failOn);
    if (n > 0) {
      console.error(`\nAbbruch (--fail-on ${o.failOn}): ${n} Befund(e) mit Schweregrad >= ${o.failOn}.`);
      process.exit(2);
    }
  }
})().catch((e) => { console.error('Fehler:', e); process.exit(1); });
