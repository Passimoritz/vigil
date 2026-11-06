# Vigil architecture

Vigil is an Electron app in plain CommonJS (no bundler, no TypeScript). Everything that does
security work lives in `src/core` and runs in plain Node – the same code powers the desktop app,
the CLI (`src/cli.js`), the benchmark (`tools/bench.js`) and the tests (`test/run.js`).

## Modules

```
electron/                 main process (Node, privileged)
  main.js                 window, IPC handlers, config, history, reports, startup
  preload.js              the ONLY bridge to the window (contextBridge → window.vigil)
  orchestrator.js         scan queue (QUEUED → RUNNING → COMPLETED/FAILED) + findings store
  api.js                  optional local REST API (127.0.0.1, bearer token)
  applock.js              app lock: IPC guard, idle timer, unlock
  domaudit.js             headless browser check of a page (own session, sandboxed)
  ollama.js, localai.js   local AI management / detection
  proxy.js                proxy for all outgoing requests

src/core/                 security engine (no Electron)
  index.js                runAudit(): ingest → prescan → modules → tools → AI → finalize
  ingest.js               collects "units" (files, archives, web responses) from targets
  prescan.js              built-in secret + pattern rules (deterministic)
  modules/*.js            static modules (supply chain, IaC, SAST, languages, mobile, web …)
  tools.js                wrappers for external scanners (trivy, semgrep, gitleaks, nmap …)
  sandbox.js              least-privilege child-process runner used by tools.js
  analyze.js, harness.js  AI analysis, redaction, validation of AI findings
  providers.js            AI providers (Ollama, Anthropic, OpenAI, Gemini, OpenAI-compatible)
  feeds.js, feedscan.js   daily detection data (gitleaks rules, retire.js) + matching
  eol.js                  end-of-support data from endoflife.date (feed), used by DB, Linux and bundled-library checks
  greenbone.js            optional Greenbone/OpenVAS scanner: GMP via gvm-cli in the WSL distro, gentle scan config, result mapping
  greenbone-setup.js      automatic Greenbone setup: own WSL distro with Docker Engine, official compose.yaml, random password; runs only during scans
  prescan-worker.js       static pre-scan in a worker thread, so large projects do not freeze the window
  runstate.js             saved progress of a check: finished steps and AI blocks, encrypted like the history; paused or interrupted checks continue from it
  toolupdate.js           daily updates of installed tools (checksum, rollback), nmap via signed installer, Vigil via git fast-forward
  schedule.js             scheduled checks: due logic, what to report, webhook payloads (runner lives in electron/main.js)
  intel.js                CISA KEV / EPSS, contextual risk, attack paths
  verify.js               SHA-256 pinning and minisign verification of downloads
  store.js                findings lifecycle (fingerprints, regressions, auto-resolve, baseline)
  securefile.js           AES-256-GCM encryption at rest for store and history
  applock.js              scrypt password hashing + lock state (pure)
  schema.js, validation.js finding shape, dedupe/sort, Zod schemas for every input
  scope.js                allowlist / ownership verification for network targets
  report*.js              HTML, Markdown, SARIF, JSON, executive summary
  findings-i18n.js, findings-en.js   English translations of finding texts

src/ui/                   renderer (sandboxed, no Node)
  index.html, styles.css  markup and styles (strict CSP)
  app/01-…09-*.js        all views (classic scripts sharing one global scope, loaded in order)
  applock.js              lock screen + lock settings
  i18n.js                 English UI dictionary (DOM text replacement)
```

## Data flow of a scan

```
UI (renderer) ──audit:run──▶ main.js ──scope check──▶ orchestrator.enqueue
                                                        │
          ┌─────────────────────────────────────────────┘
          ▼
 runAudit(targets, config)            src/core/index.js
   1 ingestTargets     → units (path/label/content)
   2 prescan           → deterministic findings (secrets, patterns)
   3 runStaticModules  → module findings
   4 tools (optional)  → sandboxed external scanners, parsed + Zod-validated
   5 feeds / OSV / CVE → dependency findings
   6 analyze (AI)      → AI findings, redacted input, validation pass
   7 finalize          → intel (KEV/EPSS), reachability, attack paths, remedies, taxonomy
          │
          ▼
 store.applyRun        fingerprint = SHA-256(target:scanner:rule:location)
                       new / updated / regression / auto-resolved
          │  (encrypted with securefile.js)
          ▼
 history + result ──▶ renderer (results, overview, history) and reports
```

Every finding is normalised by `schema.normalizeFinding` (`title, severity, category, location,
description, impact, remediation, confidence, source, ruleId …`).

## How to add …

### a check (deterministic rule)

* **Simple regex for many languages:** add an entry to `SAST_RULES` in
  `src/core/modules/static.js` (`id, sev, cat, re, title, desc`, optional `test`/`unless`) or to
  `RULES` in `src/core/modules/langs.js` (per language, with `fix`).
* **A new module:** write `run(units) → findings[]` in `src/core/modules/<name>.js` using
  `normalizeFinding`, then register it in `MODULES` in `static.js` (id, label, run).
* **Tests:** add a vulnerable fixture plus a "no false positive" fixture to `test/run.js`.
  If it is a typical web-app flaw, add a sample to `bench/vulnerable-app/` and an entry to
  `bench/expected.json`; `npm run bench` must keep recall ≥ 95 % and precision ≥ 85 %.
* **English text:** every new German title/description/fix needs a pair in `src/core/findings-en.js`
  (the test "englisch: alle Befundtexte des Übungsprojekts übersetzt" enforces this for the bench).

### an external tool

Add a `runX(targetPath, { signal, onProgress })` to `src/core/tools.js` that calls
`runTool(cmd, argsArray, { timeoutMs })` – never `child_process` directly (a self-test enforces
this). Validate the output with a Zod schema in `validation.js` and wire it into `index.js`.
Return `{ findings, notes }`; a note matching `DID_NOT_RUN` in `index.js` prevents auto-resolve.

### an AI provider

Add an entry to `PROVIDERS` in `src/core/providers.js` (`label, needsKey, defaultBaseUrl,
defaultModel`), implement `callX(cfg, messages) → { text }` and add it to the `switch` in
`callProvider` and to `fetchModels`. If it reads a key from the environment, add it to `ENV_KEY`
in `electron/main.js` and `tools/bench.js`. Non-local base URLs must be HTTPS.

### a feed

Add an object to `FEEDS` in `src/core/feeds.js`: `id, label, urls (HTTPS, allowed hosts),
maxBytes, parse(text) → data (throw on unexpected shape), count(data)`, optionally
`verify: { sha256: [...], minisign: { publicKey, sigUrl } }`. Feeds are data only – never code.
Users can pin feeds without a code change in `<userData>/feeds/pins.json`.

## i18n

The UI is written in German. `src/ui/i18n.js` holds a German → English dictionary (`EN`) plus
regex rules (`PARTS`) for texts with numbers; a MutationObserver translates every text node and the
`placeholder`, `title` and `aria-label` attributes when English is active (default). **Every new UI
string needs an `EN` entry.** Finding texts are translated in the main process via
`findings-i18n.js` / `findings-en.js`; reports via `report-en.js`. AI answers are requested in the
configured language.

## Security model

See [`THREAT_MODEL.md`](THREAT_MODEL.md). In short: sandboxed renderer with a fixed preload API,
all inputs Zod-validated in main, network targets scope-checked, external tools sandboxed, data at
rest encrypted, optional app lock, fuses in the build.

## Tests

| Command | What |
| --- | --- |
| `npm test` | unit and integration tests (`test/run.js`), includes the self-scan |
| `npm run e2e` | real app: click paths, accessibility, app lock, encryption, visual regression |
| `npm run visual` / `visual:check` | update / strictly compare screenshot baselines (`test/visual/baseline`) |
| `npm run coverage` | line/branch/function coverage per file (Node's built-in coverage) |
| `npm run bench` | recall/precision of the rules against `bench/vulnerable-app` |
