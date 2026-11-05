# Contributing to Vigil

Thanks for helping! Vigil is a **defensive** tool: it only checks what the user owns, and it
never ships exploit payloads, DoS, brute force or anything that weakens system security
(e.g. Smart App Control). Contributions that change this will not be merged.

## Setup

```bash
git clone https://github.com/Passimoritz/vigil.git
cd vigil
npm ci
npm start          # run the app
npm test           # must pass
npm run e2e        # starts the real app (Windows), must pass
```

Node 22+ and Windows 10/11 are the main targets. External scanners (trivy, semgrep, …) are
optional; tests do not need them.

## Before you open a pull request

* `npm test`, `npm run e2e` and `npm run bench` pass.
* New UI strings have an English entry in `src/ui/i18n.js`; new finding texts have a pair in
  `src/core/findings-en.js`.
* New checks come with a vulnerable fixture **and** a fixture that must stay silent.
* Intended UI changes: run `npm run visual` and commit the updated screenshots in `test/visual/baseline/`.
* Keep the style: plain CommonJS, no build step, small focused modules, comments in German or
  English, user-facing texts in plain language.
* Do not add dependencies lightly – every runtime dependency is attack surface (`npm audit --omit=dev` runs in CI).

## Where things go

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) – it explains the modules, the data flow and
step by step how to add a check, an external tool, an AI provider or a feed.

## Security rules for code in Vigil

* Renderer never gets Node: add new capabilities as a named function in `electron/preload.js` and
  a validated `ipcMain.handle` in `electron/main.js`.
* Validate every IPC/REST input (Zod schemas in `src/core/validation.js`).
* Spawn external programs only through `src/core/sandbox.js` (via `runTool` in `tools.js`).
* Secrets never go back to the renderer; store them with `safeStorage` (see existing handlers).
* Downloads must come from fixed HTTPS hosts and be checked before use (`src/core/verify.js`).

## Reporting security issues

Please do not open public issues for vulnerabilities – see [`SECURITY.md`](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the MIT License of this project.
