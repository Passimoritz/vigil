# Vigil threat model

Vigil is a defensive security-audit desktop app. It reads source code, talks to websites and
servers the user owns, runs third-party scanners and optionally sends code to an AI provider.
That makes Vigil itself an attractive target: it holds findings (a map of the user's weak spots),
API keys, test-account passwords and an always-on local API. This document lists what we protect,
the trust boundaries, the threats per boundary (STRIDE) and the controls that exist today.

Scope: the Windows desktop build (Electron 45, plain CommonJS). Out of scope: a fully compromised
Windows account (malware running as the same user can read process memory and use DPAPI exactly
like Vigil can) and physical attacks on an unlocked, logged-in machine beyond the app lock.

## Assets

| Asset | Where | Why it matters |
| --- | --- | --- |
| Findings store, scan history | `findings-store.json`, `history.json`, `history/*.json` in userData | Exact list of exploitable weaknesses, file paths, snippets, evidence |
| AI provider keys | `config.json` (`providers.*.apiKey`) or `.env` | Cost, data access at the provider |
| Test-account passwords, API-matrix tokens, MalwareBazaar key | `config.json`, encrypted with safeStorage | Access to the user's own services |
| REST API token | `config.json` | Start scans, change finding status |
| App-lock secret | `config.json` (`appLock.secret`, scrypt hash only) | Gate to the UI |
| Detection feeds | `feeds/*.json`, `threat-intel.json` | Tampering hides secrets or vulnerable libraries |
| Scan targets' source code | read-only, user's disk | Must not leave the machine unredacted |

## Trust boundaries

```
 user's files ──read──▶ ┌──────────────────────────── Vigil (main process, Node) ───────────────────────────┐
                        │ core pipeline (src/core) · store · feeds · orchestrator · REST API (127.0.0.1)    │
 renderer (sandboxed) ◀─┤ IPC (preload, contextBridge)                                                      │
                        │ child processes: trivy, semgrep, gitleaks, nmap, nuclei … (sandbox.js)            │
                        └──┬─────────────┬─────────────────┬───────────────┬──────────────────────────────────┘
                           │ HTTPS       │ HTTPS           │ HTTP(S)       │ localhost
                     AI providers   feeds/intel (GitHub,  targets (own    Ollama / LM Studio
                     (optional)     CISA, FIRST, OSV)     sites/servers)
```

## STRIDE per component

### 1. IPC (preload ↔ main)

| | Threat | Controls |
| --- | --- | --- |
| S | A web page or injected script calls IPC | Renderer only loads local `index.html`; navigation and `window.open` denied; `will-attach-webview` blocked; `contextIsolation`, `sandbox: true`, `nodeIntegration: false` |
| T | Renderer sends crafted arguments (path traversal, huge payloads) | Zod schemas (`validation.js`) for scans and status updates; IDs matched against `^[\w-]{6,80}$`; file snippets only inside already-scanned target folders (`resolveFindingFile`); model names whitelisted |
| R | No record of what the UI changed | Scan runs logged with origin (`app`/`api`) in the store |
| I | Secrets flow back to the renderer | Secret-bearing handlers return only `has…` flags; `config:get` strips the app-lock hash; `config:save` never lets the renderer overwrite secrets (`apiToken`, `webLogins`, `apiMatrix`, `malwareBazaarKeyEnc`, `appLock`) |
| D | Renderer floods long-running handlers | Single scan queue, one Ollama pull at a time, caps on list sizes |
| E | Renderer reaches Node | Sandboxed renderer, preload exposes a fixed function list, no generic `invoke` |

### 2. Renderer (UI)

| | Threat | Controls |
| --- | --- | --- |
| T/E | XSS from finding texts, file names, AI answers, feed data | Output escaped (`esc()`), Markdown rendering limited to bold/lists/code; strict CSP: `default-src 'none'; script-src 'self'; object-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'` |
| I | External links leak data | `link:open` only for allow-listed HTTPS documentation hosts (`isAllowedLink`) |
| E | Permission prompts (camera, geolocation …) | Default session denies every permission except sanitized clipboard writes |

### 3. Detection feeds and threat intel

| | Threat | Controls |
| --- | --- | --- |
| S | Attacker serves a fake feed (DNS, proxy) | HTTPS only, host allowlist (`raw.githubusercontent.com`, `cisa.gov`, `epss.cyentia.com`), redirects rejected |
| T | Feed content manipulated in transit or upstream | Shape and minimum-size checks; optional SHA-256 pins and minisign signatures per feed (`feeds/pins.json`, `src/core/verify.js`); mismatches are rejected and the last good copy stays active |
| T | Cached feed edited on disk to hide findings | Each cached feed stores a hash of its data; a mismatch makes Vigil ignore it and re-download |
| D | Huge feed or catastrophic regex (ReDoS) | Size caps (3–8 MB), regexes compiled individually, length-limited, applied per line ≤ 2000 chars |
| E | Code execution from feeds | Feeds are data only – nothing is evaluated |

Upstream gitleaks/retire.js publish rules from `master` without signatures, so pins are opt-in
(an organisation can pin the approved revision). Tools that ship minisign signatures can be
verified with `verifyMinisign`. Cosign/sigstore verification needs the transparency log and the
Fulcio certificate chain and is not implemented; such artifacts should be pinned by SHA-256.

### 4. AI providers

| | Threat | Controls |
| --- | --- | --- |
| I | Source code and secrets leave the machine | Local providers (Ollama, LM Studio) are the default; for cloud providers secrets are redacted before sending (`harness.redactSecrets`); cost/scope preview before each run |
| S | Fake provider endpoint | HTTPS required for non-local base URLs; keys only sent to the configured provider |
| T | Prompt injection inside scanned code makes the AI report false "all clear" | AI findings never auto-resolve; AI results are marked unconfirmed unless backed by a deterministic rule; a second validation pass tries to refute AI findings |
| D | Runaway token cost | Estimates, `maxTokens`, AI cache for unchanged files |

### 5. Local REST API

| | Threat | Controls |
| --- | --- | --- |
| S | Other local users or web pages call the API | Off by default, binds to `127.0.0.1` only, random 192-bit bearer token compared in constant time, any request with an `Origin` header rejected (blocks browser CSRF/DNS rebinding) |
| T | Malicious scan requests | Same Zod validation and scope enforcement as the UI; only allow-listed targets |
| D | Flooding | 120 requests and 10 scans per minute, 64 KB body cap |
| I | Token visible to other processes of the same user | Accepted risk (same-user boundary); token can be regenerated |

The app lock does not cover the REST API (it is meant for unattended scripts); disable the API if that matters.

### 6. Stored data

| | Threat | Controls |
| --- | --- | --- |
| I | Laptop theft, backup copies, other users reading the profile | Findings store and history encrypted with AES-256-GCM (`src/core/securefile.js`); the 256-bit data key is wrapped by Electron safeStorage (Windows DPAPI, bound to the user account); plaintext files are migrated on first start |
| T | Files edited to hide findings | GCM authentication tag: tampered files fail to decrypt and are moved aside (`*.unreadable-<time>`) instead of being silently replaced |
| I | Someone at an unlocked PC opens Vigil | Optional app lock: scrypt-hashed password (N=2¹⁵, r=8), on start and after configurable system idle time or when Windows locks; while locked the main process refuses all data IPC; exponential back-off after 5 wrong attempts |
| I | Crash reports leak paths/user names | Crash reports stay local; the home directory is replaced by `~` |

Limits: DPAPI protects against other accounts and offline disk access, not against malware
running as the same user. Without safeStorage (e.g. Linux without a keyring, CLI) files stay
plaintext and the settings page says so. Biometric unlock: Electron exposes Touch ID on macOS
only; Windows Hello has no Electron API and would need a native addon, so the Windows build uses
the password only.

### 7. External tools (trivy, semgrep, gitleaks, nmap, nuclei, …) — "Tool sandbox"

| | Threat | Controls |
| --- | --- | --- |
| E | Command injection through target paths/URLs | `shell: false`, arguments as arrays, NUL bytes rejected; targets validated (Zod, scope) before |
| I | A compromised or malicious scanner exfiltrates Vigil's secrets | Minimal environment: only OS basics, proxy (credentials stripped) and tool-specific `TRIVY_*`-style variables; anything named like a token/key/secret/password is removed – API keys from `.env` never reach a child process |
| T | Tool writes outside the target | Working directory = scan target (or the temp dir for network targets) |
| D | Hanging tool, gigabytes of output | Hard timeouts per tool, 64 MB output cap per stream (process killed), below-normal priority; incomplete runs never auto-resolve findings |

Not done: Windows job objects / restricted tokens / AppContainer. Node has no API for them and
creating them from PowerShell requires `Add-Type` (runtime C# compilation), which Smart App
Control and AppLocker rightly block. Vigil never modifies or bypasses Smart App Control or other
system security settings. A future option is a small signed native helper.

### 8. Active web checks (domaudit, webscan, nuclei)

Only for targets that are allow-listed or explicitly confirmed; deep checks require a domain
ownership proof (DNS TXT or `.well-known`). The headless browser for DOM checks runs in its own
in-memory session with sandbox, no downloads and no permissions. No exploit payloads, no DoS,
no brute force; per-target rate limits.

## Build hardening

* Electron fuses set at build time (`electron-builder.config.js` → `electronFuses`):
  `RunAsNode` off, `EnableNodeOptionsEnvironmentVariable` off, `EnableNodeCliInspectArguments` off,
  `EnableEmbeddedAsarIntegrityValidation` on, `OnlyLoadAppFromAsar` on, `EnableCookieEncryption` on.
  Verify a build with `npx @electron/fuses read --app dist/win-unpacked/Vigil.exe`.
* Code signing via SignPath / Azure Trusted Signing (see `SIGNING.md`, `CODE_SIGNING.md`).
* Dependabot for npm and GitHub Actions; CI runs `npm test` and `npm audit --omit=dev`.

## Self-check

`npm test` runs Vigil's own static checks against `src/` and `electron/` and fails on any
critical finding or any high finding outside the rule-definition files. It also asserts the window
hardening flags, the CSP, the fuses and that `src/core/tools.js` spawns nothing outside the sandbox.

## Reporting

See [`SECURITY.md`](../SECURITY.md).
