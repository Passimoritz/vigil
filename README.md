<p align="center">
  <img src="docs/images/banner.svg" alt="Vigil – defensive security audit for everything you own" width="100%">
</p>

<p align="center">
  <b>English</b> · <a href="README.de.md">Deutsch</a>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f2b23a"></a>
  <img alt="Platform: Windows" src="https://img.shields.io/badge/platform-Windows-0f1b2d">
  <img alt="Electron 45" src="https://img.shields.io/badge/Electron-45-47848f">
  <img alt="AI: local or cloud" src="https://img.shields.io/badge/AI-Ollama%20%7C%20Claude%20%7C%20OpenAI%20%7C%20Gemini-2b3a55">
  <img alt="Tests" src="https://img.shields.io/badge/tests-719%20core%20%2B%2065%20UI-2ea44f">
</p>

Vigil is a desktop app that checks **your own** code, websites, servers, containers, cloud accounts and files for security problems – and explains in plain language what is wrong and how to fix it.

It combines **fixed rules and live vulnerability databases** (which find known problems reliably) with an **AI review** (local via Ollama, or Claude, OpenAI, Gemini or any OpenAI-compatible service) that looks for logic and access flaws – and then has to **prove** every finding in a second cross-check. Everything is **non-destructive**: no attacks, no load tests, no password guessing.

<p align="center">
  <img src="docs/images/results.png" alt="Results view with security grade, severity filter and a finding with its fix" width="100%">
</p>

## Highlights

- **One place for everything you own** – drop a folder, a ZIP/JAR/EXE, type a URL, a server or a container image, or pick *This Windows PC*, Docker, AWS, Azure or Google Cloud (read-only).
- **Clear results** – a security grade, findings sorted by risk, no duplicates, and for each one: what is wrong, what can happen, and a concrete fix with copy-ready snippets.
- **AI that has to prove itself** – AI-only findings are cross-checked against the code; refuted ones are dropped, unclear ones are marked *unconfirmed*.
- **Privacy first** – with Ollama nothing leaves your computer. With cloud AI, detected secrets are redacted before sending. Keys and tokens are stored encrypted.
- **Up to date without app updates** – detection data (gitleaks rules, retire.js, CISA KEV, EPSS, OSV) is fetched and validated automatically, at least once a day.
- **Knows your history** – findings are tracked across runs: new, fixed, back again, false positive, accepted risk, plus trend, baseline and package search (SBOM).
- **Reports for everyone** – one-page executive summary (PDF), full PDF/HTML/Markdown report, SARIF and JSON for CI.
- **Cost and time up front** – you see the estimated cost and duration before the first token; the estimate learns from your real runs.

## Screenshots

| New scan | Overview |
| --- | --- |
| <img src="docs/images/scan.png" alt="New scan: targets, AI choice and cost preview" width="100%"> | <img src="docs/images/overview.png" alt="Overview across all scans with score, severity and trend" width="100%"> |
| **Finding details** | **Settings** |
| <img src="docs/images/overview-detail.png" alt="Detail drawer of a finding with explanation and fix" width="100%"> | <img src="docs/images/settings.png" alt="Settings grouped into General, Checks, Web & Login and Advanced" width="100%"> |

## How it works

<p align="center">
  <img src="docs/images/how-it-works.svg" alt="Collect → rules and databases → AI analysis → cross-check → merge and report" width="100%">
</p>

1. **Collect** – files, folders, archives and binaries are unpacked into units; websites, servers and systems are read passively.
2. **Rules & databases** – secrets (including deleted ones in Git history), vulnerable dependencies (OSV), actively exploited CVEs (CISA KEV), IaC (Terraform, Kubernetes, CloudFormation, Ansible), containers, Office macros and PDF scripts, malware (Microsoft Defender, signatures, optional MalwareBazaar), TLS, headers, cookies, DNS/mail and more. Installed tools such as semgrep, trivy, gitleaks or bandit are used automatically.
3. **AI analysis** – focused passes (access, injection, crypto, logic, config) follow data from source to sink. Unchanged files come from a cache, so repeat runs are fast and cheap.
4. **Cross-check** – a second AI step tries to refute every AI-only finding on the concrete code snippet.
5. **Merge & report** – duplicates are merged, each finding gets a context risk score (CVSS, KEV, EPSS, reachability) and a fix; several weaknesses can be linked into an *attack path*.

## What Vigil checks

| Area | Examples |
| --- | --- |
| Code | Injection, XSS, path traversal, SSRF, unsafe deserialization, JWT without verification, prototype pollution, weak crypto, `Math.random()` for tokens, taint flows across files, framework rules (Next.js, Nuxt, Laravel, Spring, Django, Rails, ASP.NET), crypto inventory, code quality – JS/TS, Python, Java, Go, Rust, C/C++, C#, PHP, Kotlin, Swift, Ruby, Dart, Scala, Elixir, Lua, PowerShell, Bash |
| AI apps & data | LLM tools with shell/file access, prompt injection paths, MCP configurations, pickle model files, personal data (IBAN, IDs, e-mail lists), secrets in logs and notebooks, OpenAPI/GraphQL definitions, SQL privileges |
| Credentials | API keys, passwords, private keys, connection strings – in current code and in Git history (always redacted) |
| Dependencies | Known CVEs (OSV, also offline), actively exploited ones (KEV), exploit probability (EPSS), reachability, malicious packages, abandoned packages, OpenSSF Scorecard, lockfile drift, vulnerable JS libraries, licenses, supply chain, SBOM export (CycloneDX, SPDX), VEX |
| Infrastructure | Dockerfiles, image layers, Compose, Kubernetes, Helm, Kustomize, Terraform, CloudFormation, Ansible, GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, nginx/Apache/Caddy configs, WordPress/Joomla/TYPO3 |
| Websites | Certificate, chain and domain expiry, security headers with Observatory grade, CSP and SRI suggestions, cookies, CORS, exposed files, secrets in delivered scripts, DNS & mail (SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, DNSSEC), subdomains, typo domains, Shodan InternetDB, security.txt, change watch, privacy before consent, accessibility, load time, imprint, broken links, SEO. For verified domains also: crawl, harmless test values, browser runtime check, login check, API access matrix, unauthenticated OpenAPI GET check |
| Files & programs | Malware scan (Defender, MalwareBazaar, YARA), digital signatures, PE hardening, bundled vulnerable libraries, Office macros, PDF JavaScript, archives (zip, tar, ISO, 7z, RAR, MSI, DMG …), e-mails (.eml, .msg), phishing links, obfuscated scripts, shortcuts and disk images, Android/iOS apps |
| Systems & accounts (read-only) | This Windows PC, installed programs, browser extensions, backup, router and home network, Linux servers via SSH, macOS, databases, Kubernetes, Docker, AWS/Azure/Google Cloud incl. IAM, GitHub/GitLab/Azure DevOps, Microsoft 365 / Google Workspace, Cloudflare, Hetzner, DigitalOcean, Vercel, Netlify, Have I Been Pwned |

## Staying current

- **Scheduled checks:** daily or weekly, reporting only new findings (Windows notification, webhook for Slack, Teams, Discord). Missed runs are caught up. Unattended, Vigil only checks approved targets.
- **Greenbone OpenVAS:** with at least 8 GB of memory and WSL present, Vigil offers on first start to set up the free Greenbone Community Edition: in a separate WSL environment with Docker Engine, without Docker Desktop. This downloads several GB and takes at least 40 GB of disk. Greenbone only needs memory during a scan. Checks of approved servers take much longer with it; under *Settings → Checks* you can cancel, switch off or remove it.
- **Linux packages:** the SSH check compares installed packages with OSV (Debian, Ubuntu, Rocky, AlmaLinux). Only package names and versions go to osv.dev.
- **End of support:** dates come daily from endoflife.date; the built-in values are only a fallback.
- **Tools:** Vigil updates installed tools daily from the official sources, with checksums and an automatic return to the old file if the new one does not run. For nmap, Windows asks for administrator rights once. An unmodified Git copy of Vigil fast-forwards itself. Can be switched off in the settings.

## Safe by design

Vigil is meant for systems **you own or are explicitly allowed to test**.

- Websites and servers are only checked after you confirm you are authorised; deep web checks require a **verified domain** (DNS TXT record or `/.well-known/sec-audit.txt`).
- All web checks are passive and rate-limited; if a target starts throttling, the check stops.
- No exploit payloads, no brute force, no load tests, and forms are never submitted – the login check only uses your test account, on your own host.
- Vigil suggests patches but never applies them.

## Getting started

**Requirements:** Windows 10/11, [Git](https://git-scm.com) and [Node.js](https://nodejs.org) 20 or newer. There is no installer: Vigil runs from source. Optional: [Ollama](https://ollama.com) for free, private local AI, or an API key for Claude, OpenAI or Gemini.

```bash
git clone https://github.com/Passimoritz/vigil.git
cd vigil
npm install
npm start
```

On first start a short introduction appears. **View a sample run** checks the bundled, deliberately vulnerable practice project in a few seconds – no AI needed.

API keys can be entered in the app (stored encrypted) or put into a `.env` file – see [`.env.example`](.env.example).

> **Why no installer?** Vigil has no code signature, and Windows Smart App Control blocks unsigned installers. Started from source, your own copy of the code runs in Electron. Smart App Control stays on, but it does not check Vigil's code in this case, and whether it allows Electron is decided by Windows. To update, run `git pull` and `npm install`. The "Start with Windows" option has no effect in this mode. See [SIGNING.md](SIGNING.md) for the signing status.

### Command line

```bash
node src/cli.js --provider ollama --model qwen2.5-coder:7b --out report.html ./my-project
node src/cli.js --provider anthropic --url https://my-site.example
node src/cli.js --image nginx:1.25
```

### Local REST API

Can be enabled under *Settings → Advanced*. It listens only on `127.0.0.1` (default port 7811), requires the displayed bearer token and only checks targets from your allow-list.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/stats` | open findings by severity, targets, recent runs |
| GET | `/api/findings?status=OPEN&severity=high` | filter findings |
| PATCH | `/api/findings/:id/status` | `{ "status": "FALSE_POSITIVE", "note": "…" }` |
| POST | `/api/scans` | `{ "targets": [{ "type": "url", "value": "https://…" }] }` → `202 { scanId }` |
| GET | `/api/scans/:id` | `QUEUED` / `RUNNING` / `COMPLETED` / `FAILED` |

```bash
curl -H "Authorization: Bearer <token>" "http://127.0.0.1:7811/api/findings?status=OPEN"
```

## Development

```bash
npm test          # core tests
npm run e2e       # real app window: click paths and accessibility
npm run bench     # detection rate on the practice project (with AI: npm run bench -- ollama qwen2.5-coder:14b)
npm run dist      # Windows installer (electron-builder)
```

```
electron/     app window, IPC, scan queue, local REST API, Ollama setup
src/core/     ingest, rules, modules, feeds, AI providers, analysis, store, reports
src/ui/       interface (index.html, styles.css, i18n.js, app/01–09 view scripts)
src/cli.js    command line
bench/        deliberately vulnerable practice project with expected findings
test/         core and UI tests
```

To add an AI provider, add an entry and a call in `src/core/providers.js` – everything else stays the same.

## Language

Vigil speaks **English (default)** and **German** (*Settings → General*): the interface, all finding texts, the reports (PDF, HTML, Markdown, SARIF) and the AI answers follow the selected language. On the command line use `--lang de` for German output.

## Roadmap, signing, license

- Planned features: [ROADMAP.md](ROADMAP.md)
- Code signing: [SIGNING.md](SIGNING.md) · policy: [CODE_SIGNING.md](CODE_SIGNING.md)
- License: [MIT](LICENSE)
