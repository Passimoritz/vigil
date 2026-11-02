# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).

## What gets signed

Only release builds of Vigil produced by the GitHub Actions workflow [`.github/workflows/release.yml`](.github/workflows/release.yml) from this repository are signed:

- the application files (`Vigil.exe` and the Electron runtime files built from this source)
- the installer `Vigil-Setup-<version>.exe`
- the portable build `Vigil-Portable-<version>.exe`

Local builds and pull requests from forks are never signed. Every signed file can be traced to a public commit and a public workflow run.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [Passimoritz](https://github.com/Passimoritz) |
| Approvers (release signing) | [Passimoritz](https://github.com/Passimoritz) |

Every release signing request must be approved manually by an approver in SignPath. Multi-factor authentication is required for all team members on GitHub and SignPath.

## Privacy policy

Vigil itself does not collect or send any usage data, telemetry or crash reports. Crash reports are only written to a local folder on your computer.

Network connections only happen in three cases:

- **Scanning a target you chose.** This covers websites and servers that you have confirmed you may check, plus read-only queries to your own cloud accounts made through your own command-line tools.
- **Public vulnerability data.** Vigil downloads data from OSV.dev, the CISA KEV catalogue and FIRST EPSS.
- **Cloud AI, if you choose it.** When you pick a cloud AI provider (Anthropic, OpenAI, Google Gemini) and enter your own API key, the code under analysis is sent to that provider. Detected secrets are redacted before sending. Local AI (Ollama) keeps everything on your computer.

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.
