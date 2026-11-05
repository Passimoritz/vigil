# Security policy

Vigil is a security tool, so we take vulnerabilities in Vigil itself seriously.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x (latest release) | ✔ security fixes |
| < 0.2 | ✘ please update |

Only the latest minor release receives fixes. Development builds from `main` are fixed by the next release.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately via **GitHub Security Advisories**:
<https://github.com/Passimoritz/vigil/security/advisories/new>
(repository → *Security* → *Report a vulnerability*).

Please include:

* affected version and Windows version,
* what an attacker needs (local account, network position, a crafted project/website/feed …),
* steps to reproduce or a proof of concept – without real third-party data,
* the impact you see (e.g. code execution, secret disclosure, bypass of the scope check).

If GitHub Security Advisories is not possible for you, write to passimoritz@gmail.com with the subject
"Vigil security" and we will open a private advisory for you.

## What to expect

| Step | Target time |
| --- | --- |
| Acknowledgement | within 3 working days |
| First assessment (valid / severity) | within 7 days |
| Fix for critical / high issues | within 30 days |
| Fix for medium / low issues | next regular release, at the latest 90 days |

We will keep you updated, credit you in the release notes and the advisory (unless you prefer not
to be named) and publish the advisory once a fixed release is available. Please give us the time
above before disclosing details publicly.

## Scope

In scope: the Vigil desktop app and CLI in this repository (Electron main process, renderer, IPC,
REST API, feed handling, stored data, build configuration).

Out of scope: findings in the deliberately vulnerable benchmark project `bench/vulnerable-app/`,
vulnerabilities of third-party scanners Vigil can call (report those upstream), and attacks that
require an already compromised Windows account.

Vigil only checks what you own. Do not use it, or reports about it, to test systems without permission.

The threat model is in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
