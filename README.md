# Vigil

KI-gestütztes, **defensives** Sicherheits-Audit für deine **eigenen** Artefakte: Dateien, Ordner, ZIP/JAR, EXE/Binaries sowie Links/Endpunkte, für die du eine Prüf-Berechtigung hast.

Vigil sammelt das Material, macht eine schnelle statische Vorprüfung (Secrets, Abhängigkeiten, riskante Muster) und lässt dann eine KI – **lokal (Ollama)** oder extern (**Claude, OpenAI, Gemini** oder jeder OpenAI-kompatible Anbieter) – Schwachstellen finden, einordnen und **konkret erklären, wie man sie patcht**.

## Was Vigil tut

Pro Befund bekommst du:
- **Schweregrad** (Kritisch → Info) und, wenn möglich, einen **CVSS-Basiswert**
- **Ort** (Datei:Zeile / Komponente) und **Kategorie**
- **Erreichbarkeit/Risiko** – konzeptionell: welcher Eingang, welche Voraussetzungen, wie realistisch (damit du priorisieren kannst)
- **Auswirkung** bei Ausnutzung
- **Behebung** Schritt für Schritt + **konkreter Patch** (Code/Config)

## Was Vigil bewusst NICHT tut

- Keine einsatzfertigen Angriffs-Payloads, keine Exploit-Ausführung, kein DoS, keine Massen-Scans.
- Netzwerkziele (Link/IP) werden **nur passiv** abgerufen (Antwort + Header lesen) und **nur mit bestätigter Berechtigung**. Kein Portscan, kein aktives Eindringen.

Gedacht für Code/Systeme, die dir gehören oder die du ausdrücklich prüfen darfst.

## Installation

```bash
cd vigil
npm install
```

API-Schlüssel optional in `.env` (siehe `.env.example`) **oder** in der App unter *Einstellungen*.
Für den lokalen Betrieb: [Ollama](https://ollama.com) installieren und z. B. `ollama pull qwen2.5-coder`.

## Starten

```bash
npm start
```

Dann: Anbieter oben wählen → Dateien/Ordner reinziehen (oder Link/IP eintragen) → **Analyse starten**. Ergebnis als **HTML/Markdown** exportierbar.

## CLI (zum Testen ohne GUI)

```bash
node src/cli.js --provider ollama --model qwen2.5-coder --out report.html ./mein-projekt
node src/cli.js --provider anthropic --model claude-sonnet-4-5 --url https://meine-seite.example
node src/cli.js --image nginx:1.25
```

`--image` prüft ein Container-Image über trivy (Pakete, CVEs, Fehlkonfigurationen); trivy muss installiert sein.

## Befund-Lebenszyklus

Vigil merkt sich jeden Befund über alle Läufe hinweg (lokal in `findings-store.json` im App-Datenordner). Der Fingerabdruck ist `SHA-256(Ziel:Scanner:Regel-ID:Ort)`.

| Status | Bedeutung |
| --- | --- |
| Offen / In Arbeit | aktiv; bei jedem Fund wird „zuletzt gesehen“ aktualisiert |
| Fehlalarm / Risiko akzeptiert | ausgeblendet; bleibt so, auch wenn der Befund wieder auftaucht |
| Behoben | gesetzt von Hand oder automatisch, wenn ein vollständig gelaufener Scanner den Befund nicht mehr findet |

Taucht ein behobener Befund wieder auf, steht er erneut auf „Offen“ und ist als **Regression** markiert. KI-Befunde werden nie automatisch geschlossen, weil die KI nicht bei jedem Lauf exakt dasselbe findet. Geschwärzte Fundstellen (`evidence`) zeigen bei Secrets nur die ersten 3 und letzten 2 Zeichen; der Klartext wird nie gespeichert.

Die **Übersicht** zeigt offene Befunde nach Schweregrad, alle Ziele mit „Erneut prüfen“, die letzten Läufe und eine filterbare Befundtabelle mit Statuswahl.

## Scope & Sicherheit

- Webadressen und Server werden nur geprüft, wenn sie auf der **Freigabeliste** stehen (Einstellungen) oder beim Hinzufügen ausdrücklich bestätigt werden. Bestätigte Hosts kommen automatisch auf die Liste. `example.com` gilt auch für Subdomains, `*.example.com` nur für Subdomains.
- Alle Web-Checks sind passiv (eine GET/OPTIONS-Anfrage plus eine kleine, feste Liste versehentlich offener Pfade) und gedrosselt: höchstens 2 parallel, mindestens 400 ms Abstand je Host. OSV-Abfragen: höchstens 3 parallel.
- Externe Tools laufen über `spawn` mit Argument-Arrays, ohne Shell. Eingaben aus UI und API sowie die JSON-Ausgaben von trivy, semgrep und gitleaks werden mit **Zod** validiert.

## Lokale REST-API

In den Einstellungen einschaltbar. Sie lauscht nur auf `127.0.0.1` (Standard-Port 7811), verlangt das angezeigte Bearer-Token, weist Browser-Anfragen (mit `Origin`-Header) ab und prüft ausschließlich Ziele von der Freigabeliste.

| Methode | Pfad | Zweck |
| --- | --- | --- |
| GET | `/api/stats` | offene Befunde nach Schweregrad, Ziele, letzte Läufe |
| GET | `/api/targets` | Ziele inkl. offener Befunde |
| GET | `/api/findings?status=OPEN&severity=high&targetId=&q=` | Befunde filtern |
| PATCH | `/api/findings/:id/status` | `{ "status": "FALSE_POSITIVE", "note": "…" }` |
| POST | `/api/scans` | `{ "targets": [{ "type": "url", "value": "https://…" }] }` → `202 { scanId }` |
| GET | `/api/scans/:id` | Status `QUEUED` / `RUNNING` / `COMPLETED` / `FAILED` |

```bash
curl -H "Authorization: Bearer <Token>" "http://127.0.0.1:7811/api/findings?status=OPEN"
```

Scans laufen nacheinander über eine Warteschlange, egal ob sie aus der App oder über die API kommen.

## Architektur

Vigil verlässt sich nicht auf reine KI-Einschätzung, sondern arbeitet zweistufig:

1. **Deterministische Basis** – Secret-/Muster-Regeln, Schwachstellen-DB (OSV), optional semgrep, bandit, gitleaks, trivy u. a.
2. **KI-Analyse** – fokussierte Durchgänge, die Datenflüsse von der Quelle zur Senke verfolgen und jeden Befund als prüfbare Hypothese formulieren.
3. **Gegenprüfung** – ein zweiter KI-Schritt versucht, jeden *nur* von der KI gemeldeten Befund am konkreten Code-Ausschnitt zu widerlegen. Widerlegte Funde werden verworfen, unklare als „unbestätigt“ markiert.
4. **Zusammenführen & Kontext** – Duplikate über alle Quellen werden vereint; jeder Befund bekommt einen Beleg-Status (mehrfach bestätigt / regelbasiert / KI-gegengeprüft / unbestätigt) und Kontext (Request-Handler, Internet-erreichbar, sensible Daten, Lieferkette).

Datenschutz: Bei externen KI-Anbietern werden erkannte Secrets vor dem Versand geschwärzt (abschaltbar, CLI `--no-redact`). Mit Ollama verlässt nichts den Rechner. Die Gegenprüfung lässt sich mit `--no-validate` abschalten.

Vigil schlägt Patches vor, wendet sie aber nie selbst an – jede Änderung bleibt deine Entscheidung.

```
electron/           GUI-Prozess (Fenster, IPC, Datei-Dialoge)
  main.js
  preload.js
  orchestrator.js   Scan-Warteschlange + Übernahme in den Befund-Speicher
  api.js            lokale REST-API (127.0.0.1, Token)
  ollama.js         Ollama installieren/starten, Modelle laden
src/
  core/
    ingest.js       Dateien/Ordner/ZIP/JAR/EXE/Link/IP -> Prüf-Units
    prescan.js      Secrets, Dependencies, riskante Muster (ohne KI)
    webscan.js      passive Web-/TLS-Prüfung (Header, CSP, Zertifikat, Versionen)
    tools.js        externe Scanner (trivy fs/image, semgrep, gitleaks, …)
    providers.js    Ollama / Anthropic / OpenAI / Gemini / OpenAI-kompatibel
    analyze.js      Prompt-Bau, Batching, JSON-Befunde
    harness.js      Schwärzen, Code-Slices, Gegenprüfung, Beleg-Status & Kontext
    store.js        Befund-Lebenszyklus (Fingerabdruck, Auto-Resolve, Regression)
    scope.js        Freigabeliste / Scope-Durchsetzung
    validation.js   Zod-Schemas für Eingaben und Scanner-Ausgaben
    ratelimit.js    Drosselung externer Anfragen
    report.js       HTML-, Markdown- und SARIF-Report
    schema.js       Befund-Format, CVSS/Severity, Duplikat-Erkennung
    index.js        Pipeline-Fassade (runAudit)
  ui/               Oberfläche (index.html, styles.css, renderer.js)
  cli.js            Kommandozeile
```

Neuer Anbieter: in `src/core/providers.js` einen Eintrag + Aufruf ergänzen – der Rest bleibt gleich.
