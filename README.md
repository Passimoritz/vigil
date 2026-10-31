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
```

## Architektur

```
electron/           GUI-Prozess (Fenster, IPC, Datei-Dialoge)
  main.js
  preload.js
src/
  core/
    ingest.js       Dateien/Ordner/ZIP/JAR/EXE/Link/IP -> Prüf-Units
    prescan.js      Secrets, Dependencies, riskante Muster (ohne KI)
    providers.js    Ollama / Anthropic / OpenAI / Gemini / OpenAI-kompatibel
    analyze.js      Prompt-Bau, Batching, JSON-Befunde
    report.js       HTML- und Markdown-Report
    schema.js       Befund-Format + CVSS/Severity
    index.js        Pipeline-Fassade (runAudit)
  ui/               Oberfläche (index.html, styles.css, renderer.js)
  cli.js            Kommandozeile
```

Neuer Anbieter: in `src/core/providers.js` einen Eintrag + Aufruf ergänzen – der Rest bleibt gleich.
