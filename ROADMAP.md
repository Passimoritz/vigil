# Vigil – Roadmap

Ziel: ein Analysetool, das **alles Eigene** prüfen kann – Code, Abhängigkeiten, Webseiten,
Server, Container, Cloud – und dabei genau, nachvollziehbar, günstig und defensiv bleibt.

Legende: `[x]` erledigt · `[ ]` offen · **P1** als Nächstes · **P2** danach · **P3** später

---

## Als Nächstes (Top 6)

1. [ ] **P1** Code-Signing für Installer und App, damit Windows Smart App Control und SmartScreen nicht mehr blockieren (SignPath.io für Open Source oder Azure Trusted Signing)
2. [ ] **P1** Inkrementelle Scans: KI-Ergebnisse je Datei-Hash zwischenspeichern, nur geänderte Dateien neu analysieren (spart bei Folge-Scans den Großteil der Kosten und Zeit)
3. [ ] **P1** Auto-Update mit `electron-updater` (signierte Updates, Änderungsprotokoll in der App)
4. [ ] **P1** Erreichbarkeits-Analyse für Abhängigkeiten: Wird die verwundbare Funktion überhaupt aufgerufen? Senkt Fehlalarme deutlich
5. [ ] **P2** „Fix anwenden“: Patch als Diff zeigen, in eigenem Git-Branch anwenden, Tests laufen lassen
6. [ ] **P2** Geplante Scans (täglich/wöchentlich) mit Benachrichtigung bei neuen kritischen Befunden

---

## 1. Bereits erledigt

- [x] Zwei-Stufen-Analyse: Regeln und Datenbanken plus KI mit Gegenprüfung
- [x] Duplikat-Erkennung über alle Quellen
- [x] Lokale KI (Ollama, LM Studio, Jan, GPT4All, llama.cpp …) und Cloud (Claude, OpenAI, Gemini, kompatible)
- [x] Kosten-, Token- und Zeitvorschau vor dem Start, Kostenbremse, Live-Kosten während des Laufs
- [x] Befund-Lebenszyklus (offen, in Arbeit, behoben, Fehlalarm, akzeptiert) mit Auto-Behoben und Wiederkehr-Erkennung
- [x] Scope-Schutz: Freigabeliste, Bestätigung, Domain-Verifizierung, WAF-Backoff
- [x] Threat-Intel: CISA KEV und EPSS, Kontext-Risiko 0–100, Angriffspfade
- [x] SBOM-Paketsuche, Baseline, REST-API, Exporte (PDF, HTML, Markdown, SARIF, JSON)
- [x] Lösungen mit Schritten, Versions-Patches, Code-Schnipseln, Links (heise, Videos, NVD/OSV)
- [x] Neue Oberfläche: Seitenleiste, Liste mit Detailansicht, Radar-Animation, neues App-Icon
- [x] Installer-Assistent (Deutsch, Lizenz, Ordnerwahl), Einzelinstanz

---

## 2. Vertrauen & Auslieferung

- [ ] **P1** Code-Signing (siehe oben)
- [ ] **P1** Auto-Update mit Rollback
- [ ] **P2** End-to-End-Tests der Oberfläche (Playwright für Electron) in CI
- [ ] **P2** Lokale Absturzberichte (ohne Telemetrie, nur auf Wunsch exportierbar)
- [ ] **P2** Reproduzierbare Builds und eigene SBOM von Vigil im Release
- [ ] **P3** Portable Version (ohne Installation, z. B. für USB-Stick)
- [ ] **P3** macOS- und Linux-Builds (dmg, AppImage, deb)

## 3. Analyse-Tiefe: mehr finden, weniger Fehlalarme

- [ ] **P1** Erreichbarkeits-Analyse für verwundbare Pakete (Call-Graph)
- [ ] **P2** Datenfluss-Analyse über Dateigrenzen (Taint: Eingabe → Datenbank/Shell/HTML)
- [ ] **P2** Mehr Sprachen mit eigenen Regeln: Go, Rust, C#, PHP, Kotlin, Swift
- [ ] **P2** Infrastruktur als Code: Terraform, Kubernetes, Helm, CloudFormation, Ansible
- [ ] **P2** Secrets in der kompletten Git-Historie inklusive gelöschter Branches
- [ ] **P2** Lizenz-Compliance aus der SBOM (GPL in proprietärem Code, unbekannte Lizenzen)
- [ ] **P3** Cloud-Konfiguration nur lesend (AWS, Azure, GCP): offene Buckets, zu weite IAM-Rechte
- [ ] **P3** Windows-Host-Audit nach CIS-Benchmark (Defender, BitLocker, Firewall, Updates)
- [ ] **P3** Mobile Apps (APK/IPA): Berechtigungen, hartkodierte Schlüssel, unsichere Netzwerk-Konfig
- [ ] **P3** Docker-Host lesend prüfen (laufende Container, privilegierte Mounts, offene Ports)

## 4. KI: genauer, günstiger, hilfreicher

- [ ] **P1** Ergebnis-Cache je Datei-Hash und Modell (inkrementelle Scans)
- [ ] **P2** Prompt-Caching bei Anthropic/OpenAI für gemeinsame Prompt-Teile
- [ ] **P2** Modell-Routing: kleines Modell sortiert vor, großes prüft nur Verdächtiges
- [ ] **P2** „Frag die KI zu diesem Befund“: Chat mit Code-Kontext direkt in der Detailansicht
- [ ] **P2** Lernen aus Feedback: als Fehlalarm markierte Muster beim nächsten Lauf unterdrücken
- [ ] **P3** Mehrere Modelle gegeneinander prüfen lassen (Konsens senkt Fehlalarme)
- [ ] **P3** Benchmark-Suite mit bekannten verwundbaren Projekten (OWASP Juice Shop, DVWA), um die Trefferquote je Modell zu messen

## 5. Beheben statt nur finden

- [ ] **P2** Patch als Diff mit Syntax-Hervorhebung, „In Branch anwenden“, Tests danach
- [ ] **P2** Abhängigkeits-Updates gebündelt: ein Klick für alle sicheren Minor-/Patch-Updates
- [ ] **P2** Nachprüfung: nach einem Fix nur die betroffenen Befunde erneut prüfen
- [ ] **P3** Fälligkeiten (SLA) je Schweregrad mit Erinnerung

## 6. Workflow & Integrationen

- [ ] **P2** GitHub Action und GitLab-CI-Vorlage (SARIF-Upload, Abbruch ab Schweregrad)
- [ ] **P2** Pre-commit-Hook gegen Secrets
- [ ] **P2** Tickets anlegen: GitHub Issues, GitLab, Jira (mit Lösung und Fundstelle)
- [ ] **P2** Benachrichtigungen: E-Mail, Slack, Teams, Webhook
- [ ] **P3** VS-Code-Erweiterung: Befunde direkt im Editor, „In Vigil öffnen“
- [ ] **P3** Docker-Image von Vigil als reiner Scan-Server für CI

## 7. Berichte & Compliance

- [ ] **P2** Zuordnung zu OWASP Top 10, OWASP ASVS, CWE Top 25
- [ ] **P2** Trend-Grafiken: Sicherheitswert, offene Befunde und Behebungszeit über die Zeit
- [ ] **P3** Prüfkataloge für ISO 27001, BSI IT-Grundschutz, NIS2, DSGVO (technische Maßnahmen)
- [ ] **P3** Management-Bericht mit eigenem Logo und Zusammenfassung in Klartext

## 8. Bedienung

- [ ] **P2** Einrichtungs-Assistent beim ersten Start (KI wählen, erstes Projekt, Demo-Scan)
- [ ] **P2** Befehls-Palette (Strg+K): alle Aktionen per Tastatur
- [ ] **P2** Code-Ansicht im Befund mit markierter Zeile und Umgebung
- [ ] **P2** Gruppierung nach Datei, Kategorie oder Ziel
- [ ] **P3** Hell/Dunkel manuell umschaltbar, Schriftgröße einstellbar
- [ ] **P3** Englische Oberfläche
- [ ] **P3** Barrierefreiheits-Prüfung (Screenreader, Kontraste, Tastatur) der ganzen App

## 9. Team-Betrieb

- [ ] **P3** Server-Modus mit Postgres und Warteschlange (mehrere Rechner, ein Datenbestand)
- [ ] **P3** Benutzer, Rollen, Mandanten, Anmeldung per SSO
- [ ] **P3** Unveränderliches Audit-Log aller Statusänderungen

## 10. Sicherheit von Vigil selbst

- [ ] **P2** Externe Tools isoliert ausführen (eigener Prozess mit eingeschränkten Rechten)
- [ ] **P2** Prüfsummen und Signaturen beim Laden externer Tools und Threat-Intel prüfen
- [ ] **P2** Bedrohungsmodell dokumentieren und Vigil regelmäßig mit sich selbst prüfen
- [ ] **P3** Externer Pentest vor einer öffentlichen Version

---

**Grundsatz bleibt:** Vigil prüft nur eigene oder freigegebene Ziele, zerstörungsfrei, ohne
Angriffe, ohne Last-Tests, und schwärzt Secrets, bevor etwas an eine Cloud-KI geht.
