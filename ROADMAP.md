# Vigil – Roadmap

Interaktive Fassung zum Abhaken: https://claude.ai/artifact/HEcYEefqB4xW9EvUsZdoqS

Ziel: ein Analysetool, das alles Eigene prüft – Code, Pakete, Webseiten, Server, Container, Cloud – genau, verständlich und defensiv.

## Schon erledigt

Was Vigil heute bereits kann.

- [x] **Zweistufige Prüfung: Regeln und Datenbanken plus KI mit Gegenprüfung**  
  Feste Regeln finden Bekanntes sicher, die KI findet Logikfehler – und ein zweiter KI-Schritt sortiert Fehlalarme aus.
- [x] **Keine doppelten Meldungen**  
  Findet dasselbe Problem mehrere Werkzeuge, erscheint es nur einmal.
- [x] **Lokale und Cloud-KI frei wählbar**  
  Ollama, LM Studio und andere laufen kostenlos auf dem eigenen PC; Claude, OpenAI und Gemini für mehr Genauigkeit.
- [x] **Kosten und Dauer vor dem Start sehen**  
  Vorschau auf Tokens, Preis und Zeit, Kostenbremse und Live-Kosten während des Laufs.
- [x] **Verlauf jedes Befunds**  
  Offen, in Arbeit, behoben, Fehlalarm – Vigil erkennt selbst, was behoben wurde oder wiederkommt.
- [x] **Schutz vor Prüfen fremder Ziele**  
  Freigabeliste, ausdrückliche Bestätigung und Domain-Nachweis, bevor eine Webseite tiefer geprüft wird.
- [x] **Echte Gefahrenlage einbezogen**  
  Aktiv ausgenutzte Lücken (CISA) und Ausnutzungs-Wahrscheinlichkeit (EPSS) fließen in die Risikobewertung ein.
- [x] **Angriffswege in Klartext**  
  Zeigt, wenn mehrere kleine Schwächen zusammen einen echten Angriff ermöglichen – mit beteiligten Befunden zum Anklicken.
- [x] **Neue Oberfläche und Installer**  
  Seitenleiste, Liste mit Detailansicht, Radar-Animation, neues Icon und deutscher Installations-Assistent.

## Vertrauen & Auslieferung

Damit Vigil sich problemlos installieren und aktuell halten lässt.

- [x] **Installer und App digital signieren** · Aufwand mittel   · *vorbereitet – Zertifikat nötig, siehe [SIGNING.md](SIGNING.md)*
  Windows blockiert unsignierte Programme (Smart App Control, SmartScreen). Mit Signatur lässt sich Vigil normal per Doppelklick installieren.
- [ ] **Automatische Updates** · **Als Nächstes** · Aufwand mittel  
  Neue Versionen kommen von selbst, mit Änderungsliste in der App und der Möglichkeit, zurückzugehen.
- [x] **Automatische Tests der Oberfläche** · Aufwand mittel  
  Jeder Klickweg wird vor einer neuen Version automatisch durchgespielt, damit nichts unbemerkt kaputtgeht.
- [x] **Absturzberichte nur lokal** · Aufwand klein  
  Bei einem Fehler legt Vigil einen Bericht auf dem PC ab, den man bei Bedarf weitergeben kann – ohne heimliche Datenübertragung.
- [ ] **Nachprüfbare Versionen** · Danach · Aufwand mittel  
  Jede Version kommt mit einer Liste aller enthaltenen Bausteine und lässt sich aus dem Quellcode identisch nachbauen.
- [x] **Version ohne Installation** · Aufwand klein  
  Vigil direkt vom USB-Stick oder aus einem Ordner starten.
- [ ] **Vigil für macOS und Linux** · Später · Aufwand groß  
  Dieselbe App auch auf Mac und Linux.

## Genauer finden, weniger Fehlalarme

Mehr echte Probleme erkennen und weniger Unnötiges melden.

- [x] **Prüfen, ob eine verwundbare Funktion überhaupt benutzt wird** · Aufwand groß  
  Eine Lücke in einem Paket ist nur gefährlich, wenn der eigene Code die betroffene Stelle aufruft. Das streicht viele Fehlalarme.
- [x] **Datenflüsse über mehrere Dateien verfolgen** · Aufwand groß  
  Erkennt, wenn eine Eingabe von außen über mehrere Schritte ungeprüft in Datenbank, Befehlszeile oder Webseite landet.
- [x] **Mehr Programmiersprachen** · Aufwand mittel  
  Eigene Regeln auch für Go, Rust, C#, PHP, Kotlin und Swift.
- [x] **Server-Einrichtung als Code prüfen** · Aufwand mittel  
  Fehler in Terraform, Kubernetes, Helm, CloudFormation und Ansible finden, bevor sie live gehen.
- [x] **Zugangsdaten in der gesamten Git-Historie finden** · Aufwand klein  
  Auch Schlüssel, die längst gelöscht wurden, stehen oft noch in alten Versionen und sind dort weiter abrufbar.
- [x] **Lizenzen der genutzten Pakete prüfen** · Aufwand klein  
  Warnt, wenn ein Paket eine Lizenz hat, die zum eigenen Projekt nicht passt.
- [x] **Cloud-Konten nur lesend prüfen** · Aufwand groß  
  Findet offene Speicher und zu weit gefasste Rechte in AWS, Azure und Google Cloud, ohne etwas zu ändern.
- [x] **Windows-PC nach Sicherheitsstandard prüfen** · Aufwand mittel  
  Prüft Virenschutz, Festplattenverschlüsselung, Firewall und Updates nach dem CIS-Leitfaden.
- [x] **Handy-Apps prüfen** · Aufwand groß  
  Untersucht Android- und iOS-Apps auf zu viele Berechtigungen und eingebaute Schlüssel.
- [x] **Laufende Docker-Container prüfen** · Aufwand mittel  
  Zeigt Container mit zu vielen Rechten, gefährlichen Freigaben oder offenen Ports – nur lesend.

## KI: günstiger und hilfreicher

Weniger Kosten, schnellere Läufe und Antworten auf Rückfragen.

- [x] **Nur Geändertes neu prüfen** · Aufwand mittel  
  Vigil merkt sich die KI-Ergebnisse je Datei. Beim nächsten Lauf werden nur geänderte Dateien neu analysiert – das spart den Großteil der Kosten und Zeit.
- [x] **Wiederkehrende Anweisungen zwischenspeichern** · Aufwand klein  
  Gleichbleibende Teile der KI-Anfrage werden beim Anbieter gespeichert und günstiger abgerechnet.
- [x] **Kleines Modell sortiert vor, großes prüft nach** · Aufwand mittel  
  Ein günstiges Modell siebt Unauffälliges aus; nur Verdächtiges geht an das teure, genaue Modell.
- [x] **Rückfragen zu einem Befund stellen** · Aufwand mittel  
  Direkt in der Detailansicht fragen, z. B. „Ist das bei mir wirklich ausnutzbar?“ – mit dem passenden Code als Kontext.
- [x] **Aus Fehlalarmen lernen** · Aufwand klein  
  Was als Fehlalarm markiert wurde, meldet Vigil beim nächsten Mal nicht erneut.
- [x] **Zwei Modelle gegeneinander prüfen lassen** · Aufwand mittel  
  Nur was beide Modelle finden, gilt als sicher – das senkt Fehlalarme weiter.
- [x] **Trefferquote messen** · Aufwand mittel  
  Regelmäßige Testläufe gegen absichtlich unsichere Übungsprojekte zeigen, wie gut jedes Modell wirklich findet.

## Beheben statt nur finden

Vom Befund zur fertigen Korrektur.

- [ ] **Korrektur mit einem Klick anwenden** · **Als Nächstes** · Aufwand groß  
  Vigil zeigt die Änderung Zeile für Zeile, legt sie in einem eigenen Git-Zweig an und lässt danach die Tests laufen.
- [ ] **Alle sicheren Paket-Updates auf einmal** · Danach · Aufwand mittel  
  Kleinere Updates ohne Risiko für Brüche werden gesammelt eingespielt.
- [ ] **Nur die behobenen Stellen nachprüfen** · Danach · Aufwand klein  
  Nach einer Korrektur prüft Vigil gezielt nur die betroffenen Befunde – in Sekunden statt Minuten.
- [ ] **Fristen je Dringlichkeit** · Später · Aufwand klein  
  Kritisches muss in wenigen Tagen behoben sein, Kleineres in Wochen – Vigil erinnert rechtzeitig.

## Arbeitsabläufe & Anbindungen

Vigil dort einsetzen, wo ohnehin gearbeitet wird.

- [ ] **Geplante Prüfungen mit Benachrichtigung** · **Als Nächstes** · Aufwand mittel  
  Täglich oder wöchentlich automatisch prüfen und per E-Mail, Slack, Teams oder Webhook melden, wenn etwas Neues und Kritisches auftaucht.
- [ ] **Prüfung bei jeder Code-Änderung** · Danach · Aufwand mittel  
  Fertige Vorlagen für GitHub und GitLab: Vigil prüft jeden Push und stoppt, wenn etwas Kritisches dazukommt.
- [ ] **Zugangsdaten schon vor dem Speichern abfangen** · Danach · Aufwand klein  
  Ein Haken in Git verhindert, dass Schlüssel überhaupt erst ins Repository gelangen.
- [ ] **Aufgaben direkt anlegen** · Danach · Aufwand mittel  
  Befunde mit Lösung und Fundstelle als Aufgabe in GitHub, GitLab oder Jira übernehmen.
- [ ] **Befunde direkt im Code-Editor** · Später · Aufwand groß  
  Eine Erweiterung für VS Code markiert betroffene Zeilen und öffnet Details in Vigil.
- [ ] **Vigil als reiner Prüf-Server** · Später · Aufwand mittel  
  Ein Docker-Abbild, das Prüfungen ohne Oberfläche ausführt, etwa für Build-Server.

## Berichte & Nachweise

Ergebnisse für Chef, Kunden oder Prüfer aufbereiten.

- [x] **Zuordnung zu bekannten Sicherheitslisten** · Aufwand klein  
  Jeder Befund zeigt, zu welchem Punkt der OWASP Top 10 und der CWE-Liste er gehört – Prüfer erwarten das.
- [x] **Entwicklung über die Zeit** · Aufwand mittel  
  Grafiken zeigen, ob der Sicherheitswert steigt, wie viele Befunde offen sind und wie schnell behoben wird.
- [x] **Prüfkataloge für Normen** · Aufwand groß  
  Technische Nachweise für ISO 27001, BSI IT-Grundschutz, NIS2 und DSGVO.
- [x] **Bericht für die Geschäftsführung** · Aufwand klein  
  Eine Seite in Klartext mit eigenem Logo: Lage, Risiken, nächste Schritte.

## Bedienung

Schneller ans Ziel, auch ohne Vorwissen.

- [x] **Begleitung beim ersten Start** · Aufwand mittel  
  Ein kurzer Assistent hilft bei der KI-Wahl, dem ersten Projekt und zeigt einen Beispiel-Lauf.
- [x] **Alles per Tastatur** · Danach · Aufwand klein  
  Mit Strg+K jede Aktion suchen und ausführen.
- [x] **Betroffenen Code direkt anzeigen** · Aufwand mittel  
  In der Detailansicht die markierte Zeile mit etwas Umgebung sehen, ohne den Editor zu öffnen.
- [x] **Befunde anders sortieren** · Danach · Aufwand klein  
  Nach Datei, Art des Problems oder Ziel gruppieren statt nur nach Dringlichkeit.
- [x] **Hell/Dunkel und Schriftgröße wählbar** · Aufwand klein  
  Unabhängig von der Windows-Einstellung umschalten und die Schrift größer stellen.
- [x] **Englische Oberfläche** · Aufwand mittel  
  Vigil auch auf Englisch nutzen.
- [x] **Barrierefreiheit prüfen** · Aufwand mittel  
  Bedienung mit Bildschirmleser, nur mit Tastatur und mit ausreichenden Kontrasten sicherstellen.

## Arbeiten im Team

Für mehrere Personen und Rechner.

- [ ] **Gemeinsamer Datenbestand** · Später · Aufwand groß  
  Mehrere Rechner teilen sich Befunde und Verlauf über einen zentralen Server.
- [ ] **Benutzer, Rollen und Firmen-Anmeldung** · Später · Aufwand groß  
  Wer darf prüfen, wer nur lesen – mit Anmeldung über das Firmenkonto (SSO).
- [ ] **Lückenloses Änderungsprotokoll** · Später · Aufwand mittel  
  Wer hat wann welchen Befund als behoben oder Fehlalarm markiert – nachträglich nicht veränderbar.

## Sicherheit von Vigil selbst

Ein Sicherheitswerkzeug muss selbst besonders sicher sein.

- [x] **Fremde Werkzeuge abgeschottet ausführen** · Danach · Aufwand mittel  
  Zusatzprogramme wie trivy oder semgrep laufen mit möglichst wenig Rechten, damit ein Fehler in ihnen nicht den PC gefährdet.
- [x] **Heruntergeladene Daten auf Echtheit prüfen** · Danach · Aufwand klein  
  Zusatzprogramme und Gefahren-Listen werden vor der Nutzung über Prüfsummen und Signaturen kontrolliert.
- [x] **Eigene Schwachstellen systematisch suchen** · Danach · Aufwand klein  
  Ein dokumentiertes Bedrohungsmodell und regelmäßige Prüfläufe von Vigil gegen sich selbst.
- [ ] **Externe Sicherheitsprüfung** · Später · Aufwand mittel  
  Vor einer öffentlichen Version prüfen unabhängige Fachleute Vigil.

---

Grundsatz: Vigil prüft nur eigene oder freigegebene Ziele, zerstörungsfrei, ohne Angriffe und ohne Last-Tests, und schwärzt Zugangsdaten, bevor etwas an eine Cloud-KI geht.

## Weitere Prüfungen (Ideen)

Für Vigil gedacht, noch nicht umgesetzt. Alle Ideen bleiben zerstörungsfrei und lesen nur.

- [x] **Mehr tagesaktuelle Quellen** · Aufwand klein
  Weitere geprüfte Feeds über dasselbe System einbinden:
  - Zertifikats-Transparenz (neue, unbekannte Zertifikate für die eigene Domain),
  - Phishing-Listen (taucht die eigene Domain dort auf?),
  - Have-I-Been-Pwned für die Firmen-Domain.
- [x] **Abgelaufene oder bald ablaufende Zertifikate und Domains** · Aufwand klein
  Warnung 30, 14 und 3 Tage vorher, auch für Subdomains.
- [x] **E-Mail-Sicherheit vollständig** · Aufwand klein
  MTA-STS, TLS-RPT, BIMI und DNSSEC, zusätzlich zu SPF, DMARC und DKIM.
- [x] **Browser-Erweiterungen und installierte Programme** · Aufwand mittel
  Veraltete Programme auf dem PC (über winget/Registry) gegen bekannte Lücken abgleichen.
- [x] **WLAN und Router im eigenen Netz** · Aufwand mittel
  Nur lesend:
  - offene Verwaltungsoberflächen im LAN,
  - UPnP,
  - veraltete Router-Firmware nach Herstellerangabe.
- [x] **Datenbanken direkt** · Aufwand mittel
  Mit eigenem Lesezugang:
  - Standardpasswörter,
  - öffentliche Rechte,
  - unverschlüsselte Verbindungen,
  - veraltete Version (PostgreSQL, MySQL, MongoDB, Redis).
- [x] **CI/CD-Konten** · Aufwand mittel
  GitHub-, GitLab- und Azure-DevOps-Einstellungen über die offizielle API, nur lesend:
  - Branch-Schutz,
  - Secret-Scanning an,
  - zu weit gefasste Tokens.
- [x] **Microsoft 365 / Google Workspace** · Aufwand groß
  Nur lesend:
  - Mehr-Faktor-Anmeldung für alle,
  - veraltete Anmeldeverfahren,
  - offene Freigaben.
- [x] **Datenschutz-Check von Webseiten** · Aufwand mittel
  Welche Cookies und Dritt-Dienste vor der Einwilligung geladen werden (DSGVO/TTDSG).
- [x] **Software-Stückliste ausgeben** · Aufwand klein
  SBOM im CycloneDX- und SPDX-Format für jedes geprüfte Projekt.

## Wunschliste vom 5. November 2026

126 Punkte aus der interaktiven Wunschliste sind umgesetzt – in acht Bereichen:

- **Code & Projekte:** Framework-Regeln, C/C++ und sieben weitere Sprachen, SQL-Rechte, OpenAPI/GraphQL, Krypto-Inventar, KI-Apps und MCP-Konfigurationen, Pickle-Modelldateien, personenbezogene Daten, Geheimnisse in Logs und Notebooks, Texterkennung in Bildern, Webserver-Konfigurationen, Code-Qualität, Regeln als YAML-Dateien.
- **Lieferkette & Container:** Live-Prüfung gefundener Schlüssel (optional), verwaiste Pakete, OpenSSF Scorecard, Schadpakete, Lockfile-Abgleich, Image-Schichten, Dockerfile, Helm/Kustomize, GitHub Actions, GitLab/Azure/Jenkins, CMS, SBOM-Export.
- **Webseiten:** Zertifikats- und Domain-Ablauf, MTA-STS/TLS-RPT/BIMI/DNSSEC, Datenschutz vor der Einwilligung, CSP- und SRI-Vorschläge, Geheimnisse in Skripten, Subdomains, Shodan InternetDB, Tippfehler-Domains, Änderungs-Wächter, security.txt, TLS im Detail, API-Abruf ohne Anmeldung, Observatory-Note, Barrierefreiheit, Ladezeit, Impressum, defekte Links, SEO.
- **Dateien & Erkennungsdaten:** weitere Archivformate, E-Mails, Phishing-Links, YARA, verschleierte Skripte, Verknüpfungen, Programm-Schutzfunktionen, eingebaute Bibliotheken, USB-Prüfung, Zertifikats-Transparenz, Phishing-Listen, Hersteller-Warnungen, Alarm bei neuen Lücken, OSV offline, aktuelle Vorlagen.
- **PC, Server & Cloud:** Programme, Browser-Erweiterungen, Router, Heimnetz, Linux per SSH, macOS, Datenbanken, Kubernetes, Datensicherung, CI/CD-Konten, Microsoft 365/Google Workspace, Cloud-Rechte, weitere Anbieter, Have I Been Pwned.
- **KI & Beheben:** Fix als Diff, Erklärung in drei Stufen, Laufzusammenfassung, Modellwahl nach Hardware, sieben neue Anbieter, Monatsbudget, KI darf nachschlagen, Bedrohungsmodell, strenger Datenschutz, eigene Vorgaben, Protokoll, Datei-Rangfolge, Upgrade-Hinweise, ablaufende Risikoakzeptanz.
- **Berichte & Bedienung:** VEX, Branding, Vergleichsbericht, Excel/CSV/Word, Audit-Paket, signierte Berichte, CRA/SOC 2/PCI DSS/ASVS/HIPAA, Badge, Befehlspalette, Gruppierung, Läufe vergleichen, Notizen, Rückgängig, Pause, Taskleiste, Glossar, anpassbare Übersicht, übersetzte Code-Kommentare, Browser-Erweiterung, CI-Formate.
- **Vigil selbst & Qualität:** Werkzeug-Sandbox, Download-Prüfung, Bedrohungsmodell und Selbst-Scan, verschlüsselte Befunde, App-Sperre, Electron-Fuses, Dependabot und CI, SECURITY.md, Bildvergleich der Oberfläche, Testabdeckung, größerer Benchmark, Architektur-Doku, aufgeteilte Oberfläche.

Nicht umgesetzt: Windows Hello für die App-Sperre (Electron bietet dafür unter Windows keine Schnittstelle). Noch nicht an echten Systemen ausprobiert: Live-Audits für Router, Linux, Datenbanken, Cloud- und SaaS-Konten sowie die neuen Feed-Adressen – die Tests laufen mit Attrappen.
