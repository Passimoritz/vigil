# Vigil signieren

> **Stand November 2026:** Vigil wird nicht signiert und nicht als Installer verteilt, sondern aus dem Quellcode gestartet (siehe README). Kostenlos und ohne Klarnamen käme nur [OSSign](https://ossign.org) infrage: Dort ist die Antragstellung derzeit ausgesetzt, und es verlangt mindestens 6 Monate Projektaktivität, also frühestens Mai 2027. Die Anleitungen unten gelten nur, falls das später kommt. **Weg C (SignPath) scheidet aus:** Die [Bedingungen](https://signpath.org/terms) schließen Software aus, die Schwachstellen aufspürt, etwa offene Ports oder fehlenden Passwortschutz.

Windows blockiert unsignierte Programme: **Smart App Control** verhindert den Start ganz, **SmartScreen** zeigt eine Warnung. Damit Vigil per Doppelklick installiert werden kann, müssen Installer und App mit einem Zertifikat signiert sein, dem Windows vertraut.

Ein selbst erstelltes Zertifikat hilft dabei **nicht**: Windows kennt es nicht, und es auf dem eigenen PC als vertrauenswürdig einzutragen, würde nur dort helfen und den Rechnerschutz schwächen.

## Der Build ist vorbereitet

`npm run dist` signiert automatisch, sobald Zugangsdaten als Umgebungsvariablen gesetzt sind. Die Logik steckt in [electron-builder.config.js](electron-builder.config.js). Ohne Zugangsdaten wird wie bisher unsigniert gebaut.

### Weg A – Azure Trusted Signing (empfohlen)

Microsofts eigener Signierdienst. Von Smart App Control und SmartScreen direkt anerkannt, ohne monatelangen Reputationsaufbau.

- **Kosten:** rund 10 US-Dollar im Monat (Basic-Tarif), Abrechnung über ein Azure-Abonnement.
- **Voraussetzung:** Identitätsprüfung durch Microsoft. Für Einzelpersonen nur in einigen Ländern verfügbar, sonst für Firmen mit mehrjähriger Geschäftshistorie. Den aktuellen Stand nennt die Microsoft-Dokumentation.
- **Einrichtung:**
  1. Im Azure-Portal ein „Trusted Signing Account“ anlegen.
  2. Die Identitätsprüfung durchlaufen.
  3. Ein Zertifikatprofil vom Typ „Public Trust“ erstellen.
  4. Eine App-Registrierung mit der Rolle „Trusted Signing Certificate Profile Signer“ anlegen.
- **Umgebungsvariablen** vor `npm run dist` setzen:

  ```
  AZURE_TENANT_ID=…
  AZURE_CLIENT_ID=…
  AZURE_CLIENT_SECRET=…
  VIGIL_SIGN_ENDPOINT=https://weu.codesigning.azure.net
  VIGIL_SIGN_ACCOUNT=<Name des Signing-Accounts>
  VIGIL_SIGN_PROFILE=<Name des Zertifikatprofils>
  ```

### Weg B – Klassisches Code-Signing-Zertifikat

Ein OV- oder EV-Zertifikat von einer Zertifizierungsstelle wie Certum, Sectigo oder DigiCert.

- **Kosten:** etwa 70 bis 400 Euro pro Jahr.
- **Hardware:** Seit 2023 liegt der Schlüssel immer auf einem USB-Token oder in einem Cloud-HSM.
- **Reputation:** Bei OV-Zertifikaten zeigt SmartScreen anfangs trotzdem eine Warnung, bis genug Nutzer die Datei geladen haben.
- **Umgebungsvariablen:** `CSC_LINK` (Pfad zur .pfx-Datei) und `CSC_KEY_PASSWORD`.

### Weg C – SignPath Foundation (für Vigil nicht möglich, siehe oben)

Die SignPath Foundation signiert Open-Source-Projekte kostenlos. Das Zertifikat läuft auf die Foundation, die Signatur entsteht nur in einem öffentlichen GitHub-Build. Dadurch kann jeder nachprüfen, dass die Datei aus genau diesem Quellcode stammt.

**Schon im Repository vorbereitet:**
- [LICENSE](LICENSE) mit der MIT-Lizenz (von der OSI anerkannt).
- [CODE_SIGNING.md](CODE_SIGNING.md): die Signier-Richtlinie mit Rollen und Datenschutz-Erklärung, die SignPath verlangt.
- [.github/workflows/release.yml](.github/workflows/release.yml): Bei jedem Tag `v*` wird gebaut und getestet, dann werden App und Installer über SignPath signiert und als Release veröffentlicht.
- [.signpath/app.xml](.signpath/app.xml) und [.signpath/installers.xml](.signpath/installers.xml): die Artefakt-Konfigurationen zum Einfügen in SignPath.

**Was nur du selbst erledigen kannst** (Konten und Anträge laufen auf deinen Namen):

1. **Repository öffentlich machen.** Vigil muss öffentlich auf GitHub liegen, zum Beispiel unter `github.com/Passimoritz/vigil`, und mindestens ein Release haben. Die Bewertung dauert meist einige Tage bis Wochen.
2. **Antrag stellen:** auf [signpath.org/apply](https://signpath.org/apply). Wichtige Angaben:
   - Projekt: Vigil
   - Repository-URL und Lizenz (MIT)
   - Kurzbeschreibung: defensives Sicherheits-Prüfwerkzeug für eigene Projekte
   - Link zu CODE_SIGNING.md
3. **SignPath einrichten,** sobald der Antrag angenommen ist:
   - Ein Projekt mit dem Slug `vigil` anlegen.
   - Die Signier-Richtlinie `release-signing` anlegen, mit manueller Freigabe.
   - Die Artefakt-Konfigurationen `app` und `installers` aus den XML-Dateien anlegen.
   - Die GitHub-Verbindung als „Trusted Build System“ einrichten.
4. **GitHub einrichten** unter Settings → Secrets and variables → Actions:
   - als Secret `SIGNPATH_API_TOKEN`,
   - als Variable `SIGNPATH_ORGANIZATION_ID`.
5. **Release auslösen:** `git tag v0.2.0` und `git push --tags`. Den Signier-Auftrag gibst du danach in SignPath frei.

Bis die Signierung eingerichtet ist, läuft derselbe Workflow ebenfalls, liefert aber unsignierte Dateien.

## Bis dahin

- **Ohne Installation testen:** `dist/win-unpacked/Vigil.exe` direkt starten.
- **Portable Version:** `npm run dist:portable`.
- Smart App Control **nicht** abschalten: Es lässt sich danach nur durch eine Neuinstallation von Windows wieder einschalten.
