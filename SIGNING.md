# Vigil signieren

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

### Weg C – Kostenlos für Open-Source-Projekte

Ist Vigil öffentlich auf GitHub, kann man sich bei der **SignPath Foundation** bewerben. Sie signiert Open-Source-Projekte kostenlos über eine CI-Pipeline, also über einen automatischen Build bei jeder neuen Version.

Bedingungen:
- OSI-Lizenz (MIT passt),
- öffentlicher Build,
- keine proprietären Teile.

## Bis dahin

- **Ohne Installation testen:** `dist/win-unpacked/Vigil.exe` direkt starten.
- **Portable Version:** `npm run dist:portable`.
- Smart App Control **nicht** abschalten: Es lässt sich danach nur durch eine Neuinstallation von Windows wieder einschalten.
