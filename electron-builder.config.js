'use strict';

// Build-Konfiguration: nimmt "build" aus package.json und schaltet die Signierung ein, sobald
// Zugangsdaten als Umgebungsvariablen vorhanden sind. Ohne sie wird – wie bisher – unsigniert
// gebaut. Details und Optionen: SIGNING.md
//
//  A) Azure Trusted Signing (Microsoft, guenstig, von Smart App Control anerkannt):
//     AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
//     VIGIL_SIGN_ENDPOINT, VIGIL_SIGN_ACCOUNT, VIGIL_SIGN_PROFILE
//  B) Klassisches Code-Signing-Zertifikat (.pfx): CSC_LINK + CSC_KEY_PASSWORD
//     (liest electron-builder von selbst; hier nur Zeitstempel und Hinweis)

const pkg = require('./package.json');

const config = JSON.parse(JSON.stringify(pkg.build));
const env = process.env;

if (env.VIGIL_SIGN_ENDPOINT && env.VIGIL_SIGN_ACCOUNT && env.VIGIL_SIGN_PROFILE && env.AZURE_CLIENT_ID) {
  config.win.azureSignOptions = {
    endpoint: env.VIGIL_SIGN_ENDPOINT,
    codeSigningAccountName: env.VIGIL_SIGN_ACCOUNT,
    certificateProfileName: env.VIGIL_SIGN_PROFILE,
    publisherName: config.win.signtoolOptions && config.win.signtoolOptions.publisherName,
  };
  delete config.win.signtoolOptions;
  console.log('Signierung: Azure Trusted Signing (' + env.VIGIL_SIGN_ACCOUNT + ')');
} else if (env.CSC_LINK || env.WIN_CSC_LINK) {
  config.win.signtoolOptions = { ...(config.win.signtoolOptions || {}), signingHashAlgorithms: ['sha256'], rfc3161TimeStampServer: 'http://timestamp.digicert.com' };
  console.log('Signierung: Zertifikat aus CSC_LINK');
} else {
  console.log('Signierung: keine Zugangsdaten gefunden – Build bleibt unsigniert (siehe SIGNING.md).');
}

module.exports = config;
