'use strict';

// Methode: sensible Dateien/Metadaten anhand von Name/Endung/Art erkennen -
// unabhaengig vom Inhalt (ergaenzt die inhaltsbasierten Prescan-Regeln).

const { normalizeFinding } = require('./schema');

const RULES = [
  { re: /(^|[\\/])id_rsa$|\.(pem|key|p12|pfx|jks|keystore|ppk)$/i, sev: 'high', cat: 'Secrets', what: 'Privater Schluessel / Zertifikatsdatei' },
  { re: /(^|[\\/])\.env(\.[\w-]+)?$|(^|[\\/])\.netrc$|(^|[\\/])\.pgpass$|(^|[\\/])\.git-credentials$|(^|[\\/])credentials$/i, sev: 'high', cat: 'Secrets', what: 'Zugangsdaten-Datei' },
  { re: /(^|[\\/])\.npmrc$/i, sev: 'medium', cat: 'Secrets', what: '.npmrc (moeglicher _authToken)' },
  { re: /\.(bak|old|orig|save|tmp|swp|swo)$|~$/i, sev: 'low', cat: 'Config', what: 'Backup-/Temp-/Editor-Datei (evtl. sensibler Inhalt)' },
  { re: /(^|[\\/])\.ds_store$|(^|[\\/])thumbs\.db$/i, sev: 'low', cat: 'Config', what: 'Betriebssystem-Metadaten (Dateinamen-Leak)' },
  { re: /(^|[\\/])\.(git|svn|hg)([\\/]|$)/i, sev: 'medium', cat: 'Config', what: 'Versionsverwaltungs-Metadaten mitgeliefert' },
  { re: /\.(sql|dump)$/i, sev: 'low', cat: 'Config', what: 'Datenbank-Dump' },
  { re: /\.(kdbx|ovpn|htpasswd)$|(^|[\\/])\.htpasswd$/i, sev: 'medium', cat: 'Secrets', what: 'Passwort-/VPN-/Auth-Datei' },
];

function fsaudit(units) {
  const findings = [];
  const seen = new Set();
  for (const u of units || []) {
    const label = u.label || '';
    for (const r of RULES) {
      if (!r.re.test(label)) continue;
      const key = r.what + '|' + label;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(normalizeFinding({
        title: `${r.what}: ${label.split(/[\\/]/).pop()}`,
        severity: r.sev,
        category: r.cat,
        location: label,
        description: `Die Datei "${label}" deutet auf ${r.what.toLowerCase()} hin und sollte nicht ungeschuetzt in Code, Build oder Repository liegen.`,
        reachability: 'Lesbar fuer jeden mit Zugriff auf Code, Artefakt oder Repository.',
        impact: r.cat === 'Secrets' ? 'Moeglicher Abfluss von Zugangsdaten/Schluesseln.' : 'Informations-Leak, erleichtert weitere Angriffe.',
        remediation: 'Datei entfernen bzw. aus Auslieferung/Repo ausschliessen (.gitignore/ignore) und betroffene Secrets rotieren.',
        confidence: 'medium',
      }, 'prescan'));
    }
  }
  return findings;
}

module.exports = { fsaudit };
