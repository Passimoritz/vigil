'use strict';

// Einordnung jedes Befunds in die Listen, die Pruefer erwarten:
//  - CWE (Common Weakness Enumeration) und OWASP Top 10 (2021)
//  - Normen-Kataloge: ISO/IEC 27001:2022 Anhang A, BSI IT-Grundschutz, NIS2 Art. 21, DSGVO Art. 32
// Zuordnung erst ueber die Regel-ID (genauer), sonst ueber die Kategorie. Die Kataloge sind ein
// technischer Nachweis-Baustein – sie ersetzen keine Zertifizierung oder Rechtsberatung.

const OWASP = {
  A01: 'A01:2021 – Fehlerhafte Zugriffskontrolle',
  A02: 'A02:2021 – Kryptografische Fehler',
  A03: 'A03:2021 – Injection',
  A04: 'A04:2021 – Unsicheres Design',
  A05: 'A05:2021 – Sicherheitsrelevante Fehlkonfiguration',
  A06: 'A06:2021 – Veraltete und verwundbare Komponenten',
  A07: 'A07:2021 – Fehler bei Identifizierung und Anmeldung',
  A08: 'A08:2021 – Fehlende Integrität von Software und Daten',
  A09: 'A09:2021 – Unzureichendes Protokollieren und Überwachen',
  A10: 'A10:2021 – Server-Side Request Forgery (SSRF)',
};

// [Muster auf ruleId, CWE, OWASP]
const BY_RULE = [
  // Code-Regeln: Frameworks, Sprachen, Konfigurationen (vor den allgemeinen Mustern, die sonst zu grob greifen)
  [/^sql-(grant|superuser)/i, 'CWE-269', 'A01'],
  [/^sql-default-password/i, 'CWE-1392', 'A07'],
  [/^sql-plaintext-password/i, 'CWE-798', 'A07'],
  [/csrf/i, 'CWE-352', 'A01'],
  [/server-action-no-auth/i, 'CWE-862', 'A01'],
  [/openapi-no-security/i, 'CWE-306', 'A07'],
  [/apikey-in-query|secret-in-query/i, 'CWE-598', 'A04'],
  [/no-limits|no-depth-limit/i, 'CWE-770', 'A04'],
  [/debug-on|dev-exception|custom-errors-off|error-stacktrace|graphiql/i, 'CWE-489', 'A05'],
  [/actuator|h2-console|introspection|server-tokens|trace-enabled/i, 'CWE-200', 'A05'],
  [/autoindex|dir-listing|directory-listing/i, 'CWE-548', 'A05'],
  [/old-tls|weak-ciphers/i, 'CWE-327', 'A02'],
  [/missing-headers/i, 'CWE-693', 'A05'],
  [/mcp-remote-http|openapi-http-server/i, 'CWE-319', 'A02'],
  [/broad-fs-root|chmod-777/i, 'CWE-732', 'A01'],
  [/^pii-|output-pii/i, 'CWE-359', 'A01'],
  [/^quality-duplicate/i, 'CWE-1041', 'A04'],
  [/^quality-/i, 'CWE-1120', 'A04'],
  [/weak-key-size/i, 'CWE-326', 'A02'],
  [/^crypto-/i, 'CWE-327', 'A02'],
  [/^c-gets/i, 'CWE-242', 'A04'],
  [/^c-(strcpy|sprintf|memcpy|scanf)/i, 'CWE-120', 'A04'],
  [/format-string/i, 'CWE-134', 'A03'],
  [/download-exec/i, 'CWE-494', 'A08'],
  [/invoke-expression/i, 'CWE-95', 'A03'],
  [/constantize|send-params/i, 'CWE-470', 'A03'],
  [/excessive-agency/i, 'CWE-250', 'A04'],
  [/atom-dos/i, 'CWE-400', 'A04'],
  [/sql|nosql|injection-concat|taint-sql/i, 'CWE-89', 'A03'],
  [/shell|cmd-exec|command|taint-shell|curl-pipe/i, 'CWE-78', 'A03'],
  [/eval|taint-eval|new-function/i, 'CWE-95', 'A03'],
  [/xss|innerhtml|echo|template-unescaped|taint-html/i, 'CWE-79', 'A03'],
  [/prompt-injection/i, 'CWE-1427', 'A03'],
  [/path|file-include|traversal|hostpath/i, 'CWE-22', 'A01'],
  [/ssrf/i, 'CWE-918', 'A10'],
  [/redirect/i, 'CWE-601', 'A01'],
  [/deserial|unserialize|binaryformatter|pickle/i, 'CWE-502', 'A08'],
  [/secret|password|token|key|credential|git-history/i, 'CWE-798', 'A07'],
  [/weak-hash|md5|sha1/i, 'CWE-328', 'A02'],
  [/random|rand/i, 'CWE-338', 'A02'],
  [/cipher|ecb|des|rc4/i, 'CWE-327', 'A02'],
  [/tls|cert|https|cleartext|ats|hsts|transport|no-https|mixed/i, 'CWE-319', 'A02'],
  [/unencrypted|bitlocker/i, 'CWE-311', 'A02'],
  [/jwt|session|cookie|mfa|password-policy|rdp|guest|ssh-|auth/i, 'CWE-287', 'A07'],
  [/idor|bola|mass-assignment|exported|public|wildcard|cluster-admin|cors|uac/i, 'CWE-284', 'A01'],
  [/race|toctou/i, 'CWE-362', 'A04'],
  [/redos|no-limits/i, 'CWE-1333', 'A04'],
  [/prototype-pollution/i, 'CWE-1321', 'A08'],
  [/typosquat|registry|lockfile|unpinned|latest|install-script|integrity|gha-/i, 'CWE-829', 'A08'],
  [/CVE-|GHSA-|vulnerable|dependency|updates-old|outdated|old-target/i, 'CWE-1104', 'A06'],
  [/log|no_log/i, 'CWE-532', 'A09'],
  [/privileged|docker-sock|cap|root|host-network|host-pid|priv-escalation|debuggable/i, 'CWE-250', 'A05'],
  [/license/i, 'CWE-1357', 'A06'],
];
const BY_CATEGORY = {
  Injection: ['CWE-74', 'A03'], XSS: ['CWE-79', 'A03'], Deserialization: ['CWE-502', 'A08'], Secrets: ['CWE-798', 'A07'],
  Crypto: ['CWE-327', 'A02'], Auth: ['CWE-287', 'A07'], AccessControl: ['CWE-284', 'A01'], SSRF: ['CWE-918', 'A10'],
  PathTraversal: ['CWE-22', 'A01'], Config: ['CWE-16', 'A05'], Dependencies: ['CWE-1104', 'A06'], DoS: ['CWE-400', 'A04'],
  Logging: ['CWE-532', 'A09'], Transport: ['CWE-319', 'A02'], License: ['CWE-1357', 'A06'], AttackPath: ['CWE-1220', 'A04'], Other: [null, 'A04'],
};

function classify(f) {
  // Bekannte Paket-Luecken und Lizenzen sind immer "verwundbare Komponenten" – Paketnamen wie
  // "jsonwebtoken" sollen nicht ueber das Wort "token" als Zugangsdaten eingeordnet werden.
  if (f.category === 'License') return { cwe: 'CWE-1357', owasp: 'A06' };
  if (f.category === 'Dependencies' && (/^(CVE|GHSA|PYSEC|GO|RUSTSEC)-/i.test(f.ruleId || '') || f.package)) return { cwe: 'CWE-1104', owasp: 'A06' };
  const rid = String(f.ruleId || '');
  for (const [re, cwe, ow] of BY_RULE) if (re.test(rid)) return { cwe, owasp: ow };
  const c = BY_CATEGORY[f.category] || BY_CATEGORY.Other;
  return { cwe: c[0], owasp: c[1] };
}

function applyTaxonomy(findings) {
  return findings.map((f) => {
    const t = classify(f);
    return { ...f, cwe: f.cwe || t.cwe || undefined, owasp: f.owasp || t.owasp };
  });
}

// --- Normen-Kataloge ------------------------------------------------------------
// Je Kontrolle: welche OWASP-Gruppen bzw. Kategorien sie betreffen.
const CATALOGS = {
  iso27001: {
    name: 'ISO/IEC 27001:2022 – Anhang A',
    controls: [
      { id: 'A.5.15', title: 'Zugangssteuerung', owasp: ['A01'] },
      { id: 'A.5.17', title: 'Authentisierungsinformationen', owasp: ['A07'], cats: ['Secrets'] },
      { id: 'A.8.5', title: 'Sichere Authentisierung', owasp: ['A07'] },
      { id: 'A.8.8', title: 'Umgang mit technischen Schwachstellen', owasp: ['A06'] },
      { id: 'A.8.9', title: 'Konfigurationsmanagement', owasp: ['A05'], cats: ['Config'] },
      { id: 'A.8.15', title: 'Protokollierung', owasp: ['A09'] },
      { id: 'A.8.20', title: 'Netzwerksicherheit', cats: ['Transport'] },
      { id: 'A.8.24', title: 'Verwendung von Kryptografie', owasp: ['A02'] },
      { id: 'A.8.26', title: 'Anforderungen an die Anwendungssicherheit', owasp: ['A03', 'A04', 'A10'] },
      { id: 'A.8.28', title: 'Sichere Programmierung', owasp: ['A03', 'A08'], cats: ['Injection', 'XSS', 'Deserialization'] },
      { id: 'A.5.32', title: 'Geistige Eigentumsrechte (Lizenzen)', cats: ['License'] },
    ],
  },
  bsi: {
    name: 'BSI IT-Grundschutz-Kompendium',
    controls: [
      { id: 'CON.8', title: 'Software-Entwicklung', owasp: ['A03', 'A04', 'A08'] },
      { id: 'APP.3.1', title: 'Webanwendungen und Webservices', owasp: ['A01', 'A03', 'A07', 'A10'] },
      { id: 'OPS.1.1.3', title: 'Patch- und Änderungsmanagement', owasp: ['A06'] },
      { id: 'CON.1', title: 'Kryptokonzept', owasp: ['A02'] },
      { id: 'ORP.4', title: 'Identitäts- und Berechtigungsmanagement', owasp: ['A01', 'A07'] },
      { id: 'OPS.1.1.5', title: 'Protokollierung', owasp: ['A09'] },
      { id: 'SYS.1.6', title: 'Containerisierung', match: /container|k8s|docker/i },
      { id: 'SYS.2.1', title: 'Allgemeiner Client', match: /^win-/i },
      { id: 'OPS.2.2', title: 'Cloud-Nutzung', match: /^(cloud|aws|iac)-/i },
    ],
  },
  nis2: {
    name: 'NIS2-Richtlinie – Art. 21 Abs. 2',
    controls: [
      { id: 'lit. d', title: 'Sicherheit der Lieferkette', owasp: ['A06', 'A08'], cats: ['License'] },
      { id: 'lit. e', title: 'Sicherheit bei Entwicklung und Wartung, Umgang mit Schwachstellen', owasp: ['A03', 'A04', 'A05', 'A06', 'A10'] },
      { id: 'lit. h', title: 'Kryptografie und Verschlüsselung', owasp: ['A02'] },
      { id: 'lit. i', title: 'Zugriffskontrolle und Verwaltung von Anlagen', owasp: ['A01'] },
      { id: 'lit. j', title: 'Multi-Faktor-Authentifizierung, sichere Anmeldung', owasp: ['A07'] },
    ],
  },
  dsgvo: {
    name: 'DSGVO – Art. 32 (Sicherheit der Verarbeitung)',
    controls: [
      { id: 'Abs. 1 lit. a', title: 'Verschlüsselung personenbezogener Daten', owasp: ['A02'] },
      { id: 'Abs. 1 lit. b', title: 'Vertraulichkeit und Integrität der Systeme', owasp: ['A01', 'A03', 'A05', 'A07', 'A10'] },
      { id: 'Abs. 1 lit. d', title: 'Regelmäßige Überprüfung der Wirksamkeit', owasp: ['A06', 'A09'] },
    ],
  },
  // EU Cyber Resilience Act (Verordnung (EU) 2024/2847), Anhang I – grundlegende Anforderungen
  cra: {
    name: 'EU Cyber Resilience Act – Anhang I',
    controls: [
      { id: 'Teil I (2) a', title: 'Keine bekannten ausnutzbaren Schwachstellen bei Auslieferung', owasp: ['A06'], kev: true },
      { id: 'Teil I (2) b', title: 'Sichere Standardkonfiguration', owasp: ['A05'], cats: ['Config'] },
      { id: 'Teil I (2) d', title: 'Schutz vor unbefugtem Zugriff (Authentisierung, Zugriffskontrolle)', owasp: ['A01', 'A07'] },
      { id: 'Teil I (2) e', title: 'Vertraulichkeit gespeicherter und übertragener Daten', owasp: ['A02'], cats: ['Secrets', 'Transport'] },
      { id: 'Teil I (2) f', title: 'Integrität von Daten, Befehlen und Programmen', owasp: ['A03', 'A08'] },
      { id: 'Teil I (2) h', title: 'Verfügbarkeit wesentlicher Funktionen', cats: ['DoS'] },
      { id: 'Teil I (2) j', title: 'Begrenzung der Angriffsfläche', owasp: ['A05', 'A10'], match: /port|exposed|debug|admin/i },
      { id: 'Teil I (2) l', title: 'Protokollierung und Überwachung sicherheitsrelevanter Vorgänge', owasp: ['A09'] },
      { id: 'Teil II (1)', title: 'Schwachstellen und Komponenten erfassen (SBOM)', cats: ['Dependencies', 'License'] },
      { id: 'Teil II (2)', title: 'Schwachstellen unverzüglich durch Sicherheitsupdates beheben', match: /^(CVE|GHSA|PYSEC|GO|RUSTSEC)-/i },
    ],
  },
  soc2: {
    name: 'SOC 2 – Trust Services Criteria',
    controls: [
      { id: 'CC6.1', title: 'Logische Zugriffskontrolle', owasp: ['A01', 'A07'], cats: ['Secrets'] },
      { id: 'CC6.6', title: 'Schutz vor Bedrohungen von außen', owasp: ['A05', 'A10'] },
      { id: 'CC6.7', title: 'Schutz bei der Übertragung', owasp: ['A02'], cats: ['Transport'] },
      { id: 'CC6.8', title: 'Schutz vor Schadsoftware und unautorisierter Software', owasp: ['A08'], match: /malware|typosquat|install-script/i },
      { id: 'CC7.1', title: 'Erkennung von Schwachstellen und Fehlkonfigurationen', owasp: ['A06'], cats: ['Config'] },
      { id: 'CC7.2', title: 'Überwachung sicherheitsrelevanter Ereignisse', owasp: ['A09'] },
      { id: 'CC8.1', title: 'Änderungsmanagement und sichere Entwicklung', owasp: ['A03', 'A04'] },
    ],
  },
  pcidss: {
    name: 'PCI DSS 4.0',
    controls: [
      { id: '2.2', title: 'Systemkomponenten sicher konfiguriert', owasp: ['A05'], cats: ['Config'] },
      { id: '3.5', title: 'Gespeicherte Kontodaten geschützt', owasp: ['A02'], cats: ['Crypto'] },
      { id: '4.2', title: 'Starke Kryptografie bei der Übertragung', cats: ['Transport'] },
      { id: '6.2.4', title: 'Entwicklung verhindert typische Software-Angriffe', owasp: ['A03', 'A04', 'A10'], cats: ['Injection', 'XSS'] },
      { id: '6.3.3', title: 'Bekannte Schwachstellen durch Patches behoben', owasp: ['A06'] },
      { id: '7.2', title: 'Zugriff nach Bedarf vergeben und kontrolliert', owasp: ['A01'] },
      { id: '8.3', title: 'Starke Authentisierung', owasp: ['A07'] },
      { id: '8.6', title: 'Zugangsdaten von Konten nicht im Code', cats: ['Secrets'] },
      { id: '10.2', title: 'Protokollierung von Ereignissen', owasp: ['A09'] },
    ],
  },
  asvs: {
    name: 'OWASP ASVS 4.0',
    controls: [
      { id: 'V1', title: 'Architektur und Bedrohungsmodell', owasp: ['A04'] },
      { id: 'V2', title: 'Authentisierung', owasp: ['A07'] },
      { id: 'V3', title: 'Sitzungsverwaltung', match: /session|cookie|jwt/i },
      { id: 'V4', title: 'Zugriffskontrolle', owasp: ['A01'] },
      { id: 'V5', title: 'Validierung, Bereinigung und Kodierung', owasp: ['A03'] },
      { id: 'V6', title: 'Gespeicherte Kryptografie', owasp: ['A02'], cats: ['Crypto'] },
      { id: 'V7', title: 'Fehlerbehandlung und Protokollierung', owasp: ['A09'] },
      { id: 'V8', title: 'Datenschutz', cats: ['Secrets'] },
      { id: 'V9', title: 'Kommunikation', cats: ['Transport'] },
      { id: 'V10', title: 'Schadcode', owasp: ['A08'] },
      { id: 'V12', title: 'Dateien und Ressourcen', cats: ['PathTraversal', 'SSRF'] },
      { id: 'V13', title: 'API und Webdienste', match: /api|graphql|cors/i },
      { id: 'V14', title: 'Konfiguration', owasp: ['A05', 'A06'] },
    ],
  },
  hipaa: {
    name: 'HIPAA Security Rule – § 164.312',
    controls: [
      { id: '(a)(1)', title: 'Zugriffskontrolle', owasp: ['A01'] },
      { id: '(a)(2)(iv)', title: 'Ver- und Entschlüsselung', owasp: ['A02'], cats: ['Secrets'] },
      { id: '(b)', title: 'Protokollierung (Audit Controls)', owasp: ['A09'] },
      { id: '(c)(1)', title: 'Integrität', owasp: ['A03', 'A08'] },
      { id: '(d)', title: 'Authentisierung von Personen und Systemen', owasp: ['A07'] },
      { id: '(e)(1)', title: 'Übertragungssicherheit', cats: ['Transport'] },
      { id: '§ 164.308(a)(1)', title: 'Risikoanalyse und Risikomanagement', owasp: ['A05', 'A06'] },
    ],
  },
};

function controlHits(control, findings) {
  return findings.filter((f) => (control.owasp && control.owasp.includes(f.owasp)) || (control.cats && control.cats.includes(f.category)) || (control.match && control.match.test(f.ruleId || '')) || (control.kev && f.inCisaKev));
}

// Uebersicht je Katalog: Kontrolle -> offene Befunde (nach Schwere), Status ok/offen.
// keys (optional): nur diese Kataloge, z. B. ['iso27001', 'cra'] – leer/fehlend = alle
function complianceReport(findings, keys) {
  const active = findings.filter((f) => !f.suppressed && !['FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED'].includes(f.status));
  const want = Array.isArray(keys) && keys.length ? new Set(keys) : null;
  return Object.entries(CATALOGS).filter(([key]) => !want || want.has(key)).map(([key, cat]) => ({
    key, name: cat.name,
    controls: cat.controls.map((c) => {
      const hits = controlHits(c, active);
      const worst = ['critical', 'high', 'medium', 'low', 'info'].find((s) => hits.some((h) => h.severity === s)) || null;
      return { id: c.id, title: c.title, count: hits.length, worst, status: !hits.length ? 'ok' : ['critical', 'high'].includes(worst) ? 'fail' : 'warn', findings: hits.slice(0, 10).map((h) => h.title) };
    }),
  }));
}

module.exports = { applyTaxonomy, classify, complianceReport, OWASP, CATALOGS };
