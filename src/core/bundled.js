'use strict';

// Eingebaute (statisch gelinkte oder mitgelieferte) Bibliotheken in Programmen erkennen:
// OpenSSL, zlib, libpng, curl ueber ihre Versions-Zeichenketten, Java-Bibliotheken (z. B. log4j)
// in JAR/WAR-Dateien ueber META-INF/maven/…/pom.properties (auch umgepackte "fat jars"). Danach Abgleich mit
// - eingebautem Wissen zu bekannten schweren Luecken und Support-Ende (offline, nach Datum),
// - OSV.dev: Maven-Pakete werden in den normalen CVE-Abgleich (cve.js) gegeben.

const path = require('path');
const { normalizeFinding } = require('./schema');

// Versionen vergleichen, auch mit Buchstaben (OpenSSL "1.0.2k" > "1.0.2")
function verKey(v) {
  const out = [];
  for (const part of String(v).split(/[.\-_]/)) {
    const m = part.match(/^(\d+)([a-z]*)/i);
    if (!m) { out.push(-1); break; } // "beta" o. ae.: kleiner als die Endversion
    out.push(Number(m[1]));
    if (m[2]) out.push(/^(alpha|beta|rc|pre|m)/i.test(m[2]) ? -1 : m[2].toLowerCase().charCodeAt(0) - 96);
  }
  return out;
}
function cmp(a, b) {
  const x = verKey(a), y = verKey(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d < 0 ? -1 : 1; }
  return 0;
}
const inRange = (v, lo, hi) => (!lo || cmp(v, lo) >= 0) && (!hi || cmp(v, hi) < 0);

// Bekannte schwere Luecken bzw. Support-Ende. eol: Datum, ab dem es keine Sicherheitsupdates mehr gibt.
const KNOWN = {
  openssl: [
    { from: '1.0.1', below: '1.0.1g', sev: 'critical', cve: 'CVE-2014-0160', what: 'Heartbleed: Angreifer können den Arbeitsspeicher des Servers auslesen (Schlüssel, Passwörter)' },
    { from: '3.0.0', below: '3.0.7', sev: 'high', cve: 'CVE-2022-3602', what: 'Pufferüberlauf bei der Prüfung von Zertifikaten' },
    { from: '0', below: '1.1.0', eol: '2019-12-31', sev: 'high' },
    { from: '1.1.0', below: '1.1.1', eol: '2019-09-11', sev: 'high' },
    { from: '1.1.1', below: '3.0.0', eol: '2023-09-11', sev: 'medium' },
    { from: '3.0.0', below: '3.1.0', eol: '2026-09-07', sev: 'medium' },
    { from: '3.1.0', below: '3.2.0', eol: '2025-03-14', sev: 'medium' },
    { from: '3.2.0', below: '3.3.0', eol: '2025-11-23', sev: 'medium' },
    { from: '3.3.0', below: '3.4.0', eol: '2026-04-09', sev: 'medium' },
    { from: '3.4.0', below: '3.5.0', eol: '2026-10-22', sev: 'medium' },
  ],
  zlib: [
    { from: '0', below: '1.2.12', sev: 'high', cve: 'CVE-2018-25032', what: 'Speicherfehler beim Komprimieren bestimmter Eingaben' },
    { from: '1.2.12', below: '1.2.13', sev: 'high', cve: 'CVE-2022-37434', what: 'Pufferüberlauf beim Lesen manipulierter gzip-Kopfdaten' },
  ],
  libpng: [
    { from: '0', below: '1.6.37', sev: 'medium', cve: 'CVE-2019-7317', what: 'Speicherfehler (use-after-free) beim Verarbeiten von Bildern' },
  ],
  curl: [
    { from: '7.69.0', below: '8.4.0', sev: 'high', cve: 'CVE-2023-38545', what: 'Pufferüberlauf bei Verbindungen über SOCKS5-Proxys' },
  ],
};
const LABEL = { openssl: 'OpenSSL', zlib: 'zlib', libpng: 'libpng', curl: 'curl/libcurl' };

const PATTERNS = [
  ['openssl', /\bOpenSSL (\d+\.\d+\.\d+[a-z]{0,2})(?:-[a-z0-9]+)?\s+\d{1,2} [A-Z][a-z]{2} \d{4}/g],
  ['zlib', /\b(?:deflate|inflate) (\d\.\d+\.\d+(?:\.\d+)?) Copyright/g],
  ['libpng', /\blibpng version (\d\.\d+\.\d+)/g],
  ['curl', /\blibcurl\/(\d+\.\d+\.\d+)\b/g],
];

// Liefert erkannte Bibliotheken [{ lib, version, maven? }]
function detectBundled(buf, { maxBytes = 96 * 1024 * 1024 } = {}) {
  if (!Buffer.isBuffer(buf) || !buf.length) return [];
  const text = buf.subarray(0, maxBytes).toString('latin1');
  const found = new Map();
  for (const [lib, re] of PATTERNS) {
    re.lastIndex = 0;
    let m, n = 0;
    while ((m = re.exec(text)) && n++ < 20) found.set(`${lib}@${m[1]}`, { lib, version: m[1] });
  }
  return [...found.values()];
}

// pom.properties aus einem JAR-Eintrag -> Maven-Paket
function parsePomProperties(text) {
  const get = (k) => (String(text).match(new RegExp(`^${k}\\s*[=:]\\s*(.+)$`, 'm')) || [])[1];
  const g = get('groupId'), a = get('artifactId'), v = get('version');
  if (!g || !a || !v) return null;
  return { version: v.trim(), maven: `${g.trim()}:${a.trim()}` };
}

function bundledFindings(libs, label, { now = Date.now() } = {}) {
  const out = [];
  const where = String(label || '').replace(/\\/g, '/');
  for (const l of libs) {
    for (const k of KNOWN[l.lib] || []) {
      if (!inRange(l.version, k.from, k.below)) continue;
      if (k.eol && Date.parse(k.eol) > now) continue;
      const name = LABEL[l.lib] || l.lib;
      out.push(normalizeFinding({
        ruleId: k.cve ? `bundled-${l.lib}-${k.cve}` : `bundled-${l.lib}-eol`, severity: k.sev, category: 'Dependencies', confidence: 'medium',
        title: k.cve ? `Eingebaute Bibliothek mit bekannter Lücke: ${name} ${l.version} (${k.cve})` : `Eingebaute Bibliothek ohne Sicherheitsupdates: ${name} ${l.version}`,
        description: k.cve
          ? `In „${path.basename(where)}“ steckt ${name} in Version ${l.version}. Diese Version hat die bekannte Lücke ${k.cve}: ${k.what}.`
          : `In „${path.basename(where)}“ steckt ${name} in Version ${l.version}. Für diese Versionsreihe gibt es seit ${k.eol} keine Sicherheitsupdates mehr.`,
        impact: 'Die Bibliothek ist fest im Programm eingebaut – ein Update des Systems behebt die Lücke hier nicht.',
        remediation: `Das Programm mit einer aktuellen ${name}-Version neu bauen bzw. eine aktuelle Fassung des Programms installieren.`,
        location: where, package: { ecosystem: l.maven ? 'Maven' : 'bundled', name: l.maven || l.lib, version: l.version, fixed: k.below },
        sourceModule: 'bundled-libs',
      }, 'bundled-libs'));
    }
  }
  return out;
}

module.exports = { detectBundled, parsePomProperties, bundledFindings, cmp, KNOWN };
