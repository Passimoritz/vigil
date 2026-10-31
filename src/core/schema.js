'use strict';

// Zentrale Definitionen fuer Befunde (Findings) und Hilfsfunktionen.

const crypto = require('crypto');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CATEGORIES = [
  'Injection', 'XSS', 'Deserialization', 'Secrets', 'Crypto', 'Auth',
  'AccessControl', 'SSRF', 'PathTraversal', 'Config', 'Dependencies',
  'DoS', 'Logging', 'Transport', 'Other',
];

// CVSS-Basiswert -> Schweregrad (grobe, uebliche Abbildung).
function cvssToSeverity(score) {
  if (score == null || Number.isNaN(score)) return null;
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0.0) return 'low';
  return 'info';
}

function clampScore(v) {
  const n = Number(v);
  if (Number.isNaN(n)) return null;
  return Math.max(0, Math.min(10, Math.round(n * 10) / 10));
}

// Rohen Befund (von KI oder Prescan) in eine einheitliche Form bringen.
function normalizeFinding(raw, source) {
  const f = raw && typeof raw === 'object' ? raw : {};
  const cvss = clampScore(f.cvss);
  let severity = String(f.severity || '').toLowerCase().trim();
  if (!SEVERITIES.includes(severity)) {
    severity = cvssToSeverity(cvss) || 'medium';
  }
  let category = String(f.category || 'Other').trim();
  if (!CATEGORIES.includes(category)) category = 'Other';

  return {
    title: String(f.title || 'Unbenannter Befund').trim().slice(0, 200),
    severity,
    cvss,
    category,
    location: String(f.location || f.file || '').trim().slice(0, 300),
    description: String(f.description || '').trim(),
    reachability: String(f.reachability || f.exploitability || '').trim(),
    impact: String(f.impact || '').trim(),
    remediation: String(f.remediation || '').trim(),
    patch: String(f.patch || '').trim(),
    confidence: ['high', 'medium', 'low'].includes(String(f.confidence || '').toLowerCase())
      ? String(f.confidence).toLowerCase()
      : 'medium',
    source: source || f.source || 'ai',
  };
}

// Stabiler Fingerabdruck eines Befunds (fuer Baseline-Vergleich und
// dauerhaftes Ausblenden). Gleicher Ort + Titel + Kategorie -> gleicher Abdruck.
function fingerprint(f) {
  const basis = [
    String(f.category || '').toLowerCase().trim(),
    String(f.location || '').toLowerCase().trim(),
    String(f.title || '').toLowerCase().replace(/\s+/g, ' ').trim().slice(0, 80),
  ].join('|');
  return crypto.createHash('sha1').update(basis).digest('hex').slice(0, 16);
}

function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (s !== 0) return s;
    return (b.cvss || 0) - (a.cvss || 0);
  });
}

// Anzahl der Befunde mit Schweregrad >= level (fuer CLI --fail-on).
function atOrAbove(counts, level) {
  const order = SEVERITIES; // critical..info
  const max = order.indexOf(level);
  if (max < 0) return 0;
  let n = 0;
  for (let i = 0; i <= max; i++) n += (counts && counts[order[i]]) || 0;
  return n;
}

function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return { total: findings.length, counts };
}

module.exports = {
  SEVERITIES,
  SEVERITY_RANK,
  CATEGORIES,
  cvssToSeverity,
  clampScore,
  normalizeFinding,
  fingerprint,
  sortFindings,
  summarize,
  atOrAbove,
};
