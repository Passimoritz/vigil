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

// --- Duplikate zusammenfuehren -------------------------------------------
// Dieselbe Luecke wird oft mehrfach gemeldet: Vorpruefung + gitleaks + trufflehog
// fuer ein Secret, OSV + trivy + grype fuer eine CVE, oder die KI in mehreren
// Durchgaengen mit leicht anderem Titel/Zeile. Hier wird das quellenuebergreifend
// zu einem Befund verdichtet; die Quellen bleiben in `sources` erhalten.

const VULN_ID_RE = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b/gi;
const TOOL_PREFIX_RE = /^(gitleaks|trufflehog|trivy|grype|semgrep|bandit|checkov|retire\.js|hadolint|osv-scanner|nuclei|binary)\s*:\s*/i;
const STOP = new Set(['der', 'die', 'das', 'und', 'oder', 'mit', 'ohne', 'von', 'fuer', 'im', 'auf', 'ein', 'eine', 'einer', 'des', 'the', 'and', 'for', 'with', 'via', 'moegliches', 'moeglicher', 'potential', 'potentielle', 'potenzielle']);
const CONF_RANK = { high: 0, medium: 1, low: 2 };

function vulnIds(f) {
  // Titel + Wirkungstext: OSV/osv-scanner/grype nennen dort auch die Aliase (GHSA <-> CVE).
  const ids = (String(f.title || '') + ' ' + String(f.impact || '')).match(VULN_ID_RE) || [];
  return [...new Set(ids.map((s) => s.toUpperCase()))];
}

// "C:\proj\src\app.js line 12" / "./src/app.js:12-14" -> { file: 'src/app.js', line: 12 }
function splitLoc(loc) {
  let s = String(loc || '').trim().toLowerCase().replace(/\\/g, '/').replace(/^\.\//, '').replace(/:\?$/, '');
  let line = null;
  const m = s.match(/^(.*?)(?::l?|#l|\s+\(?(?:line|zeile|l\.)\s*)(\d+)(?:\s*[-–:,]\s*\d+)?\)?\s*$/);
  if (m && m[1]) { s = m[1]; line = Number(m[2]); }
  // Nur die letzten zwei Segmente vergleichen: Tools melden absolute, die Vorpruefung relative Pfade.
  const file = s.split('/').filter(Boolean).slice(-2).join('/');
  return { file, line };
}

function titleTokens(t) {
  return new Set(String(t || '').toLowerCase().replace(TOOL_PREFIX_RE, '')
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !STOP.has(w)));
}
function similarity(a, b) {
  if (!a.size || !b.size) return 0;
  let inter = 0;
  for (const w of a) if (b.has(w)) inter++;
  return inter / (a.size + b.size - inter);
}

function isDuplicate(a, b) {
  if (a.ids.length && b.ids.length && a.f.category === b.f.category) return a.ids.some((id) => b.ids.includes(id));
  if (a.loc.file !== b.loc.file) return false;
  const sameCat = a.f.category === b.f.category;
  const sim = similarity(a.tokens, b.tokens);
  if (!a.loc.file) return sameCat && sim >= 0.8;
  if (a.loc.line != null && b.loc.line != null) {
    if (a.loc.line === b.loc.line) return sameCat || sim >= 0.35;
    return sameCat && sim >= 0.6 && Math.abs(a.loc.line - b.loc.line) <= 3;
  }
  return sameCat && sim >= 0.5;
}

function longest(vals) { return vals.reduce((best, v) => (String(v || '').length > String(best || '').length ? v : best), ''); }

function mergeGroup(group) {
  const ranked = [...group].sort((a, b) =>
    (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
    ((CONF_RANK[a.confidence] ?? 1) - (CONF_RANK[b.confidence] ?? 1)) ||
    ((b.cvss || 0) - (a.cvss || 0)));
  const primary = ranked[0];
  if (group.length === 1) return { ...primary, sources: [primary.source] };
  const cvssVals = group.map((f) => f.cvss).filter((v) => v != null);
  // Lesbarer Titel: eigene Pruefungen/KI statt Tool-Regel-IDs ("gitleaks: aws-access-token").
  const readable = ranked.find((f) => !TOOL_PREFIX_RE.test(f.title || '')) || primary;
  // Ort: mit Zeilennummer bevorzugt, dann der kuerzeste (relativer statt absoluter Pfad).
  const withLine = group.filter((f) => splitLoc(f.location).line != null);
  const locPool = (withLine.length ? withLine : group).map((f) => f.location).filter(Boolean);
  return {
    ...primary,
    title: readable.title,
    cvss: cvssVals.length ? Math.max(...cvssVals) : null,
    location: locPool.length ? locPool.reduce((a, b) => (b.length < a.length ? b : a)) : primary.location,
    description: longest(group.map((f) => f.description)),
    reachability: longest(group.map((f) => f.reachability)),
    impact: longest(group.map((f) => f.impact)),
    remediation: longest(group.map((f) => f.remediation)),
    patch: longest(group.map((f) => f.patch)),
    sources: [...new Set(group.map((f) => f.source))],
    mergedCount: group.length,
  };
}

function dedupeFindings(findings) {
  const groups = []; // [{ items, keys }]
  for (const f of findings) {
    const k = { f, ids: vulnIds(f), loc: splitLoc(f.location), tokens: titleTokens(f.title) };
    const g = groups.find((grp) => grp.keys.some((x) => isDuplicate(x, k)));
    if (g) { g.items.push(f); g.keys.push(k); }
    else groups.push({ items: [f], keys: [k] });
  }
  return groups.map((g) => mergeGroup(g.items));
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
  dedupeFindings,
  splitLoc,
  sortFindings,
  summarize,
  atOrAbove,
};
