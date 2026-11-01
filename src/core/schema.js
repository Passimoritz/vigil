'use strict';

// Zentrale Definitionen fuer Befunde (Findings) und Hilfsfunktionen.

const crypto = require('crypto');
const { UnifiedFindingSchema, check } = require('./validation');

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

// Secret fuer die Anzeige/Speicherung kuerzen: nur die ersten 3 und letzten 2 Zeichen bleiben.
function redactSecret(s) {
  const v = String(s || '').trim();
  if (!v) return '';
  if (v.length <= 8) return '****';
  return `${v.slice(0, 3)}****…**${v.slice(-2)}`;
}

// Stabile Regel-ID: explizit gesetzt, sonst CVE/GHSA aus dem Titel, sonst Kurzform des Titels.
function deriveRuleId(f) {
  if (f.ruleId) return String(f.ruleId).trim().slice(0, 200);
  const id = String(f.title || '').match(VULN_ID_RE);
  if (id) return id[0].toUpperCase();
  return String(f.title || 'befund').toLowerCase().replace(TOOL_PREFIX_RE, '')
    .replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/ß/g, 'ss')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'befund';
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

  // "https://x.com - Response-Header der 301-Antwort" -> Ort = URL, Rest = Detail.
  let location = String(f.location || f.file || '').trim();
  let locationDetail = '';
  const lm = location.match(/^(https?:\/\/[^\s'"]+)\s+(.+)$/i);
  if (lm) {
    location = lm[1].replace(/[,.;]+$/, '');
    locationDetail = lm[2].replace(/^[-–—:>|,\s]+/, '').replace(/^\((.*)\)$/, '$1').trim();
  }

  const out = {
    ruleId: deriveRuleId(f),
    ...(locationDetail ? { locationDetail: locationDetail.slice(0, 200) } : {}),
    ...(f.evidence ? { evidence: String(f.evidence).slice(0, 500) } : {}),
    title: String(f.title || 'Unbenannter Befund').trim().slice(0, 200),
    severity,
    cvss,
    category,
    location: location.slice(0, 300),
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
  // Zod-Pruefung als letzte Sicherung: was hier durchfaellt, ist ein Programmierfehler.
  const v = check(UnifiedFindingSchema, out);
  if (!v.ok) throw new Error('Ungueltiger Befund: ' + v.error);
  return out;
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

// Host eines Web-Orts: "https://www.x.com/de - Response-Header …" -> "x.com"; "x.com:443" -> "x.com".
function hostKey(loc) {
  const s = String(loc || '').trim().toLowerCase();
  const m = s.match(/https?:\/\/([^\s/'"?#)]+)/) || s.match(/^((?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?$/);
  return m ? m[1].replace(/:\d+$/, '').replace(/^www\./, '') : null;
}

// Themen eines Web-Befunds – dieselbe Luecke, egal wie Titel oder Kategorie formuliert sind.
const WEB_TOPICS = [
  ['hsts', /hsts|strict-transport/i, 'HSTS'],
  ['csp', /\bcsp\b|content-security-policy/i, 'Content-Security-Policy'],
  ['xcto', /x-content-type|nosniff/i, 'X-Content-Type-Options'],
  ['clickjacking', /x-frame-options|clickjacking|frame-ancestors/i, 'X-Frame-Options'],
  ['referrer', /referrer-policy/i, 'Referrer-Policy'],
  ['permissions', /permissions-policy/i, 'Permissions-Policy'],
  ['powered-by', /x-powered-by/i, 'X-Powered-By'],
  ['banner', /server-banner|server-header|server header|\bbanner\b|software-(?:typ|version)|server:\s/i, 'Server-Banner'],
];
const GENERIC_HEADERS = /sicherheits-?header|security[- ]?header|response-header/i;
function webTopics(f) {
  const text = `${f.ruleId || ''} ${f.title || ''}`;
  const set = new Set(WEB_TOPICS.filter(([, re]) => re.test(text)).map(([k]) => k));
  if (!set.size && GENERIC_HEADERS.test(text)) set.add('headers');
  return set;
}
// Sammel-Befund ("Fehlende Header: HSTS, CSP, …") statt einer einzelnen Luecke.
const isAggregate = (topics) => topics.size >= 2 || topics.has('headers');
const intersects = (a, b) => [...a].some((x) => b.has(x));

// "C:\proj\src\app.js line 12" / "./src/app.js:12-14" -> { file: 'src/app.js', line: 12 }
function splitLoc(loc) {
  // Web-Orte zaehlen nur ueber den Host – die KI haengt gern Beschreibungen an die URL.
  if (/https?:\/\//i.test(String(loc || ''))) return { file: 'web:' + hostKey(loc), line: null };
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
  // Web-Befunde: gleicher Host + gleiches Thema = gleiche Luecke (Kategorie/Wortlaut egal).
  // Sammel-Befunde werden nur untereinander vereint und danach in absorbAggregates aufgeloest.
  if (a.host && a.host === b.host && a.topics.size && b.topics.size) {
    const aggA = isAggregate(a.topics), aggB = isAggregate(b.topics);
    if (aggA && aggB) return intersects(a.topics, b.topics) || a.topics.has('headers') || b.topics.has('headers');
    if (aggA || aggB) return false;
    return [...a.topics].every((t) => b.topics.has(t)) && a.topics.size === b.topics.size;
  }
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
  // Ort: saubere URL bzw. Zeilennummer bevorzugt, dann der kuerzeste (relativer statt absoluter Pfad).
  const cleanUrl = group.filter((f) => /^https?:\/\/\S+$/i.test(String(f.location || '').trim()));
  const withLine = group.filter((f) => splitLoc(f.location).line != null);
  const locPool = (cleanUrl.length ? cleanUrl : withLine.length ? withLine : group).map((f) => f.location).filter(Boolean);
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
    ...((group.find((f) => f.evidence) || {}).evidence ? { evidence: group.find((f) => f.evidence).evidence } : {}),
    sources: [...new Set(group.map((f) => f.source))],
    mergedCount: group.length,
  };
}

// Sammel-Befunde aufloesen: Was ein Einzelbefund am selben Host schon abdeckt, wird dort als
// weitere Quelle vermerkt. Bleibt nichts uebrig, faellt der Sammel-Befund weg; sonst nennt er
// nur noch die wirklich zusaetzlich fehlenden Header.
function absorbAggregates(list) {
  const out = [];
  const singles = list.filter((f) => { const t = webTopics(f); return t.size && !isAggregate(t) && hostKey(f.location); });
  for (const f of list) {
    const topics = webTopics(f);
    const host = hostKey(f.location);
    if (!host || !isAggregate(topics)) { out.push(f); continue; }
    const covering = singles.filter((s) => hostKey(s.location) === host && intersects(webTopics(s), topics));
    for (const s of covering) {
      s.sources = [...new Set([...(s.sources || [s.source]), ...(f.sources || [f.source])])];
      s.mergedCount = (s.mergedCount || 1) + 1;
    }
    const covered = new Set(covering.flatMap((s) => [...webTopics(s)]));
    const rest = WEB_TOPICS.filter(([k]) => topics.has(k) && !covered.has(k));
    if (!rest.length && covering.length) {
      // komplett abgedeckt: weitere Duplikat-Zaehlung beim ersten Abdecker
      covering[0].mergedCount += (f.mergedCount || 1) - 1;
      continue;
    }
    if (!rest.length) { out.push(f); continue; } // nur generisch "Header fehlen" und nichts zum Zuordnen
    out.push({
      ...f,
      ruleId: 'missing-security-headers',
      title: rest.length === 1 ? `${rest[0][2]} fehlt` : `Weitere fehlende Sicherheits-Header: ${rest.map((r) => r[2]).join(', ')}`,
    });
  }
  return out;
}

// Offene Ports eines Hosts (reine Info von nmap) zu einem Befund buendeln – riskante Dienste bleiben einzeln.
function groupOpenPorts(list) {
  const byHost = new Map();
  const out = [];
  for (const f of list) {
    if (f.source === 'nmap' && f.severity === 'info' && /^offener port/i.test(f.title || '')) {
      const host = hostKey(f.location) || f.location;
      if (!byHost.has(host)) { byHost.set(host, []); out.push({ __ports: host }); }
      byHost.get(host).push(f);
    } else out.push(f);
  }
  return out.map((f) => {
    if (!f.__ports) return f;
    const ports = byHost.get(f.__ports);
    if (ports.length === 1) return ports[0];
    const names = ports.map((p) => (p.title.match(/port\s+(\S+)/i) || [])[1] || p.location);
    return {
      ...ports[0],
      ruleId: 'open-ports',
      title: `Offene Ports: ${names.join(', ')}`,
      location: f.__ports,
      description: `Von außen erreichbar: ${names.join(', ')}. Jeder offene Dienst ist Angriffsfläche – prüfe, ob alle davon öffentlich nötig sind.`,
      groupedCount: ports.length,
    };
  });
}

function dedupeFindings(findings) {
  const groups = []; // [{ items, keys }]
  for (const f of findings) {
    const loc = splitLoc(f.location);
    const k = { f, ids: vulnIds(f), loc, tokens: titleTokens(f.title), host: hostKey(f.location), topics: webTopics(f) };
    const g = groups.find((grp) => grp.keys.some((x) => isDuplicate(x, k)));
    if (g) { g.items.push(f); g.keys.push(k); }
    else groups.push({ items: [f], keys: [k] });
  }
  return groupOpenPorts(absorbAggregates(groups.map((g) => mergeGroup(g.items))));
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
  redactSecret,
  dedupeFindings,
  splitLoc,
  sortFindings,
  summarize,
  atOrAbove,
};
