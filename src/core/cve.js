'use strict';

const { throttle, limiter } = require('./ratelimit');
// Abhaengigkeiten gegen die OSV.dev-Datenbank pruefen (bekannte CVEs/Advisories).
// OSV ist kostenlos und braucht keinen API-Key. https://osv.dev

const { normalizeFinding, cvssToSeverity } = require('./schema');

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';
const MAX_DETAILS = 80; // Obergrenze fuer Detail-Abfragen

async function withTimeout(ms, fn, extSignal) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  const signal = extSignal ? AbortSignal.any([ctrl.signal, extSignal]) : ctrl.signal;
  try { return await fn(signal); } finally { clearTimeout(t); }
}

// OSV.dev schonen: max. 3 parallele Abfragen, mind. 100 ms Abstand.
const OSV_LIMIT = limiter(3);
const osvFetch = (url, init) => OSV_LIMIT(async () => { await throttle('osv', 100); return fetch(url, init); });

async function postJson(url, body, ms = 20000, extSignal) {
  const res = await withTimeout(ms, (signal) => osvFetch(url, {
    method: 'POST', signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }), extSignal);
  if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
  return res.json();
}

async function getJson(url, ms = 20000, extSignal) {
  const res = await withTimeout(ms, (signal) => osvFetch(url, { signal }), extSignal);
  if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
  return res.json();
}

// --- Kompakter CVSS v3.x Basiswert-Rechner aus einem Vektor-String ------
function cvssFromVector(vec) {
  if (!vec || !/^CVSS:3/.test(vec)) return null;
  const m = {};
  vec.split('/').forEach((p) => { const [k, v] = p.split(':'); if (k && v) m[k] = v; });
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const scopeChanged = m.S === 'C';
  const PR = scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }[m.PR]
    : { N: 0.85, L: 0.62, H: 0.27 }[m.PR];
  const imp = { H: 0.56, L: 0.22, N: 0 };
  if (AV == null || AC == null || UI == null || PR == null || imp[m.C] == null) return null;
  const iscBase = 1 - (1 - imp[m.C]) * (1 - imp[m.I]) * (1 - imp[m.A]);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  const expl = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  const raw = scopeChanged ? 1.08 * (impact + expl) : impact + expl;
  const roundUp = (x) => Math.ceil(x * 10) / 10;
  return Math.min(roundUp(raw), 10);
}

function severityFromVuln(vuln) {
  // 1) CVSS-Vektor -> Basiswert (0/ungueltig ignorieren, dann Label nutzen)
  for (const s of vuln.severity || []) {
    const score = cvssFromVector(s.score);
    if (score != null && score > 0) return { cvss: score, severity: cvssToSeverity(score) };
  }
  // 2) database_specific.severity (z.B. GHSA: CRITICAL/HIGH/MODERATE/LOW)
  const label = (vuln.database_specific?.severity || '').toUpperCase();
  const map = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
  if (map[label]) return { cvss: null, severity: map[label] };
  return { cvss: null, severity: 'medium' };
}

function fixedVersions(vuln, pkgName) {
  const fixes = new Set();
  for (const aff of vuln.affected || []) {
    if (pkgName && aff.package?.name && aff.package.name.toLowerCase() !== pkgName.toLowerCase()) continue;
    for (const r of aff.ranges || []) {
      for (const ev of r.events || []) if (ev.fixed) fixes.add(ev.fixed);
    }
  }
  return [...fixes];
}

// Betroffene Funktionen laut Advisory (Go: imports[].symbols, andere: affected_functions)
function affectedSymbols(vuln, pkgName) {
  const out = new Set();
  for (const aff of vuln.affected || []) {
    if (pkgName && aff.package?.name && aff.package.name.toLowerCase() !== pkgName.toLowerCase()) continue;
    const es = aff.ecosystem_specific || {};
    for (const imp of es.imports || []) for (const s of imp.symbols || []) out.add(String(s));
    for (const s of es.affected_functions || []) out.add(String(s));
  }
  return [...out].slice(0, 30);
}

// deps: [{ecosystem,name,version,raw}]
async function lookupCves(deps, onProgress = () => {}, signal) {
  const notes = [];
  const withVer = deps.filter((d) => d.name && d.version);
  if (!withVer.length) {
    return { findings: [], notes: deps.length ? ['CVE-Abgleich: keine Abhaengigkeiten mit konkreter Version gefunden.'] : [] };
  }

  onProgress({ phase: 'cve', message: `CVE-Abgleich: frage OSV.dev zu ${withVer.length} Paket(en) …` });

  let batch;
  try {
    batch = await postJson(OSV_BATCH, {
      queries: withVer.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
    }, 20000, signal);
  } catch (e) {
    return { findings: [], notes: [`CVE-Abgleich nicht moeglich (offline/OSV nicht erreichbar?): ${e.message}`] };
  }

  // vulnId -> betroffene Pakete
  const idToPkgs = new Map();
  (batch.results || []).forEach((r, i) => {
    const dep = withVer[i];
    for (const v of (r && r.vulns) || []) {
      if (!idToPkgs.has(v.id)) idToPkgs.set(v.id, []);
      idToPkgs.get(v.id).push(dep);
    }
  });

  if (!idToPkgs.size) {
    return { findings: [], notes: [`CVE-Abgleich: keine bekannten Schwachstellen in ${withVer.length} gepruefte(n) Paket(en).`] };
  }

  const ids = [...idToPkgs.keys()].slice(0, MAX_DETAILS);
  if (idToPkgs.size > MAX_DETAILS) notes.push(`CVE-Abgleich: ${idToPkgs.size} Advisories gefunden, Details für die ersten ${MAX_DETAILS} geholt.`);
  onProgress({ phase: 'cve', message: `CVE-Abgleich: hole Details zu ${ids.length} Advisory(s) …` });

  const findings = [];
  let done = 0;
  for (const id of ids) {
    if (signal && signal.aborted) break;
    let vuln;
    try { vuln = await getJson(OSV_VULN + id, 20000, signal); }
    catch { done++; continue; }
    const { cvss, severity } = severityFromVuln(vuln);
    const pkgs = idToPkgs.get(id) || [];
    const cve = (vuln.aliases || []).find((a) => /^CVE-/.test(a)) || id;
    for (const dep of pkgs) {
      const fixes = fixedVersions(vuln, dep.name);
      const fixText = fixes.length ? `Auf eine gepatchte Version aktualisieren (behoben ab: ${fixes.join(', ')}).` : 'Auf die neueste gepatchte Version aktualisieren (siehe Advisory).';
      findings.push(normalizeFinding({
        title: `Verwundbare Abhaengigkeit: ${dep.name} ${dep.version} (${cve})`,
        severity,
        cvss,
        category: 'Dependencies',
        location: `${dep.ecosystem}: ${dep.name}@${dep.version}`,
        package: { ecosystem: dep.ecosystem, name: dep.name, version: dep.version, fixed: fixes[0] || '' },
        vulnSymbols: affectedSymbols(vuln, dep.name),
        description: `${vuln.summary || id}. ${(vuln.details || '').slice(0, 500)}`.trim(),
        reachability: 'Abhaengig davon, ob die verwundbare Funktion des Pakets im Projekt tatsaechlich genutzt wird. Transitive/ungenutzte Pfade haben geringeres reales Risiko.',
        impact: `Bekannte Schwachstelle laut ${vuln.id}${vuln.aliases?.length ? ' / ' + vuln.aliases.join(', ') : ''}.`,
        remediation: fixText,
        patch: fixes.length ? `# ${dep.name}: ${dep.version} -> ${fixes[0]}  (Lockfile aktualisieren & testen)` : '',
        confidence: 'high',
      }, 'osv'));
    }
    done++;
    if (done % 10 === 0) onProgress({ phase: 'cve', message: `CVE-Details: ${done}/${ids.length}` });
  }

  notes.push(`CVE-Abgleich: ${findings.length} Treffer aus OSV.dev.`);
  return { findings, notes };
}

module.exports = { lookupCves, cvssFromVector };
