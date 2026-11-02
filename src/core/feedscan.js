'use strict';

// Prueft mit den taeglich geladenen Feeds (feeds.js):
//  - Zugangsdaten nach den aktuellen gitleaks-Regeln (Vorfilter ueber Schluesselwoerter, Entropie)
//  - verwundbare JavaScript-Bibliotheken nach der aktuellen retire.js-Datenbank – in Projektdateien
//    und in den Skripten, die eine geprueften Webseite einbindet

const { normalizeFinding, redactSecret } = require('./schema');
const { shannon } = require('./feeds');

const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const MAX_LINE = 2000;
const CRITICAL = /private.?key|aws|gcp|azure|stripe|github|gitlab|slack|openai|anthropic|database|postgres|mongodb/i;

function scanSecretsWithFeed(units, rules) {
  const out = [];
  if (!rules || !rules.length) return out;
  for (const u of units) {
    if (u.kind === 'binary-strings' && (u.content || '').length > 2e6) continue;
    const lines = String(u.content || '').split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > MAX_LINE || line.length < 8) continue;
      const low = line.toLowerCase();
      for (const r of rules) {
        if (r.keywords.length && !r.keywords.some((k) => low.includes(k))) continue;
        r.re.lastIndex = 0;
        const m = r.re.exec(line);
        if (!m) continue;
        const secret = (m.groups && Object.values(m.groups).find(Boolean)) || m[1] || m[0];
        if (r.entropy && shannon(secret) < r.entropy) continue;
        if (/example|dummy|sample|placeholder|xxxx|your[_-]?key|changeme|test(ing)?[_-]?key/i.test(secret)) continue;
        out.push(normalizeFinding({
          ruleId: `gl-${r.id}`, severity: CRITICAL.test(r.id) ? 'critical' : 'high', category: 'Secrets', confidence: 'medium',
          title: `Zugangsdaten im Code: ${r.description}`,
          description: `In dieser Zeile steht ein Wert im Format „${r.description}“ (${redactSecret(secret)}). Erkannt mit der täglich aktualisierten Regel „${r.id}“ (gitleaks).`,
          impact: 'Wer den Code oder das Repository sieht, kann den Zugang benutzen.',
          remediation: 'Schlüssel beim Anbieter sperren und neu erzeugen, dann aus dem Code entfernen und über eine Umgebungsvariable oder einen Secret-Manager laden.',
          location: `${base(u)}:${i + 1}`, sourceModule: 'feed-secrets',
        }, 'gitleaks-feed'));
        break; // eine Regel je Zeile reicht
      }
    }
  }
  return out;
}

// --- Versionen vergleichen ("1.12.4" < "3.5.0", Vorabversionen zaehlen als kleiner) ----------
function cmpVer(a, b) {
  const pa = String(a).split(/[.+-]/), pb = String(b).split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i], y = pb[i];
    if (x === undefined) return /^\d/.test(y) ? -1 : 1;
    if (y === undefined) return /^\d/.test(x) ? 1 : -1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { const d = Number(x) - Number(y); if (d) return d < 0 ? -1 : 1; continue; }
    if (nx !== ny) return nx ? 1 : -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
const affects = (v, ver) => (!v.atOrAbove || cmpVer(ver, v.atOrAbove) >= 0) && (!v.below || cmpVer(ver, v.below) < 0);
const SEV = ['critical', 'high', 'medium', 'low'];

function libFinding(lib, version, vulns, location, where) {
  const sev = SEV.find((s) => vulns.some((v) => String(v.severity || '').toLowerCase() === s)) || 'medium';
  const ids = [...new Set(vulns.flatMap((v) => [...((v.identifiers && v.identifiers.CVE) || []), ...((v.identifiers && v.identifiers.githubID) ? [v.identifiers.githubID] : [])]))];
  const summaries = [...new Set(vulns.map((v) => v.identifiers && v.identifiers.summary).filter(Boolean))].slice(0, 3);
  const fixed = vulns.map((v) => v.below).filter(Boolean).sort(cmpVer).pop();
  const links = [...new Set(vulns.flatMap((v) => v.info || []))].filter((u) => /^https:\/\//.test(u)).slice(0, 4).map((url) => ({ label: url.replace(/^https:\/\/(www\.)?/, '').slice(0, 60), url }));
  return normalizeFinding({
    ruleId: `retire-${lib}${ids[0] ? '-' + ids[0] : ''}`, severity: sev, category: 'Dependencies', confidence: 'high',
    title: `Verwundbare JavaScript-Bibliothek: ${lib} ${version}${ids.length ? ` (${ids.slice(0, 2).join(', ')}${ids.length > 2 ? ' …' : ''})` : ''}`,
    description: `${where} bindet ${lib} in Version ${version} ein. Für diese Version sind ${vulns.length} Schwachstelle(n) bekannt${summaries.length ? ': ' + summaries.join('; ') : ''}.`,
    impact: 'Bekannte Lücken in Bibliotheken im Browser werden oft für XSS oder das Übernehmen von Sitzungen genutzt – Angreifer müssen nur die Versionsnummer erkennen.',
    remediation: fixed ? `${lib} auf mindestens ${fixed} aktualisieren (besser die neueste Version).` : `${lib} auf die neueste Version aktualisieren.`,
    location, links, package: { ecosystem: 'npm', name: lib, version, fixed: fixed || '' }, sourceModule: 'feed-jslibs',
  }, 'retire-feed');
}

function detect(lib, text, kind) {
  for (const re of lib[kind] || []) {
    const m = re.exec(text);
    // Endungen wie ".min", ".slim", ".js" gehoeren nicht zur Versionsnummer
    if (m && m[1]) { const v = m[1].replace(/([.-](min|slim|js|prod|production|umd|esm|bundle))+$/i, '').replace(/[.-]+$/, ''); if (/^\d/.test(v)) return v; }
  }
  return null;
}

// Projektdateien: Dateiname bzw. Kopf der Datei
function scanJsLibs(units, libs) {
  const out = [];
  if (!libs || !libs.length) return out;
  for (const u of units) {
    const p = base(u);
    if (!/\.m?js$/i.test(p)) continue;
    const name = p.split('/').pop();
    const head = String(u.content || '').slice(0, 60000);
    for (const lib of libs) {
      const version = detect(lib, name, 'filename') || detect(lib, head, 'filecontent');
      if (!version) continue;
      const vulns = lib.vulns.filter((v) => affects(v, version));
      if (vulns.length) out.push(libFinding(lib.name, version, vulns, p, `Die Datei „${name}“`));
    }
  }
  return out;
}

// Webseiten: Adressen der eingebundenen Skripte (z. B. CDN-Pfade mit Versionsnummer)
function scanScriptUris(uris, libs, pageUrl) {
  const out = [];
  if (!libs || !libs.length) return out;
  const seen = new Set();
  for (const uri of uris || []) {
    const name = String(uri).split('?')[0].split('/').pop();
    for (const lib of libs) {
      const version = detect(lib, uri, 'uri') || detect(lib, name, 'filename');
      if (!version || seen.has(lib.name + version)) continue;
      seen.add(lib.name + version);
      const vulns = lib.vulns.filter((v) => affects(v, version));
      if (vulns.length) { const f = libFinding(lib.name, version, vulns, pageUrl || uri, `Die Webseite ${pageUrl || ''}`.trim()); f.evidence = String(uri).slice(0, 480); out.push(f); }
    }
  }
  return out;
}

module.exports = { scanSecretsWithFeed, scanJsLibs, scanScriptUris, cmpVer };
