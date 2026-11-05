'use strict';

// Paketliste (SBOM) eines geprueften Projekts als CycloneDX 1.5 JSON bzw. SPDX 2.3 JSON.
// Quelle: result.meta.sbom aus der Pipeline ([{ ecosystem, name, version }]); bekannte Luecken aus
// den Befunden (package + CVE/GHSA/MAL-Kennung) landen bei CycloneDX im Abschnitt "vulnerabilities".

const crypto = require('crypto');

const VIGIL_VERSION = (() => { try { return require('../../package.json').version; } catch { return '0.0.0'; } })();
const PURL_TYPE = { npm: 'npm', PyPI: 'pypi', Go: 'golang', Maven: 'maven', 'crates.io': 'cargo', RubyGems: 'gem', NuGet: 'nuget', Packagist: 'composer' };
const enc = (s) => encodeURIComponent(s).replace(/%2F/g, '/');

function purl(p) {
  const type = PURL_TYPE[p.ecosystem];
  if (!type || !p.name) return null;
  const v = p.version ? '@' + encodeURIComponent(p.version) : '';
  if (type === 'npm' && p.name.startsWith('@')) { const [scope, n] = p.name.split('/'); return `pkg:npm/${encodeURIComponent(scope)}/${encodeURIComponent(n || '')}${v}`; }
  if (type === 'maven') { const [g, a] = p.name.split(':'); return a ? `pkg:maven/${enc(g)}/${encodeURIComponent(a)}${v}` : null; }
  if (type === 'pypi') return `pkg:pypi/${encodeURIComponent(p.name.toLowerCase().replace(/[-_.]+/g, '-'))}${v}`;
  if (type === 'golang') return `pkg:golang/${enc(p.name)}${p.version ? '@v' + encodeURIComponent(p.version.replace(/^v/, '')) : ''}`;
  if (type === 'composer') return `pkg:composer/${enc(p.name)}${v}`;
  return `pkg:${type}/${encodeURIComponent(p.name)}${v}`;
}

function packagesOf(result) {
  const list = (result && result.meta && Array.isArray(result.meta.sbom)) ? result.meta.sbom : [];
  const seen = new Map();
  for (const p of list) {
    if (!p || !p.name) continue;
    const k = `${p.ecosystem}:${p.name}@${p.version || ''}`;
    if (!seen.has(k)) seen.set(k, { ecosystem: String(p.ecosystem || ''), name: String(p.name), version: String(p.version || '') });
  }
  return [...seen.values()].sort((a, b) => (a.ecosystem + a.name).localeCompare(b.ecosystem + b.name));
}

const projectName = (opts) => String((opts && opts.name) || 'vigil-project').replace(/[\\/]+$/, '').split(/[\\/]/).pop() || 'vigil-project';
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'));

// opts: { name, now: Date }
function toCycloneDx(result, opts = {}) {
  const pkgs = packagesOf(result);
  const now = opts.now || new Date();
  const comps = pkgs.map((p) => {
    const ref = purl(p) || `${p.ecosystem}:${p.name}@${p.version}`;
    const c = { type: 'library', 'bom-ref': ref, name: p.name, ...(p.version ? { version: p.version } : {}) };
    if (p.ecosystem === 'Maven' && p.name.includes(':')) { const [g, a] = p.name.split(':'); c.group = g; c.name = a; }
    if (p.ecosystem === 'npm' && p.name.startsWith('@')) { const [g, a] = p.name.split('/'); c.group = g; c.name = a || p.name; }
    if (purl(p)) c.purl = purl(p);
    c.properties = [{ name: 'vigil:ecosystem', value: p.ecosystem }];
    return c;
  });
  const refOf = new Map(pkgs.map((p, i) => [`${p.ecosystem}:${p.name}@${p.version}`.toLowerCase(), comps[i]['bom-ref']]));
  const vulns = new Map();
  const SEV = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };
  for (const f of (result && result.findings) || []) {
    if (!f.package || !f.package.name) continue;
    const ref = refOf.get(`${f.package.ecosystem}:${f.package.name}@${f.package.version || ''}`.toLowerCase());
    if (!ref) continue;
    const id = (String(f.ruleId || '') + ' ' + String(f.title || '')).match(/\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|MAL-\d{4}-\d+|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b/i);
    if (!id && f.ruleId !== 'malicious-package') continue;
    const vid = id ? id[1].toUpperCase() : `VIGIL-${f.ruleId}-${f.package.name}`;
    const v = vulns.get(vid) || { id: vid, source: { name: /^CVE-/.test(vid) ? 'NVD' : 'OSV' }, ratings: [{ severity: SEV[f.severity] || 'unknown', ...(f.cvss != null ? { score: f.cvss, method: 'CVSSv31' } : {}) }], description: String(f.title || '').slice(0, 300), ...(f.package.fixed ? { recommendation: `Upgrade to ${f.package.fixed}` } : {}), affects: [] };
    if (!v.affects.some((a) => a.ref === ref)) v.affects.push({ ref });
    vulns.set(vid, v);
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:' + uuid(),
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: 'application', name: 'Vigil', version: VIGIL_VERSION }] },
      component: { type: 'application', 'bom-ref': 'vigil-root', name: projectName(opts) },
    },
    components: comps,
    dependencies: [{ ref: 'vigil-root', dependsOn: comps.map((c) => c['bom-ref']) }],
    ...(vulns.size ? { vulnerabilities: [...vulns.values()] } : {}),
  };
}

function toSpdx(result, opts = {}) {
  const pkgs = packagesOf(result);
  const now = opts.now || new Date();
  const name = projectName(opts);
  const sid = (s, i) => `SPDXRef-Package-${String(s).replace(/[^A-Za-z0-9.-]+/g, '-').slice(0, 60)}-${i}`;
  const root = { SPDXID: 'SPDXRef-Package-root', name, downloadLocation: 'NOASSERTION', filesAnalyzed: false, licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION', primaryPackagePurpose: 'APPLICATION' };
  const packages = pkgs.map((p, i) => ({
    SPDXID: sid(p.name, i + 1), name: p.name, ...(p.version ? { versionInfo: p.version } : {}),
    downloadLocation: 'NOASSERTION', filesAnalyzed: false, licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION',
    primaryPackagePurpose: 'LIBRARY',
    ...(purl(p) ? { externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: purl(p) }] } : {}),
  }));
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${name}-sbom`,
    documentNamespace: `https://spdx.org/spdxdocs/vigil-${encodeURIComponent(name)}-${uuid()}`,
    creationInfo: { created: now.toISOString().replace(/\.\d{3}Z$/, 'Z'), creators: [`Tool: Vigil-${VIGIL_VERSION}`] },
    packages: [root, ...packages],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Package-root' },
      ...packages.map((p) => ({ spdxElementId: 'SPDXRef-Package-root', relationshipType: 'DEPENDS_ON', relatedSpdxElement: p.SPDXID })),
    ],
  };
}

// format: 'cyclonedx' | 'spdx' -> JSON-Text
function sbomJson(result, format, opts) {
  const doc = format === 'spdx' ? toSpdx(result, opts) : toCycloneDx(result, opts);
  return JSON.stringify(doc, null, 2);
}

module.exports = { toCycloneDx, toSpdx, sbomJson, purl, packagesOf };
