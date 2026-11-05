'use strict';

// Zustand der direkten Abhaengigkeiten ueber deps.dev (Open Source Insights, nur lesende GETs):
//  - verwaist: seit ueber 2 Jahren keine neue Version oder Quell-Repository archiviert
//  - OpenSSF Scorecard: niedriger Wert -> Hinweis
// Gedrosselt (max. 4 parallel, 60 ms Abstand) und auf die ersten 60 Pakete begrenzt.

const { normalizeFinding } = require('./schema');
const { throttle, limiter } = require('./ratelimit');
const { check, DepsDevPackageSchema, DepsDevVersionSchema, DepsDevProjectSchema } = require('./validation');

const API = 'https://api.deps.dev/v3';
const SYSTEM = { npm: 'npm', PyPI: 'pypi', Go: 'go', Maven: 'maven', 'crates.io': 'cargo', RubyGems: 'rubygems', NuGet: 'nuget' };
const M = 'package-health';
const TWO_YEARS = 2 * 365.25 * 24 * 3600 * 1000;
const LIMIT = limiter(4);

async function getJson(fetchImpl, url, schema, signal) {
  return LIMIT(async () => {
    await throttle('depsdev', 60);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    try {
      const res = await fetchImpl(url, { headers: { Accept: 'application/json' }, signal: signal ? AbortSignal.any([ctrl.signal, signal]) : ctrl.signal });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const v = check(schema, await res.json());
      if (!v.ok) throw new Error('Antwort unerwartet');
      return v.data;
    } finally { clearTimeout(t); }
  });
}

const day = (iso) => String(iso || '').slice(0, 10);
const loc = (d) => `${d.ecosystem}: ${d.name}${d.version ? '@' + d.version : ''}`;

// deps: [{ ecosystem, name, version }] (direkte Abhaengigkeiten aus den Manifesten)
async function checkPackageHealth(deps, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const now = opts.now || Date.now();
  const max = opts.max || 60;
  const uniq = [...new Map(deps.filter((d) => SYSTEM[d.ecosystem] && d.name).map((d) => [`${d.ecosystem}:${d.name}`, d])).values()].slice(0, max);
  const findings = [], notes = [];
  if (!uniq.length) return { findings, notes, ran: false };
  (opts.onProgress || (() => {}))({ phase: 'cve', message: `Pakete: Pflegezustand und Scorecard für ${uniq.length} Paket(e) (deps.dev) …` });
  let failed = 0;
  const repos = new Map(); // Projekt-ID -> Promise (mehrere Pakete teilen sich ein Repository)
  await Promise.all(uniq.map(async (d) => {
    if (opts.signal && opts.signal.aborted) return;
    const sys = SYSTEM[d.ecosystem];
    try {
      const pkg = await getJson(fetchImpl, `${API}/systems/${sys}/packages/${encodeURIComponent(d.name)}`, DepsDevPackageSchema, opts.signal);
      if (!pkg || !pkg.versions.length) return;
      const dated = pkg.versions.filter((v) => v.publishedAt).sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt));
      const latest = dated[0];
      if (latest && now - Date.parse(latest.publishedAt) > TWO_YEARS) {
        findings.push(normalizeFinding({
          ruleId: 'pkg-abandoned', severity: 'low', category: 'Dependencies', confidence: 'medium', sourceModule: M,
          title: `Paket seit über 2 Jahren ohne neue Version: ${d.name}`,
          location: loc(d), package: { ecosystem: d.ecosystem, name: d.name, version: d.version || '' },
          description: `Die letzte Version von „${d.name}“ (${latest.versionKey.version}) erschien am ${day(latest.publishedAt)}. Wird ein Paket nicht mehr gepflegt, bleiben neue Lücken offen – und verwaiste Pakete werden gern von Fremden übernommen.`,
          impact: 'Künftige Schwachstellen werden voraussichtlich nicht mehr behoben.',
          remediation: 'Prüfen, ob es einen gepflegten Nachfolger oder Fork gibt, und das Paket mittelfristig ersetzen.',
        }, M));
      }
      const def = pkg.versions.find((v) => v.isDefault) || latest || pkg.versions[pkg.versions.length - 1];
      const ver = await getJson(fetchImpl, `${API}/systems/${sys}/packages/${encodeURIComponent(d.name)}/versions/${encodeURIComponent(def.versionKey.version)}`, DepsDevVersionSchema, opts.signal);
      const proj = ver && ver.relatedProjects.find((p) => p.relationType === 'SOURCE_REPO' && /^(github\.com|gitlab\.com)\//.test(p.projectKey.id));
      if (!proj) return;
      const id = proj.projectKey.id;
      if (!repos.has(id)) repos.set(id, getJson(fetchImpl, `${API}/projects/${encodeURIComponent(id)}`, DepsDevProjectSchema, opts.signal));
      const pr = await repos.get(id);
      const sc = pr && pr.scorecard;
      if (!sc) return;
      const maintained = sc.checks.find((c) => c.name === 'Maintained');
      if (maintained && /archived/i.test(maintained.reason || '')) {
        findings.push(normalizeFinding({
          ruleId: 'pkg-repo-archived', severity: 'medium', category: 'Dependencies', confidence: 'high', sourceModule: M,
          title: `Quell-Repository archiviert: ${d.name}`,
          location: loc(d), package: { ecosystem: d.ecosystem, name: d.name, version: d.version || '' },
          description: `Das Repository ${id} ist als archiviert markiert – die Entwickler nehmen keine Änderungen mehr an, auch keine Sicherheitskorrekturen.`,
          impact: 'Künftige Schwachstellen werden nicht mehr behoben.',
          remediation: 'Auf einen gepflegten Nachfolger oder Fork umsteigen.',
          links: [{ label: id, url: `https://${id}` }],
        }, M));
      }
      if (sc.overallScore < 5) {
        const weak = sc.checks.filter((c) => typeof c.score === 'number' && c.score >= 0 && c.score <= 2).map((c) => c.name).slice(0, 6);
        findings.push(normalizeFinding({
          ruleId: 'pkg-low-scorecard', severity: sc.overallScore < 3 ? 'low' : 'info', category: 'Dependencies', confidence: 'medium', sourceModule: M,
          title: `Niedriger OpenSSF-Scorecard-Wert: ${d.name} (${sc.overallScore.toFixed(1)}/10)`,
          location: loc(d), package: { ecosystem: d.ecosystem, name: d.name, version: d.version || '' },
          description: `Die OpenSSF Scorecard bewertet die Sicherheitspraktiken des Repositorys ${id} mit ${sc.overallScore.toFixed(1)} von 10. Ein niedriger Wert heißt nicht, dass das Paket unsicher ist – aber Übernahmen und unbemerkte Manipulationen sind wahrscheinlicher.${weak.length ? ` Schwach bewertet: ${weak.join(', ')}.` : ''}`,
          impact: 'Höheres Risiko für Lieferketten-Angriffe über dieses Paket.',
          remediation: 'Für kritische Stellen eine besser gepflegte Alternative erwägen oder die Version fest pinnen und Updates bewusst prüfen.',
          links: [{ label: 'OpenSSF Scorecard', url: `https://scorecard.dev/viewer/?uri=${id}` }],
        }, M));
      }
    } catch (e) { failed++; if (failed <= 3) notes.push(`Paket-Zustand (deps.dev) für ${d.name} nicht abrufbar: ${e.message}`); }
  }));
  if (failed > 3) notes.push(`Paket-Zustand (deps.dev): ${failed} Paket(e) insgesamt nicht abrufbar.`);
  return { findings, notes, ran: failed === 0 };
}

module.exports = { checkPackageHealth, SYSTEM };
