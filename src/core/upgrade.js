'use strict';

// Upgrade-Hinweise fuer Abhaengigkeits-Befunde: Sprung ueber eine Hauptversion (semver)?
// Wo stehen Changelog bzw. Release Notes (aus den Metadaten der Paket-Registry)? Welche
// Release Notes zwischen den Versionen erwaehnen Brueche? Optional fasst die KI zusammen.
// Nur lesende HTTPS-Abfragen an feste Registries (npm, PyPI, RubyGems, crates.io, Packagist)
// und die GitHub-API (Release Notes). Es wird nichts installiert oder geaendert.

const parseVer = (v) => {
  const m = String(v || '').trim().replace(/^[v=^~]+/, '').match(/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+.]?(.*))?$/);
  return m ? { major: +m[1], minor: +(m[2] || 0), patch: +(m[3] || 0), pre: m[4] || '' } : null;
};
const cmpVer = (a, b) => (a.major - b.major) || (a.minor - b.minor) || (a.patch - b.patch);

// Art des Versionssprungs; in 0.x gilt nach semver schon ein Minor-Sprung als brechend.
function semverJump(from, to) {
  const a = parseVer(from), b = parseVer(to);
  if (!a || !b) return { kind: 'unknown', breaking: null, from, to };
  let kind = 'patch';
  if (b.major !== a.major) kind = 'major';
  else if (b.minor !== a.minor) kind = 'minor';
  const breaking = kind === 'major' || (a.major === 0 && kind === 'minor');
  return { kind, breaking, majors: Math.max(0, b.major - a.major), from, to };
}

const ghRepo = (url) => {
  const m = String(url || '').match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$/i);
  return m ? { owner: m[1], repo: m[2] } : null;
};
const httpsOnly = (u) => (/^https:\/\/[^\s]+$/i.test(String(u || '')) ? String(u) : null);

async function getJson(url, { fetchImpl = fetch, signal, headers = {} } = {}) {
  const r = await fetchImpl(url, { headers: { Accept: 'application/json', 'User-Agent': 'Vigil-Security-Audit', ...headers }, signal: signal || AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

// Registry-Metadaten -> { repository, homepage, changelog, releaseNotes, registryUrl }
async function registryInfo(pkg, opts = {}) {
  const eco = String(pkg.ecosystem || '').toLowerCase();
  const name = String(pkg.name || '');
  const ver = pkg.fixed || pkg.version || '';
  const out = { repository: null, homepage: null, changelog: null, releaseNotes: null, registryUrl: null };
  try {
    if (eco === 'npm') {
      const enc = name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
      const j = await getJson(`https://registry.npmjs.org/${enc}/${encodeURIComponent(ver || 'latest')}`, opts);
      const repo = typeof j.repository === 'string' ? j.repository : j.repository && j.repository.url;
      out.repository = repo ? String(repo).replace(/^git\+/, '').replace(/^git:\/\//, 'https://').replace(/^github:/, 'https://github.com/') : null;
      out.homepage = httpsOnly(j.homepage);
      out.registryUrl = `https://www.npmjs.com/package/${name}`;
    } else if (eco === 'pypi') {
      const j = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/${ver ? encodeURIComponent(ver) + '/' : ''}json`, opts);
      const urls = (j.info && j.info.project_urls) || {};
      const pick = (re) => Object.entries(urls).find(([k]) => re.test(k));
      out.changelog = httpsOnly((pick(/change|history|news/i) || [])[1]);
      out.releaseNotes = httpsOnly((pick(/release/i) || [])[1]);
      out.repository = (pick(/source|repo|code|github/i) || [])[1] || null;
      out.homepage = httpsOnly((j.info && j.info.home_page) || (pick(/home/i) || [])[1]);
      out.registryUrl = `https://pypi.org/project/${name}/`;
    } else if (eco === 'rubygems') {
      const j = await getJson(`https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`, opts);
      out.changelog = httpsOnly(j.changelog_uri); out.repository = j.source_code_uri || null; out.homepage = httpsOnly(j.homepage_uri);
      out.registryUrl = `https://rubygems.org/gems/${name}`;
    } else if (eco === 'crates.io' || eco === 'cargo') {
      const j = await getJson(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, opts);
      out.repository = (j.crate && j.crate.repository) || null; out.homepage = httpsOnly(j.crate && j.crate.homepage);
      out.registryUrl = `https://crates.io/crates/${name}`;
    } else if (eco === 'packagist' || eco === 'composer') {
      const j = await getJson(`https://repo.packagist.org/p2/${name.split('/').map(encodeURIComponent).join('/')}.json`, opts);
      const v = ((j.packages && j.packages[name]) || [])[0] || {};
      out.repository = (v.source && v.source.url) || null; out.homepage = httpsOnly(v.homepage);
      out.registryUrl = `https://packagist.org/packages/${name}`;
    } else if (eco === 'go') {
      if (/^github\.com\//.test(name)) out.repository = 'https://' + name.split('/').slice(0, 3).join('/');
      out.registryUrl = `https://pkg.go.dev/${name}`;
    } else if (eco === 'maven') {
      const [g, a] = name.split(':');
      if (g && a) out.registryUrl = `https://central.sonatype.com/artifact/${g}/${a}`;
    }
  } catch (e) { out.error = e.message; }
  out.repository = out.repository ? httpsOnly(String(out.repository).replace(/\.git$/, '').replace(/^http:/, 'https:')) : null;
  return out;
}

// Release Notes zwischen from (exklusiv) und to (inklusive) von GitHub holen
async function githubReleases(repo, from, to, opts = {}) {
  const j = await getJson(`https://api.github.com/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/releases?per_page=40`, { ...opts, headers: { Accept: 'application/vnd.github+json' } });
  const a = parseVer(from), b = parseVer(to);
  return (Array.isArray(j) ? j : []).map((r) => ({ tag: r.tag_name, name: r.name, url: httpsOnly(r.html_url), body: String(r.body || '').slice(0, 6000), v: parseVer(String(r.tag_name || '').replace(/^[^\d]*/, '')) }))
    .filter((r) => r.v && (!a || cmpVer(r.v, a) > 0) && (!b || cmpVer(r.v, b) <= 0))
    .sort((x, y) => cmpVer(x.v, y.v));
}

const BREAK_RE = /\b(breaking|BREAKING CHANGE|backwards?[- ]incompatible|no longer|removed|drop(?:ped|s)? support|deprecat\w*|renamed|now requires|minimum (?:node|python|ruby|php|go) version|migration)\b/i;
function breakingLines(releases, max = 12) {
  const out = [];
  for (const r of releases) {
    for (const line of r.body.split(/\r?\n/)) {
      const l = line.replace(/^[\s>*#-]+/, '').trim();
      if (l.length > 8 && l.length < 300 && BREAK_RE.test(l)) out.push({ tag: r.tag, text: l });
      if (out.length >= max) return out;
    }
  }
  return out;
}

const UPGRADE_PROMPT = `Du hilfst bei einem Sicherheits-Update einer Abhaengigkeit im eigenen Projekt. Fasse anhand der mitgelieferten Release Notes zusammen, worauf man beim Update achten muss: brechende Aenderungen, entfernte/umbenannte APIs, neue Mindestversionen, Migrationsschritte. Nur was in den Release Notes steht – nichts erfinden; steht dort nichts dazu, sag das. Hoechstens 6 Stichpunkte mit "- ", Markdown erlaubt (**fett**, Backticks).`;

// pkg: { ecosystem, name, version, fixed }; config optional (KI-Zusammenfassung); aiCall aus aifix
async function upgradeGuide({ pkg = {}, config = null, fetchImpl = fetch, signal, aiCall = null } = {}) {
  const from = pkg.version || '', to = pkg.fixed || '';
  const jump = semverJump(from, to);
  const opts = { fetchImpl, signal };
  const info = await registryInfo(pkg, opts);
  const repo = ghRepo(info.repository);
  const links = [];
  const add = (label, url, kind = 'doc') => { if (url && !links.some((l) => l.url === url)) links.push({ label, url, kind }); };
  add('Changelog', info.changelog); add('Release Notes', info.releaseNotes);
  let releases = [], relError = null;
  if (repo) {
    add('GitHub Releases', `https://github.com/${repo.owner}/${repo.repo}/releases`);
    if (from && to) add(`Vergleich ${from} → ${to}`, `https://github.com/${repo.owner}/${repo.repo}/compare/v${from.replace(/^v/, '')}...v${to.replace(/^v/, '')}`);
    try { releases = await githubReleases(repo, from, to, opts); } catch (e) { relError = e.message; }
    releases.slice(-5).forEach((r) => add(`Release ${r.tag}`, r.url, 'news'));
  }
  add('Repository', info.repository); add('Registry', info.registryUrl);
  const hints = breakingLines(releases);
  let aiSummary = null, cost = null;
  if (config && config.provider && aiCall && releases.length) {
    const notes = releases.map((r) => `### ${r.tag}${r.name && r.name !== r.tag ? ' – ' + r.name : ''}\n${r.body}`).join('\n\n').slice(0, 14000);
    try {
      const r = await aiCall(config, { system: UPGRADE_PROMPT, user: `Paket: ${pkg.ecosystem}:${pkg.name} – Update von ${from || '?'} auf ${to || '?'} (${jump.kind}-Sprung).\n\n## Release Notes\n${notes}\n\n${config.lang === 'de' ? 'Antworte auf Deutsch.' : 'Answer in English.'}`, json: false, kind: 'upgrade', maxTokens: 700 });
      aiSummary = r.text.trim() || null; cost = r.cost;
    } catch (e) { relError = relError || e.message; }
  }
  return { ok: true, pkg: { ecosystem: pkg.ecosystem, name: pkg.name, from, to }, jump, links, hints, releases: releases.map((r) => ({ tag: r.tag, url: r.url })), aiSummary, cost, error: info.error || relError || null };
}

module.exports = { semverJump, parseVer, registryInfo, githubReleases, breakingLines, upgradeGuide, ghRepo };
