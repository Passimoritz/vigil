'use strict';

// WordPress, Joomla und TYPO3: unsichere Einstellungen im Projekt, Bestand an Kern/Erweiterungen
// mit Version (Projektdateien oder Hinweise einer freigegebenen Webseite) und der Abgleich gegen
// die NVD-Datenbank (nur lesende Abfragen, gedrosselt).

const { normalizeFinding, cvssToSeverity } = require('../schema');
const { throttle } = require('../ratelimit');
const { check, NvdResponseSchema } = require('../validation');

const M = 'cms-audit';
const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const CMS_NAME = { wordpress: 'WordPress', joomla: 'Joomla', typo3: 'TYPO3' };

function mk(u, idx, o) {
  return normalizeFinding({ category: 'Config', confidence: 'high', ...o, location: idx == null || idx < 0 ? base(u) : `${base(u)}:${lineOf(u.content || '', idx)}`, sourceModule: M }, M);
}

// --- Einstellungen im Projekt ---------------------------------------------------------------
function cmsConfig(units) {
  const out = [];
  for (const u of units) {
    const p = base(u).toLowerCase();
    const c = u.content || '';
    if (/(^|\/)wp-config\.php$/.test(p)) {
      const dbg = c.search(/define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*(true|1|['"]true['"])\s*\)/i);
      if (dbg >= 0) out.push(mk(u, dbg, { ruleId: 'wp-debug-on', severity: 'medium', title: 'WordPress läuft im Debug-Modus (WP_DEBUG)', description: 'Mit WP_DEBUG = true zeigt WordPress Fehlermeldungen samt Pfaden und Datenbankdetails an bzw. schreibt sie nach wp-content/debug.log – das ist oft öffentlich abrufbar.', impact: 'Angreifer erfahren Pfade, Plugin-Namen und Fehlerdetails für gezielte Angriffe.', remediation: "define('WP_DEBUG', false); auf dem Live-System setzen (Debugging nur lokal)." }));
      if (!/define\s*\(\s*['"]DISALLOW_FILE_EDIT['"]\s*,\s*(true|1)\s*\)/i.test(c)) out.push(mk(u, null, { ruleId: 'wp-file-edit-allowed', severity: 'low', title: 'WordPress erlaubt das Bearbeiten von Code im Admin-Bereich', description: 'Ohne DISALLOW_FILE_EDIT kann jeder Administrator – oder wer ein Admin-Konto übernimmt – Theme- und Plugin-Dateien direkt im Browser ändern und so eigenen PHP-Code auf dem Server ausführen.', impact: 'Aus einem gekaperten Admin-Konto wird sofort Codeausführung auf dem Server.', remediation: "define('DISALLOW_FILE_EDIT', true); in wp-config.php ergänzen." }));
    }
    if (/(^|\/)configuration\.php$/.test(p) && /class\s+JConfig/.test(c)) {
      const dbg = c.search(/public\s+\$debug\s*=\s*['"]?(1|true)['"]?\s*;/i);
      if (dbg >= 0) out.push(mk(u, dbg, { ruleId: 'joomla-debug-on', severity: 'medium', title: 'Joomla läuft im Debug-Modus', description: 'Im Debug-Modus zeigt Joomla Abfragen, Pfade und Sprachschlüssel auf jeder Seite an.', impact: 'Angreifer erfahren Datenbank- und Systemdetails für gezielte Angriffe.', remediation: "public $debug = '0'; setzen (System › Konfiguration › System › Debug-System: Nein)." }));
      const er = c.search(/public\s+\$error_reporting\s*=\s*['"](maximum|development|-1)['"]/i);
      if (er >= 0) out.push(mk(u, er, { ruleId: 'joomla-error-reporting', severity: 'low', title: 'Joomla zeigt alle Fehlermeldungen an', description: 'Mit maximaler Fehlerberichterstattung landen PHP-Fehler samt Pfaden im Browser.', impact: 'Fehlerdetails verraten den Aufbau der Installation.', remediation: "public $error_reporting = 'none'; auf dem Live-System setzen." }));
    }
    if (/(^|\/)(localconfiguration|additionalconfiguration|settings|additional)\.php$/.test(p) && /['"](SYS|BE|FE)['"]\s*=>/.test(c)) {
      const de = c.search(/['"]displayErrors['"]\s*=>\s*['"]?(1|-1|true)['"]?/i);
      const ip = c.search(/['"]devIPmask['"]\s*=>\s*['"]\*['"]/);
      const at = de >= 0 ? de : ip;
      if (at >= 0) out.push(mk(u, at, { ruleId: 'typo3-debug-on', severity: 'medium', title: 'TYPO3 zeigt Fehlerdetails für alle Besucher', description: 'displayErrors bzw. devIPmask = * schaltet die ausführliche Fehlerausgabe für jede Adresse frei – inklusive Stacktraces und Pfaden.', impact: 'Angreifer erfahren Pfade, Erweiterungen und Fehlerdetails für gezielte Angriffe.', remediation: "Auf dem Live-System 'displayErrors' => 0 und 'devIPmask' => '' (bzw. nur die eigene IP) setzen." }));
    }
  }
  return out;
}

// --- Bestand: Kern, Plugins, Themes mit Version ---------------------------------------------
const verOk = (v) => /^\d+(\.\d+){0,3}[\w.-]*$/.test(String(v || ''));
const slugOk = (s) => /^[a-z0-9][a-z0-9_-]{1,79}$/i.test(String(s || ''));
function cmsInventory(units) {
  const items = [];
  const push = (it) => { if (verOk(it.version) && slugOk(it.slug) && !items.some((x) => x.cms === it.cms && x.slug === it.slug && x.kind === it.kind)) items.push(it); };
  for (const u of units) {
    const p = base(u);
    const c = u.content || '';
    let m;
    if (/(^|\/)wp-includes\/version\.php$/i.test(p) && (m = c.match(/\$wp_version\s*=\s*['"]([^'"]+)['"]/))) push({ cms: 'wordpress', kind: 'core', slug: 'wordpress', version: m[1], location: p });
    if ((m = p.match(/(?:^|\/)wp-content\/plugins\/([^/]+)\/[^/]+\.php$/i)) && /Plugin Name\s*:/i.test(c)) { const v = c.match(/^\s*\*?\s*Version\s*:\s*([\w.-]+)/im); if (v) push({ cms: 'wordpress', kind: 'plugin', slug: m[1].toLowerCase(), version: v[1], location: p }); }
    if ((m = p.match(/(?:^|\/)wp-content\/plugins\/([^/]+)\/readme\.txt$/i))) { const v = c.match(/^\s*Stable tag\s*:\s*([\w.-]+)/im); if (v && !/trunk/i.test(v[1])) push({ cms: 'wordpress', kind: 'plugin', slug: m[1].toLowerCase(), version: v[1], location: p }); }
    if ((m = p.match(/(?:^|\/)wp-content\/themes\/([^/]+)\/style\.css$/i)) && /Theme Name\s*:/i.test(c)) { const v = c.match(/^\s*\*?\s*Version\s*:\s*([\w.-]+)/im); if (v) push({ cms: 'wordpress', kind: 'theme', slug: m[1].toLowerCase(), version: v[1], location: p }); }
    if (/(^|\/)libraries\/src\/Version\.php$/i.test(p)) {
      const g = (k) => (c.match(new RegExp(`const\\s+${k}\\s*=\\s*['"]?(\\d+)`)) || [])[1];
      if (g('MAJOR_VERSION')) push({ cms: 'joomla', kind: 'core', slug: 'joomla', version: [g('MAJOR_VERSION'), g('MINOR_VERSION') || 0, g('PATCH_VERSION') || 0].join('.'), location: p });
    }
    if (/(^|\/)administrator\/manifests\/files\/joomla\.xml$/i.test(p) && (m = c.match(/<version>([^<]+)<\/version>/))) push({ cms: 'joomla', kind: 'core', slug: 'joomla', version: m[1].trim(), location: p });
    if (/(^|\/)typo3\/sysext\/core\/Classes\/Information\/Typo3Version\.php$/i.test(p) && (m = c.match(/const\s+VERSION\s*=\s*['"]([^'"]+)['"]/))) push({ cms: 'typo3', kind: 'core', slug: 'typo3', version: m[1], location: p });
    if (/(^|\/)composer\.lock$/i.test(p)) {
      try { const j = JSON.parse(c); const core = (j.packages || []).find((x) => x.name === 'typo3/cms-core'); if (core) push({ cms: 'typo3', kind: 'core', slug: 'typo3', version: String(core.version).replace(/^v/, ''), location: p }); } catch { /* defekt */ }
    }
  }
  return items;
}

// --- Hinweise einer freigegebenen Webseite ---------------------------------------------------
// pages: [{ url, html }] -> [{ cms, kind, slug, version?, location, source:'web' }]
function cmsFromHtml(pages) {
  const items = [];
  for (const pg of (pages || []).slice(0, 10)) {
    const h = String(pg.html || '').slice(0, 500000);
    const gen = h.match(/<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i) || h.match(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i);
    if (gen) {
      const g = gen[1];
      let m;
      if ((m = g.match(/WordPress\s+([\d.]+)/i))) items.push({ cms: 'wordpress', kind: 'core', slug: 'wordpress', version: m[1], location: pg.url, source: 'web' });
      else if ((m = g.match(/TYPO3\s+([\d.]+)/i))) items.push({ cms: 'typo3', kind: 'core', slug: 'typo3', version: m[1], location: pg.url, source: 'web' });
      else if (/Joomla/i.test(g)) items.push({ cms: 'joomla', kind: 'core', slug: 'joomla', version: (g.match(/([\d]+\.[\d.]+)/) || [])[1] || '', location: pg.url, source: 'web' });
    }
    for (const m of h.matchAll(/\/wp-content\/(plugins|themes)\/([a-z0-9_-]+)\/[^"'\s?]*\?ver=([\d.]+)/gi)) {
      const it = { cms: 'wordpress', kind: m[1].toLowerCase() === 'plugins' ? 'plugin' : 'theme', slug: m[2].toLowerCase(), version: m[3], location: pg.url, source: 'web', weak: true };
      if (!items.some((x) => x.slug === it.slug && x.kind === it.kind)) items.push(it);
    }
    if (items.length >= 40) break;
  }
  const seen = new Set();
  return items.filter((x) => { const k = `${x.cms}:${x.kind}:${x.slug}`; if (seen.has(k)) return false; seen.add(k); return true; });
}
// Sichtbare Versionsnummer des CMS-Kerns als Hinweis (die Pruefung selbst bleibt lesend)
function webVersionFindings(items, targetUrl) {
  return items.filter((x) => x.kind === 'core' && x.version).slice(0, 1).map((x) => normalizeFinding({
    ruleId: 'cms-version-public', severity: 'info', category: 'Config', confidence: 'high', sourceModule: M,
    title: `CMS-Version öffentlich sichtbar: ${CMS_NAME[x.cms]} ${x.version}`,
    location: targetUrl,
    description: `Die Seite nennt im generator-Tag „${CMS_NAME[x.cms]} ${x.version}“. Damit sehen automatisierte Scanner sofort, welche bekannten Lücken sie ausprobieren können.`,
    impact: 'Erleichtert gezielte Angriffe auf bekannte Lücken dieser Version.',
    remediation: 'Generator-Tag entfernen (WordPress: remove_action(\'wp_head\', \'wp_generator\');) und vor allem das CMS aktuell halten.',
  }, 'cms-web'));
}

// --- Abgleich mit der NVD (CPE-Suche, nur GET) ------------------------------------------------
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
function cpeFor(it) {
  if (it.kind === 'core') return { wordpress: 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*', joomla: 'cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*', typo3: 'cpe:2.3:a:typo3:typo3:*:*:*:*:*:*:*:*' }[it.cms];
  if (it.cms === 'wordpress') return `cpe:2.3:a:*:${it.slug}:*:*:*:*:*:wordpress:*:*`;
  return null;
}
function nvdScore(cve) {
  const m = cve.metrics || {};
  for (const k of ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2']) {
    const s = Array.isArray(m[k]) && m[k][0] && m[k][0].cvssData && Number(m[k][0].cvssData.baseScore);
    if (s >= 0) return s;
  }
  return null;
}

// items aus cmsInventory/cmsFromHtml -> Befunde. opts: { fetchImpl, signal, max, gapMs, apiKey }
async function lookupCmsVulns(items, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const max = opts.max || 6;
  const gap = opts.gapMs != null ? opts.gapMs : (opts.apiKey ? 700 : 6500); // NVD: 5 Abfragen je 30 s ohne Schluessel
  const findings = [], notes = [];
  const todo = items.filter((x) => x.version && cpeFor(x) && !x.weak).slice(0, max);
  let ok = 0;
  for (const it of todo) {
    if (opts.signal && opts.signal.aborted) break;
    const q = new URLSearchParams({ virtualMatchString: cpeFor(it), versionStart: it.version, versionStartType: 'including', versionEnd: it.version, versionEndType: 'including', resultsPerPage: '50' });
    let data;
    try {
      await throttle('nvd', gap);
      const res = await fetchImpl(`${NVD}?${q}`, { headers: { Accept: 'application/json', ...(opts.apiKey ? { apiKey: opts.apiKey } : {}) }, signal: opts.signal });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const v = check(NvdResponseSchema, await res.json());
      if (!v.ok) throw new Error('Antwort unerwartet');
      data = v.data;
    } catch (e) { notes.push(`CMS-Abgleich (NVD) für ${it.slug} nicht möglich: ${e.message}`); continue; }
    ok++;
    const cves = data.vulnerabilities.map((x) => ({ id: x.cve.id, score: nvdScore(x.cve) }));
    if (!cves.length) continue;
    const top = Math.max(...cves.map((x) => x.score || 0));
    const label = it.kind === 'core' ? CMS_NAME[it.cms] : it.slug;
    findings.push(normalizeFinding({
      ruleId: `cms-vulnerable-${it.kind}`, severity: cvssToSeverity(top) || 'medium', cvss: top || null, category: 'Dependencies', confidence: it.source === 'web' ? 'medium' : 'high', sourceModule: M,
      title: it.kind === 'core' ? `Verwundbare ${CMS_NAME[it.cms]}-Version: ${it.version}` : it.kind === 'plugin' ? `Verwundbares WordPress-Plugin: ${it.slug} ${it.version}` : `Verwundbares WordPress-Theme: ${it.slug} ${it.version}`,
      location: it.location,
      package: { ecosystem: CMS_NAME[it.cms], name: it.slug, version: it.version },
      description: `Für „${label}“ in Version ${it.version} sind in der NVD ${cves.length} Schwachstelle(n) eingetragen.`,
      impact: `Bekannte Lücken: ${cves.slice(0, 8).map((x) => x.id).join(', ')}${cves.length > 8 ? ' …' : ''}.`,
      remediation: it.kind === 'core' ? `${CMS_NAME[it.cms]} auf die aktuelle Version aktualisieren und automatische Sicherheitsupdates einschalten.` : it.kind === 'plugin' ? `WordPress-Plugin „${it.slug}“ aktualisieren oder entfernen, falls es nicht mehr gepflegt wird.` : `WordPress-Theme „${it.slug}“ aktualisieren oder entfernen, falls es nicht mehr gepflegt wird.`,
      links: cves.slice(0, 5).map((x) => ({ label: x.id, url: `https://nvd.nist.gov/vuln/detail/${x.id}` })),
    }, it.source === 'web' ? 'cms-web' : 'cms-nvd'));
  }
  return { findings, notes, ran: todo.length > 0 && ok === todo.length };
}

module.exports = { cmsConfig, cmsInventory, cmsFromHtml, webVersionFindings, lookupCmsVulns, cpeFor };
