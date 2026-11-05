'use strict';

// Support-Enden aus einer gepflegten Quelle (endoflife.date) statt aus Tabellen im Code.
// Der Feed wird wie die anderen taeglich geladen (feeds.js). Fehlt er, greifen die Pruefungen auf ihre
// eingebauten Fallback-Werte zurueck – status() liefert dann null.

// Nur was Vigil wirklich vergleicht; der Rest der Quelle (rund 3 MB) wird nicht gespeichert.
const PRODUCTS = ['postgresql', 'mysql', 'mariadb', 'mongodb', 'redis', 'openssl', 'debian', 'ubuntu', 'rocky-linux', 'almalinux', 'nginx', 'apache-http-server', 'php', 'nodejs', 'python', 'tomcat', 'kubernetes'];
const FEED_URL = 'https://endoflife.date/api/v1/products/full';

function parseFull(text) {
  const j = JSON.parse(text);
  if (!j || !Array.isArray(j.result)) throw new Error('Format unerwartet');
  const out = {};
  for (const p of j.result) {
    if (!p || !PRODUCTS.includes(p.name) || !Array.isArray(p.releases)) continue;
    out[p.name] = p.releases.filter((r) => r && r.name).map((r) => ({
      cycle: String(r.name).slice(0, 40),
      eolFrom: typeof r.eolFrom === 'string' ? r.eolFrom.slice(0, 10) : null,
      isEol: r.isEol === true,
      latest: r.latest && r.latest.name ? String(r.latest.name).slice(0, 40) : null,
    }));
  }
  if (Object.keys(out).length < 8) throw new Error(`nur ${Object.keys(out).length} Produkte – Format unerwartet`);
  return out;
}

let current = null;
// Beim Start eines Laufs gesetzt (index.js), damit die Pruefungen nichts durchreichen muessen.
function use(data) { current = data && typeof data === 'object' ? data : null; }

// Passende Versionsreihe zu einer Version: laengster Treffer ("10.11.6" -> "10.11", "16.2" -> "16").
function cycleOf(releases, version) {
  const v = String(version || '').trim();
  let best = null;
  for (const r of releases || []) {
    if ((v === r.cycle || v.startsWith(`${r.cycle}.`)) && (!best || r.cycle.length > best.cycle.length)) best = r;
  }
  return best;
}

// { cycle, eolFrom, isEol, latest } oder null, wenn die Quelle fehlt oder die Reihe unbekannt ist.
function status(product, version, { now = Date.now(), data = current } = {}) {
  const r = data && cycleOf(data[product], version);
  if (!r) return null;
  const t = r.eolFrom ? Date.parse(r.eolFrom) : NaN;
  return { cycle: r.cycle, eolFrom: r.eolFrom, latest: r.latest, isEol: Number.isNaN(t) ? r.isEol : t <= now };
}

module.exports = { PRODUCTS, FEED_URL, parseFull, use, status, cycleOf };
