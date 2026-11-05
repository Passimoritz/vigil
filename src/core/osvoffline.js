'use strict';

// Optionaler Offline-Vorrat der OSV-Datenbank – nur fuer die Oekosysteme, die in den gespeicherten
// SBOMs vorkommen (npm, PyPI, Maven …). Quelle: die offiziellen Komplett-Abzuege
// https://osv-vulnerabilities.storage.googleapis.com/<Oekosystem>/all.zip. Daraus baut Vigil einen
// kompakten Index (Paket -> betroffene Versionsbereiche) und nutzt ihn, wenn OSV.dev nicht
// erreichbar ist. Standardmaessig AUS (die Abzuege sind gross).

const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const { fetchLimited } = require('./feeds');

const BASE = 'https://osv-vulnerabilities.storage.googleapis.com/';
const MAX_AGE_MS = 3 * 24 * 60 * 60 * 1000;
const KNOWN_ECOS = new Set(['npm', 'PyPI', 'Maven', 'Go', 'crates.io', 'NuGet', 'RubyGems', 'Packagist', 'Pub', 'Hex']);
const ecoFile = (dir, eco) => path.join(dir, `${eco.replace(/[^A-Za-z0-9.-]/g, '_')}.json`);

// Versionen vergleichen (semver-artig; Vorabversionen kleiner)
function cmpVer(a, b) {
  const pa = String(a).replace(/^v/, '').split(/[.+-]/), pb = String(b).replace(/^v/, '').split(/[.+-]/);
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

// Ein OSV-Eintrag -> kompakte Datensaetze je Paket dieses Oekosystems
function compactVuln(v, eco) {
  const out = [];
  const sev = (v.database_specific && v.database_specific.severity) || ((v.severity || [])[0] || {}).score || '';
  for (const a of v.affected || []) {
    if (!a.package || a.package.ecosystem !== eco || !a.package.name) continue;
    const ranges = (a.ranges || []).filter((r) => r.type === 'ECOSYSTEM' || r.type === 'SEMVER').map((r) => (r.events || []).map((e) => (e.introduced != null ? ['i', String(e.introduced)] : e.fixed != null ? ['f', String(e.fixed)] : e.last_affected != null ? ['l', String(e.last_affected)] : null)).filter(Boolean)).filter((r) => r.length);
    const versions = ranges.length ? undefined : (a.versions || []).slice(0, 400).map(String);
    if (!ranges.length && !(versions && versions.length)) continue;
    out.push([a.package.name.toLowerCase(), { id: v.id, a: (v.aliases || []).filter((x) => /^CVE-/.test(x)).slice(0, 3), s: String(v.summary || '').slice(0, 200), sev: String(sev).slice(0, 60), r: ranges, v: versions, p: v.published || '' }]);
  }
  return out;
}

function affects(rec, version) {
  if (rec.v && rec.v.includes(version)) return true;
  for (const evs of rec.r || []) {
    let hit = false;
    for (const [k, val] of evs) {
      if (k === 'i') { if (val === '0' || cmpVer(version, val) >= 0) hit = true; }
      else if (k === 'f') { if (hit && cmpVer(version, val) < 0) return true; hit = false; }
      else if (k === 'l') { if (hit && cmpVer(version, val) <= 0) return true; hit = false; }
    }
    if (hit) return true;
  }
  return false;
}

// Zip-Abzug -> Index { pkgs: { name: [rec…] }, count }
function buildIndex(zipBuf, eco, { maxEntries = 400000, maxEntryBytes = 4 * 1024 * 1024 } = {}) {
  const zip = new AdmZip(zipBuf);
  const pkgs = {};
  let count = 0;
  for (const e of zip.getEntries().slice(0, maxEntries)) {
    if (e.isDirectory || !/\.json$/i.test(e.entryName) || e.header.size > maxEntryBytes) continue;
    let v; try { v = JSON.parse(e.getData().toString('utf8')); } catch { continue; }
    if (!v || !v.id || v.withdrawn) continue;
    for (const [name, rec] of compactVuln(v, eco)) { (pkgs[name] = pkgs[name] || []).push(rec); count++; }
  }
  return { pkgs, count };
}

function ecosystemsOf(sboms) {
  const s = new Set();
  for (const x of Object.values(sboms || {})) for (const p of x.packages || []) if (KNOWN_ECOS.has(p.ecosystem)) s.add(p.ecosystem);
  return [...s];
}

async function syncOffline(dir, ecosystems, { fetchImpl = fetch, now = Date.now(), force = false, maxBytes = 700 * 1024 * 1024 } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const results = [];
  for (const eco of ecosystems.filter((e) => KNOWN_ECOS.has(e))) {
    const f = ecoFile(dir, eco);
    let old = null; try { old = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { /* neu */ }
    if (!force && old && now - Date.parse(old.fetchedAt) < MAX_AGE_MS) { results.push({ id: eco, skipped: true }); continue; }
    try {
      const buf = await fetchLimited(`${BASE}${encodeURIComponent(eco)}/all.zip`, maxBytes, fetchImpl, { binary: true, timeoutMs: 15 * 60 * 1000 });
      const idx = buildIndex(buf, eco);
      if (!idx.count) throw new Error('keine Einträge – Format unerwartet');
      fs.writeFileSync(f + '.tmp', JSON.stringify({ eco, fetchedAt: new Date(now).toISOString(), count: idx.count, pkgs: idx.pkgs }));
      fs.renameSync(f + '.tmp', f);
      results.push({ id: eco, ok: true, count: idx.count });
    } catch (e) {
      if (old) { old.lastError = e.message; try { fs.writeFileSync(f, JSON.stringify(old)); } catch { /* egal */ } }
      results.push({ id: eco, ok: false, error: e.message });
    }
  }
  return results;
}

function offlineStatus(dir) {
  let files = []; try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { return []; }
  return files.map((f) => { try { const d = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); return { eco: d.eco, fetchedAt: d.fetchedAt, count: d.count, lastError: d.lastError }; } catch { return null; } }).filter(Boolean);
}

// Abfrage: deps [{ecosystem,name,version}] -> Map("eco|name|version" -> [rec…])
function createOfflineQuery(dir) {
  const cache = new Map();
  const load = (eco) => { if (!cache.has(eco)) { try { cache.set(eco, JSON.parse(fs.readFileSync(ecoFile(dir, eco), 'utf8')).pkgs); } catch { cache.set(eco, null); } } return cache.get(eco); };
  const q = (deps) => {
    const out = new Map();
    for (const d of deps || []) {
      if (!d || !d.name || !d.version) continue;
      const pk = load(d.ecosystem);
      if (!pk) continue;
      const recs = (pk[String(d.name).toLowerCase()] || []).filter((r) => affects(r, String(d.version)));
      if (recs.length) out.set(`${d.ecosystem}|${d.name}|${d.version}`, recs);
    }
    return out;
  };
  q.available = (eco) => !!load(eco);
  return q;
}

module.exports = { syncOffline, offlineStatus, createOfflineQuery, buildIndex, compactVuln, affects, ecosystemsOf, cmpVer, BASE };
