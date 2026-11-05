'use strict';

// Hintergrund-Ueberwachung ohne neuen Scan (laeuft alle 6 Stunden mit der Feed-Aktualisierung):
//  - Neue OSV-Advisories fuer Pakete in den gespeicherten SBOMs (GitHub Advisory Database u. a.)
//  - Sicherheitshinweise des BSI (CERT-Bund), die ein Paket aus den SBOMs nennen
//  - Certificate Transparency: neue, bisher unbekannte Zertifikate fuer die eigenen,
//    nachgewiesenen Domains (crt.sh)
// Ergebnisse landen als "Hinweise" in der Uebersicht und als Windows-Benachrichtigung.
// Beim ersten Lauf wird nur der Ist-Stand gemerkt (keine Flut alter Meldungen).

const fs = require('fs');
const { fetchLimited } = require('./feeds');

const MAX_ALERTS = 300;
const readJson = (f, def) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return def; } };
const writeJson = (f, d) => { fs.writeFileSync(f + '.tmp', JSON.stringify(d)); fs.renameSync(f + '.tmp', f); };

// --- Hinweis-Speicher --------------------------------------------------------------------------
function loadAlerts(file) { const d = readJson(file, { alerts: [] }); return Array.isArray(d.alerts) ? d.alerts : []; }
// Fuegt neue Hinweise hinzu (Schluessel eindeutig); liefert nur die wirklich neuen zurueck
function addAlerts(file, alerts, now = Date.now()) {
  const list = loadAlerts(file);
  const keys = new Set(list.map((a) => a.key));
  const fresh = [];
  for (const a of alerts || []) { if (!a || !a.key || keys.has(a.key)) continue; keys.add(a.key); const x = { at: new Date(now).toISOString(), ...a }; list.unshift(x); fresh.push(x); }
  if (fresh.length) writeJson(file, { alerts: list.slice(0, MAX_ALERTS) });
  return fresh;
}
function dismissAlert(file, key) {
  const list = loadAlerts(file);
  const next = key === '*' ? list.map((a) => ({ ...a, dismissed: true })) : list.map((a) => (a.key === key ? { ...a, dismissed: true } : a));
  writeJson(file, { alerts: next });
  return { ok: true };
}

// --- Pakete aus den SBOMs ------------------------------------------------------------------------
function sbomPackages(sboms, cap = 3000) {
  const map = new Map();
  for (const [targetId, s] of Object.entries(sboms || {})) {
    for (const p of (s && s.packages) || []) {
      if (!p || !p.name || !p.version || !p.ecosystem) continue;
      const k = `${p.ecosystem}|${p.name}|${p.version}`;
      if (!map.has(k)) { if (map.size >= cap) continue; map.set(k, { ecosystem: p.ecosystem, name: p.name, version: p.version, targets: [] }); }
      const e = map.get(k); if (!e.targets.includes(targetId)) e.targets.push(targetId);
    }
  }
  return [...map.values()];
}

// OSV online: querybatch -> Map(key -> [{id}])
async function osvQueryOnline(pkgs, { fetchImpl = fetch, signal } = {}) {
  const out = new Map();
  for (let i = 0; i < pkgs.length; i += 500) {
    const chunk = pkgs.slice(i, i + 500);
    const r = await fetchImpl('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }), signal: signal || AbortSignal.timeout(30000) });
    if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
    const j = await r.json();
    (j.results || []).forEach((res, n) => { const p = chunk[n]; if (p) out.set(`${p.ecosystem}|${p.name}|${p.version}`, ((res && res.vulns) || []).map((v) => ({ id: v.id }))); });
  }
  return out;
}
async function osvDetails(id, fetchImpl) {
  try { const r = await fetchImpl(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(20000) }); return r.ok ? await r.json() : null; } catch { return null; }
}
const sevLabel = (v) => { const l = String((v && v.database_specific && v.database_specific.severity) || '').toUpperCase(); return { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' }[l] || 'medium'; };

// Neue Advisories fuer gespeicherte SBOMs. query(pkgs) -> Map(key -> [{id, s?, sev?}])
async function checkSbomCves(sboms, stateFile, { query, details = async () => null, now = Date.now(), maxDetails = 25 } = {}) {
  const pkgs = sbomPackages(sboms);
  const state = readJson(stateFile, { known: {} });
  const known = state.known || {};
  if (!pkgs.length) return { alerts: [], checked: 0 };
  const res = await query(pkgs);
  const alerts = [];
  let detailCalls = 0;
  for (const p of pkgs) {
    const k = `${p.ecosystem}|${p.name}|${p.version}`;
    const ids = (res.get(k) || []).map((x) => x.id || x);
    const first = !known[k]; // Paket neu im Bestand -> Stand nur merken
    const seen = new Set(known[k] || []);
    for (const id of ids) {
      if (first || seen.has(id)) continue;
      const rec = (res.get(k) || []).find((x) => (x.id || x) === id) || {};
      let summary = rec.s || '', severity = rec.sevLevel || 'medium', aliases = rec.a || [];
      if (!summary && detailCalls < maxDetails) { detailCalls++; const v = await details(id); if (v) { summary = v.summary || ''; severity = sevLabel(v); aliases = (v.aliases || []).filter((a) => /^CVE-/.test(a)); } }
      alerts.push({
        key: `newcve:${id}:${k}`, type: 'newcve', severity, targets: p.targets,
        title: `Neue Schwachstelle in ${p.name} ${p.version}: ${aliases[0] || id}`,
        detail: `${summary || id} – betrifft ein Paket aus einer gespeicherten Prüfung (${p.ecosystem}). Ein neuer Scan zeigt Details und die Lösung.`,
        link: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
      });
    }
    known[k] = [...new Set([...(known[k] || []), ...ids])].slice(-200);
  }
  writeJson(stateFile, { known, at: new Date(now).toISOString() });
  return { alerts, checked: pkgs.length };
}

// --- BSI CERT-Bund: Meldungen, die ein Paket aus den SBOMs nennen ------------------------------
const GENERIC = new Set(['core', 'common', 'utils', 'util', 'test', 'tests', 'client', 'server', 'http', 'https', 'json', 'html', 'node', 'java', 'python', 'react', 'types', 'config', 'api', 'app', 'web', 'base', 'data', 'time', 'date', 'path', 'file', 'cache', 'debug', 'log', 'logger', 'request', 'parser', 'string', 'color', 'colors', 'chalk', 'commander', 'tools', 'tool', 'windows', 'linux', 'cloud', 'docker', 'chrome', 'microsoft', 'google', 'apache', 'mozilla', 'mail', 'image', 'video']);
function advisoryAlerts(items, sboms) {
  const names = new Map();
  for (const p of sbomPackages(sboms)) {
    const short = String(p.name).toLowerCase().split(/[/:]/).pop();
    if (short.length < 4 || GENERIC.has(short)) continue;
    if (!names.has(short)) names.set(short, p);
  }
  const alerts = [];
  for (const it of items || []) {
    const t = String(it.title || '').toLowerCase();
    for (const [n, p] of names) {
      const re = new RegExp(`(^|[^a-z0-9-])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^a-z0-9-]|$)`);
      if (!re.test(t)) continue;
      alerts.push({ key: `advisory:${it.link || it.title}:${n}`, type: 'advisory', severity: /kritisch|critical|hoch|high/i.test(it.title) ? 'high' : 'medium', targets: p.targets, title: `BSI-Sicherheitshinweis zu ${p.name}: ${String(it.title).slice(0, 160)}`, detail: `${it.summary ? it.summary.slice(0, 300) + ' – ' : ''}Das Paket ${p.name} ${p.version} steckt in einer gespeicherten Prüfung.`, link: it.link || '' });
      break;
    }
  }
  return alerts;
}

// --- Certificate Transparency (crt.sh) ---------------------------------------------------------
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
async function crtsh(domain, fetchImpl) {
  const all = new Map();
  for (const q of [domain, `%.${domain}`]) {
    const text = await fetchLimited(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json&exclude=expired`, 30 * 1024 * 1024, fetchImpl, { timeoutMs: 90000 });
    let arr; try { arr = JSON.parse(text || '[]'); } catch { throw new Error('crt.sh: Antwort nicht lesbar'); }
    if (!Array.isArray(arr)) throw new Error('crt.sh: Format unerwartet');
    for (const c of arr.slice(0, 8000)) if (c && c.id != null) all.set(String(c.id), { id: String(c.id), issuer: String(c.issuer_name || '').slice(0, 300), names: String(c.name_value || c.common_name || '').split(/\n/).map((s) => s.trim().toLowerCase()).filter(Boolean).slice(0, 50), notBefore: c.not_before || '', logged: c.entry_timestamp || '' });
  }
  return [...all.values()];
}
const issuerShort = (i) => (String(i).match(/O=("[^"]+"|[^,]+)/) || String(i).match(/CN=([^,]+)/) || [])[1] || String(i).slice(0, 60);

async function checkCt(domains, stateFile, { fetchImpl = fetch, now = Date.now() } = {}) {
  const state = readJson(stateFile, { domains: {} });
  const alerts = [], notes = [];
  for (const raw of [...new Set((domains || []).map((d) => String(d).toLowerCase().replace(/^www\./, '').replace(/\.$/, '')))].slice(0, 30)) {
    if (!DOMAIN_RE.test(raw)) continue;
    let certs;
    try { certs = await crtsh(raw, fetchImpl); } catch (e) { notes.push(`CT-Log ${raw}: ${e.message}`); continue; }
    const prev = state.domains[raw];
    const issuers = new Set((prev && prev.issuers) || []);
    if (prev) {
      const seen = new Set(prev.ids || []);
      for (const c of certs.filter((x) => !seen.has(x.id)).slice(0, 20)) {
        const newIssuer = !issuers.has(issuerShort(c.issuer));
        alerts.push({
          key: `ct:${c.id}`, type: 'ct', severity: newIssuer ? 'high' : 'low', domain: raw,
          title: newIssuer ? `Neues Zertifikat von einer bisher unbekannten Stelle (${issuerShort(c.issuer)}) für ${c.names[0] || raw}` : `Neues Zertifikat für ${c.names[0] || raw}`,
          detail: `Ausgestellt von ${issuerShort(c.issuer)} für ${c.names.slice(0, 5).join(', ') || raw}, gültig ab ${String(c.notBefore || '?').slice(0, 10)}. Wenn du das nicht selbst beantragt hast (oder dein Hoster), kann jemand Zertifikate für deine Domain bekommen haben.`,
          link: `https://crt.sh/?id=${encodeURIComponent(c.id)}`,
        });
      }
    }
    for (const c of certs) issuers.add(issuerShort(c.issuer));
    state.domains[raw] = { ids: [...new Set([...((prev && prev.ids) || []), ...certs.map((c) => c.id)])].slice(-20000), issuers: [...issuers].slice(0, 200), at: new Date(now).toISOString() };
  }
  writeJson(stateFile, state);
  return { alerts, notes };
}

module.exports = { loadAlerts, addAlerts, dismissAlert, sbomPackages, osvQueryOnline, osvDetails, checkSbomCves, advisoryAlerts, checkCt, issuerShort };
