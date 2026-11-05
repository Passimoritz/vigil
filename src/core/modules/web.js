'use strict';

// Netzwerk-Module fuer Web-Ziele – ausschliesslich lesend und gedrosselt.
//
//  web-exposure-audit  SPA-404-Canary, SourceMaps, sensible Artefakte, GraphQL-Introspection
//  cors-reflection     CORS-Test mit harmloser .invalid-Origin
//  dns-mail-drift      SPF, DMARC, DKIM, CAA, verwaiste CNAMEs (inkl. Subdomains aus CT-Logs)
//
// Ein WafGuard bricht ab, sobald das Ziel drosselt (3x 429/503/403 in Folge) – so sperrt
// Vigil weder sich selbst aus, noch belastet es fremde Schutzsysteme.

const crypto = require('crypto');
const dns = require('dns').promises;
const { normalizeFinding } = require('../schema');
const { throttle } = require('../ratelimit');

const TIMEOUT = 10000;
const MAX_BODY = 300 * 1024;
const UA = 'Vigil-Audit/0.2 (+authorized,passive)';

class Throttled extends Error { constructor(host) { super(`Ziel ${host} drosselt Anfragen (WAF/Rate-Limit) – Web-Prüfung abgebrochen.`); this.throttled = true; } }

// Zaehlt aufeinanderfolgende Sperr-Antworten je Host.
class WafGuard {
  constructor(rps = 4) { this.gap = Math.max(50, Math.round(1000 / Math.max(1, rps))); this.strikes = new Map(); }
  async before(host) { await throttle('web:' + host, this.gap); }
  after(host, status) {
    if (status === 429 || status === 503 || status === 403) {
      const n = (this.strikes.get(host) || 0) + 1;
      this.strikes.set(host, n);
      if (n >= 3) throw new Throttled(host);
    } else this.strikes.set(host, 0);
  }
}

async function request(guard, url, { method = 'GET', headers = {}, body, signal, readBody = true } = {}) {
  const host = new URL(url).host;
  await guard.before(host);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  const sig = signal ? AbortSignal.any([ctrl.signal, signal]) : ctrl.signal;
  try {
    const res = await fetch(url, { method, headers: { 'User-Agent': UA, ...headers }, body, redirect: 'manual', signal: sig });
    guard.after(host, res.status);
    let text = '';
    if (readBody && method !== 'HEAD') { const buf = Buffer.from(await res.arrayBuffer()); text = buf.subarray(0, MAX_BODY).toString('utf8'); }
    return { ok: true, status: res.status, headers: res.headers, body: text };
  } catch (e) {
    if (e.throttled) throw e;
    return { ok: false, error: e.message };
  } finally { clearTimeout(t); }
}

const W = (module, o) => normalizeFinding({ ...o, sourceModule: module }, module);
const sig = (r) => `${r.status}|${(r.headers && r.headers.get('content-type')) || ''}|${crypto.createHash('sha1').update(r.body || '').digest('hex')}|${(r.body || '').length}`;

// Artefakte: Pfad, Inhaltssignatur, Schwere, Titel. Nur GET, kleine feste Liste.
const ARTIFACTS = [
  ['/.env', /^[A-Z0-9_]+\s*=/m, 'critical', '.env-Datei öffentlich'],
  ['/.git/HEAD', /^ref:\s/m, 'high', 'Git-Repository öffentlich (.git)'],
  ['/docker-compose.yml', /^services:|^version:/m, 'high', 'docker-compose.yml öffentlich'],
  ['/swagger.json', /"swagger"\s*:|"openapi"\s*:/, 'low', 'API-Dokumentation öffentlich (swagger.json)'],
  ['/openapi.json', /"openapi"\s*:/, 'low', 'API-Dokumentation öffentlich (openapi.json)'],
  ['/actuator/env', /"propertySources"|"activeProfiles"/, 'high', 'Spring Actuator /env offen'],
  ['/actuator/heapdump', null, 'critical', 'Spring Actuator Heapdump offen', (r) => /octet-stream|hprof/.test(r.headers.get('content-type') || '') && r.status === 200],
  ['/server-status', /Apache Server Status|Scoreboard/, 'medium', 'Apache server-status offen'],
];

async function exposure(baseUrl, guard, signal) {
  const M = 'web-exposure-audit';
  const out = [];
  const origin = new URL(baseUrl).origin;
  // SPA-Schutz: Wie sieht eine garantiert nicht existierende Seite aus?
  const canary = await request(guard, `${origin}/sec-audit-404-canary-${crypto.randomUUID()}`, { signal });
  const fallback = canary.ok && canary.status === 200 ? sig(canary) : null;
  const isFallback = (r) => fallback && sig(r) === fallback;

  for (const [p, re, severity, title, custom] of ARTIFACTS) {
    if (signal && signal.aborted) break;
    const r = await request(guard, origin + p, { signal, readBody: !custom });
    if (!r.ok || r.status !== 200 || isFallback(r)) continue;
    if (custom ? custom(r) : re.test(r.body)) {
      out.push(W(M, { ruleId: 'exposed-' + p.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase(), severity, category: severity === 'critical' ? 'Secrets' : 'Config', title, location: origin + p, evidence: `HTTP 200, ${r.headers.get('content-type') || '?'}`, description: `Unter ${p} ist Inhalt öffentlich abrufbar, der nicht ins Web gehört.`, remediation: `Zugriff auf ${p} sperren bzw. Datei aus dem Web-Root entfernen.`, confidence: 'high' }));
    }
  }

  // SourceMaps der eingebundenen Skripte
  const page = await request(guard, baseUrl, { signal });
  if (page.ok && /text\/html/.test(page.headers.get('content-type') || '')) {
    const srcs = [...page.body.matchAll(/<script[^>]+src=["']([^"']+\.js)(?:\?[^"']*)?["']/gi)].map((m) => m[1]).slice(0, 6);
    for (const s of srcs) {
      let u; try { u = new URL(s, baseUrl); } catch { continue; }
      if (u.origin !== origin) continue;
      const r = await request(guard, u.href + '.map', { signal });
      if (r.ok && r.status === 200 && !isFallback(r) && /"sources"\s*:/.test(r.body)) {
        out.push(W(M, { ruleId: 'web-sourcemap-exposed', severity: 'high', category: 'Config', title: 'Produktions-SourceMap öffentlich', location: u.href + '.map', evidence: `${(r.body.match(/"sources"\s*:\s*\[([^\]]{0,120})/) || [])[1] || ''}…`, description: 'Die SourceMap enthält den lesbaren Original-Quellcode inklusive Kommentaren, interner API-Pfade und ggf. eingebetteter Schlüssel.', remediation: 'SourceMaps nicht mit ausliefern bzw. Zugriff sperren.', confidence: 'high' }));
        break;
      }
    }
  }

  // GraphQL-Introspection mit harmloser Leseabfrage
  for (const p of ['/graphql', '/api/graphql']) {
    if (signal && signal.aborted) break;
    const r = await request(guard, origin + p, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: '{ __schema { queryType { name } } }' }), signal });
    if (r.ok && r.status === 200 && /"__schema"\s*:\s*\{/.test(r.body)) {
      out.push(W(M, { ruleId: 'graphql-introspection', severity: 'medium', category: 'Config', title: 'GraphQL-Introspection aktiv', location: origin + p, evidence: r.body.slice(0, 120), description: 'Die API liefert ihr komplettes Schema an jeden aus.', remediation: 'Introspection in Produktion deaktivieren.', confidence: 'high' }));
      break;
    }
  }
  return out;
}

async function corsReflection(baseUrl, guard, signal) {
  const canaryOrigin = 'https://untrusted-audit-canary.invalid';
  const r = await request(guard, baseUrl, { headers: { Origin: canaryOrigin }, signal, readBody: false });
  if (!r.ok) return [];
  const acao = r.headers.get('access-control-allow-origin') || '';
  const creds = (r.headers.get('access-control-allow-credentials') || '').toLowerCase() === 'true';
  if (acao !== canaryOrigin) return [];
  return [W('web-tls-posture', { ruleId: 'cors-origin-reflection', severity: creds ? 'critical' : 'medium', category: 'AccessControl', title: creds ? 'CORS spiegelt beliebige Herkunft mit Credentials' : 'CORS spiegelt beliebige Herkunft', location: baseUrl, evidence: `Origin: ${canaryOrigin} → Access-Control-Allow-Origin: ${acao}${creds ? ', Allow-Credentials: true' : ''}`, description: creds ? 'Jede fremde Webseite kann im Namen eingeloggter Nutzer Antworten deiner Seite lesen – inklusive privater Daten.' : 'Jede fremde Herkunft darf Antworten lesen.', remediation: 'Origins gegen eine feste Liste prüfen.', confidence: 'high' })];
}

// --- DNS & Mail -------------------------------------------------------------
const TAKEOVER = [
  ['github.io', 'GitHub Pages'], ['herokuapp.com', 'Heroku'], ['herokudns.com', 'Heroku'], ['s3.amazonaws.com', 'AWS S3'], ['s3-website', 'AWS S3'],
  ['cloudfront.net', 'CloudFront'], ['azurewebsites.net', 'Azure App Service'], ['cloudapp.net', 'Azure'], ['blob.core.windows.net', 'Azure Blob'], ['trafficmanager.net', 'Azure Traffic Manager'],
  ['vercel.app', 'Vercel'], ['netlify.app', 'Netlify'], ['netlify.com', 'Netlify'], ['pages.dev', 'Cloudflare Pages'], ['ghost.io', 'Ghost'], ['myshopify.com', 'Shopify'], ['surge.sh', 'Surge'], ['bitbucket.io', 'Bitbucket'], ['fastly.net', 'Fastly'], ['readthedocs.io', 'Read the Docs'],
];
const txt = async (name) => { try { return (await dns.resolveTxt(name)).map((r) => r.join('')); } catch { return []; } };
const resolves = async (name) => { try { await dns.lookup(name); return true; } catch (e) { return !(e.code === 'ENOTFOUND' || e.code === 'ENODATA'); } };

async function danglingCname(host) {
  let cname; try { [cname] = await dns.resolveCname(host); } catch { return null; }
  if (!cname) return null;
  const provider = TAKEOVER.find(([suffix]) => cname.toLowerCase().includes(suffix));
  if (!provider || await resolves(cname)) return null;
  return W('dns-mail-drift', { ruleId: 'dns-dangling-cname', severity: 'critical', category: 'Config', title: `Verwaister CNAME: ${host} → ${provider[1]}`, location: `DNS ${host}`, evidence: `${host} CNAME ${cname} (NXDOMAIN)`, description: `${host} zeigt auf ${cname}, das nicht mehr existiert. Wer die Ressource bei ${provider[1]} neu anlegt, übernimmt die Subdomain.`, remediation: 'DNS-Eintrag löschen oder Ressource wieder belegen.', confidence: 'medium' });
}

// Ergebnis je Domain 10 Minuten merken: DNS-Pruefung und Subdomain-Suche fragen crt.sh nur einmal.
const crtCache = new Map();
async function crtShSubdomains(domain, signal) {
  const hit = crtCache.get(domain);
  if (hit && Date.now() - hit.at < 600000) return hit.names;
  const names = await crtShFetch(domain, signal);
  if (names.length) crtCache.set(domain, { at: Date.now(), names });
  return names;
}
async function crtShFetch(domain, signal) {
  try {
    const ctrl = AbortSignal.timeout(15000);
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent('%.' + domain)}&output=json`, { headers: { 'User-Agent': UA }, signal: signal ? AbortSignal.any([ctrl, signal]) : ctrl });
    if (!res.ok) return [];
    const rows = await res.json();
    const names = new Set();
    for (const r of rows) for (const n of String(r.name_value || '').split('\n')) { const h = n.trim().toLowerCase(); if (h.endsWith('.' + domain) && !h.includes('*')) names.add(h); }
    return [...names].slice(0, 40);
  } catch { return []; }
}

async function dnsMail(domain, { signal, deep } = {}) {
  const M = 'dns-mail-drift';
  const out = [];
  const loc = `DNS ${domain}`;
  const spf = (await txt(domain)).find((t) => /^v=spf1\b/i.test(t));
  if (!spf) out.push(W(M, { ruleId: 'dns-spf-missing', severity: 'medium', category: 'Config', title: 'Kein SPF-Eintrag', location: loc, description: 'Ohne SPF kann jeder Server Mails im Namen der Domain verschicken.', remediation: 'SPF-TXT-Eintrag anlegen.', confidence: 'high' }));
  else {
    if (/[+?]all\b/i.test(spf)) out.push(W(M, { ruleId: 'dns-spf-permissive', severity: 'high', category: 'Config', title: 'SPF erlaubt beliebige Absender (+all/?all)', location: loc, evidence: spf, description: 'Der SPF-Eintrag schützt praktisch nicht.', remediation: 'Mit -all bzw. ~all abschließen.', confidence: 'high' }));
    const lookups = (spf.match(/\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/gi) || []).length;
    if (lookups > 10) out.push(W(M, { ruleId: 'dns-spf-too-many-lookups', severity: 'medium', category: 'Config', title: `SPF mit ${lookups} DNS-Lookups (Limit 10)`, location: loc, evidence: spf, description: 'Mehr als 10 Lookups machen SPF ungültig – Empfänger werten ihn dann als Fehler.', remediation: 'Includes zusammenfassen oder SPF-Flattening verwenden.', confidence: 'medium' }));
  }
  const dmarc = (await txt('_dmarc.' + domain)).find((t) => /^v=DMARC1/i.test(t));
  if (!dmarc) out.push(W(M, { ruleId: 'dns-dmarc-missing', severity: 'medium', category: 'Config', title: 'Kein DMARC-Eintrag', location: `DNS _dmarc.${domain}`, description: 'Empfänger wissen nicht, wie sie mit gefälschten Mails umgehen sollen.', remediation: 'DMARC-TXT-Eintrag anlegen.', confidence: 'high' }));
  else if (/\bp=none\b/i.test(dmarc)) out.push(W(M, { ruleId: 'dns-dmarc-none', severity: 'low', category: 'Config', title: 'DMARC nur im Beobachtungsmodus (p=none)', location: `DNS _dmarc.${domain}`, evidence: dmarc, description: 'Gefälschte Mails werden trotzdem zugestellt.', remediation: 'Auf p=quarantine bzw. p=reject verschärfen.', confidence: 'high' }));
  let dkim = false;
  for (const s of ['default', 'google', 'selector1', 'selector2', 'k1', 'mail', 's1', 's2', 'dkim']) { if ((await txt(`${s}._domainkey.${domain}`)).some((t) => /v=DKIM1|p=/.test(t))) { dkim = true; break; } }
  if (!dkim && spf) out.push(W(M, { ruleId: 'dns-dkim-missing', severity: 'info', category: 'Config', title: 'Kein DKIM-Schlüssel unter üblichen Selektoren gefunden', location: loc, description: 'Möglicherweise wird DKIM unter einem anderen Selektor genutzt – bitte prüfen.', remediation: 'DKIM im Mail-Dienst aktivieren.', confidence: 'low' }));
  let caa = []; try { caa = await dns.resolveCaa(domain); } catch { /* keiner */ }
  if (!caa.length) out.push(W(M, { ruleId: 'dns-caa-missing', severity: 'low', category: 'Config', title: 'Kein CAA-Eintrag', location: loc, description: 'Jede Zertifizierungsstelle darf Zertifikate für die Domain ausstellen.', remediation: 'CAA-Eintrag für die genutzte CA setzen.', confidence: 'high' }));
  // Verwaiste CNAMEs: Domain selbst + (nur bei verifizierten Zielen) Subdomains aus CT-Logs
  const hosts = [domain, 'www.' + domain, ...(deep ? await crtShSubdomains(domain, signal) : [])];
  for (const h of [...new Set(hosts)]) {
    if (signal && signal.aborted) break;
    const f = await danglingCname(h);
    if (f) out.push(f);
  }
  return out;
}

const registrableDomain = (host) => { const parts = host.split('.'); return parts.length > 2 && !/^\d+$/.test(parts[parts.length - 1]) ? parts.slice(-2).join('.') : host; };

// Fuehrt alle Web-Module fuer ein Ziel aus. deep=false: nur passive Abfragen (Header/DNS).
async function runWebModules(targetUrl, { deep = false, rps = 4, signal, onProgress = () => {} } = {}) {
  const guard = new WafGuard(rps);
  const findings = [];
  const ran = [];
  const notes = [];
  let throttled = false;
  const url = /^https?:\/\//i.test(targetUrl) ? targetUrl : 'https://' + targetUrl;
  const host = new URL(url).hostname;
  const steps = [
    ['cors-reflection', 'CORS-Test', () => corsReflection(url, guard, signal), true],
    ['web-exposure-audit', 'Offene Dateien, SourceMaps, GraphQL', () => exposure(url, guard, signal), deep],
    ['dns-mail-drift', 'DNS & Mail (SPF, DMARC, CAA, CNAME)', () => dnsMail(registrableDomain(host), { signal, deep }), !/^\d+\.\d+\.\d+\.\d+$/.test(host) && host !== 'localhost'],
  ];
  for (const [id, label, fn, enabled] of steps) {
    if (!enabled || (signal && signal.aborted)) continue;
    onProgress({ phase: 'webscan', message: `${label}: ${host} …` });
    try { findings.push(...(await fn())); ran.push(id); }
    catch (e) {
      if (e.throttled) { throttled = true; notes.push(e.message); break; }
      notes.push(`${label}: ${e.message}`);
    }
  }
  if (!deep) notes.push(`Tiefe Web-Prüfung (offene Dateien, SourceMaps, GraphQL, Subdomains) für ${host} übersprungen – Domain ist nicht verifiziert.`);
  return { findings, ran, notes, throttled };
}

module.exports = { runWebModules, WafGuard, Throttled, dnsMail, registrableDomain, TAKEOVER, request, crtShSubdomains };
