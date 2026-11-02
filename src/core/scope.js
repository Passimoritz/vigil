'use strict';

// Scope-Durchsetzung: Gescannt werden nur lokale Pfade, Container-Images, bestaetigte
// Ziele oder Domains/Hosts auf der Freigabeliste (Allowlist). Alles andere wird abgewiesen.

const net = require('net');

function hostOf(t) {
  const v = String(t.value || '').trim();
  if (t.type === 'url') { try { return new URL(v).hostname.toLowerCase(); } catch { return null; } }
  if (t.type === 'endpoint') {
    const m = v.match(/^\[([^\]]+)\](?::\d+)?$/); // [IPv6]:port
    if (m) return m[1].toLowerCase();
    return (net.isIPv6(v) ? v : v.replace(/:\d+$/, '')).toLowerCase();
  }
  return null;
}

// Interne Adressen (RFC 1918, Loopback, Link-Local, ULA, .local/.internal/.lan).
function isInternalHost(host) {
  if (!host) return false;
  if (host === 'localhost' || /\.(local|internal|lan|home\.arpa|localhost)$/.test(host)) return true;
  if (net.isIPv4(host)) {
    const [a, b] = host.split('.').map(Number);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  if (net.isIPv6(host)) return host === '::1' || /^f[cd]/i.test(host) || /^fe80:/i.test(host);
  return false;
}

// Eintrag "example.com" deckt auch Subdomains ab; "*.example.com" nur Subdomains.
function normalizeAllowlist(list) {
  return [...new Set((list || []).map((s) => String(s).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '')).filter(Boolean))];
}
function isAllowlisted(host, allowlist) {
  if (!host) return false;
  return normalizeAllowlist(allowlist).some((e) => (e.startsWith('*.') ? host.endsWith(e.slice(1)) : host === e || host.endsWith('.' + e)));
}

// targets -> { ok, targets (mit gesetztem authorized), allow (neu freizugebende Hosts), errors }
// interactive=true (App): Eine ausdrueckliche Bestaetigung im UI gibt den Host frei.
// interactive=false (REST-API): nur, was bereits auf der Freigabeliste steht.
function enforceScope(targets, allowlist, { interactive = false } = {}) {
  const out = [];
  const allow = [];
  const errors = [];
  for (const t of targets) {
    if (t.type === 'path' || t.type === 'image' || t.type === 'system') { out.push({ ...t, authorized: false }); continue; }
    const host = hostOf(t);
    if (!host) { errors.push(`${t.value}: Adresse nicht lesbar.`); continue; }
    if (isAllowlisted(host, allowlist)) { out.push({ ...t, authorized: true }); continue; }
    if (interactive && t.authorized) { out.push({ ...t, authorized: true }); allow.push(host); continue; }
    errors.push(`${t.value}: nicht freigegeben. ${interactive ? 'Bestätige, dass du das Ziel prüfen darfst.' : 'Erst in Vigil unter Einstellungen › Freigegebene Ziele eintragen.'}`);
  }
  return { ok: errors.length === 0, targets: out, allow: [...new Set(allow)], errors };
}

// Domain-Nachweis: Token als DNS-TXT unter _sec-audit-verify.<domain> oder unter
// https://<host>/.well-known/sec-audit.txt. Interne Adressen gelten ohne Nachweis.
async function verifyOwnership(t, token, { fetchImpl = fetch, resolveTxt } = {}) {
  const host = hostOf(t);
  if (!host) return { ok: false, error: 'Adresse nicht lesbar.' };
  if (isInternalHost(host)) return { ok: true, method: 'internal' };
  const dns = require('dns').promises;
  const rt = resolveTxt || dns.resolveTxt.bind(dns);
  const parts = host.split('.');
  const candidates = [...new Set([host, parts.slice(-2).join('.')])];
  for (const d of candidates) {
    try {
      const recs = (await rt('_sec-audit-verify.' + d)).map((r) => r.join(''));
      if (recs.some((r) => r.trim() === token)) return { ok: true, method: 'dns', domain: d };
    } catch { /* kein Eintrag */ }
  }
  try {
    const res = await fetchImpl(`https://${host}/.well-known/sec-audit.txt`, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
    if (res.ok && (await res.text()).split(/\s+/).includes(token)) return { ok: true, method: 'well-known' };
  } catch { /* nicht erreichbar */ }
  return { ok: false, error: `Kein Nachweis gefunden. Lege einen TXT-Eintrag „_sec-audit-verify.${candidates[candidates.length - 1]}“ mit dem Token an – oder die Datei /.well-known/sec-audit.txt.` };
}

module.exports = { hostOf, isInternalHost, isAllowlisted, normalizeAllowlist, enforceScope, verifyOwnership };
