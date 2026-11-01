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
    if (t.type === 'path' || t.type === 'image') { out.push({ ...t, authorized: false }); continue; }
    const host = hostOf(t);
    if (!host) { errors.push(`${t.value}: Adresse nicht lesbar.`); continue; }
    if (isAllowlisted(host, allowlist)) { out.push({ ...t, authorized: true }); continue; }
    if (interactive && t.authorized) { out.push({ ...t, authorized: true }); allow.push(host); continue; }
    errors.push(`${t.value}: nicht freigegeben. ${interactive ? 'Bestätige, dass du das Ziel prüfen darfst.' : 'Erst in Vigil unter Einstellungen › Freigegebene Ziele eintragen.'}`);
  }
  return { ok: errors.length === 0, targets: out, allow: [...new Set(allow)], errors };
}

module.exports = { hostOf, isInternalHost, isAllowlisted, normalizeAllowlist, enforceScope };
