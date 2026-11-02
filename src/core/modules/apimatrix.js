'use strict';

// API-Rechtematrix (api-auth-matrix): differentieller BOLA/IDOR-Test fuer konfigurierte
// GET-Endpunkte. Ablauf je Endpunkt:
//   1. Nutzer A holt sein eigenes Objekt (Basislinie, muss 200 liefern).
//   2. Derselbe GET ohne Anmeldung und mit dem Token von Nutzer B.
//   3. Erhaelt B bzw. "anonym" A's private Werte -> CRITICAL.
// Nur GET, nur fuer verifizierte Ziele, gedrosselt. Tokens stammen aus der lokal
// verschluesselt gespeicherten Konfiguration und erscheinen nie in Befunden.

const { normalizeFinding } = require('../schema');
const { WafGuard } = require('./web');

const TIMEOUT = 10000;

async function get(guard, url, headers, signal) {
  const host = new URL(url).host;
  await guard.before(host);
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json', 'User-Agent': 'Vigil-Audit/0.2', ...headers }, redirect: 'manual', signal: signal ? AbortSignal.any([AbortSignal.timeout(TIMEOUT), signal]) : AbortSignal.timeout(TIMEOUT) });
    guard.after(host, res.status);
    const text = (await res.text()).slice(0, 200000);
    let json = null; try { json = JSON.parse(text); } catch { /* kein JSON */ }
    return { status: res.status, text, json };
  } catch (e) { if (e.throttled) throw e; return { status: 0, text: '', json: null, error: e.message }; }
}

// Markante Werte aus A's Antwort (Strings >= 6 Zeichen, keine generischen Schluessel/Zeitstempel).
function privateValues(json, out = new Set(), depth = 0) {
  if (depth > 5 || out.size > 40 || json == null) return out;
  if (typeof json === 'string') { if (json.length >= 6 && !/^\d{4}-\d{2}-\d{2}|^(true|false|null|ok|success)$/i.test(json)) out.add(json); return out; }
  if (Array.isArray(json)) { json.slice(0, 20).forEach((v) => privateValues(v, out, depth + 1)); return out; }
  if (typeof json === 'object') for (const v of Object.values(json)) privateValues(v, out, depth + 1);
  return out;
}

const hdr = (token) => (token ? { Authorization: /^(Bearer|Basic|Token)\s/i.test(token) ? token : `Bearer ${token}` } : {});

// cfg: { endpoints: ['/api/invoices/{id}'], resourceIdA, tokenA, tokenB }
async function runApiMatrix(baseUrl, cfg, { signal, onProgress = () => {}, rps = 3 } = {}) {
  const findings = [];
  const notes = [];
  if (!cfg || !cfg.tokenA || !cfg.resourceIdA || !(cfg.endpoints || []).length) return { ran: false, findings, notes };
  const guard = new WafGuard(rps);
  const origin = new URL(/^https?:/.test(baseUrl) ? baseUrl : 'https://' + baseUrl).origin;
  for (const tpl of cfg.endpoints.slice(0, 20)) {
    if (signal && signal.aborted) break;
    const url = origin + String(tpl).replace(/\{[^}]+\}|:\w+/, encodeURIComponent(cfg.resourceIdA));
    onProgress({ phase: 'webscan', message: `API-Rechtematrix: ${tpl} …` });
    const a = await get(guard, url, hdr(cfg.tokenA), signal);
    if (a.status !== 200) { notes.push(`API-Rechtematrix: ${tpl} liefert für Nutzer A ${a.status || a.error} – übersprungen.`); continue; }
    const secrets = [...privateValues(a.json || a.text)].slice(0, 25);
    for (const [who, token, ruleId] of [['ohne Anmeldung', null, 'api-unauthenticated-access'], ['als Nutzer B', cfg.tokenB, 'api-bola-cross-tenant']]) {
      if (who === 'als Nutzer B' && !token) continue;
      const r = await get(guard, url, hdr(token), signal);
      if (r.status !== 200) continue;
      const leaked = secrets.filter((v) => r.text.includes(v));
      if (!leaked.length && !(r.text === a.text && a.text.length > 20)) continue;
      findings.push(normalizeFinding({
        ruleId, severity: 'critical', category: 'AccessControl', sourceModule: 'api-auth-matrix',
        title: `${who === 'ohne Anmeldung' ? 'Fremde Daten ohne Anmeldung abrufbar' : 'Nutzer B liest Daten von Nutzer A (BOLA/IDOR)'}: ${tpl}`,
        location: `GET ${tpl}`,
        evidence: `A: HTTP 200 · ${who}: HTTP 200 · ${leaked.length} private Werte von A in der Antwort`,
        description: `Der Endpunkt liefert das Objekt ${who} mit denselben privaten Daten wie für den Eigentümer. Es fehlt die Prüfung, ob das Objekt dem anfragenden Nutzer gehört.`,
        remediation: 'Besitz bzw. Mandant serverseitig bei jedem Objektzugriff prüfen.', confidence: 'high',
      }, 'api-auth-matrix'));
    }
  }
  return { ran: true, findings, notes };
}

module.exports = { runApiMatrix, privateValues };
