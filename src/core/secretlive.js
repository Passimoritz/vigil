'use strict';

// Optional (Einstellung, Standard AUS): Ist ein gefundener Schluessel noch gueltig?
// Je Anbieter genau EINE harmlose, nur lesende Identitaets-Abfrage an die offizielle Adresse:
//   GitHub GET /user · AWS STS GetCallerIdentity · Slack auth.test · OpenAI/Anthropic Modell-Liste
//   Stripe Kontostand lesen
// Es wird nie geschrieben. Gespeichert wird nur das Urteil (aktiv/ungueltig/unklar), nie der Schluessel.

const crypto = require('crypto');
const { throttle } = require('./ratelimit');

const DETECT = [
  { provider: 'GitHub', re: /\b(gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{20,})\b/ },
  { provider: 'Slack', re: /\b(xox[bpar]-[0-9A-Za-z-]{10,})\b/ },
  { provider: 'Anthropic', re: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/ },
  { provider: 'OpenAI', re: /\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b/ },
  { provider: 'Stripe', re: /\b((?:sk|rk)_live_[0-9A-Za-z]{10,})\b/ },
  { provider: 'AWS', re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/ },
];
const LOOKS_FAKE = /example|sample|dummy|placeholder|xxxx|0000000000|1234567890|abcdefghij|EXAMPLE/i;

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hmac = (k, s) => crypto.createHmac('sha256', k).update(s, 'utf8').digest();

// AWS Signature V4 fuer STS GetCallerIdentity (POST, keine Parameter ausser Action/Version)
function signSts(accessKeyId, secretKey, now = new Date(), sessionToken) {
  const host = 'sts.amazonaws.com', region = 'us-east-1', service = 'sts';
  const body = 'Action=GetCallerIdentity&Version=2011-06-15';
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const date = amzDate.slice(0, 8);
  const ctype = 'application/x-www-form-urlencoded; charset=utf-8';
  const headers = `content-type:${ctype}\nhost:${host}\nx-amz-date:${amzDate}\n`;
  const signed = 'content-type;host;x-amz-date';
  const canonical = ['POST', '/', '', headers, signed, sha256(body)].join('\n');
  const scope = `${date}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256(canonical)].join('\n');
  const key = hmac(hmac(hmac(hmac('AWS4' + secretKey, date), region), service), 'aws4_request');
  const sig = crypto.createHmac('sha256', key).update(toSign, 'utf8').digest('hex');
  return {
    url: `https://${host}/`, body,
    headers: { 'Content-Type': ctype, 'X-Amz-Date': amzDate, Authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${sig}`, ...(sessionToken ? { 'X-Amz-Security-Token': sessionToken } : {}) },
  };
}

// Anfrage je Anbieter -> 'active' | 'inactive' | 'unknown'
async function probe(provider, key, extra, fetchImpl, signal) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 10000);
  const sig = signal ? AbortSignal.any([ctrl.signal, signal]) : ctrl.signal;
  const go = (url, init = {}) => fetchImpl(url, { ...init, redirect: 'error', signal: sig });
  try {
    await throttle('secret-live-' + provider, 1000);
    if (provider === 'GitHub') {
      const r = await go('https://api.github.com/user', { headers: { Authorization: `Bearer ${key}`, Accept: 'application/vnd.github+json', 'User-Agent': 'Vigil-secret-check' } });
      return r.status === 200 ? 'active' : r.status === 401 ? 'inactive' : 'unknown';
    }
    if (provider === 'Slack') {
      const r = await go('https://slack.com/api/auth.test', { method: 'POST', headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: '' });
      if (!r.ok) return 'unknown';
      const j = await r.json().catch(() => ({}));
      return j.ok === true ? 'active' : /invalid_auth|token_revoked|account_inactive|not_authed|token_expired/.test(String(j.error || '')) ? 'inactive' : 'unknown';
    }
    if (provider === 'OpenAI') {
      const r = await go('https://api.openai.com/v1/models', { headers: { Authorization: `Bearer ${key}` } });
      return r.status === 200 ? 'active' : r.status === 401 ? 'inactive' : 'unknown';
    }
    if (provider === 'Anthropic') {
      const r = await go('https://api.anthropic.com/v1/models', { headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } });
      return r.status === 200 ? 'active' : r.status === 401 ? 'inactive' : 'unknown';
    }
    if (provider === 'Stripe') {
      const r = await go('https://api.stripe.com/v1/balance', { headers: { Authorization: `Bearer ${key}` } });
      // 403 bei eingeschraenkten Schluesseln (rk_): Schluessel gilt, darf nur den Kontostand nicht lesen
      return r.status === 200 || r.status === 403 ? 'active' : r.status === 401 ? 'inactive' : 'unknown';
    }
    if (provider === 'AWS') {
      if (!extra) return 'unknown';
      const s = signSts(key, extra);
      const r = await go(s.url, { method: 'POST', headers: s.headers, body: s.body });
      if (r.status === 200) return 'active';
      const txt = await r.text().catch(() => '');
      return /InvalidClientTokenId|ExpiredToken/.test(txt) ? 'inactive' : 'unknown';
    }
    return 'unknown';
  } catch { return 'unknown'; }
  finally { clearTimeout(t); }
}

// AWS braucht zusaetzlich den geheimen Schluessel – nur aus der Naehe der Fundstelle
function awsSecretNear(lines, idx) {
  const win = lines.slice(Math.max(0, idx - 6), idx + 7).join('\n');
  const m = win.match(/aws_?secret_?access_?key\W{0,6}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/i) || win.match(/["'=:\s]([A-Za-z0-9/+]{40})["'\s]/);
  return m ? m[1] : null;
}

const NOTE = {
  active: (p) => ` Live-Prüfung: Der Schlüssel ist laut ${p} noch gültig (geprüft mit einer harmlosen, nur lesenden Identitätsabfrage). Sofort beim Anbieter sperren und neu erzeugen.`,
  inactive: (p) => ` Live-Prüfung: ${p} lehnt den Schlüssel ab – er ist vermutlich bereits gesperrt. Trotzdem aus dem Code und der Git-Historie entfernen.`,
};

// findings: Befunde der Vorpruefung; units: eingelesene Dateien. opts: { fetchImpl, signal, max, onProgress }
async function verifyLiveSecrets(findings, units, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const max = opts.max || 20;
  const byLabel = new Map(units.map((u) => [String(u.label || ''), u]));
  const cache = new Map(); // Hash des Schluessels -> Urteil (nur im Speicher dieses Laufs)
  const notes = [];
  let checked = 0, active = 0;
  const out = [];
  for (const f0 of findings) {
    const f = { ...f0 };
    out.push(f);
    if (f.category !== 'Secrets' || checked >= max) continue;
    const m = String(f.location || '').match(/^(.*):(\d+)$/);
    const u = m && byLabel.get(m[1]);
    if (!u) continue;
    const lines = String(u.content || '').split('\n');
    const idx = Number(m[2]) - 1;
    const line = lines[idx] || '';
    const hit = DETECT.map((d) => ({ d, m: line.match(d.re) })).find((x) => x.m);
    if (!hit || LOOKS_FAKE.test(hit.m[1])) continue;
    const key = hit.m[1];
    const extra = hit.d.provider === 'AWS' ? awsSecretNear(lines, idx) : null;
    const h = sha256(hit.d.provider + ':' + key);
    if (!cache.has(h)) {
      if (opts.signal && opts.signal.aborted) break;
      checked++;
      (opts.onProgress || (() => {}))({ phase: 'prescan', message: `Live-Prüfung eines ${hit.d.provider}-Schlüssels …` });
      cache.set(h, await probe(hit.d.provider, key, extra, fetchImpl, opts.signal));
    }
    const verdict = cache.get(h);
    f.liveCheck = { verdict, provider: hit.d.provider, at: new Date().toISOString() };
    if (verdict === 'active') { f.severity = 'critical'; f.confidence = 'high'; f.description = (f.description || '') + NOTE.active(hit.d.provider); active++; }
    else if (verdict === 'inactive') { f.severity = 'low'; f.description = (f.description || '') + NOTE.inactive(hit.d.provider); }
  }
  if (checked) notes.push(`Live-Prüfung: ${checked} Schlüssel geprüft, ${active} davon noch gültig.`);
  return { findings: out, notes, checked };
}

module.exports = { verifyLiveSecrets, signSts, probe, DETECT };
