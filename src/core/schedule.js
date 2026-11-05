'use strict';

// Geplante Pruefungen: wann ist ein Plan faellig, welche Befunde sind eine Meldung wert, wie sieht die
// Nachricht an einen Webhook aus. Reine Logik; Ablauf und Speichern stehen in electron/main.js.
// Verpasste Laeufe (Rechner aus, App zu) werden beim naechsten Start einmal nachgeholt.

const crypto = require('crypto');

const FREQS = ['daily', 'weekly'];
const SEVS = ['critical', 'high', 'medium', 'low'];
const atOrAbove = (sev, min) => { const a = SEVS.indexOf(sev), b = SEVS.indexOf(min); return a >= 0 && b >= 0 && a <= b; };
const DAY = 24 * 60 * 60 * 1000;

function normalize(raw = {}, prev = null) {
  const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(String(raw.time)) ? String(raw.time) : '03:00';
  const weekday = Number.isInteger(raw.weekday) && raw.weekday >= 0 && raw.weekday <= 6 ? raw.weekday : 1;
  return {
    id: (prev && prev.id) || (typeof raw.id === 'string' && /^[\w-]{4,40}$/.test(raw.id) ? raw.id : crypto.randomUUID()),
    name: String(raw.name || '').trim().slice(0, 80) || 'Geplante Prüfung',
    targets: (Array.isArray(raw.targets) ? raw.targets : []).slice(0, 50),
    freq: FREQS.includes(raw.freq) ? raw.freq : 'daily',
    time, weekday,
    minSeverity: SEVS.includes(raw.minSeverity) ? raw.minSeverity : 'high',
    enabled: raw.enabled !== false,
    webhookEnc: prev ? prev.webhookEnc || '' : '',
    createdAt: (prev && prev.createdAt) || new Date().toISOString(),
    lastRun: (prev && prev.lastRun) || null,
    lastStatus: (prev && prev.lastStatus) || null,
  };
}

// Naechster geplanter Zeitpunkt NACH "after" (lokale Zeit, damit "03:00" auch nach der Zeitumstellung stimmt).
function nextRun(s, after) {
  const [h, m] = s.time.split(':').map(Number);
  const d = new Date(after);
  d.setHours(h, m, 0, 0);
  if (s.freq === 'weekly') {
    let add = (s.weekday - d.getDay() + 7) % 7;
    if (add === 0 && d.getTime() <= after) add = 7;
    d.setDate(d.getDate() + add);
  } else if (d.getTime() <= after) d.setDate(d.getDate() + 1);
  return d.getTime();
}

function isDue(s, now = Date.now()) {
  if (!s || !s.enabled || !s.targets || !s.targets.length) return false;
  const from = Date.parse(s.lastRun || s.createdAt);
  return !Number.isNaN(from) && now >= nextRun(s, from);
}

// Wert einer Meldung: nur NEUE, offene Befunde ab der gewaehlten Schwere.
function alertsOf(result, minSeverity = 'high') {
  return ((result && result.findings) || []).filter((f) => f.isNew && !f.suppressed && atOrAbove(f.severity, minSeverity));
}

function validWebhook(url) {
  try {
    const u = new URL(String(url));
    return u.protocol === 'https:' && !u.username && !u.password && String(url).length < 1000;
  } catch { return false; }
}

// Geht an einen vom Nutzer eingetragenen Empfaenger: nur Schwere, Titel und Ort – keine Belege, kein Code.
function webhookPayload(url, { name, alerts, error }) {
  const lines = alerts.slice(0, 10).map((f) => `[${f.severity}] ${f.title}${f.location ? ` (${f.location})` : ''}`.slice(0, 300));
  const more = alerts.length > 10 ? `\n… und ${alerts.length - 10} weitere` : '';
  const text = error ? `Vigil – ${name}: ${error}` : `Vigil – ${name}: ${alerts.length} neue(r) Befund(e)\n${lines.join('\n')}${more}`;
  let host = '';
  try { host = new URL(url).hostname; } catch { /* unten generisch */ }
  if (/(^|\.)discord(app)?\.com$/.test(host)) return { content: text.slice(0, 1900) };
  if (/(^|\.)(slack\.com|office\.com|office365\.com|logic\.azure\.com)$/.test(host)) return { text };
  return { source: 'vigil', schedule: name, text, error: error || null, findings: alerts.slice(0, 50).map((f) => ({ severity: f.severity, title: f.title, location: f.location || '' })) };
}

async function sendWebhook(url, payload, { fetchImpl = fetch, signal } = {}) {
  if (!validWebhook(url)) return { ok: false, error: 'Nur https-Adressen sind erlaubt.' };
  const t = AbortSignal.timeout(15000);
  try {
    const r = await fetchImpl(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), redirect: 'error', signal: signal ? AbortSignal.any([t, signal]) : t });
    return r.ok ? { ok: true } : { ok: false, error: `HTTP ${r.status}` };
  } catch (e) { return { ok: false, error: e.message }; }
}

module.exports = { FREQS, SEVS, DAY, normalize, nextRun, isDue, alertsOf, validWebhook, webhookPayload, sendWebhook };
