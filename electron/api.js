'use strict';

// Lokale REST-API (nur 127.0.0.1, Bearer-Token). Fuer Skripte/CI auf demselben Rechner.
//   GET    /api/stats                   Kennzahlen (offene Befunde nach Schweregrad, Ziele, letzte Laeufe)
//   GET    /api/targets                 Ziele inkl. offener Befunde
//   GET    /api/findings?status=&severity=&targetId=&q=&limit=
//   PATCH  /api/findings/:id/status     { status, note? }
//   POST   /api/scans                   { targets:[{type,value}], providerId? }  -> 202 { scanId }
//   GET    /api/scans/:id               Status eines Laufs
//   POST   /api/targets/:id/baseline    aktuellen Stand als Baseline setzen
//   GET    /api/sbom?q=lodash@4.17      wo ist ein Paket (in welcher Version) im Einsatz?

const http = require('http');
const crypto = require('crypto');
const { check, ScanRequestSchema, StatusUpdateSchema } = require('../src/core/validation');

const MAX_BODY = 64 * 1024;
const RATE = { windowMs: 60000, max: 120, scansPerWindow: 10 };

function createApi({ orchestrator, getConfig, enforceScope }) {
  let server = null;
  const hits = [];
  const scanHits = [];

  const send = (res, code, body) => {
    const data = JSON.stringify(body);
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(data), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    res.end(data);
  };
  const overLimit = (arr, max) => {
    const now = Date.now();
    while (arr.length && now - arr[0] > RATE.windowMs) arr.shift();
    if (arr.length >= max) return true;
    arr.push(now);
    return false;
  };
  const tokenOk = (req, token) => {
    const m = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    if (!m || !token) return false;
    const a = Buffer.from(m[1]), b = Buffer.from(token);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  };
  const readJson = (req) => new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error('Anfrage zu groß.'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(Object.assign(new Error('Ungültiges JSON.'), { code: 400 })); } });
    req.on('error', reject);
  });

  async function handle(req, res) {
    const cfg = getConfig();
    // Nur lokale Aufrufer ohne Browser-Herkunft (keine Cross-Site-Anfragen aus Webseiten).
    if (req.headers.origin) return send(res, 403, { error: 'Browser-Anfragen sind nicht erlaubt.' });
    if (!tokenOk(req, cfg.apiToken)) return send(res, 401, { error: 'Token fehlt oder ist falsch.' });
    if (overLimit(hits, RATE.max)) return send(res, 429, { error: 'Zu viele Anfragen – bitte kurz warten.' });

    const url = new URL(req.url, 'http://127.0.0.1');
    const parts = url.pathname.replace(/\/+$/, '').split('/').filter(Boolean); // ['api', ...]
    if (parts[0] !== 'api') return send(res, 404, { error: 'Nicht gefunden.' });
    const [, res1, id, sub] = parts;

    try {
      if (req.method === 'GET' && res1 === 'stats' && !id) return send(res, 200, orchestrator.stats());
      if (req.method === 'GET' && res1 === 'targets' && !id) return send(res, 200, { targets: orchestrator.targets() });
      if (req.method === 'POST' && res1 === 'targets' && id && sub === 'baseline') {
        const r = orchestrator.setBaseline(id);
        return r.ok ? send(res, 200, r) : send(res, 404, { error: r.error });
      }
      if (req.method === 'GET' && res1 === 'sbom' && !id) {
        const q = String(url.searchParams.get('q') || '').slice(0, 120);
        return q ? send(res, 200, { query: q, matches: orchestrator.searchSbom(q) }) : send(res, 400, { error: 'Parameter q fehlt (z. B. ?q=lodash@4.17).' });
      }
      if (req.method === 'GET' && res1 === 'findings' && !id) {
        const q = Object.fromEntries(url.searchParams);
        return send(res, 200, { findings: orchestrator.listFindings(q) });
      }
      if (req.method === 'PATCH' && res1 === 'findings' && id && sub === 'status') {
        const v = check(StatusUpdateSchema, await readJson(req));
        if (!v.ok) return send(res, 400, { error: v.error });
        const r = orchestrator.setStatus(id, v.data.status, v.data.note);
        return r.ok ? send(res, 200, { finding: r.finding }) : send(res, 404, { error: r.error });
      }
      if (req.method === 'POST' && res1 === 'scans' && !id) {
        if (overLimit(scanHits, RATE.scansPerWindow)) return send(res, 429, { error: 'Zu viele Scans pro Minute.' });
        const v = check(ScanRequestSchema, await readJson(req));
        if (!v.ok) return send(res, 400, { error: v.error });
        // Ueber die API gibt es keine Bestaetigung: nur bereits freigegebene Ziele.
        const scope = enforceScope(v.data.targets.map((t) => ({ ...t, authorized: false })), cfg.allowlist, { interactive: false });
        if (!scope.ok) return send(res, 403, { error: 'Ziel außerhalb des freigegebenen Bereichs.', details: scope.errors });
        const job = orchestrator.enqueue({ targets: scope.targets, providerId: v.data.providerId || cfg.selected, origin: 'api' });
        return send(res, 202, { scanId: job.id, status: 'QUEUED' });
      }
      if (req.method === 'GET' && res1 === 'scans' && id) {
        const run = orchestrator.getRun(id);
        return run ? send(res, 200, run) : send(res, 404, { error: 'Lauf nicht gefunden.' });
      }
      return send(res, 404, { error: 'Nicht gefunden.' });
    } catch (e) {
      return send(res, e.code || 500, { error: e.code ? e.message : 'Interner Fehler.' });
    }
  }

  return {
    start(port) {
      return new Promise((resolve) => {
        if (server) return resolve({ ok: true, port: server.address().port });
        const s = http.createServer((req, res) => { handle(req, res); });
        s.on('error', (e) => { server = null; resolve({ ok: false, error: e.code === 'EADDRINUSE' ? `Port ${port} ist schon belegt.` : e.message }); });
        s.listen(port, '127.0.0.1', () => { server = s; resolve({ ok: true, port }); });
      });
    },
    stop() { return new Promise((r) => { if (!server) return r(); server.close(() => r()); server = null; }); },
    running: () => !!server,
  };
}

module.exports = { createApi };
