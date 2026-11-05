'use strict';

// Helm-Charts und Kustomize-Overlays rendern (helm template / kustomize build bzw. kubectl kustomize),
// falls die Werkzeuge installiert sind, und die fertigen Manifeste mit den Kubernetes-Regeln aus
// iac.js pruefen. Fehlt ein Werkzeug, wird still uebersprungen. Kein Cluster-Zugriff.

const fs = require('fs');
const path = require('path');
const { kubernetes } = require('./iac');
const { check, RenderedManifestsSchema } = require('../validation');

const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const fileName = (u) => base(u).split('/').pop().toLowerCase();
const dirLabel = (u) => { const b = base(u); const i = b.lastIndexOf('/'); return i < 0 ? '.' : b.slice(0, i); };

function isDir(p) { try { return fs.statSync(p).isDirectory(); } catch { return false; } }

// Chart-/Kustomize-Ordner aus den eingelesenen Dateien (nur echte Ordner auf der Platte)
function renderTargets(units) {
  const charts = [], kusts = [];
  for (const u of units) {
    if (!u.path || /!\//.test(String(u.label || '')) || !path.isAbsolute(String(u.path))) continue;
    const dir = path.dirname(u.path);
    if (!isDir(dir)) continue;
    const n = fileName(u);
    if (n === 'chart.yaml') charts.push({ dir, label: dirLabel(u) });
    else if (n === 'kustomization.yaml' || n === 'kustomization.yml' || n === 'kustomization') kusts.push({ dir, label: dirLabel(u) });
  }
  // Unter-Charts (charts/<name>) rendert helm mit dem Eltern-Chart
  const top = charts.filter((c) => !charts.some((p) => p !== c && c.dir.startsWith(p.dir + path.sep)));
  return { charts: top.slice(0, 10), kusts: kusts.slice(0, 10) };
}

// helm template: Ausgabe nach "# Source: chart/templates/x.yaml" aufteilen
function splitHelm(out, chartLabel) {
  const parts = [];
  const re = /^# Source: (.+)$/gm; let m; const marks = [];
  while ((m = re.exec(out))) marks.push({ at: m.index, src: m[1].trim() });
  if (!marks.length) return [{ label: `${chartLabel} [helm template]`, content: out }];
  marks.forEach((mk, i) => {
    const content = out.slice(mk.at, i + 1 < marks.length ? marks[i + 1].at : out.length);
    const rel = mk.src.split('/').slice(1).join('/') || mk.src;
    parts.push({ label: `${chartLabel}/${rel} [helm template]`, content });
  });
  return parts;
}

// opts: { run(cmd, args, opts) -> {ok, code, stdout, stderr}, signal, onProgress }
async function renderAndCheck(units, opts = {}) {
  const run = opts.run || require('../tools').runTool;
  const { charts, kusts } = renderTargets(units);
  const findings = [], notes = [], ran = [];
  if (!charts.length && !kusts.length) return { findings, notes, ran };
  const tag = (list, src) => list.map((f) => ({ ...f, source: src, sourceModule: src }));
  const take = (stdout) => { const v = check(RenderedManifestsSchema, String(stdout || '')); return v.ok ? v.data : null; };
  let helmMissing = false, helmOk = 0;
  for (const c of charts) {
    if (helmMissing || (opts.signal && opts.signal.aborted)) break;
    (opts.onProgress || (() => {}))({ phase: 'prescan', message: `Helm-Chart rendern: ${c.label} …` });
    const r = await run('helm', ['template', 'vigil-audit', c.dir], { signal: opts.signal, timeoutMs: 90000 });
    if (!r.ok) { helmMissing = true; break; }
    const out = r.code === 0 ? take(r.stdout) : null;
    if (out == null) { notes.push(`Helm-Chart ${c.label} ließ sich nicht rendern – nur die Vorlagen wurden geprüft.`); continue; }
    helmOk++;
    for (const u of splitHelm(out, c.label)) findings.push(...tag(kubernetes(u), 'helm-render'));
  }
  if (helmOk && helmOk === charts.length) ran.push('helm-render');
  // kustomize: eigenes Programm oder ueber kubectl
  let kTool = null, kOk = 0;
  for (const k of kusts) {
    if (opts.signal && opts.signal.aborted) break;
    (opts.onProgress || (() => {}))({ phase: 'prescan', message: `Kustomize rendern: ${k.label} …` });
    let r = null;
    for (const [cmd, args] of kTool ? [kTool] : [['kustomize', ['build']], ['kubectl', ['kustomize']]]) {
      const x = await run(cmd, [...args, k.dir], { signal: opts.signal, timeoutMs: 90000 });
      if (x.ok) { r = x; kTool = [cmd, args]; break; }
    }
    if (!r) break; // weder kustomize noch kubectl installiert
    const out = r.code === 0 ? take(r.stdout) : null;
    if (out == null) { notes.push(`Kustomize-Ordner ${k.label} ließ sich nicht rendern.`); continue; }
    kOk++;
    findings.push(...tag(kubernetes({ label: `${k.label}/kustomization.yaml [kustomize build]`, content: out }), 'kustomize-render'));
  }
  if (kOk && kOk === kusts.length) ran.push('kustomize-render');
  if (helmOk || kOk) notes.push(`Gerenderte Manifeste geprüft: ${helmOk} Helm-Chart(s), ${kOk} Kustomize-Ordner, ${findings.length} Fund(e).`);
  return { findings, notes, ran };
}

module.exports = { renderAndCheck, renderTargets, splitHelm };
