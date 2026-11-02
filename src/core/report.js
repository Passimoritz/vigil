'use strict';

// Rendert Analyse-Ergebnisse als Markdown oder eigenstaendiges HTML.

const SEV_LABEL = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Info' };
const SEV_COLOR = { critical: '#b3123c', high: '#d9480f', medium: '#c48a00', low: '#2b7a3b', info: '#555' };
const EVIDENCE_LABEL = { 'confirmed-multi': 'mehrfach bestaetigt', deterministic: 'regelbasiert belegt', 'ai-verified': 'KI-gegengeprueft', unverified: 'unbestaetigt (nur KI)' };
const CONTEXT_LABEL = { 'internet-exposed': 'aus dem Internet erreichbar', 'request-handler': 'in einem Request-Handler', 'sensitive-data': 'beruehrt sensible Daten', 'supply-chain': 'Lieferkette' };

// "Beleg: … · Kontext: …" fuer einen Befund (leer, wenn nichts bekannt).
function evidenceLine(f) {
  const parts = [];
  if (f.assurance) parts.push('Beleg: ' + (EVIDENCE_LABEL[f.assurance] || f.assurance));
  if (f.evidence) parts.push('Fundstelle: ' + f.evidence);
  const ctx = (f.context || []).map((c) => CONTEXT_LABEL[c]).filter(Boolean);
  if (ctx.length) parts.push('Kontext: ' + ctx.join(', '));
  return parts.join(' · ');
}

function esc(s) {
  return String(s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

const { OWASP, complianceReport } = require('./taxonomy');
const ST_LABEL = { ok: 'kein offener Befund', warn: 'offene Befunde', fail: 'dringende Befunde' };
const ST_COLOR = { ok: '#2b7a3b', warn: '#c48a00', fail: '#b3123c' };

// Kapitel "Nachweise fuer Normen": je Katalog die Kontrollen mit offenen Befunden
function complianceHtml(findings) {
  const cats = complianceReport(findings);
  return `<section class="compliance"><h2>Nachweise für Normen</h2>
  <p class="meta">Technische Einordnung der offenen Befunde in gängige Kataloge. Ersetzt keine Zertifizierung oder Rechtsberatung, liefert aber prüfbare Belege für die jeweiligen Anforderungen.</p>
  ${cats.map((c) => `<h3>${esc(c.name)}</h3><table><thead><tr><th>Anforderung</th><th>Stand</th><th>Offene Befunde</th></tr></thead><tbody>${c.controls.map((k) => `<tr><td><b>${esc(k.id)}</b> ${esc(k.title)}</td><td><span class="st" style="background:${ST_COLOR[k.status]}">${ST_LABEL[k.status]}</span></td><td>${k.count ? `${k.count}: ${esc(k.findings.slice(0, 3).join('; '))}${k.count > 3 ? ' …' : ''}` : '–'}</td></tr>`).join('')}</tbody></table>`).join('')}
  </section>`;
}

// Bericht fuer die Geschaeftsfuehrung: eine Seite, Klartext, optional mit eigenem Logo.
// opts: { logoDataUrl, company, posture (0–100), trend: [{at, open}] }
function toExecutive(result, opts = {}) {
  const findings = (result.findings || []).filter((f) => !f.suppressed);
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  const posture = opts.posture ?? Math.max(0, Math.round(100 - (c.critical * 12 + c.high * 6 + c.medium * 2 + c.low * 0.5)));
  const grade = posture >= 90 ? 'A' : posture >= 78 ? 'B' : posture >= 62 ? 'C' : posture >= 45 ? 'D' : 'E';
  const lage = c.critical ? `Es gibt ${c.critical} kritische ${c.critical === 1 ? 'Schwachstelle' : 'Schwachstellen'}, die kurzfristig behoben werden ${c.critical === 1 ? 'muss' : 'müssen'}.`
    : c.high ? `Keine kritischen Schwachstellen, aber ${c.high} mit hohem Risiko.` : 'Keine kritischen oder hohen Risiken gefunden.';
  const top = findings.filter((f) => ['critical', 'high'].includes(f.severity)).slice(0, 5);
  const plain = (f) => String(f.title).replace(/^(Möglicher )?Angriffsweg:\s*/, '').replace(/\s*\(.*?\)\s*$/, '');
  const comp = complianceReport(findings).map((k) => ({ name: k.name, fail: k.controls.filter((x) => x.status === 'fail').length, warn: k.controls.filter((x) => x.status === 'warn').length, total: k.controls.length }));
  const trend = (opts.trend || []).slice(-12);
  const max = Math.max(1, ...trend.map((t) => t.open));
  const spark = trend.length > 1 ? `<svg viewBox="0 0 240 50" width="240" height="50" aria-label="Offene Befunde im Verlauf"><polyline fill="none" stroke="#9a5b00" stroke-width="2" points="${trend.map((t, i) => `${(i / (trend.length - 1)) * 236 + 2},${48 - (t.open / max) * 44}`).join(' ')}"/></svg>` : '';
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><title>Sicherheitslage – Kurzbericht</title>
<style>
  @page { size: A4; margin: 16mm; }
  body { font: 14px/1.55 system-ui, Segoe UI, sans-serif; color: #15181d; margin: 0; padding: 28px 34px; max-width: 820px; }
  header { display: flex; align-items: center; justify-content: space-between; border-bottom: 2px solid #15181d; padding-bottom: 12px; }
  header img { max-height: 48px; max-width: 200px; }
  h1 { font-size: 22px; margin: 0; } h2 { font-size: 15px; margin: 22px 0 8px; text-transform: uppercase; letter-spacing: .05em; color: #555; }
  .grade { display: flex; gap: 22px; align-items: center; margin-top: 18px; }
  .grade b { font-size: 54px; line-height: 1; width: 86px; height: 86px; display: grid; place-items: center; border-radius: 18px; color: #fff; background: ${posture >= 78 ? '#2b7a3b' : posture >= 50 ? '#c48a00' : '#b3123c'}; }
  .counts span { display: inline-block; margin-right: 14px; } .counts i { font-style: normal; font-weight: 700; }
  ol li { margin: 6px 0; } table { border-collapse: collapse; width: 100%; } td { padding: 5px 8px; border-bottom: 1px solid #ddd; }
  .muted { color: #666; font-size: 12px; } footer { margin-top: 26px; color: #777; font-size: 11.5px; }
</style></head><body>
<header><div><h1>Sicherheitslage – Kurzbericht</h1><div class="muted">${esc(opts.company || '')}${opts.company ? ' · ' : ''}Stand ${esc(new Date(result.meta?.at || Date.now()).toLocaleDateString('de-DE'))}</div></div>${opts.logoDataUrl && /^data:image\/(png|jpe?g|svg\+xml|webp);base64,/.test(opts.logoDataUrl) ? `<img src="${esc(opts.logoDataUrl)}" alt="Logo">` : ''}</header>
<div class="grade"><b>${grade}</b><div><div style="font-size:18px;font-weight:700">Sicherheitswert ${posture} von 100</div><p>${esc(lage)}</p>
<div class="counts"><span><i style="color:#b3123c">${c.critical}</i> kritisch</span><span><i style="color:#d9480f">${c.high}</i> hoch</span><span><i style="color:#c48a00">${c.medium}</i> mittel</span><span><i>${c.low + c.info}</i> gering</span></div></div>${spark ? `<div>${spark}<div class="muted">offene Befunde, letzte ${trend.length} Prüfungen</div></div>` : ''}</div>
<h2>Die wichtigsten Risiken</h2>
${top.length ? `<ol>${top.map((f) => `<li><b>${esc(plain(f))}</b><br><span class="muted">${esc((f.impact || f.description || '').split(/(?<=\.)\s/)[0].slice(0, 220))}</span></li>`).join('')}</ol>` : '<p>Keine dringenden Risiken.</p>'}
<h2>Nächste Schritte</h2>
<ol>${top.length ? top.slice(0, 3).map((f) => `<li>${esc((f.steps && f.steps[0]) || f.remediation || 'Beheben lassen')}</li>`).join('') : '<li>Regelmäßig weiter prüfen (z. B. monatlich) und neue Befunde zeitnah beheben.</li>'}${c.medium ? `<li>${c.medium} mittlere Befunde im normalen Entwicklungsablauf abarbeiten.</li>` : ''}</ol>
<h2>Normen auf einen Blick</h2>
<table>${comp.map((k) => `<tr><td>${esc(k.name)}</td><td>${k.fail ? `<b style="color:#b3123c">${k.fail} Anforderung(en) mit dringenden Befunden</b>` : k.warn ? `<span style="color:#c48a00">${k.warn} Anforderung(en) mit offenen Befunden</span>` : '<span style="color:#2b7a3b">keine offenen Befunde</span>'}</td></tr>`).join('')}</table>
<footer>Erstellt mit Vigil – zerstörungsfreie Prüfung eigener bzw. freigegebener Systeme. Technische Details im vollständigen Bericht.</footer>
</body></html>`;
}

function toMarkdown(result, title = 'Vigil Sicherheits-Audit') {
  const { findings, summary, meta, errors } = result;
  const L = [];
  L.push(`# ${title}`, '');
  L.push(`_Erstellt: ${meta?.at || new Date().toISOString()} · Anbieter: ${meta?.provider || '-'} / ${meta?.model || '-'}_`, '');
  // Executive Summary: Lage auf einen Blick
  const toxic = findings.filter((f) => /^toxic-/.test(f.ruleId || ''));
  const kev = findings.filter((f) => f.inCisaKev);
  const lc = result.lifecycle;
  L.push('## Executive Summary', '');
  L.push(`- **Offene Befunde:** ${summary.total} (kritisch ${summary.counts.critical || 0}, hoch ${summary.counts.high || 0})`);
  if (toxic.length) L.push(`- **Angriffswege:** ${toxic.length} – ${toxic.map((t) => t.title.replace(/^(Möglicher )?Angriffsweg:\s*/, '')).join('; ')}`);
  if (kev.length) L.push(`- **Aktiv ausgenutzt (CISA KEV):** ${kev.length} – ${kev.map((f) => (f.cves || [f.ruleId]).join('/')).join(', ')}`);
  if (lc) L.push(`- **Seit dem letzten Lauf:** ${lc.created} neu, ${lc.resolved} behoben, ${lc.reopened} wieder aufgetaucht`);
  L.push('');
  L.push('## Zusammenfassung', '');
  L.push(`Befunde gesamt: **${summary.total}**`, '');
  L.push('| Schweregrad | Anzahl |', '| --- | --- |');
  for (const s of ['critical', 'high', 'medium', 'low', 'info']) L.push(`| ${SEV_LABEL[s]} | ${summary.counts[s] || 0} |`);
  L.push('');
  if (errors && errors.length) {
    L.push('## Hinweise/Fehler', '');
    errors.forEach((e) => L.push(`- ${e}`));
    L.push('');
  }
  L.push('## Befunde', '');
  findings.forEach((f, i) => {
    L.push(`### ${i + 1}. [${SEV_LABEL[f.severity]}] ${f.title}`, '');
    L.push(`- **CVSS:** ${f.cvss ?? '—'} · **Kategorie:** ${f.category}${f.cwe ? ' · **' + f.cwe + '**' : ''}${f.owasp ? ' · OWASP ' + f.owasp : ''} · **Confidence:** ${f.confidence} · **Quelle:** ${(f.sources || [f.source]).join(", ")}`);
    if (f.location) L.push(`- **Ort:** \`${f.location}\``);
    if (evidenceLine(f)) L.push(`- ${evidenceLine(f)}`);
    L.push('');
    if (f.description) L.push(`**Beschreibung:** ${f.description}`, '');
    if (f.reachability) L.push(`**Erreichbarkeit/Risiko:** ${f.reachability}`, '');
    if (f.impact) L.push(`**Auswirkung:** ${f.impact}`, '');
    if (f.remediation) L.push(`**Behebung:** ${f.remediation}`, '');
    if (f.patch) L.push('**Patch:**', '```', f.patch, '```', '');
    if (f.explanation) L.push(`**Warum das wichtig ist:** ${f.explanation}`, '');
    if (f.steps && f.steps.length) { L.push('**Schritte:**'); f.steps.forEach((s, j) => L.push(`${j + 1}. ${s}`)); L.push(''); }
    if (f.versionPatch) { L.push(`**Versions-Patch (${f.versionPatch.title}):**`, '```', [f.versionPatch.command, f.versionPatch.manifest].filter(Boolean).join('\n\n'), '```', ''); }
    for (const [k, v] of Object.entries(f.snippets || {}).slice(0, 3)) L.push(`**${k}:**`, '```', v, '```', '');
    if (f.links && f.links.length) L.push('**Mehr dazu:** ' + f.links.map((l) => `[${l.label}](${l.url})`).join(' · '), '');
    L.push('---', '');
  });
  return L.join('\n');
}

function toHtml(result, title = 'Vigil Sicherheits-Audit') {
  const { findings, summary, meta, errors } = result;
  const bars = ['critical', 'high', 'medium', 'low', 'info'].map((s) =>
    `<span class="pill" style="background:${SEV_COLOR[s]}">${SEV_LABEL[s]}: ${summary.counts[s] || 0}</span>`
  ).join(' ');

  const cards = findings.map((f, i) => `
    <div class="card sev-${f.severity}">
      <div class="card-head">
        <span class="sev" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span>
        <span class="num">#${i + 1}</span>
        <h3>${esc(f.title)}</h3>
      </div>
      <div class="meta">CVSS ${f.cvss ?? '—'} · ${esc(f.category)}${f.cwe ? ` · ${esc(f.cwe)}` : ''}${f.owasp ? ` · OWASP ${esc(OWASP[f.owasp] || f.owasp)}` : ''} · Confidence: ${esc(f.confidence)} · Quelle: ${esc((f.sources || [f.source]).join(", "))}${f.location ? ` · <code>${esc(f.location)}</code>` : ''}${evidenceLine(f) ? ' · ' + esc(evidenceLine(f)) : ''}</div>
      ${f.description ? `<p><b>Beschreibung:</b> ${esc(f.description)}</p>` : ''}
      ${f.reachability ? `<p><b>Erreichbarkeit/Risiko:</b> ${esc(f.reachability)}</p>` : ''}
      ${f.impact ? `<p><b>Auswirkung:</b> ${esc(f.impact)}</p>` : ''}
      ${f.remediation ? `<p class="fix"><b>Behebung:</b> ${esc(f.remediation)}</p>` : ''}
      ${f.explanation ? `<p><b>Warum das wichtig ist:</b> ${esc(f.explanation)}</p>` : ''}
      ${f.steps && f.steps.length ? `<ol>${f.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
      ${f.versionPatch ? `<p><b>Versions-Patch (${esc(f.versionPatch.title)}):</b></p><pre>${esc([f.versionPatch.command, f.versionPatch.manifest].filter(Boolean).join('\n\n'))}</pre>` : ''}
      ${Object.entries(f.snippets || {}).slice(0, 3).map(([k, v]) => `<p><b>${esc(k)}:</b></p><pre>${esc(v)}</pre>`).join('')}
      ${f.links && f.links.length ? `<p><b>Mehr dazu:</b> ${f.links.map((l) => `<a href="${esc(l.url)}">${esc(l.label)}</a>`).join(' · ')}</p>` : ''}
      ${f.patch ? `<pre class="patch">${esc(f.patch)}</pre>` : ''}
    </div>`).join('\n');

  return `<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.55 system-ui, Segoe UI, sans-serif; margin: 0; background: #f6f7f9; color: #15181d; }
  @media (prefers-color-scheme: dark){ body{ background:#14171c; color:#e6e8ec; } .card{ background:#1d2128; } .meta{ color:#9aa2ad; } pre.patch{ background:#0f1216; } }
  header { padding: 24px 28px; background: #10131a; color: #fff; }
  header h1 { margin: 0 0 6px; font-size: 20px; }
  header .sub { opacity: .75; font-size: 13px; }
  .pill { display:inline-block; color:#fff; padding:3px 10px; border-radius:999px; font-size:12px; margin:8px 6px 0 0; }
  main { max-width: 960px; margin: 0 auto; padding: 20px 16px 60px; }
  .card { background:#fff; border:1px solid rgba(128,128,128,.2); border-left-width:5px; border-radius:10px; padding:16px 18px; margin:14px 0; }
  .card.sev-critical{ border-left-color:${SEV_COLOR.critical}; } .card.sev-high{ border-left-color:${SEV_COLOR.high}; }
  .card.sev-medium{ border-left-color:${SEV_COLOR.medium}; } .card.sev-low{ border-left-color:${SEV_COLOR.low}; } .card.sev-info{ border-left-color:${SEV_COLOR.info}; }
  .card-head { display:flex; align-items:center; gap:10px; }
  .card-head h3 { margin:0; font-size:16px; }
  .sev { color:#fff; font-size:11px; padding:2px 8px; border-radius:6px; text-transform:uppercase; letter-spacing:.04em; }
  .num { color:#888; font-size:12px; }
  .meta { color:#667; font-size:12.5px; margin:8px 0 4px; }
  .fix { background: rgba(43,122,59,.1); padding:8px 10px; border-radius:6px; }
  pre.patch { background:#0f1216; color:#e6e8ec; padding:12px; border-radius:8px; overflow:auto; font-size:12.5px; }
  code { background: rgba(128,128,128,.15); padding:1px 5px; border-radius:4px; }
  .errors { background: rgba(217,72,15,.12); border-radius:8px; padding:10px 14px; font-size:13px; }
  .compliance table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:14px; } .compliance td, .compliance th { text-align:left; padding:6px 8px; border-bottom:1px solid rgba(128,128,128,.25); vertical-align:top; }
  .compliance .st { color:#fff; font-size:11px; padding:2px 8px; border-radius:999px; white-space:nowrap; }
</style></head>
<body>
<header>
  <h1>${esc(title)}</h1>
  <div class="sub">Erstellt: ${esc(meta?.at || '')} · Anbieter: ${esc(meta?.provider || '-')} / ${esc(meta?.model || '-')} · Befunde: ${summary.total}</div>
  <div>${bars}</div>
</header>
<main>
  ${errors && errors.length ? `<div class="errors"><b>Hinweise/Fehler:</b><ul>${errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>` : ''}
  ${findings.length ? cards : '<p>Keine Befunde.</p>'}
  ${complianceHtml(findings)}
</main>
</body></html>`;
}

// --- SARIF 2.1.0 (fuer VS Code, GitHub Code Scanning, CI u. a.) ----------
function sevToLevel(s) {
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'medium') return 'warning';
  return 'note'; // low / info
}
// Ort "pfad:zeile" bzw. "host:port" aufteilen (gierig: letzter :Zahl zaehlt).
function splitLocation(loc) {
  const s = String(loc || '');
  const m = s.match(/^(.*):(\d+)$/);
  if (m) return { uri: m[1], line: parseInt(m[2], 10) };
  return { uri: s, line: null };
}

function toSarif(result, toolVersion = '0.1.0') {
  const findings = result.findings || [];
  const rules = new Map();
  const results = findings.map((f) => {
    const ruleId = 'vigil/' + (f.category || 'Other');
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: (f.category || 'Other').replace(/\s+/g, ''),
        shortDescription: { text: `Vigil-Kategorie: ${f.category || 'Other'}` },
        defaultConfiguration: { level: sevToLevel(f.severity) },
      });
    }
    const extra = [
      f.description, f.reachability && `Erreichbarkeit: ${f.reachability}`,
      f.impact && `Auswirkung: ${f.impact}`, f.remediation && `Behebung: ${f.remediation}`,
    ].filter(Boolean);
    const r = {
      ruleId,
      level: sevToLevel(f.severity),
      message: { text: `${f.title}${extra.length ? '\n' + extra.join('\n') : ''}` },
      properties: {
        severity: f.severity, cvss: f.cvss, confidence: f.confidence,
        source: f.source, sources: f.sources || [f.source], category: f.category,
        assurance: f.assurance, evidence: f.evidence, context: f.context, ruleId: f.ruleId,
        cwe: f.cwe, owasp: f.owasp ? OWASP[f.owasp] : undefined,
        tags: ['security', f.cwe, f.owasp && `OWASP-${f.owasp}`].filter(Boolean),
      },
    };
    const { uri, line } = splitLocation(f.location);
    if (uri) {
      r.locations = [{
        physicalLocation: {
          artifactLocation: { uri },
          ...(line ? { region: { startLine: line } } : {}),
        },
      }];
    }
    return r;
  });
  const sarif = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'Vigil',
          informationUri: 'https://github.com/',
          version: toolVersion,
          rules: [...rules.values()],
        },
      },
      results,
    }],
  };
  return JSON.stringify(sarif, null, 2);
}

// Maschinenlesbarer Bericht inkl. Gesamtlage aus dem Befund-Speicher.
function toJson(result, posture) {
  return JSON.stringify({
    generatedAt: new Date().toISOString(),
    posture: posture ? { score: posture.posture, open: posture.open, toxic: posture.toxic, kev: posture.kev, newSinceBaseline: posture.newSinceBaseline } : null,
    summary: result.summary, lifecycle: result.lifecycle || null, meta: { ...(result.meta || {}), sbom: undefined },
    findings: (result.findings || []).map((f) => ({ id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, status: f.status, cvss: f.cvss, epssScore: f.epssScore, inCisaKev: !!f.inCisaKev, contextualRiskScore: f.contextualRiskScore, category: f.category, location: f.location, evidence: f.evidence, sources: f.sources, remediation: f.remediation, steps: f.steps, versionPatch: f.versionPatch, links: f.links, linkedFindingIds: f.linkedFindingIds })),
  }, null, 2);
}

module.exports = { toMarkdown, toHtml, toSarif, toJson, toExecutive, complianceHtml, sevToLevel, SEV_LABEL, SEV_COLOR };
