'use strict';

// Rendert Analyse-Ergebnisse als Markdown oder eigenstaendiges HTML.

const SEV_LABEL = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Info' };
const SEV_COLOR = { critical: '#b3123c', high: '#d9480f', medium: '#c48a00', low: '#2b7a3b', info: '#555' };

function esc(s) {
  return String(s || '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function toMarkdown(result, title = 'Vigil Sicherheits-Audit') {
  const { findings, summary, meta, errors } = result;
  const L = [];
  L.push(`# ${title}`, '');
  L.push(`_Erstellt: ${meta?.at || new Date().toISOString()} · Anbieter: ${meta?.provider || '-'} / ${meta?.model || '-'}_`, '');
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
    L.push(`- **CVSS:** ${f.cvss ?? '—'} · **Kategorie:** ${f.category} · **Confidence:** ${f.confidence} · **Quelle:** ${f.source}`);
    if (f.location) L.push(`- **Ort:** \`${f.location}\``);
    L.push('');
    if (f.description) L.push(`**Beschreibung:** ${f.description}`, '');
    if (f.reachability) L.push(`**Erreichbarkeit/Risiko:** ${f.reachability}`, '');
    if (f.impact) L.push(`**Auswirkung:** ${f.impact}`, '');
    if (f.remediation) L.push(`**Behebung:** ${f.remediation}`, '');
    if (f.patch) L.push('**Patch:**', '```', f.patch, '```', '');
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
      <div class="meta">CVSS ${f.cvss ?? '—'} · ${esc(f.category)} · Confidence: ${esc(f.confidence)} · Quelle: ${esc(f.source)}${f.location ? ` · <code>${esc(f.location)}</code>` : ''}</div>
      ${f.description ? `<p><b>Beschreibung:</b> ${esc(f.description)}</p>` : ''}
      ${f.reachability ? `<p><b>Erreichbarkeit/Risiko:</b> ${esc(f.reachability)}</p>` : ''}
      ${f.impact ? `<p><b>Auswirkung:</b> ${esc(f.impact)}</p>` : ''}
      ${f.remediation ? `<p class="fix"><b>Behebung:</b> ${esc(f.remediation)}</p>` : ''}
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
        source: f.source, category: f.category,
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

module.exports = { toMarkdown, toHtml, toSarif, sevToLevel, SEV_LABEL, SEV_COLOR };
