'use strict';

// Vergleich zweier Laeufe aus dem Verlauf: neu / behoben / unveraendert.
// Schluessel ist der Fingerabdruck aus dem Befund-Speicher (id), sonst Regel + Ort + Titel.
// Ausgabe als HTML (auch Grundlage fuer das PDF) und Markdown – deutsch, englisch ueber report-en.

const { SEV, SEV_LABEL, SEV_COLOR, clean } = require('./reportdoc');

const SEV_RANK = Object.fromEntries(SEV.map((s, i) => [s, i]));
const keyOf = (f) => f.id || `${f.ruleId || ''}|${String(f.location || '').toLowerCase()}|${String(f.title || '').toLowerCase()}`;
const counted = (f) => !f.suppressed && !['FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED'].includes(f.status);
const bySev = (a, b) => (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || String(a.title).localeCompare(String(b.title));

// a = aelterer Lauf, b = neuerer Lauf (Ergebnisse wie im Verlauf gespeichert)
function diffResults(a, b) {
  const A = new Map(((a && a.findings) || []).filter(counted).map((f) => [keyOf(f), f]));
  const B = new Map(((b && b.findings) || []).filter(counted).map((f) => [keyOf(f), f]));
  const added = [], fixed = [], unchanged = [];
  for (const [k, f] of B) {
    if (!A.has(k)) added.push(f);
    else { const old = A.get(k); unchanged.push({ ...f, previousSeverity: old.severity !== f.severity ? old.severity : undefined }); }
  }
  for (const [k, f] of A) if (!B.has(k)) fixed.push(f);
  added.sort(bySev); fixed.sort(bySev); unchanged.sort(bySev);
  const count = (list) => Object.fromEntries(SEV.map((s) => [s, list.filter((f) => f.severity === s).length]));
  return { added, fixed, unchanged, counts: { added: count(added), fixed: count(fixed), unchanged: count(unchanged) }, totals: { before: A.size, after: B.size } };
}

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = (iso) => { try { return new Date(iso).toLocaleString('de-DE', { dateStyle: 'long', timeStyle: 'short' }); } catch { return String(iso || ''); } };

// meta: { a: { at, targets }, b: { at, targets }, accent }
function toCompareHtml(diff, meta = {}) {
  const accent = /^#[0-9a-f]{6}$/i.test(String(meta.accent || '')) ? meta.accent : '#b7791f';
  const col = (title, list, cls) => `<section class="col ${cls}"><h2>${title} <span class="n">${list.length}</span></h2>${list.length ? `<ul>${list.map((f) => `<li><span class="tag" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span><div><b>${esc(clean(f.title))}</b>${f.previousSeverity ? `<small class="chg">${SEV_LABEL[f.previousSeverity]} → ${SEV_LABEL[f.severity]}</small>` : ''}<div class="loc">${esc(f.location || '')}</div></div></li>`).join('')}</ul>` : '<p class="muted">Keine.</p>'}</section>`;
  const who = (m) => `${esc(fmt(m && m.at))}${m && m.targets && m.targets.length ? ` · ${esc(m.targets.join(', '))}` : ''}`;
  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vergleich zweier Prüfungen</title>
<style>
  @page { size: A4 landscape; margin: 12mm; }
  * { box-sizing: border-box; } html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0; padding: 28px 34px; font: 13px/1.5 "Segoe UI", system-ui, sans-serif; color: #1e293b; background: #fff; }
  header { border-bottom: 3px solid ${accent}; padding-bottom: 10px; margin-bottom: 16px; }
  h1 { margin: 0 0 4px; font-size: 22px; color: #0f172a; } .muted { color: #64748b; }
  .runs { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 12.5px; margin-top: 6px; }
  .runs div { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 6px 10px; }
  .sum { display: flex; gap: 18px; margin: 12px 0 18px; font-size: 14px; } .sum b { font-size: 20px; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; align-items: start; }
  .col { border: 1px solid #e2e8f0; border-radius: 12px; padding: 10px 12px; break-inside: avoid-page; }
  .col h2 { font-size: 14px; margin: 0 0 8px; display: flex; justify-content: space-between; } .col h2 .n { color: #64748b; }
  .added { border-top: 4px solid #c0123c; } .fixed { border-top: 4px solid #2f855a; } .unchanged { border-top: 4px solid #94a3b8; }
  ul { list-style: none; margin: 0; padding: 0; } li { display: grid; grid-template-columns: auto 1fr; gap: 8px; padding: 6px 0; border-bottom: 1px solid #f1f5f9; break-inside: avoid; }
  .tag { color: #fff; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; height: fit-content; white-space: nowrap; }
  .loc { font-family: Consolas, monospace; font-size: 11px; color: #64748b; word-break: break-all; } .chg { display: block; color: #b45309; font-size: 11px; }
  footer { margin-top: 18px; font-size: 11px; color: #94a3b8; }
  @media (max-width: 800px) { .grid, .runs { grid-template-columns: 1fr; } }
</style></head><body>
<header><h1>Vergleich zweier Prüfungen</h1>
<div class="runs"><div><b>Vorher:</b> ${who(meta.a)}</div><div><b>Nachher:</b> ${who(meta.b)}</div></div></header>
<div class="sum"><span><b>${diff.added.length}</b> neu</span><span><b>${diff.fixed.length}</b> behoben</span><span><b>${diff.unchanged.length}</b> unverändert</span><span class="muted">offen vorher ${diff.totals.before} · nachher ${diff.totals.after}</span></div>
<div class="grid">${col('Neu', diff.added, 'added')}${col('Behoben', diff.fixed, 'fixed')}${col('Unverändert', diff.unchanged, 'unchanged')}</div>
<footer>Erstellt mit Vigil · ${esc(fmt(new Date().toISOString()))}</footer>
</body></html>`;
}

function toCompareMarkdown(diff, meta = {}) {
  const L = [];
  const who = (m) => `${fmt(m && m.at)}${m && m.targets && m.targets.length ? ` · ${m.targets.map((t) => '`' + t + '`').join(', ')}` : ''}`;
  L.push('# Vergleich zweier Prüfungen', '');
  L.push(`- **Vorher:** ${who(meta.a)}`, `- **Nachher:** ${who(meta.b)}`, '');
  L.push('| Neu | Behoben | Unverändert |', '|:-:|:-:|:-:|', `| ${diff.added.length} | ${diff.fixed.length} | ${diff.unchanged.length} |`, '');
  const cell = (x) => String(x || '').split('|').join('\\|');
  for (const [title, list] of [['Neu', diff.added], ['Behoben', diff.fixed], ['Unverändert', diff.unchanged]]) {
    L.push(`## ${title}`, '');
    if (!list.length) { L.push('Keine.', ''); continue; }
    L.push('| Schwere | Befund | Ort |', '|:--|:--|:--|');
    list.forEach((f) => L.push(`| ${SEV_LABEL[f.severity]} | ${cell(clean(f.title))} | \`${cell(f.location)}\` |`));
    L.push('');
  }
  L.push('---', '_Erstellt mit Vigil – zerstörungsfreie Prüfung eigener bzw. freigegebener Systeme._');
  return L.join('\n');
}

module.exports = { diffResults, toCompareHtml, toCompareMarkdown, keyOf };
