'use strict';

// Weitere Export-Formate fuer Ergebnisse:
//  - Tabellen: CSV und Excel (.xlsx, minimales Office Open XML ueber adm-zip)
//  - Word (.docx): vollstaendiger Bericht mit Ueberschriften, Tabellen und Absaetzen
//  - VEX: OpenVEX 0.2 und CycloneDX 1.5 (VEX) fuer Befunde mit Status Fehlalarm / Risiko akzeptiert
//  - README-Abzeichen (SVG) samt Markdown-Schnipsel
//  - CI: GitLab SAST (JSON), JUnit XML, Checkstyle XML
//  - CycloneDX-SBOM aus dem Paket-Inventar eines Laufs
// Alle Texte entstehen deutsch; mit { lang: 'en' } werden Beschriftungen ueber report-en uebersetzt
// (die Befundtexte selbst uebersetzt der Aufrufer vorher mit findings-i18n.localizeResult).

const crypto = require('crypto');
const AdmZip = require('adm-zip');
const { stats, fixText, clean, firstSentence, sources, SEV, SEV_LABEL, SEV_HELP, CAT_LABEL, branding } = require('./reportdoc');
const { complianceReport, OWASP } = require('./taxonomy');

const HIDDEN = new Set(['FALSE_POSITIVE', 'ACCEPTED_RISK', 'RESOLVED']);
const isOpen = (f) => !f.suppressed && !HIDDEN.has(f.status);
const STATUS_DE = { OPEN: 'Offen', IN_PROGRESS: 'In Arbeit', ACCEPTED_RISK: 'Risiko akzeptiert', FALSE_POSITIVE: 'Fehlalarm', RESOLVED: 'Behoben' };
// Beschriftung in der gewuenschten Sprache (Woerterbuch der Berichte)
function labeler(lang) {
  if (lang === 'de') return (s) => s;
  const { translateReportText } = require('./report-en');
  return (s) => translateReportText(s);
}
const xml = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c])).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
const uuidFrom = (s) => { const h = crypto.createHash('sha256').update(String(s)).digest('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`; };
const splitLoc = (loc) => { const m = String(loc || '').match(/^(.*?):(\d+)(?::\d+)?$/); return m && !/^[a-z]+:\/\/[^/]*$/i.test(m[1]) ? { file: m[1], line: Number(m[2]) } : { file: String(loc || ''), line: null }; };

// --- Tabellen-Zeilen (gemeinsam fuer CSV und Excel) ------------------------------
function rows(result, opts = {}) {
  const L = labeler(opts.lang);
  const list = (result.findings || []).filter((f) => opts.all || isOpen(f));
  const head = ['Nr.', 'Schwere', 'Befund', 'Bereich', 'Ort', 'Status', 'CWE', 'OWASP', 'CVSS', 'EPSS', 'CISA KEV', 'Regel', 'Erkannt durch', 'Lösung', 'Notiz'].map(L);
  const body = list.map((f, i) => [
    i + 1, L(SEV_LABEL[f.severity] || f.severity), clean(f.title), L(CAT_LABEL[f.category] || f.category || ''), f.location || '',
    L(STATUS_DE[f.status || 'OPEN'] || f.status || ''), f.cwe || '', f.owasp || '', f.cvss != null ? Number(f.cvss) : '', f.epssScore != null ? Number(f.epssScore) : '',
    f.inCisaKev ? L('ja') : '', f.ruleId || '', sources(f).map(L).join(', '), [fixText(f), ...(Array.isArray(f.steps) ? f.steps : [])].filter(Boolean).join(' | '), f.note || '',
  ]);
  return { head, body };
}

function toCsv(result, opts = {}) {
  const { head, body } = rows(result, opts);
  const cell = (v) => { const s = String(v == null ? '' : v); return /[",\n\r;]/.test(s) || /^[=+\-@]/.test(s) ? '"' + (/^[=+\-@]/.test(s) ? "'" : '') + s.replace(/"/g, '""') + '"' : s; };
  // BOM, damit Excel UTF-8 erkennt; fuehrende = + - @ entschaerft (keine Formeln aus Befundtexten)
  return '﻿' + [head, ...body].map((r) => r.map(cell).join(',')).join('\r\n') + '\r\n';
}

// --- Excel (.xlsx) -------------------------------------------------------------------
const colName = (i) => { let s = ''; i++; while (i > 0) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; };
function sheetXml(head, body, widths) {
  const cellXml = (v, r, c, style) => {
    const ref = colName(c) + r;
    if (typeof v === 'number' && Number.isFinite(v)) return `<c r="${ref}"${style ? ` s="${style}"` : ''}><v>${v}</v></c>`;
    const s = String(v == null ? '' : v);
    if (!s) return '';
    return `<c r="${ref}" t="inlineStr"${style ? ` s="${style}"` : ''}><is><t xml:space="preserve">${xml(s.slice(0, 32000))}</t></is></c>`;
  };
  const all = [head, ...body];
  const last = colName(head.length - 1) + all.length;
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
<cols>${head.map((_, i) => `<col min="${i + 1}" max="${i + 1}" width="${widths[i] || 14}" customWidth="1"/>`).join('')}</cols>
<sheetData>${all.map((r, ri) => `<row r="${ri + 1}">${r.map((v, ci) => cellXml(v, ri + 1, ci, ri === 0 ? 1 : 2)).join('')}</row>`).join('')}</sheetData>
<autoFilter ref="A1:${last}"/>
</worksheet>`;
}
function toXlsx(result, opts = {}) {
  const { head, body } = rows(result, opts);
  const L = labeler(opts.lang);
  const zip = new AdmZip();
  const add = (name, s) => zip.addFile(name, Buffer.from(s, 'utf8'));
  const sheets = [{ name: L('Befunde'), xml: sheetXml(head, body, [6, 11, 60, 18, 45, 14, 11, 9, 7, 7, 9, 26, 22, 70, 40]) }];
  // Zweites Blatt: Normen-Einordnung
  const comp = complianceReport((result.findings || []).filter(isOpen), opts.frameworks);
  const cHead = ['Katalog', 'Anforderung', 'Titel', 'Stand', 'Offene Befunde'].map(L);
  const ST = { ok: 'erfüllt (keine offenen Befunde)', warn: 'offene Befunde', fail: 'dringende Befunde' };
  const cBody = comp.flatMap((c) => c.controls.map((k) => [L(c.name), L(k.id), L(k.title), L(ST[k.status]), k.count]));
  sheets.push({ name: L('Normen'), xml: sheetXml(cHead, cBody, [36, 16, 60, 28, 14]) });
  add('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>${sheets.map((_, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`);
  add('_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`);
  add('docProps/core.xml', coreProps(opts.title || L('Sicherheitsbericht')));
  add('xl/workbook.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s, i) => `<sheet name="${xml(s.name.slice(0, 31))}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets>${`<definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'${xml(sheets[0].name.slice(0, 31))}'!$A$1:$${colName(head.length - 1)}$${body.length + 1}</definedName></definedNames>`}</workbook>`);
  add('xl/_rels/workbook.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheets.map((_, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('')}<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`);
  add('xl/styles.xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF0F1B2D"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs></styleSheet>`);
  sheets.forEach((s, i) => add(`xl/worksheets/sheet${i + 1}.xml`, s.xml));
  return zip.toBuffer();
}
function coreProps(title) {
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${xml(title)}</dc:title><dc:creator>Vigil</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${now}</dcterms:created></cp:coreProperties>`;
}

// --- Word (.docx) ---------------------------------------------------------------------
function toDocx(result, opts = {}) {
  const L = labeler(opts.lang);
  const all = result.findings || [];
  const findings = all.filter(isOpen);
  const s = stats(findings);
  const b = branding(opts);
  const accent = b.accent.slice(1).toUpperCase();
  const meta = result.meta || {};
  const date = (() => { try { return new Date(meta.at || Date.now()).toLocaleString(opts.lang === 'de' ? 'de-DE' : 'en-GB', { dateStyle: 'long', timeStyle: 'short' }); } catch { return String(meta.at || ''); } })();
  const targets = (opts.targets || []).map((t) => (typeof t === 'string' ? t : t.value)).filter(Boolean);
  const run = (t, o = {}) => `<w:r>${o.b || o.color || o.mono || o.sz ? `<w:rPr>${o.b ? '<w:b/>' : ''}${o.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>' : ''}${o.color ? `<w:color w:val="${o.color}"/>` : ''}${o.sz ? `<w:sz w:val="${o.sz}"/>` : ''}</w:rPr>` : ''}${String(t).split('\n').map((x, i) => `${i ? '<w:br/>' : ''}<w:t xml:space="preserve">${xml(x)}</w:t>`).join('')}</w:r>`;
  const p = (content, style) => `<w:p>${style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : ''}${Array.isArray(content) ? content.join('') : run(content)}</w:p>`;
  const h = (lvl, t) => p(t, `Heading${lvl}`);
  const cellP = (v, head) => `<w:tc><w:tcPr>${head ? '<w:shd w:val="clear" w:color="auto" w:fill="0F1B2D"/>' : ''}</w:tcPr>${p([run(v, head ? { b: true, color: 'FFFFFF' } : {})])}</w:tc>`;
  const table = (head, body) => `<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/><w:tblBorders>${['top', 'left', 'bottom', 'right', 'insideH', 'insideV'].map((k) => `<w:${k} w:val="single" w:sz="4" w:space="0" w:color="D7DDE5"/>`).join('')}</w:tblBorders></w:tblPr><w:tr><w:trPr><w:tblHeader/></w:trPr>${head.map((x) => cellP(x, true)).join('')}</w:tr>${body.map((r) => `<w:tr><w:trPr><w:cantSplit/></w:trPr>${r.map((x) => cellP(x)).join('')}</w:tr>`).join('')}</w:tbl>${p('')}`;
  const B = [];
  B.push(p(opts.title || L('Sicherheitsbericht'), 'Title'));
  B.push(p([run(`${opts.company ? opts.company + ' · ' : ''}${L('Erstellt am {0}').replace('{0}', date)}`, { color: '64748B' })]));
  if (targets.length) B.push(p([run(L('Ziele: {0}').replace('{0}', targets.join(', ')), { mono: true, sz: 18 })]));
  if (b.coverText) B.push(p(b.coverText));
  B.push(p([run(`${L('Note')} ${s.grade} · ${L('Sicherheitswert')} ${s.posture}/100`, { b: true, sz: 32, color: accent })]));
  B.push(p([run(L(s.verdict) || s.verdict, { b: true })]));
  B.push(table(SEV.map((sv) => L(SEV_LABEL[sv])).concat(L('Angriffswege')), [SEV.map((sv) => String(s.c[sv])).concat(String(s.toxic))]));
  const top = findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 6);
  B.push(h(1, L('Auf einen Blick')));
  B.push(h(2, L('Die wichtigsten Risiken')));
  if (top.length) top.forEach((f, i) => B.push(p([run(`${i + 1}. ${clean(f.title)}`, { b: true }), run(` – ${firstSentence(f.impact || f.description, 200)}`)])));
  else B.push(p(L('Keine kritischen oder hohen Risiken.')));
  if (findings.length) {
    B.push(h(1, L('Alle Befunde')));
    B.push(table(['Nr.', 'Schwere', 'Befund', 'Bereich', 'Ort'].map(L), findings.map((f, i) => [String(i + 1), L(SEV_LABEL[f.severity]), clean(f.title), L(CAT_LABEL[f.category] || f.category || ''), String(f.location || '')])));
    B.push(h(1, L('Befunde im Detail')));
    for (const sv of SEV) {
      const list = findings.filter((f) => f.severity === sv);
      if (!list.length) continue;
      B.push(h(2, `${L(SEV_LABEL[sv])} (${list.length}) – ${L(SEV_HELP[sv])}`));
      for (const f of list) {
        B.push(h(3, `${findings.indexOf(f) + 1}. ${clean(f.title)}`));
        B.push(p([run([L(CAT_LABEL[f.category] || f.category || ''), f.cwe, f.owasp && `OWASP ${f.owasp}`, f.cvss != null && `CVSS ${Number(f.cvss).toFixed(1)}`, f.inCisaKev && L('aktiv ausgenutzt')].filter(Boolean).join(' · '), { color: '64748B' })]));
        if (f.location) B.push(p([run(f.location, { mono: true, sz: 18 })]));
        if (f.description) B.push(p([run(L('Was ist los?') + ' ', { b: true }), run(f.description)]));
        if (f.impact) B.push(p([run(L('Was kann passieren?') + ' ', { b: true }), run(f.impact)]));
        if (fixText(f)) B.push(p([run(L('Lösung') + ': ', { b: true }), run(fixText(f))]));
        (Array.isArray(f.steps) ? f.steps : []).forEach((st, j) => B.push(p(`${j + 1}. ${st}`)));
        const snip = f.versionPatch ? [f.versionPatch.command, f.versionPatch.manifest].filter(Boolean).join('\n\n') : Object.values(f.snippets || {})[0] || f.patch;
        if (snip) B.push(p([run(String(snip).slice(0, 3000), { mono: true, sz: 17 })], 'Code'));
        if (f.note) B.push(p([run(L('Notiz') + ': ', { b: true, color: '92400E' }), run(f.note)]));
        if (f.evidence) B.push(p([run(L('Fundstelle:') + ' ', { b: true }), run(f.evidence, { mono: true, sz: 18 })]));
      }
    }
  } else B.push(p(L('Bei dieser Prüfung wurden keine offenen Befunde gefunden.')));
  B.push(h(1, L('Nachweise für Normen')));
  B.push(p([run(L('Technische Einordnung der offenen Befunde in gängige Kataloge – ein prüfbarer Baustein für Audits, ersetzt aber keine Zertifizierung oder Rechtsberatung.'), { color: '64748B' })]));
  const ST = { ok: 'erfüllt (keine offenen Befunde)', warn: 'offene Befunde', fail: 'dringende Befunde' };
  for (const c of complianceReport(findings, opts.frameworks)) {
    B.push(h(2, L(c.name)));
    B.push(table(['Anforderung', 'Stand', 'Offene Befunde'].map(L), c.controls.map((k) => [`${L(k.id)} ${L(k.title)}`, L(ST[k.status]), k.count ? `${k.count}: ${k.findings.slice(0, 2).map(clean).join('; ')}` : '–'])));
  }
  B.push(h(1, L('Anhang')));
  B.push(h(2, L('Was die Stufen bedeuten')));
  SEV.forEach((sv) => B.push(p([run(L(SEV_LABEL[sv]) + ': ', { b: true }), run(L(SEV_HELP[sv]))])));
  if (result.errors && result.errors.length) { B.push(h(2, L('Hinweise zum Lauf'))); result.errors.slice(0, 30).forEach((e) => B.push(p('• ' + e))); }
  B.push(p([run(L('Erstellt mit Vigil – zerstörungsfreie Prüfung eigener bzw. freigegebener Systeme.') + (b.footerText ? '\n' + b.footerText : ''), { color: '64748B', sz: 18 })]));

  const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
  const footer = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr ${W}><w:p><w:pPr><w:jc w:val="center"/></w:pPr>${run(`Vigil · ${L('Sicherheitsbericht')}${b.footerText ? ' · ' + b.footerText : ''} · `, { color: '94A3B8', sz: 16 })}<w:r><w:rPr><w:color w:val="94A3B8"/><w:sz w:val="16"/></w:rPr><w:fldSimple w:instr="PAGE"><w:r><w:t>1</w:t></w:r></w:fldSimple></w:r></w:p></w:ftr>`;
  const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document ${W}><w:body>${B.join('')}<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1077" w:bottom="1134" w:left="1077" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  const style = (id, name, o) => `<w:style w:type="paragraph" w:styleId="${id}"><w:name w:val="${name}"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="${o.before}" w:after="${o.after}"/>${o.outline != null ? `<w:outlineLvl w:val="${o.outline}"/>` : ''}</w:pPr><w:rPr><w:b/><w:color w:val="${o.color}"/><w:sz w:val="${o.sz}"/></w:rPr></w:style>`;
  const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles ${W}><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Segoe UI" w:hAnsi="Segoe UI" w:cs="Segoe UI"/><w:sz w:val="20"/><w:lang w:val="${opts.lang === 'de' ? 'de-DE' : 'en-GB'}"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="80"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
${style('Title', 'Title', { before: 0, after: 120, color: '0F172A', sz: 44 })}${style('Heading1', 'heading 1', { before: 360, after: 120, color: '0F172A', sz: 32, outline: 0 })}${style('Heading2', 'heading 2', { before: 240, after: 80, color: accent, sz: 26, outline: 1 })}${style('Heading3', 'heading 3', { before: 200, after: 60, color: '1E293B', sz: 22, outline: 2 })}
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F1F5F9"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="17"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>`;
  const zip = new AdmZip();
  const add = (name, str) => zip.addFile(name, Buffer.from(str, 'utf8'));
  add('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`);
  add('_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`);
  add('docProps/core.xml', coreProps(opts.title || L('Sicherheitsbericht')));
  add('word/_rels/document.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`);
  add('word/document.xml', doc);
  add('word/styles.xml', styles);
  add('word/footer1.xml', footer);
  return zip.toBuffer();
}

// --- VEX ---------------------------------------------------------------------------------
const PURL_TYPE = { npm: 'npm', pypi: 'pypi', maven: 'maven', go: 'golang', 'crates.io': 'cargo', cargo: 'cargo', nuget: 'nuget', rubygems: 'gem', packagist: 'composer', pub: 'pub' };
function purlOf(pkg) {
  if (!pkg || !pkg.name) return null;
  const type = PURL_TYPE[String(pkg.ecosystem || 'npm').toLowerCase()] || String(pkg.ecosystem || 'generic').toLowerCase();
  let name = String(pkg.name);
  if (type === 'maven' && name.includes(':')) name = name.replace(':', '/');
  const enc = name.split('/').map((x) => encodeURIComponent(x).replace(/%40/g, '%40')).join('/');
  return `pkg:${type}/${enc}${pkg.version ? '@' + encodeURIComponent(pkg.version) : ''}`;
}
// Paket eines Befunds (Abhaengigkeits-Funde tragen package/version bzw. stehen im Titel)
function packageOf(f) {
  if (f.package) return typeof f.package === 'object' ? f.package : { name: f.package, version: f.version || f.installedVersion, ecosystem: f.ecosystem };
  const m = /^([@\w./-]+)@([\w.+-]+)/.exec(String(f.title || ''));
  return m && f.category === 'Dependencies' ? { name: m[1], version: m[2], ecosystem: f.ecosystem || 'npm' } : null;
}
const vexCandidates = (result) => (result.findings || []).filter((f) => f.status === 'FALSE_POSITIVE' || f.status === 'ACCEPTED_RISK');
const vulnId = (f) => (/^(CVE|GHSA|PYSEC|GO|RUSTSEC|OSV)-/i.test(f.ruleId || '') ? f.ruleId : `VIGIL-${String(f.ruleId || f.category || 'finding').replace(/[^\w.-]+/g, '-')}`);
// Begruendung aus der Status-Notiz ableiten (Fehlalarm)
function justification(note) {
  const n = String(note || '').toLowerCase();
  if (/nicht erreichbar|unreachable|not reachable|ungenutzt|unused|nie aufgerufen|never called|execute path/.test(n)) return { openvex: 'vulnerable_code_not_in_execute_path', cdx: 'code_not_reachable' };
  if (/abgesichert|mitigat|schutz|protected|waf|filter|escap|sanitiz|validier/.test(n)) return { openvex: 'inline_mitigations_already_exist', cdx: 'protected_by_mitigating_control' };
  if (/test|beispiel|example|fixture|dummy|attrappe/.test(n)) return { openvex: 'vulnerable_code_not_present', cdx: 'code_not_present' };
  return { openvex: 'vulnerable_code_not_present', cdx: 'code_not_present' };
}
function productOf(f, opts) {
  const pkg = packageOf(f);
  const purl = purlOf(pkg);
  if (purl) return { id: purl, name: pkg.name, version: pkg.version, purl, type: 'library' };
  const target = (opts.targets || []).map((t) => (typeof t === 'string' ? t : t.value)).filter(Boolean)[0] || 'project';
  const loc = splitLoc(f.location).file || target;
  return { id: `urn:vigil:${encodeURIComponent(loc)}`, name: loc, type: 'application' };
}
function toOpenVex(result, opts = {}) {
  const now = new Date().toISOString();
  const doc = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://openvex.dev/docs/vigil/${uuidFrom(now + JSON.stringify(vexCandidates(result).map((f) => f.id)))}`,
    author: opts.company || 'Vigil',
    role: 'Document Creator',
    timestamp: now,
    version: 1,
    tooling: 'Vigil',
    statements: vexCandidates(result).map((f) => {
      const p = productOf(f, opts);
      const note = String(f.statusNote || f.note || '').trim();
      const st = { vulnerability: { name: vulnId(f), description: clean(f.title) }, products: [{ '@id': p.id, ...(p.purl ? { identifiers: { purl: p.purl } } : {}) }], timestamp: f.statusChangedAt || now };
      if (f.status === 'FALSE_POSITIVE') return { ...st, status: 'not_affected', justification: justification(note).openvex, impact_statement: note || 'Marked as false positive in Vigil.' };
      return { ...st, status: 'affected', action_statement: note ? `Risk accepted: ${note}` : 'Risk accepted in Vigil – no fix planned.' };
    }),
  };
  return JSON.stringify(doc, null, 2);
}
function toCycloneDxVex(result, opts = {}) {
  const comps = new Map();
  const vulns = vexCandidates(result).map((f) => {
    const p = productOf(f, opts);
    if (!comps.has(p.id)) comps.set(p.id, { 'bom-ref': p.id, type: p.type, name: p.name, ...(p.version ? { version: String(p.version) } : {}), ...(p.purl ? { purl: p.purl } : {}) });
    const note = String(f.statusNote || f.note || '').trim();
    const analysis = f.status === 'FALSE_POSITIVE'
      ? { state: 'false_positive', justification: justification(note).cdx, detail: note || 'Marked as false positive in Vigil.' }
      : { state: 'exploitable', response: ['will_not_fix'], detail: note ? `Risk accepted: ${note}` : 'Risk accepted in Vigil.' };
    return {
      'bom-ref': `vuln-${String(f.id || uuidFrom(f.title + f.location)).slice(0, 24)}`, id: vulnId(f), source: { name: /^(CVE|GHSA)/i.test(f.ruleId || '') ? (/^CVE/i.test(f.ruleId) ? 'NVD' : 'GitHub') : 'Vigil' },
      ...(f.cwe ? { cwes: [Number(String(f.cwe).replace(/\D/g, ''))].filter(Boolean) } : {}), description: clean(f.title),
      ratings: [{ severity: f.severity === 'info' ? 'info' : f.severity, ...(f.cvss != null ? { score: Number(f.cvss), method: 'CVSSv31' } : {}) }],
      analysis, affects: [{ ref: p.id }],
    };
  });
  return JSON.stringify({
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${uuidFrom(Date.now() + ':' + vulns.length)}`, version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'Vigil', author: 'Vigil' }] }, ...(opts.company ? { supplier: { name: opts.company } } : {}) },
    components: [...comps.values()], vulnerabilities: vulns,
  }, null, 2);
}

// CycloneDX-SBOM aus dem Paket-Inventar eines Laufs (meta.sbom)
function toCycloneDxSbom(packages) {
  const seen = new Set();
  const components = (packages || []).filter((p) => p && p.name).map((p) => ({ type: 'library', name: String(p.name), ...(p.version ? { version: String(p.version) } : {}), purl: purlOf(p) || undefined, 'bom-ref': purlOf(p) || `${p.name}@${p.version || ''}` }))
    .filter((c) => (seen.has(c['bom-ref']) ? false : seen.add(c['bom-ref'])));
  return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1, metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'Vigil' }] } }, components }, null, 2);
}

// --- README-Abzeichen ------------------------------------------------------------------
const GRADE_COLOR = { A: '#2f855a', B: '#4c9a2a', C: '#b7791f', D: '#d9480f', E: '#c0123c', F: '#9f1239' };
function badgeSvg({ grade = 'A', date = new Date().toISOString().slice(0, 10), label = 'Vigil security' } = {}) {
  const right = `${grade} · ${date}`;
  // Breite grob ueber die Zeichenzahl (Verdana 11px ~ 6.5px je Zeichen)
  const wl = Math.round(label.length * 6.4 + 14), wr = Math.round(right.length * 6.6 + 14), w = wl + wr;
  const color = GRADE_COLOR[grade] || '#64748b';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${xml(label)}: ${xml(right)}"><title>${xml(label)}: ${xml(right)}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="${wl}" height="20" fill="#0f1b2d"/><rect x="${wl}" width="${wr}" height="20" fill="${color}"/><rect width="${w}" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="${wl / 2}" y="14">${xml(label)}</text><text x="${wl + wr / 2}" y="14" font-weight="bold">${xml(right)}</text></g></svg>`;
}
function badgeMarkdown(fileName, { grade, date, label = 'Vigil security' } = {}) {
  return `![${label}: ${grade} (${date})](${String(fileName || 'vigil-badge.svg').replace(/[()\s]/g, (c) => encodeURIComponent(c))})`;
}

// --- CI-Formate ----------------------------------------------------------------------------
const GL_SEV = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
function toGitlabSast(result, version = '0.2.0') {
  const now = new Date().toISOString().replace(/\.\d+Z$/, '');
  const vulns = (result.findings || []).filter(isOpen).map((f) => {
    const { file, line } = splitLoc(f.location);
    const ids = [{ type: 'vigil_rule', name: `Vigil ${f.ruleId || f.category || 'finding'}`, value: String(f.ruleId || f.category || 'finding') }];
    if (f.cwe) ids.push({ type: 'cwe', name: f.cwe, value: String(f.cwe).replace(/\D/g, ''), url: `https://cwe.mitre.org/data/definitions/${String(f.cwe).replace(/\D/g, '')}.html` });
    if (/^CVE-/i.test(f.ruleId || '')) ids.push({ type: 'cve', name: f.ruleId, value: f.ruleId, url: `https://nvd.nist.gov/vuln/detail/${f.ruleId}` });
    if (f.owasp) ids.push({ type: 'owasp', name: OWASP[f.owasp] || f.owasp, value: f.owasp });
    return {
      id: uuidFrom(f.id || `${f.ruleId}|${f.location}|${f.title}`), category: 'sast', name: clean(f.title).slice(0, 255),
      description: [f.description, f.impact].filter(Boolean).join('\n\n') || clean(f.title), severity: GL_SEV[f.severity] || 'Unknown',
      solution: [fixText(f), ...(Array.isArray(f.steps) ? f.steps : [])].filter(Boolean).join('\n') || undefined,
      scanner: { id: 'vigil', name: 'Vigil' }, identifiers: ids,
      location: { file: file || 'unknown', ...(line ? { start_line: line, end_line: line } : {}) },
    };
  });
  const tool = { id: 'vigil', name: 'Vigil', version, vendor: { name: 'Vigil' } };
  return JSON.stringify({ version: '15.0.7', scan: { analyzer: tool, scanner: tool, type: 'sast', start_time: now, end_time: now, status: 'success' }, vulnerabilities: vulns }, null, 2);
}
function toJunit(result) {
  const open = (result.findings || []).filter(isOpen);
  const cases = open.map((f) => {
    const { file, line } = splitLoc(f.location);
    const type = f.severity === 'critical' || f.severity === 'high' ? 'error' : 'failure';
    return `    <testcase classname="vigil.${xml(f.category || 'Other')}" name="${xml(clean(f.title))}" file="${xml(file)}"${line ? ` line="${line}"` : ''}>
      <${type} type="${xml(f.severity)}" message="${xml(`[${f.severity}] ${clean(f.title)}`)}">${xml([f.location, f.description, fixText(f) && 'Fix: ' + fixText(f)].filter(Boolean).join('\n'))}</${type}>
    </testcase>`;
  });
  const errors = open.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  if (!cases.length) cases.push('    <testcase classname="vigil" name="Keine offenen Befunde / no open findings"/>');
  return `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="Vigil" tests="${Math.max(1, open.length)}" failures="${open.length - errors}" errors="${errors}">
  <testsuite name="Vigil security audit" tests="${Math.max(1, open.length)}" failures="${open.length - errors}" errors="${errors}" timestamp="${new Date().toISOString().replace(/\.\d+Z$/, '')}">
${cases.join('\n')}
  </testsuite>
</testsuites>
`;
}
const CS_SEV = { critical: 'error', high: 'error', medium: 'warning', low: 'info', info: 'info' };
function toCheckstyle(result) {
  const byFile = new Map();
  for (const f of (result.findings || []).filter(isOpen)) {
    const { file, line } = splitLoc(f.location);
    const k = file || 'unknown';
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k).push({ f, line });
  }
  return `<?xml version="1.0" encoding="UTF-8"?>
<checkstyle version="4.3">
${[...byFile].map(([file, list]) => `  <file name="${xml(file)}">
${list.map(({ f, line }) => `    <error line="${line || 1}" severity="${CS_SEV[f.severity] || 'info'}" message="${xml(clean(f.title) + (fixText(f) ? ' – ' + fixText(f) : ''))}" source="vigil.${xml(f.ruleId || f.category || 'finding')}"/>`).join('\n')}
  </file>`).join('\n')}
</checkstyle>
`;
}

module.exports = { toCsv, toXlsx, toDocx, toOpenVex, toCycloneDxVex, toCycloneDxSbom, badgeSvg, badgeMarkdown, toGitlabSast, toJunit, toCheckstyle, purlOf, justification, rows };
