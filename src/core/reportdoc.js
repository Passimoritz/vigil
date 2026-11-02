'use strict';

// Vollstaendiger Bericht als HTML (auch Grundlage fuer das PDF) und als Markdown.
//
// Aufbau:  1 Deckblatt (Note, Lage, Verteilung)   2 Auf einen Blick (Top-Risiken, naechste Schritte)
//          3 Alle Befunde als Tabelle              4 Befunde im Detail, nach Schwere gruppiert
//          5 Normen (ISO 27001, BSI, NIS2, DSGVO)   6 Anhang: Methodik, Hinweise, Erklaerung der Stufen
// Druck: helles Layout, A4, keine Karte wird ueber einen Seitenumbruch zerrissen. Im Browser
// (HTML-Export) zusaetzlich Filter nach Schwere und Suche – ohne externe Dateien.

const { OWASP, complianceReport } = require('./taxonomy');

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Hinweis' };
const SEV_COLOR = { critical: '#c0123c', high: '#d9480f', medium: '#b7791f', low: '#2f855a', info: '#64748b' };
const SEV_HELP = {
  critical: 'Sofort handeln – direkt ausnutzbar, große Wirkung.',
  high: 'Zeitnah beheben (Tage) – ernsthaftes Risiko.',
  medium: 'Im normalen Ablauf beheben (Wochen).',
  low: 'Bei Gelegenheit beheben.',
  info: 'Zur Kenntnis, kein direktes Risiko.',
};
const CAT_LABEL = { Injection: 'Eingabe-Lücke', XSS: 'Skript-Einschleusung', Deserialization: 'Unsicheres Einlesen', Secrets: 'Zugangsdaten', Crypto: 'Verschlüsselung', Auth: 'Anmeldung', AccessControl: 'Zugriffsrechte', SSRF: 'Server-Anfragen', PathTraversal: 'Dateipfade', Config: 'Konfiguration', Dependencies: 'Pakete', DoS: 'Verfügbarkeit', Logging: 'Protokollierung', Transport: 'Transport', License: 'Lizenz', AttackPath: 'Angriffsweg', Other: 'Sonstiges' };
const SOURCE_LABEL = { ai: 'KI-Analyse', prescan: 'Regeln', osv: 'OSV.dev', webscan: 'Server-Check', correlator: 'Angriffsweg-Analyse' };
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const clean = (t) => String(t || '').replace(/^(Möglicher )?Angriffsweg:\s*/, '').replace(/^(gitleaks|trufflehog|trivy|grype|semgrep|bandit|checkov|retire\.js|hadolint|osv-scanner|nuclei)\s*:\s*/i, '');
const fmtDate = (iso) => { try { return new Date(iso || Date.now()).toLocaleString('de-DE', { dateStyle: 'long', timeStyle: 'short' }); } catch { return String(iso || ''); } };

function stats(findings) {
  const c = Object.fromEntries(SEV.map((s) => [s, 0]));
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  const toxic = findings.filter((f) => f.category === 'AttackPath' || /^toxic-/.test(f.ruleId || '')).length;
  const kev = findings.filter((f) => f.inCisaKev).length;
  const posture = Math.max(0, Math.round(100 - (c.critical * 12 + c.high * 6 + c.medium * 2 + c.low * 0.5 + toxic * 15 + kev * 8)));
  const grade = posture >= 92 ? 'A' : posture >= 78 ? 'B' : posture >= 60 ? 'C' : posture >= 40 ? 'D' : posture >= 20 ? 'E' : 'F';
  const tone = posture >= 78 ? SEV_COLOR.low : posture >= 50 ? SEV_COLOR.medium : SEV_COLOR.critical;
  const verdict = !findings.length ? 'Keine Befunde – sehr gut aufgestellt.'
    : c.critical ? `${c.critical} kritische ${c.critical === 1 ? 'Schwachstelle muss' : 'Schwachstellen müssen'} sofort behoben werden.`
      : c.high ? `Keine kritischen Befunde, aber ${c.high} mit hohem Risiko – zeitnah beheben.`
        : 'Keine kritischen oder hohen Risiken – die übrigen Punkte im normalen Ablauf abarbeiten.';
  return { c, toxic, kev, posture, grade, tone, verdict, total: findings.length };
}

// Platzhalter wie "Siehe Lösungsschritte." sind im Bericht wertlos – dann zählen nur die Schritte
const fixText = (f) => (/^siehe (lösung|loesung|sshd|schnipsel)/i.test(String(f.remediation || '').trim()) ? '' : String(f.remediation || ''));
const firstSentence = (s, max = 220) => { const t = String(s || '').split(/(?<=[.!?])\s/)[0]; return t.length > max ? t.slice(0, max - 1) + '…' : t; };
const sources = (f) => [...new Set((f.sources && f.sources.length ? f.sources : [f.source]).filter(Boolean))].map((s) => SOURCE_LABEL[s] || s);

function sevBar(c, total) {
  if (!total) return '<div class="bar"><span style="flex:1;background:#d7dde5"></span></div>';
  return `<div class="bar">${SEV.filter((s) => c[s]).map((s) => `<span style="flex:${c[s]};background:${SEV_COLOR[s]}" title="${SEV_LABEL[s]}: ${c[s]}"></span>`).join('')}</div>`;
}

function findingCard(f, n) {
  const chips = [
    `<span class="chip">${esc(CAT_LABEL[f.category] || f.category)}</span>`,
    f.cwe ? `<span class="chip">${esc(f.cwe)}</span>` : '',
    f.owasp ? `<span class="chip" title="${esc(OWASP[f.owasp] || '')}">OWASP ${esc(f.owasp)}</span>` : '',
    f.cvss != null ? `<span class="chip">CVSS ${esc(Number(f.cvss).toFixed(1))}</span>` : '',
    f.contextualRiskScore != null ? `<span class="chip">Risiko ${Math.round(f.contextualRiskScore)}</span>` : '',
    f.inCisaKev ? '<span class="chip warn">aktiv ausgenutzt</span>' : '',
    f.reach === 'unused' || f.reach === 'function-unused' ? '<span class="chip ok">betroffene Stelle ungenutzt</span>' : '',
  ].filter(Boolean).join('');
  const steps = Array.isArray(f.steps) && f.steps.length ? `<ol class="steps">${f.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>` : '';
  const snippets = Object.entries(f.snippets || {}).slice(0, 2).map(([k, v]) => `<div class="code"><div class="code-h">${esc(k)}</div><pre>${esc(v)}</pre></div>`).join('');
  const patch = f.versionPatch ? `<div class="code"><div class="code-h">${esc(f.versionPatch.title || 'Aktualisieren')}</div><pre>${esc([f.versionPatch.command, f.versionPatch.manifest].filter(Boolean).join('\n\n'))}</pre></div>` : f.patch ? `<div class="code"><div class="code-h">Änderung</div><pre>${esc(f.patch)}</pre></div>` : '';
  const links = Array.isArray(f.links) && f.links.length ? `<p class="links">Mehr dazu: ${f.links.slice(0, 5).map((l) => `<a href="${esc(l.url)}">${esc(l.label)}</a>`).join(' · ')}</p>` : '';
  return `<article class="finding sev-${f.severity}" id="f${n}" data-sev="${f.severity}" data-text="${esc(`${f.title} ${f.location} ${f.category}`.toLowerCase())}">
  <header>
    <span class="num">${n}</span>
    <div class="fh">
      <div class="fh-top"><span class="sev" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span>${chips}</div>
      <h3>${esc(clean(f.title))}</h3>
      ${f.location ? `<div class="loc">${esc(f.location)}</div>` : ''}
    </div>
  </header>
  <div class="cols">
    ${f.description ? `<section><h4>Was ist los?</h4><p>${esc(f.description)}</p></section>` : ''}
    ${f.impact || f.reachability ? `<section><h4>Was kann passieren?</h4>${f.impact ? `<p>${esc(f.impact)}</p>` : ''}${f.reachability ? `<p class="muted">${esc(f.reachability)}</p>` : ''}</section>` : ''}
  </div>
  ${f.explanation ? `<p class="why">${esc(f.explanation)}</p>` : ''}
  <section class="fix"><h4>Lösung</h4>${fixText(f) ? `<p>${esc(fixText(f))}</p>` : ''}${steps}${patch}${snippets}</section>
  ${f.evidence ? `<p class="evidence"><b>Fundstelle:</b> <code>${esc(f.evidence)}</code></p>` : ''}
  <footer>Erkannt durch ${esc(sources(f).join(', ') || '–')}${f.confidence ? ` · Verlässlichkeit ${esc({ high: 'hoch', medium: 'mittel', low: 'niedrig' }[f.confidence] || f.confidence)}` : ''}${f.ruleId ? ` · Regel ${esc(f.ruleId)}` : ''}</footer>
  ${links}
</article>`;
}

const SHIELD = '<svg viewBox="0 0 1024 1024" width="34" height="34" aria-hidden="true"><rect width="1024" height="1024" rx="224" fill="#0f1b2d" stroke="rgba(255,255,255,.18)" stroke-width="16"/><path fill="#f2b23a" d="M272 252 L392 252 L512 560 L632 252 L752 252 L752 500 C752 660 652 776 512 852 C372 776 272 660 272 500 Z"/></svg>';

// opts: { title, targets: [{type,value}], company, logoDataUrl }
function toHtml(result, opts = {}) {
  if (typeof opts === 'string') opts = { title: opts };
  const all = result.findings || [];
  const hidden = all.filter((f) => f.suppressed || f.status === 'FALSE_POSITIVE' || f.status === 'ACCEPTED_RISK');
  const findings = all.filter((f) => !hidden.includes(f));
  const meta = result.meta || {};
  const s = stats(findings);
  const title = opts.title || 'Sicherheitsbericht';
  const targets = (opts.targets || []).map((t) => (typeof t === 'string' ? t : t.value)).filter(Boolean);
  const top = findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 6);
  const nextSteps = [...new Set((top.length ? top : findings.slice(0, 3)).slice(0, 4).map((f) => (Array.isArray(f.steps) && f.steps[0]) || fixText(f)).filter(Boolean))];
  const idx = new Map(findings.map((f, i) => [f, i + 1]));
  const groups = SEV.map((sv) => ({ sv, list: findings.filter((f) => f.severity === sv) })).filter((g) => g.list.length);
  const comp = complianceReport(findings);
  const ST = { ok: ['erfüllt (keine offenen Befunde)', SEV_COLOR.low], warn: ['offene Befunde', SEV_COLOR.medium], fail: ['dringende Befunde', SEV_COLOR.critical] };
  const logo = opts.logoDataUrl && /^data:image\/(png|jpe?g|svg\+xml|webp);base64,/.test(opts.logoDataUrl) ? `<img class="logo" src="${esc(opts.logoDataUrl)}" alt="Logo">` : '';
  const modules = (meta.modulesRun || []).filter(Boolean);
  const nNorm = findings.length ? 4 : 3;

  return `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}${targets[0] ? ' – ' + esc(targets[0]) : ''}</title>
<style>
  @page { size: A4; margin: 15mm 14mm 17mm; }
  :root { --ink:#0f172a; --text:#1e293b; --muted:#64748b; --line:#e2e8f0; --soft:#f8fafc; --accent:#b7791f; }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0; font: 13.5px/1.6 "Segoe UI", system-ui, -apple-system, Roboto, sans-serif; color: var(--text); background: #eef1f5; }
  .page { max-width: 900px; margin: 0 auto; background: #fff; box-shadow: 0 10px 40px -20px rgba(15,23,42,.35); }
  main { padding: 6px 44px 40px; }
  a { color: #1d4ed8; text-decoration: none; }
  h2 { font-size: 19px; color: var(--ink); margin: 34px 0 12px; padding-bottom: 8px; border-bottom: 2px solid var(--ink); display: flex; align-items: baseline; gap: 10px; }
  h2 .n { color: var(--accent); font-size: 14px; font-weight: 700; }
  h4 { margin: 0 0 4px; font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
  p { margin: 0 0 6px; }
  code, pre { font-family: "Cascadia Code", Consolas, monospace; }
  .muted { color: var(--muted); }

  .cover { background: linear-gradient(160deg, #0f1b2d 0%, #18293f 100%); color: #e8edf5; padding: 34px 44px 32px; }
  .brand { display: flex; align-items: center; gap: 12px; font-weight: 700; letter-spacing: .02em; }
  .brand small { display: block; font-weight: 400; color: #9fb0c8; font-size: 12px; }
  .brand .logo { margin-left: auto; max-height: 40px; max-width: 180px; background: #fff; border-radius: 6px; padding: 4px 8px; }
  .cover h1 { font-size: 30px; margin: 30px 0 4px; color: #fff; letter-spacing: -.01em; }
  .cover .sub { color: #b6c3d6; font-size: 13px; }
  .cover .targets { margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }
  .cover .targets span { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.14); border-radius: 6px; padding: 2px 8px; word-break: break-all; }
  .cover .conf { margin-top: 26px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,.12); font-size: 11.5px; color: #9fb0c8; display: flex; justify-content: space-between; gap: 12px; }
  .cover-top { margin-top: 18px; background: rgba(255,255,255,.05); border: 1px solid rgba(255,255,255,.12); border-radius: 12px; padding: 12px 16px; }
  .cover-top h4 { color: #9fb0c8; }
  .cover-top ol { margin: 4px 0 0; padding-left: 20px; color: #e8edf5; }
  .cover-top li { margin: 4px 0; }
  .facts { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 20px; }
  .facts div { background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.12); border-radius: 10px; padding: 10px 12px; }
  .facts b { display: block; font-size: 22px; color: #fff; font-variant-numeric: tabular-nums; }
  .facts span { font-size: 11.5px; color: #9fb0c8; }
  .verdict { display: grid; grid-template-columns: auto 1fr; gap: 24px; align-items: center; margin-top: 18px; background: #fff; color: var(--text); border-radius: 14px; padding: 20px 22px; }
  .ring { width: 112px; height: 112px; border-radius: 50%; display: grid; place-items: center; background: conic-gradient(var(--tone) calc(var(--p) * 1%), #e5e9f0 0); }
  .ring > div { width: 88px; height: 88px; border-radius: 50%; background: #fff; display: grid; place-items: center; text-align: center; line-height: 1.05; }
  .ring b { font-size: 34px; color: var(--ink); display: block; }
  .ring small { font-size: 11px; color: var(--muted); }
  .v-title { font-size: 17px; font-weight: 700; color: var(--ink); margin-bottom: 8px; }
  .bar { display: flex; height: 12px; border-radius: 999px; overflow: hidden; gap: 2px; margin: 8px 0 10px; }
  .counts { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 12.5px; }
  .counts span { display: inline-flex; align-items: center; gap: 6px; }
  .counts i { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .counts b { font-variant-numeric: tabular-nums; }

  .glance { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; }
  .box { border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; background: var(--soft); break-inside: avoid; }
  .toplist { list-style: none; margin: 0; padding: 0; }
  .toplist li { display: grid; grid-template-columns: auto 1fr; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--line); }
  .toplist li:last-child { border-bottom: 0; }
  .toplist .dot { width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; }
  .toplist a { color: var(--ink); font-weight: 600; }
  .toplist .muted { font-size: 12.5px; }
  .nextlist { margin: 0; padding-left: 18px; }
  .nextlist li { margin: 6px 0; }

  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th { text-align: left; font-size: 10.5px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); padding: 8px; border-bottom: 2px solid var(--line); background: var(--soft); }
  td { padding: 7px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  tr { break-inside: avoid; }
  thead { display: table-header-group; }
  td.nr { color: var(--muted); width: 34px; font-variant-numeric: tabular-nums; }
  td .tag { display: inline-block; color: #fff; font-size: 10.5px; font-weight: 700; padding: 1px 7px; border-radius: 5px; white-space: nowrap; }
  td.loc { font-family: "Cascadia Code", Consolas, monospace; font-size: 11px; color: var(--muted); overflow-wrap: anywhere; max-width: 230px; }
  td a { color: var(--ink); font-weight: 600; }

  .group-h { display: flex; align-items: center; gap: 10px; margin: 26px 0 10px; font-size: 14px; font-weight: 700; color: var(--ink); break-after: avoid; }
  .group-h i { width: 12px; height: 12px; border-radius: 3px; }
  .group-h small { font-weight: 400; color: var(--muted); }
  .finding { border: 1px solid var(--line); border-left: 5px solid var(--c); border-radius: 12px; padding: 14px 16px 10px; margin: 0 0 14px; break-inside: avoid; background: #fff; }
  .finding.sev-critical { --c: ${SEV_COLOR.critical}; } .finding.sev-high { --c: ${SEV_COLOR.high}; } .finding.sev-medium { --c: ${SEV_COLOR.medium}; } .finding.sev-low { --c: ${SEV_COLOR.low}; } .finding.sev-info { --c: ${SEV_COLOR.info}; }
  .finding > header { display: grid; grid-template-columns: auto 1fr; gap: 12px; margin-bottom: 10px; }
  .num { width: 28px; height: 28px; border-radius: 8px; background: var(--soft); border: 1px solid var(--line); display: grid; place-items: center; font-size: 12px; font-weight: 700; color: var(--muted); }
  .fh-top { display: flex; flex-wrap: wrap; gap: 5px; align-items: center; }
  .sev { color: #fff; font-size: 10.5px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; padding: 2px 8px; border-radius: 5px; }
  .chip { font-size: 11px; padding: 1px 8px; border-radius: 999px; background: var(--soft); border: 1px solid var(--line); color: #475569; }
  .chip.warn { background: #fde8ec; border-color: #f5b5c3; color: #9f1239; }
  .chip.ok { background: #e7f6ee; border-color: #b6e2c9; color: #276749; }
  .finding h3 { font-size: 15.5px; margin: 6px 0 2px; color: var(--ink); line-height: 1.35; }
  .loc { font-family: "Cascadia Code", Consolas, monospace; font-size: 11.5px; color: var(--muted); word-break: break-all; }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .cols section:only-child { grid-column: 1 / -1; }
  .why { margin-top: 6px; color: #334155; font-size: 12.5px; }
  .fix { margin-top: 10px; background: #f1f8f4; border: 1px solid #cfe9db; border-radius: 10px; padding: 10px 12px; }
  .fix h4 { color: #276749; }
  .steps { margin: 4px 0; padding-left: 18px; }
  .code { margin-top: 8px; border-radius: 8px; overflow: hidden; border: 1px solid #1f2a3d; break-inside: avoid; }
  .code-h { background: #1f2a3d; color: #cbd5e1; font-size: 11px; padding: 4px 10px; }
  .code pre { margin: 0; background: #0f172a; color: #e2e8f0; padding: 10px 12px; font-size: 11.5px; white-space: pre-wrap; word-break: break-word; }
  .evidence { font-size: 12px; margin-top: 8px; } .evidence code { background: var(--soft); border: 1px solid var(--line); border-radius: 4px; padding: 0 4px; word-break: break-all; }
  .finding footer { margin-top: 8px; font-size: 11.5px; color: var(--muted); }
  .links { font-size: 11.5px; margin: 4px 0 0; }

  .norm { break-inside: avoid; margin-bottom: 14px; }
  .norm h3 { font-size: 13.5px; margin: 0 0 6px; color: var(--ink); }
  .st { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
  .appendix dt { font-weight: 700; color: var(--ink); margin-top: 6px; }
  .appendix dd { margin: 0 0 4px; color: #334155; }
  .notes li { font-size: 12.5px; color: #334155; }
  .end { margin-top: 30px; padding-top: 10px; border-top: 1px solid var(--line); font-size: 11.5px; color: var(--muted); }

  .toolbar { position: sticky; top: 0; z-index: 5; display: flex; gap: 6px; flex-wrap: wrap; align-items: center; padding: 10px 44px; background: rgba(255,255,255,.95); border-bottom: 1px solid var(--line); backdrop-filter: blur(4px); }
  .toolbar button { font: inherit; font-size: 12px; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--line); background: #fff; cursor: pointer; }
  .toolbar button.on { background: var(--ink); color: #fff; border-color: var(--ink); }
  .toolbar input { margin-left: auto; font: inherit; font-size: 12.5px; padding: 5px 10px; border-radius: 8px; border: 1px solid var(--line); min-width: 220px; }
  .hide { display: none !important; }

  @media print {
    body { background: #fff; }
    .page { max-width: none; box-shadow: none; }
    .toolbar { display: none; }
    main { padding: 0 1mm; }
    .cover { margin: 0; padding: 14mm 12mm 12mm; border-radius: 6mm; break-after: page; min-height: 262mm; display: flex; flex-direction: column; }
    .cover .conf { margin-top: auto; }
    h2 { break-after: avoid; }
    .section-break { break-before: page; }
    a { color: var(--ink); }
  }
  @media screen and (max-width: 720px) { main, .cover, .toolbar { padding-left: 18px; padding-right: 18px; } .glance, .cols { grid-template-columns: 1fr; } .facts { grid-template-columns: repeat(2, 1fr); } .verdict { grid-template-columns: 1fr; } }
</style></head><body><div class="page">

<section class="cover">
  <div class="brand">${SHIELD}<div>Vigil<small>Sicherheits-Prüfung</small></div>${logo}</div>
  <h1>${esc(title)}</h1>
  <div class="sub">${opts.company ? esc(opts.company) + ' · ' : ''}Erstellt am ${esc(fmtDate(meta.at))}</div>
  ${targets.length ? `<div class="targets">${targets.slice(0, 8).map((t) => `<span>${esc(t)}</span>`).join('')}${targets.length > 8 ? `<span>+${targets.length - 8}</span>` : ''}</div>` : ''}
  <div class="facts">
    <div><b>${s.total}</b><span>offene Befunde</span></div>
    <div><b>${s.c.critical + s.c.high}</b><span>kritisch oder hoch</span></div>
    <div><b>${s.toxic}</b><span>Angriffswege</span></div>
    <div><b>${s.kev}</b><span>aktiv ausgenutzt (CISA)</span></div>
  </div>
  <div class="verdict">
    <div class="ring" style="--p:${s.posture};--tone:${s.tone}"><div><b>${s.grade}</b><small>${s.posture} / 100</small></div></div>
    <div>
      <div class="v-title">${esc(s.verdict)}</div>
      ${sevBar(s.c, s.total)}
      <div class="counts">${SEV.map((sv) => `<span><i style="background:${SEV_COLOR[sv]}"></i><b>${s.c[sv]}</b> ${SEV_LABEL[sv]}</span>`).join('')}</div>
    </div>
  </div>
  ${top.length ? `<div class="cover-top"><h4>Zuerst beheben</h4><ol>${top.slice(0, 4).map((f) => `<li>${esc(clean(f.title))}</li>`).join('')}</ol></div>` : ''}
  <div class="conf"><span>Vertraulich – enthält Informationen über Schwachstellen.</span><span>Zugangsdaten sind gekürzt.</span></div>
</section>

<nav class="toolbar" aria-label="Filter">
  <button class="on" data-f="">Alle (${s.total})</button>
  ${SEV.filter((sv) => s.c[sv]).map((sv) => `<button data-f="${sv}">${SEV_LABEL[sv]} (${s.c[sv]})</button>`).join('')}
  <input type="search" id="q" placeholder="Befunde durchsuchen …" aria-label="Befunde durchsuchen">
</nav>

<main>
  <h2><span class="n">1</span> Auf einen Blick</h2>
  <div class="glance">
    <div class="box"><h4>Die wichtigsten Risiken</h4>
      ${top.length ? `<ul class="toplist">${top.map((f) => `<li><span class="dot" style="background:${SEV_COLOR[f.severity]}"></span><div><a href="#f${idx.get(f)}">${esc(clean(f.title))}</a><div class="muted">${esc(firstSentence(f.impact || f.description))}</div></div></li>`).join('')}</ul>` : '<p class="muted">Keine kritischen oder hohen Risiken.</p>'}
    </div>
    <div class="box"><h4>Als Nächstes tun</h4>
      ${nextSteps.length ? `<ol class="nextlist">${nextSteps.map((t) => `<li>${esc(t)}</li>`).join('')}</ol>` : '<p class="muted">Regelmäßig weiter prüfen.</p>'}
      ${hidden.length ? `<p class="muted" style="margin-top:10px">${hidden.length} Befund(e) sind als Fehlalarm oder akzeptiertes Risiko markiert und hier nicht aufgeführt.</p>` : ''}
    </div>
  </div>

  ${findings.length ? `<h2 class="section-break"><span class="n">2</span> Alle Befunde</h2>
  <table><thead><tr><th>Nr.</th><th>Schwere</th><th>Befund</th><th>Bereich</th><th>Ort</th></tr></thead><tbody>
  ${findings.map((f, i) => `<tr data-sev="${f.severity}" data-text="${esc(`${f.title} ${f.location} ${f.category}`.toLowerCase())}"><td class="nr">${i + 1}</td><td><span class="tag" style="background:${SEV_COLOR[f.severity]}">${SEV_LABEL[f.severity]}</span></td><td><a href="#f${i + 1}">${esc(clean(f.title))}</a></td><td>${esc(CAT_LABEL[f.category] || f.category)}</td><td class="loc">${esc(String(f.location || '').split(String.fromCharCode(92)).join('/'))}</td></tr>`).join('')}
  </tbody></table>

  <h2 class="section-break"><span class="n">3</span> Befunde im Detail</h2>
  ${groups.map((g) => `<div class="group-h"><i style="background:${SEV_COLOR[g.sv]}"></i>${SEV_LABEL[g.sv]} <small>${g.list.length} · ${esc(SEV_HELP[g.sv])}</small></div>${g.list.map((f) => findingCard(f, idx.get(f))).join('')}`).join('')}` : '<h2><span class="n">2</span> Befunde</h2><p>Bei dieser Prüfung wurden keine offenen Befunde gefunden.</p>'}

  <h2 class="section-break"><span class="n">${nNorm}</span> Nachweise für Normen</h2>
  <p class="muted">Technische Einordnung der offenen Befunde in gängige Kataloge – ein prüfbarer Baustein für Audits, ersetzt aber keine Zertifizierung oder Rechtsberatung.</p>
  ${comp.map((cat) => `<div class="norm"><h3>${esc(cat.name)}</h3><table><thead><tr><th>Anforderung</th><th>Stand</th><th>Offene Befunde</th></tr></thead><tbody>${cat.controls.map((k) => `<tr><td><b>${esc(k.id)}</b> ${esc(k.title)}</td><td><span class="st" style="background:${ST[k.status][1]}"></span>${ST[k.status][0]}</td><td>${k.count ? `${k.count}: ${esc(k.findings.slice(0, 2).map(clean).join('; '))}${k.count > 2 ? ' …' : ''}` : '–'}</td></tr>`).join('')}</tbody></table></div>`).join('')}

  <h2><span class="n">${nNorm + 1}</span> Anhang</h2>
  <div class="glance appendix">
    <div class="box"><h4>So wurde geprüft</h4>
      <p>Feste Regeln und öffentliche Schwachstellen-Datenbanken (OSV.dev, CISA KEV, EPSS, gitleaks, retire.js)${meta.model && meta.provider && meta.provider !== 'regeln' ? `, dazu KI-Analyse mit ${esc(meta.provider)} / ${esc(meta.model)} und Gegenprüfung jedes KI-Funds` : ''}. Alle Prüfungen sind zerstörungsfrei.</p>
      ${modules.length ? `<p class="muted">Gelaufene Prüfungen: ${esc(modules.join(', '))}</p>` : ''}
      ${meta.units ? `<p class="muted">${meta.units} Dateien eingelesen.</p>` : ''}
    </div>
    <div class="box"><h4>Was die Stufen bedeuten</h4><dl>${SEV.map((sv) => `<dt><span class="st" style="background:${SEV_COLOR[sv]}"></span>${SEV_LABEL[sv]}</dt><dd>${esc(SEV_HELP[sv])}</dd>`).join('')}</dl></div>
  </div>
  ${result.errors && result.errors.length ? `<div class="box" style="margin-top:14px"><h4>Hinweise zum Lauf</h4><ul class="notes">${result.errors.slice(0, 30).map((e) => `<li>${esc(e)}</li>`).join('')}</ul></div>` : ''}
  <div class="end">Erstellt mit Vigil · ${esc(fmtDate(meta.at))} · Gefundene Zugangsdaten sind in diesem Bericht gekürzt.</div>
</main></div>
<script>
(function () {
  var btns = document.querySelectorAll('.toolbar button'), q = document.getElementById('q'), sev = '';
  function apply() { var t = (q.value || '').toLowerCase(); document.querySelectorAll('.finding, tbody tr[data-sev]').forEach(function (el) { var ok = (!sev || el.getAttribute('data-sev') === sev) && (!t || (el.getAttribute('data-text') || '').indexOf(t) >= 0); el.classList.toggle('hide', !ok); }); }
  btns.forEach(function (b) { b.onclick = function () { btns.forEach(function (x) { x.classList.remove('on'); }); b.classList.add('on'); sev = b.getAttribute('data-f'); apply(); }; });
  q.oninput = apply;
})();
</script>
</body></html>`;
}

// --- Markdown (fuer Tickets, Wikis, Pull Requests) -----------------------------------------
function toMarkdown(result, opts = {}) {
  if (typeof opts === 'string') opts = { title: opts };
  const all = result.findings || [];
  const findings = all.filter((f) => !(f.suppressed || f.status === 'FALSE_POSITIVE' || f.status === 'ACCEPTED_RISK'));
  const s = stats(findings);
  const meta = result.meta || {};
  const targets = (opts.targets || []).map((t) => (typeof t === 'string' ? t : t.value)).filter(Boolean);
  const L = [];
  L.push(`# ${opts.title || 'Sicherheitsbericht'}`, '');
  L.push(`> **Note ${s.grade}** · Sicherheitswert ${s.posture}/100 · ${s.verdict}`, '');
  L.push(`Erstellt am ${fmtDate(meta.at)}${targets.length ? ` · Ziele: ${targets.map((t) => '`' + t + '`').join(', ')}` : ''}`, '');
  L.push('| Kritisch | Hoch | Mittel | Niedrig | Hinweis | Angriffswege |', '|:-:|:-:|:-:|:-:|:-:|:-:|', `| ${s.c.critical} | ${s.c.high} | ${s.c.medium} | ${s.c.low} | ${s.c.info} | ${s.toxic} |`, '');
  const top = findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 6);
  if (top.length) { L.push('## Die wichtigsten Risiken', ''); top.forEach((f) => L.push(`- **${clean(f.title)}** – ${firstSentence(f.impact || f.description, 160)}`)); L.push(''); }
  if (findings.length) {
    L.push('## Übersicht', '', '| Nr. | Schwere | Befund | Ort |', '|--:|:--|:--|:--|');
    const cell = (x) => String(x || '').split('|').join('\\|');
    findings.forEach((f, i) => L.push(`| ${i + 1} | ${SEV_LABEL[f.severity]} | ${cell(clean(f.title))} | \`${cell(f.location)}\` |`));
    L.push('', '## Befunde im Detail', '');
    findings.forEach((f, i) => {
      L.push(`### ${i + 1}. ${clean(f.title)}`, '');
      L.push(`**${SEV_LABEL[f.severity]}** · ${CAT_LABEL[f.category] || f.category}${f.cwe ? ' · ' + f.cwe : ''}${f.owasp ? ' · OWASP ' + f.owasp : ''}${f.location ? ` · \`${f.location}\`` : ''}`, '');
      if (f.description) L.push(`**Was ist los?** ${f.description}`, '');
      if (f.impact) L.push(`**Was kann passieren?** ${f.impact}`, '');
      if (fixText(f)) L.push(`**Lösung:** ${fixText(f)}`, '');
      if (Array.isArray(f.steps) && f.steps.length) { f.steps.forEach((st, j) => L.push(`${j + 1}. ${st}`)); L.push(''); }
      const snip = f.versionPatch ? [f.versionPatch.command, f.versionPatch.manifest].filter(Boolean).join('\n\n') : Object.values(f.snippets || {})[0] || f.patch;
      if (snip) L.push('```', snip, '```', '');
      if (Array.isArray(f.links) && f.links.length) L.push('Mehr dazu: ' + f.links.slice(0, 4).map((l) => `[${l.label}](${l.url})`).join(' · '), '');
    });
  } else L.push('Keine offenen Befunde.', '');
  if (result.errors && result.errors.length) { L.push('<details><summary>Hinweise zum Lauf</summary>', ''); result.errors.forEach((e) => L.push(`- ${e}`)); L.push('', '</details>', ''); }
  L.push('---', '_Erstellt mit Vigil – zerstörungsfreie Prüfung eigener bzw. freigegebener Systeme._');
  return L.join('\n');
}

module.exports = { toHtml, toMarkdown, stats, SEV_LABEL, SEV_COLOR };
