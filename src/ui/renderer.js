'use strict';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', info: 'Hinweis' };
const SEV_CLS = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
const SEV_HELP = {
  critical: 'Sofort beheben – leicht ausnutzbar, großer Schaden möglich.',
  high: 'Zeitnah beheben – ernstes Risiko.',
  medium: 'Beheben, wenn möglich – mittleres Risiko.',
  low: 'Kleineres Risiko – gut, es zu beheben.',
  info: 'Nur ein Hinweis, kein akutes Risiko.',
};
const PHASES = [
  { key: 'ingest', label: 'Sammeln' },
  { key: 'prescan', label: 'Vorprüfung' },
  { key: 'cve', label: 'Schwachstellen-DB' },
  { key: 'webscan', label: 'Server-Checks' },
  { key: 'active', label: 'Aktiv-Scan' },
  { key: 'analyze', label: 'KI-Analyse' },
  { key: 'validate', label: 'Gegenprüfung' },
  { key: 'done', label: 'Fertig' },
];

const state = { targets: [], providers: [], config: null, lastFindings: [], lastResult: null, filter: 'all', query: '', onlyNew: false, onlyProven: false, showSuppressed: false, running: false };
let RULE_NAMES = null; // Namen der eingebauten Regeln (lazy via IPC)

// --- Ziele --------------------------------------------------------------
const KIND_LABEL = { path: 'Datei/Ordner', url: 'Webadresse', endpoint: 'Server', image: 'Container-Image' };
function addTarget(type, value, authorized = false) {
  if (!value) return;
  if (state.targets.some((t) => t.type === type && t.value === value)) return;
  state.targets.push({ type, value, authorized });
  renderTargets();
}
function renderTargets() {
  const ul = $('targetList');
  ul.innerHTML = '';
  state.targets.forEach((t, i) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="t-kind ${t.type}">${KIND_LABEL[t.type]}</span><span class="t-val" title="${esc(t.value)}">${esc(t.value)}</span>`;
    const rm = document.createElement('button');
    rm.className = 't-rm'; rm.textContent = '✕'; rm.setAttribute('aria-label', 'Entfernen');
    rm.onclick = () => { state.targets.splice(i, 1); renderTargets(); };
    li.appendChild(rm);
    ul.appendChild(li);
  });
  $('targetCount').textContent = state.targets.length;
  $('targets').hidden = state.targets.length === 0;
  updateRunState();
}

// Freitext deuten: lokaler Pfad, Webadresse, Container-Image oder Server (IP/Host).
function classifyInput(v) {
  if (/^image:/i.test(v)) return { type: 'image', value: v.slice(6).trim() };
  if (/^https?:\/\//i.test(v)) return { type: 'url', value: v };
  if (/^[a-z]:[\\/]|^\\\\|^\/|^\.{1,2}[\\/]|^~[\\/]/i.test(v)) return { type: 'path', value: v };
  // Image mit Tag (nginx:1.25, ghcr.io/org/app:2.1) oder Digest – ein reiner Zahlen-"Tag" ist ein Port.
  const img = v.match(/^[a-z0-9][a-z0-9._/-]*(?::([\w][\w.-]*)|@sha256:[a-f0-9]{64})$/);
  if (img && !(img[1] && /^\d+$/.test(img[1]))) return { type: 'image', value: v };
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$|^localhost(?::\d+)?$|^\[?[0-9a-f:]+\]?$|:\d+$/i.test(v)) return { type: 'endpoint', value: v };
  if (/^[\w-]+(\.[\w-]+)+(\/.*)?$/.test(v)) return { type: 'url', value: 'https://' + v };
  return { type: 'endpoint', value: v };
}

// Webadressen und Server brauchen eine Freigabe; steht der Host schon auf der Liste, entfaellt die Bestaetigung.
function hostOfTarget(t) {
  if (t.type === 'url') { try { return new URL(t.value).hostname.toLowerCase(); } catch { return ''; } }
  if (t.type !== 'endpoint') return '';
  const m = t.value.match(/^\[([^\]]+)\]/);
  return (m ? m[1] : t.value.replace(/:\d+$/, '')).toLowerCase();
}
function isAllowlisted(host) {
  return !!host && (state.config.allowlist || []).some((e) => (e.startsWith('*.') ? host.endsWith(e.slice(1)) : host === e || host.endsWith('.' + e)));
}
const needsConfirm = (t) => (t.type === 'url' || t.type === 'endpoint') && !isAllowlisted(hostOfTarget(t));

function onTargetInput() {
  const v = $('targetInput').value.trim();
  const t = v ? classifyInput(v) : null;
  $('authRow').hidden = !(t && needsConfirm(t));
  $('authLabel').textContent = t && t.type === 'url' ? 'Diese Webseite gehört mir bzw. ich darf sie prüfen.' : 'Ich bin berechtigt, diesen Server zu prüfen.';
  $('webNote').hidden = !(t && (t.type === 'url' || t.type === 'endpoint'));
  $('imageNote').hidden = !(t && t.type === 'image');
}
function addTypedTarget() {
  const v = $('targetInput').value.trim();
  if (!v) return;
  const t = classifyInput(v);
  if (needsConfirm(t) && !$('authChk').checked) { flash('Bitte bestätige zuerst, dass du dieses Ziel prüfen darfst.'); $('authChk').focus(); return; }
  addTarget(t.type, t.value, t.type === 'url' || t.type === 'endpoint');
  $('targetInput').value = ''; $('authChk').checked = false; onTargetInput();
}

// Startknopf + Hinweis: sagt immer, was als Naechstes fehlt.
// Nur Dateien/Ordner analysiert die KI – Webadressen, Server und Images laufen ohne sie.
const needsAi = () => state.targets.some((t) => t.type === 'path');
function updateRunState() {
  const ready = needsAi() ? aiReady() : { ok: true, label: 'den passiven Checks (ohne KI)' };
  $('runBtn').disabled = state.running || !state.targets.length || !ready.ok;
  if (state.running) return;
  if (!state.targets.length) $('runHint').textContent = 'Füge oben zuerst etwas zur Prüfliste hinzu.';
  else if (!ready.ok) $('runHint').textContent = ready.why;
  else $('runHint').textContent = `Bereit – ${state.targets.length} ${state.targets.length === 1 ? 'Ziel' : 'Ziele'} mit ${ready.label}. Je nach Umfang dauert das ein paar Minuten.`;
}

// --- Drag & Drop --------------------------------------------------------
function setupDropzone() {
  const dz = $('dropzone');
  ['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('drag'); }));
  dz.addEventListener('drop', (e) => {
    let added = 0;
    for (const f of Array.from(e.dataTransfer.files || [])) {
      const p = window.vigil.pathForFile(f);
      if (p) { addTarget('path', p); added++; }
    }
    if (!added) flash('Konnte die Pfade nicht lesen – nutze die Auswahl-Buttons.');
  });
  dz.addEventListener('click', (e) => { if (!e.target.closest('button')) $('pickFilesBtn').click(); });
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('pickFilesBtn').click(); } });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());
}

// --- Analyse ------------------------------------------------------------
function renderStepper(activeKey) {
  const ai = PHASES.findIndex((p) => p.key === activeKey);
  $('stepper').innerHTML = PHASES.map((p, i) => {
    const cls = i < ai ? 'past' : i === ai ? 'active' : '';
    return `<span class="pstep ${cls}">${esc(p.label)}</span>`;
  }).join('<span class="psep">›</span>');
}
async function runAudit() {
  if (state.running || !state.targets.length) return;
  state.running = true; updateRunState();
  $('cancelBtn').hidden = false; $('cancelBtn').disabled = false;
  $('progressPanel').hidden = false;
  $('emptyState').hidden = true;
  $('resultPanel').hidden = true;
  $('log').textContent = '';
  $('costPanel').hidden = true; $('costPanel').innerHTML = '';
  $('barFill').style.width = '0%';
  $('progressTitle').textContent = 'Prüfung läuft …';
  $('progressPanel').classList.remove('done');
  renderStepper('ingest');
  $('progressPanel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  const unsub = window.vigil.onProgress((p) => {
    renderStepper(p.phase);
    $('log').textContent += `[${p.phase}]${p.total ? ` ${p.done}/${p.total}` : ''} ${p.message}\n`;
    $('log').scrollTop = $('log').scrollHeight;
    if (p.total) $('barFill').style.width = Math.round((p.done / p.total) * 100) + '%';
    if (p.cost) updateCost(p.cost, false);
  });

  const res = await window.vigil.runAudit({ targets: state.targets, providerId: state.config.selected });
  // Bestaetigte Hosts hat der Main-Prozess auf die Freigabeliste gesetzt.
  try { state.config.allowlist = (await window.vigil.getConfig()).allowlist || []; } catch { /* egal */ }
  unsub();
  state.running = false; updateRunState();
  $('cancelBtn').hidden = true;

  if (!res.ok) {
    $('progressTitle').textContent = 'Fehler';
    renderStepper('');
    $('log').hidden = false; $('logToggle').setAttribute('aria-expanded', 'true');
    $('log').textContent += '\nFEHLER: ' + res.error + '\n';
    return;
  }
  $('barFill').style.width = '100%';
  $('progressTitle').textContent = res.canceled ? 'Abgebrochen – Teilergebnis' : 'Prüfung abgeschlossen';
  $('progressPanel').classList.add('done');
  renderStepper(res.canceled ? '' : 'done');
  if (res.result) {
    if (res.result.meta && res.result.meta.usage) updateCost(res.result.meta.usage, true);
    renderResult(res.result);
    $('resultPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

// Live-Anzeige von Token-/$-Verbrauch. Nur bei nicht-lokalen Anbietern sichtbar.
function fmtUsd(u) {
  if (u >= 0.1) return '$' + u.toFixed(2);
  if (u >= 0.005) return '$' + u.toFixed(3);
  if (u > 0) return '< $0,005';
  return '$0,00';
}
function fmtTok(n) { return Number(n || 0).toLocaleString('de-DE'); }
function updateCost(cost, done) {
  const el = $('costPanel');
  if (!cost || cost.local) { el.hidden = true; return; } // lokal = kostenlos, nichts anzeigen
  el.hidden = false;
  const inT = fmtTok(cost.inputTokens), outT = fmtTok(cost.outputTokens);
  const totalT = fmtTok((cost.inputTokens || 0) + (cost.outputTokens || 0));
  const label = cost.estimate ? 'Geschätzte Kosten (vor dem Lauf)' : (done ? 'Kosten insgesamt' : 'Bisher verbraucht');
  const usd = cost.priced
    ? `<span class="cost-usd">≈ ${esc(fmtUsd(cost.usd || 0))}</span>`
    : `<span class="cost-usd muted">keine $-Schätzung</span>`;
  el.innerHTML =
    `<div class="cost-row"><span class="cost-badge" aria-hidden="true">$</span>` +
    `<span class="cost-label">${esc(label)}</span>${usd}</div>` +
    `<div class="cost-tok small muted">${esc(totalT)} Tokens · ${esc(inT)} Eingang · ${esc(outT)} Ausgang` +
    `${cost.priced ? '' : ' · Modell/Anbieter nicht in der Preisliste'}</div>`;
}

// Sicherheitsnote A–F aus den (nicht ausgeblendeten) Befunden.
const SEV_WEIGHT = { critical: 30, high: 14, medium: 5, low: 1.5, info: 0 };
function riskScore(counts) {
  const penalty = SEV_ORDER.reduce((sum, s) => sum + (counts[s] || 0) * SEV_WEIGHT[s], 0);
  const score = Math.max(0, Math.round(100 - penalty));
  const grade = score >= 92 ? 'A' : score >= 78 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : score >= 20 ? 'E' : 'F';
  return { score, grade };
}
function visibleCounts() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  state.lastFindings.forEach((f) => { if (!f.suppressed) counts[f.severity]++; });
  return counts;
}
const plural = (n, one, many) => (n === 1 ? one : many);

function renderVerdict() {
  const c = visibleCounts();
  const total = SEV_ORDER.reduce((n, s) => n + c[s], 0);
  let kind = 'ok', head = 'Keine Probleme gefunden.', sub = 'Vigil hat nichts Auffälliges entdeckt – gute Arbeit.';
  if (total > 0) {
    sub = 'Klick auf eine Stufe, um die Liste zu filtern, oder auf einen Befund für Details und Lösung.';
    if (c.critical) { kind = 'crit'; head = `${c.critical} kritische${c.high ? ` und ${c.high} hohe` : ''} ${plural(c.critical + c.high, 'Lücke', 'Lücken')} – bitte zuerst beheben.`; }
    else if (c.high) { kind = 'high'; head = `${c.high} ${plural(c.high, 'Problem', 'Probleme')} mit hohem Risiko gefunden.`; }
    else if (c.medium) { kind = 'med'; head = `${c.medium} ${plural(c.medium, 'Problem', 'Probleme')} mittleren Risikos gefunden.`; }
    else { kind = 'low'; head = `Nur ${total} ${plural(total, 'kleiner Hinweis', 'kleinere Hinweise')} – insgesamt solide.`; }
  }
  const { score, grade } = riskScore(c);
  const bar = total
    ? SEV_ORDER.filter((s) => c[s]).map((s) => `<span style="flex-grow:${c[s]};background:var(--${SEV_CLS[s]})" title="${SEV_LABEL[s]}: ${c[s]}"></span>`).join('')
    : '<span style="flex-grow:1;background:var(--low)"></span>';
  const stats = SEV_ORDER.map((s) => `<button type="button" class="stat c-${SEV_CLS[s]}${state.filter === s ? ' active' : ''}" data-f="${s}" title="${esc(SEV_HELP[s])}"${c[s] ? '' : ' disabled'}>
      <span class="stat-n">${c[s]}</span><span class="stat-l">${SEV_LABEL[s]}</span></button>`).join('');
  const merged = state.lastFindings.reduce((n, f) => n + Math.max(0, (f.mergedCount || 1) - 1), 0);
  const meta = (state.lastResult && state.lastResult.meta) || {};
  const notes = [];
  if (merged) notes.push(`${merged} doppelte ${plural(merged, 'Meldung', 'Meldungen')} aus verschiedenen Prüfungen zusammengeführt.`);
  if (meta.refuted) notes.push(`${meta.refuted} KI-${plural(meta.refuted, 'Befund', 'Befunde')} bei der Gegenprüfung widerlegt und verworfen.`);
  if (meta.redacted) notes.push(`${meta.redacted} ${plural(meta.redacted, 'Secret', 'Secrets')} vor dem Versand an die KI geschwärzt.`);
  const unverified = state.lastFindings.filter((f) => !f.suppressed && f.assurance === 'unverified').length;
  const mergeNote = notes.map((n) => `<div class="merge-note">${esc(n)}</div>`).join('') +
    (unverified ? `<div class="merge-note warn">${unverified} ${plural(unverified, 'Befund ist', 'Befunde sind')} nur von der KI gemeldet und unbestätigt – bitte selbst prüfen.</div>` : '');

  const v = $('verdict');
  v.className = 'verdict v-' + kind;
  v.innerHTML = `
    <div class="score" style="--p:${score}" role="img" aria-label="Sicherheitsnote ${grade}, ${score} von 100">
      <div class="score-inner"><span class="score-grade">${grade}</span><span class="score-label">${score} / 100</span></div>
    </div>
    <div class="v-main">
      <div class="v-head">${esc(head)}</div>
      <div class="v-sub">${esc(sub)}</div>
      <div class="sev-bar" aria-hidden="true">${bar}</div>
      <div class="stats">${stats}</div>
      ${mergeNote}
    </div>`;
  v.querySelectorAll('.stat').forEach((b) => b.onclick = () => setFilter(state.filter === b.dataset.f ? 'all' : b.dataset.f));
}

function setFilter(f) {
  state.filter = f;
  renderVerdict(); renderFilters(); renderFindings();
}
function renderFilters() {
  const c = visibleCounts();
  const total = SEV_ORDER.reduce((n, s) => n + c[s], 0);
  const btn = (f, label, n, dot) => `<button class="fbtn${state.filter === f ? ' active' : ''}" data-f="${f}" role="tab" aria-selected="${state.filter === f}">${dot ? `<span class="fdot" style="--c:var(--${dot})"></span>` : ''}${label}<span class="fcount">${n}</span></button>`;
  const box = $('filters');
  box.innerHTML = btn('all', 'Alle', total) + SEV_ORDER.filter((s) => c[s]).map((s) => btn(s, SEV_LABEL[s], c[s], SEV_CLS[s])).join('');
  box.querySelectorAll('.fbtn').forEach((b) => b.onclick = () => setFilter(b.dataset.f));
}

function renderResult(result) {
  state.lastFindings = result.findings || [];
  state.lastResult = result;
  state.filter = 'all'; state.query = ''; state.onlyNew = false; state.onlyProven = false; state.showSuppressed = false;
  $('findingSearch').value = '';
  $('resultPanel').hidden = false;
  $('emptyState').hidden = true;

  if (result.errors && result.errors.length) {
    $('log').hidden = false; $('logToggle').setAttribute('aria-expanded', 'true');
    $('log').textContent += '\nHinweise:\n' + result.errors.map((e) => '  - ' + e).join('\n') + '\n';
  }
  refreshResultView();
}
function refreshResultView() {
  renderVerdict(); renderFilters(); updateBaselineStatus(); renderViewToggles(); renderFindings();
}

// Werkzeug-Praefix ("gitleaks: …") aus dem Titel nehmen – die Quelle steht daneben.
const TOOL_PREFIX = /^(gitleaks|trufflehog|trivy|grype|semgrep|bandit|checkov|retire\.js|hadolint|osv-scanner|nuclei|binary)\s*:\s*/i;
function cleanTitle(t) {
  const s = String(t || '').replace(TOOL_PREFIX, '').trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function findingSources(f) { return f.sources && f.sources.length ? f.sources : [f.source]; }
function matchesQuery(f, q) {
  if (!q) return true;
  const hay = [f.title, f.location, f.category, f.description, ...findingSources(f).map(sourceLabel)].join(' ').toLowerCase();
  return q.split(/\s+/).every((w) => hay.includes(w));
}
const CONF_LABEL = { high: 'hoch', medium: 'mittel', low: 'niedrig' };
// Beleg-Stufen: KI-Funde zaehlen erst, wenn sie deterministisch oder per Gegenpruefung bestaetigt sind.
const EVIDENCE = {
  'confirmed-multi': { label: 'Mehrfach bestätigt', cls: 'ev-strong', help: 'Von mehreren unabhängigen Prüfungen gefunden.' },
  deterministic: { label: 'Regelbasiert belegt', cls: 'ev-strong', help: 'Von einer deterministischen Prüfung (Muster, Datenbank, Tool) gefunden – nicht nur von der KI.' },
  'ai-verified': { label: 'KI-gegengeprüft', cls: 'ev-ok', help: 'Nur die KI hat es gemeldet, aber die Gegenprüfung am Code-Ausschnitt hat es bestätigt.' },
  unverified: { label: 'Unbestätigt', cls: 'ev-weak', help: 'Nur von der KI gemeldet und nicht bestätigt – bitte selbst prüfen, kann ein Fehlalarm sein.' },
};
const CONTEXT = {
  'internet-exposed': 'aus dem Internet erreichbar',
  'request-handler': 'in einem Request-Handler',
  'sensitive-data': 'berührt sensible Daten',
  'supply-chain': 'Lieferkette (Abhängigkeit)',
};
const CHEV = '<svg class="chev" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="m9 6 6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function findingCard(f) {
  const srcs = findingSources(f);
  const srcNames = srcs.map(sourceLabel).join(', ');
  const badges = `${f.isNew && state.lastResult && state.lastResult.hasBaseline ? '<span class="badge-new" title="Seit dem letzten Lauf neu aufgetaucht">neu</span>' : ''}${f.inCisaKev ? '<span class="badge-kev" title="Steht im CISA-Katalog aktiv ausgenutzter Lücken – höchste Priorität">aktiv ausgenutzt</span>' : ''}${f.epssScore >= 0.1 ? `<span class="badge-epss" title="EPSS: Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen">EPSS ${Math.round(f.epssScore * 100)} %</span>` : ''}${f.regression ? '<span class="badge-reg" title="War schon als behoben markiert und ist wieder da">wieder da</span>' : ''}${f.status && f.status !== 'OPEN' ? `<span class="badge-status st-${f.status}">${esc(STATUS_LABEL[f.status])}</span>` : ''}`;
  const srcChip = srcs.length > 1
    ? `<span class="src-chip" title="Gefunden von: ${esc(srcNames)}">${esc(srcs.map(sourceLabel).join(' + '))}</span>`
    : `<span>${esc(srcNames)}</span>`;
  const sub = [
    f.location ? `<span class="f-loc" title="${esc(f.location)}">${esc(f.location)}</span>` : '',
    `<span>${esc(f.category)}</span>`,
    srcChip,
  ].filter(Boolean).join('<span class="f-sep">·</span>') + badges;
  const ev = EVIDENCE[f.assurance];
  // Feste Spalten: leere Platzhalter, damit Zeilen ohne Beleg/CVSS nicht verrutschen.
  const evChip = ev ? `<span class="ev-chip ${ev.cls}" title="${esc(ev.help)}">${ev.label}</span>` : '<span class="col-empty"></span>';
  const ctx = (f.context || []).filter((c) => CONTEXT[c]);
  const ctxRow = ctx.length ? `<div class="ctx-row">${ctx.map((c) => `<span class="ctx-chip ctx-${c}">${CONTEXT[c]}</span>`).join('')}</div>` : '';
  const check = f.validation && f.validation.reason
    ? `<div class="f-sec check-sec"><h4>Gegenprüfung: ${f.validation.verdict === 'confirmed' ? 'bestätigt' : 'nicht eindeutig'}</h4><p>${esc(f.validation.reason)}</p></div>` : '';
  const danger = [f.impact, f.reachability].filter(Boolean).join(' ');
  const secs = [
    f.description && `<div class="f-sec${danger ? '' : ' full'}"><h4>Das Problem</h4><p>${esc(f.description)}</p></div>`,
    danger && `<div class="f-sec${f.description ? '' : ' full'}"><h4>Wie gefährlich ist das?</h4><p>${esc(danger)}</p></div>`,
  ].filter(Boolean).join('');
  // Kontext-Risiko (0–100) statt reinem CVSS – beruecksichtigt KEV, EPSS und Exposition.
  const risk = f.contextualRiskScore != null ? f.contextualRiskScore : (f.cvss != null ? f.cvss * 10 : null);
  const cvss = risk != null ? `<span class="cvss risk-${risk >= 85 ? 'crit' : risk >= 65 ? 'high' : risk >= 40 ? 'med' : 'low'}" title="Kontext-Risiko 0–100${f.cvss != null ? ' · CVSS ' + Number(f.cvss).toFixed(1) : ''}${f.epssScore != null ? ' · EPSS ' + Math.round(f.epssScore * 100) + ' %' : ''}"><small>RISIKO</small>${Math.round(risk)}</span>` : '<span class="col-empty"></span>';
  return `
    <div class="card finding sev-${f.severity}${f.suppressed ? ' is-suppressed' : ''}">
      <button class="card-head" aria-expanded="false">
        <span class="sev-tag" title="${esc(SEV_HELP[f.severity])}">${SEV_LABEL[f.severity]}</span>
        <span class="f-main"><span class="f-title">${esc(cleanTitle(f.title))}</span><span class="f-sub">${sub}</span></span>
        ${evChip}${cvss}${CHEV}
      </button>
      <div class="card-body"><div class="inner"><div class="pad">
        ${f.locationDetail ? `<p class="loc-detail"><span>Fundort</span> ${esc(f.locationDetail)}</p>` : ''}
        ${ctxRow}
        ${secs ? `<div class="f-cols">${secs}</div>` : ''}
        ${check}
        ${f.evidence ? `<div class="f-sec evidence"><h4>Fundstelle</h4><code>${esc(f.evidence)}</code></div>` : ''}
        ${solutionBlock(f)}
        <div class="f-foot">
          <span class="muted">${srcs.length > 1 ? 'Gefunden von' : 'Quelle'}: ${esc(srcNames)}${f.confidence ? ' · Sicherheit: ' + esc(CONF_LABEL[f.confidence] || f.confidence) : ''}${f.ruleId ? ' · Regel: ' + esc(f.ruleId) : ''}</span>
          ${f.id ? statusSelect(f.id, f.status || 'OPEN') : ''}
        </div>
      </div></div></div>
    </div>`;
}

// --- Loesungsteil: Warum, Schritte, Versions-Patch, Schnipsel, Links -------
const LINK_ICON = { doc: '📘', news: '📰', video: '▶' };
const SNIP_LABEL = { nginx: 'nginx', apache: 'Apache', caddy: 'Caddy', express: 'Node/Express', node: 'Node.js', php: 'PHP', compose: 'docker-compose', dockerfile: 'Dockerfile', yaml: 'GitHub Actions', sshd_config: 'sshd_config', shell: 'Shell', ufw: 'ufw', fail2ban: 'fail2ban', dns: 'DNS-Eintrag', prisma: 'Prisma', sql: 'SQL', html: 'HTML', vite: 'Vite', webpack: 'webpack', npmrc: '.npmrc', ci: 'CI', certbot: 'certbot', csp: 'CSP', http: 'HTTP', apollo: 'Apollo', yoga: 'GraphQL Yoga', terser: 'terser' };
function copyBtn(text) { return `<button type="button" class="btn tiny copy-btn" data-copy="${esc(text)}">Kopieren</button>`; }
function solutionBlock(f) {
  const parts = [];
  if (f.explanation) parts.push(`<div class="sol-why"><h4>Warum das wichtig ist</h4><p>${esc(f.explanation)}</p></div>`);
  const steps = f.steps && f.steps.length ? f.steps : (f.remediation ? [f.remediation] : []);
  if (steps.length) parts.push(`<div class="sol-steps"><h4>✔ So behebst du es</h4><ol>${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>${f.remediation && f.steps && f.steps.length && !f.steps.includes(f.remediation) && !/^Siehe /.test(f.remediation) ? `<p class="muted small">Konkret hier: ${esc(f.remediation)}</p>` : ''}</div>`);
  if (f.versionPatch) {
    const vp = f.versionPatch;
    const code = [vp.command, vp.manifest].filter(Boolean).join('\n\n');
    parts.push(`<div class="sol-patch"><div class="sol-head"><h4>⬆ Versions-Patch · ${esc(vp.title)}</h4>${copyBtn(vp.command || code)}</div><pre>${esc(code)}</pre>${vp.note ? `<p class="muted small">${esc(vp.note)}</p>` : ''}</div>`);
  }
  const snips = Object.entries(f.snippets || {});
  if (f.patch) snips.unshift(['patch', f.patch]);
  if (snips.length) {
    parts.push(`<div class="sol-snips"><div class="snip-tabs" role="tablist">${snips.map(([k], i) => `<button type="button" class="snip-tab${i ? '' : ' active'}" data-i="${i}">${esc(k === 'patch' ? 'Vorschlag' : SNIP_LABEL[k] || k)}</button>`).join('')}</div>${snips.map(([, v], i) => `<div class="snip-pane"${i ? ' hidden' : ''}>${copyBtn(v)}<pre>${esc(v)}</pre></div>`).join('')}</div>`);
  }
  if (f.links && f.links.length) {
    parts.push(`<div class="sol-links"><h4>Mehr dazu</h4><div class="link-row">${f.links.slice(0, 10).map((l) => `<button type="button" class="link-chip kind-${esc(l.kind || 'doc')}" data-url="${esc(l.url)}" title="${esc(l.url)}">${LINK_ICON[l.kind] || '🔗'} ${esc(l.label)}</button>`).join('')}</div></div>`);
  }
  return parts.length ? `<div class="solution">${parts.join('')}</div>` : '';
}
function bindSolutionControls(root) {
  root.querySelectorAll('.copy-btn').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Kopiert ✓'; setTimeout(() => { b.textContent = 'Kopieren'; }, 1400); } catch { b.textContent = 'Nicht möglich'; }
  });
  root.querySelectorAll('.snip-tabs').forEach((tabs) => tabs.querySelectorAll('.snip-tab').forEach((t) => t.onclick = (e) => {
    e.stopPropagation();
    tabs.querySelectorAll('.snip-tab').forEach((x) => x.classList.toggle('active', x === t));
    tabs.parentElement.querySelectorAll('.snip-pane').forEach((p, i) => { p.hidden = String(i) !== t.dataset.i; });
  }));
  root.querySelectorAll('.link-chip').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    const r = await window.vigil.openLink(b.dataset.url);
    if (r && r.ok === false) flash(r.error || 'Link nicht erlaubt.');
  });
}

// Banner fuer Angriffspfade (Toxic Combinations) – ganz oben, weil am dringendsten.
function toxicBanner(list) {
  const toxic = list.filter((f) => /^toxic-/.test(f.ruleId || '') && !f.suppressed);
  if (!toxic.length) return '';
  return `<div class="toxic-banner" role="alert"><div class="toxic-ico">⚠</div><div><b>${toxic.length} ${toxic.length === 1 ? 'Angriffspfad' : 'Angriffspfade'} erkannt</b><ul>${toxic.map((t) => `<li>${esc(t.title.replace(/^Angriffspfad:\s*/, ''))}</li>`).join('')}</ul><span class="muted small">Mehrere Schwächen ergeben zusammen einen vollständigen Angriffsweg. Ein Glied zu brechen genügt.</span></div></div>`;
}

function renderFindings() {
  const box = $('findings');
  const q = state.query.trim().toLowerCase();
  let list = state.filter === 'all' ? state.lastFindings : state.lastFindings.filter((f) => f.severity === state.filter);
  if (!state.showSuppressed) list = list.filter((f) => !f.suppressed);
  if (state.onlyNew) list = list.filter((f) => f.isNew);
  if (state.onlyProven) list = list.filter((f) => f.assurance !== 'unverified');
  list = list.filter((f) => matchesQuery(f, q));
  if (!list.length) {
    box.innerHTML = state.lastFindings.length
      ? '<div class="empty"><b>Keine Treffer</b>Für diese Ansicht gibt es keine Befunde – Filter oder Suche anpassen.</div>'
      : '<div class="empty"><b>Alles sauber</b>Vigil hat in diesem Lauf nichts gefunden.</div>';
    return;
  }
  box.innerHTML = SEV_ORDER.map((s) => {
    const items = list.filter((f) => f.severity === s);
    if (!items.length) return '';
    return `<div class="group-head sev-${s}">${SEV_LABEL[s]} <span class="gcount">${items.length}</span></div>` + items.map(findingCard).join('');
  }).join('');
  box.insertAdjacentHTML('afterbegin', toxicBanner(state.lastFindings));
  bindSolutionControls(box);
  box.querySelectorAll('.card-head').forEach((h) => h.onclick = () => {
    const open = h.parentElement.classList.toggle('open');
    h.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  bindStatusSelects(box, (id, status) => {
    state.lastFindings.forEach((f) => { if (f.id === id) { f.status = status; f.suppressed = HIDDEN_STATUS.has(status); } });
    refreshResultView();
  });
}

// --- Befund-Status (Lebenszyklus) ---------------------------------------
const STATUS_LABEL = { OPEN: 'Offen', IN_PROGRESS: 'In Arbeit', ACCEPTED_RISK: 'Risiko akzeptiert', FALSE_POSITIVE: 'Fehlalarm', RESOLVED: 'Behoben' };
const HIDDEN_STATUS = new Set(['FALSE_POSITIVE', 'ACCEPTED_RISK']);
function statusSelect(id, status) {
  return `<select class="status-select st-${status}" data-id="${esc(id)}" aria-label="Status des Befunds">${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}"${k === status ? ' selected' : ''}>${v}</option>`).join('')}</select>`;
}
function bindStatusSelects(root, onChanged) {
  root.querySelectorAll('.status-select').forEach((sel) => {
    sel.onclick = (e) => e.stopPropagation();
    sel.onchange = async () => {
      const r = await window.vigil.setFindingStatus(sel.dataset.id, sel.value);
      if (r.ok) onChanged(sel.dataset.id, r.status);
      else flash('Status nicht gespeichert: ' + r.error);
    };
  });
}

// Vergleich mit frueheren Laeufen (aus dem Befund-Speicher).
function updateBaselineStatus() {
  const el = $('baselineStatus'); if (!el) return;
  const lc = state.lastResult && state.lastResult.lifecycle;
  if (!lc) { el.textContent = ''; return; }
  if (!state.lastResult.hasBaseline) { el.textContent = 'Erster Lauf für dieses Ziel – ab dem nächsten Lauf siehst du hier, was neu ist und was behoben wurde.'; return; }
  const parts = [`${lc.created} neu`, `${lc.updated} bekannt`];
  if (lc.reopened) parts.push(`${lc.reopened} wieder aufgetaucht`);
  if (lc.resolved) parts.push(`${lc.resolved} automatisch als behoben markiert`);
  el.textContent = 'Im Vergleich zum letzten Lauf: ' + parts.join(' · ') + '.';
}
function renderViewToggles() {
  const box = $('viewToggles'); if (!box) return;
  const r = state.lastResult;
  const newCount = state.lastFindings.filter((f) => f.isNew).length;
  const suppCount = state.lastFindings.filter((f) => f.suppressed).length;
  let html = '';
  if (r && r.hasBaseline && (newCount || state.onlyNew)) html += `<button class="fbtn toggle${state.onlyNew ? ' active' : ''}" data-t="onlyNew">Nur neue (${newCount})</button>`;
  const provenCount = state.lastFindings.filter((f) => !f.suppressed && f.assurance && f.assurance !== 'unverified').length;
  if (state.lastFindings.some((f) => f.assurance === 'unverified') || state.onlyProven) html += `<button class="fbtn toggle${state.onlyProven ? ' active' : ''}" data-t="onlyProven" title="Nur Befunde, die regelbasiert oder per Gegenprüfung bestätigt sind">Nur belegte (${provenCount})</button>`;
  if (suppCount || state.showSuppressed) html += `<button class="fbtn toggle${state.showSuppressed ? ' active' : ''}" data-t="showSupp">Fehlalarme &amp; akzeptierte zeigen (${suppCount})</button>`;
  box.innerHTML = html;
  box.querySelectorAll('.fbtn').forEach((b) => b.onclick = () => {
    if (b.dataset.t === 'onlyNew') state.onlyNew = !state.onlyNew;
    else if (b.dataset.t === 'onlyProven') state.onlyProven = !state.onlyProven;
    else state.showSuppressed = !state.showSuppressed;
    renderViewToggles(); renderFindings();
  });
}
function sourceLabel(s) { return ({ osv: 'Schwachstellen-DB (OSV)', prescan: 'statische Prüfung', webscan: 'Server-Check', nmap: 'nmap', nuclei: 'nuclei', gitleaks: 'gitleaks', trufflehog: 'trufflehog', trivy: 'trivy', grype: 'grype', semgrep: 'semgrep', bandit: 'bandit', checkov: 'checkov', retire: 'retire.js', hadolint: 'hadolint', 'osv-scanner': 'osv-scanner', binary: 'Binary-Analyse', ai: 'KI', 'supply-chain-audit': 'Lieferkette', 'container-host-audit': 'Container-Prüfung', 'semgrep-custom-sast': 'Code-Regeln', 'llm-prompt-security': 'KI-Sicherheit', 'linux-host-audit': 'Server-Konfig', 'web-exposure-audit': 'Web-Exposure', 'web-tls-posture': 'Web/TLS', 'dns-mail-drift': 'DNS & Mail', 'headless-dom-audit': 'Browser-Prüfung', 'api-auth-matrix': 'API-Rechtematrix', correlator: 'Angriffspfad-Analyse' })[s] || s || 'KI'; }

// --- Scan-Verlauf -------------------------------------------------------
async function openHistory() {
  const runs = await window.vigil.historyList();
  renderHistory(runs);
  $('historyOverlay').hidden = false;
}
function renderHistory(runs) {
  const box = $('historyList');
  if (!runs || !runs.length) { box.innerHTML = '<p class="muted">Noch keine Läufe gespeichert.</p>'; return; }
  box.innerHTML = runs.map((r) => {
    const c = r.counts || {};
    const when = new Date(r.at).toLocaleString('de-DE');
    const tgt = (r.targets || []).join(', ');
    return `<button type="button" class="hist-row" data-id="${esc(r.id)}">
      <span class="hist-when">${esc(when)}</span>
      <span class="hist-tgt" title="${esc(tgt)}">${esc(tgt || '—')}</span>
      <span class="hist-counts">${r.total || 0} Befund(e)${c.critical ? ` · ${c.critical} kritisch` : ''}${c.high ? ` · ${c.high} hoch` : ''}</span>
    </button>`;
  }).join('');
  box.querySelectorAll('.hist-row').forEach((b) => b.onclick = async () => {
    const res = await window.vigil.historyOpen(b.dataset.id);
    if (res.ok) { $('historyOverlay').hidden = true; renderResult(res.result); $('resultPanel').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  });
}

// --- Eigene Regeln & Muster --------------------------------------------
function renderCustomRules() {
  const box = $('customRules'); if (!box) return;
  const list = state.config.customRules || (state.config.customRules = []);
  box.innerHTML = list.length ? list.map((r, i) => `
    <div class="rule-row" data-i="${i}">
      <input type="text" class="r-name" placeholder="Name" value="${esc(r.name || '')}" />
      <input type="text" class="r-re" placeholder="Regex, z. B. ACME-[0-9]{6}" value="${esc(r.regex || '')}" />
      <select class="r-sev">${['critical', 'high', 'medium', 'low', 'info'].map((s) => `<option value="${s}"${(r.severity || 'medium') === s ? ' selected' : ''}>${SEV_LABEL[s]}</option>`).join('')}</select>
      <button type="button" class="btn ghost tiny r-del" aria-label="Regel entfernen">✕</button>
    </div>`).join('') : '<p class="muted small">Noch keine eigenen Regeln.</p>';
  box.querySelectorAll('.r-del').forEach((b) => b.onclick = () => {
    collectCustomRules();
    state.config.customRules.splice(+b.closest('.rule-row').dataset.i, 1);
    renderCustomRules();
  });
}
function collectCustomRules() {
  const out = [];
  $('customRules').querySelectorAll('.rule-row').forEach((row) => {
    const name = row.querySelector('.r-name').value.trim();
    const regex = row.querySelector('.r-re').value.trim();
    const severity = row.querySelector('.r-sev').value;
    if (regex) out.push({ name: name || 'Eigene Regel', regex, severity });
  });
  state.config.customRules = out;
}
async function renderDisabledRules() {
  const box = $('disabledRules'); if (!box) return;
  if (!RULE_NAMES) { try { RULE_NAMES = await window.vigil.getRuleNames(); } catch { RULE_NAMES = { secrets: [], patterns: [] }; } }
  const disabled = new Set(state.config.disabledRules || []);
  const all = [...(RULE_NAMES.secrets || []).map((n) => ({ n, g: 'Secret' })), ...(RULE_NAMES.patterns || []).map((p) => ({ n: p.name, g: p.cat }))];
  box.innerHTML = all.map((x) => `<label class="check small"><input type="checkbox" class="r-off" value="${esc(x.n)}"${disabled.has(x.n) ? ' checked' : ''}/> ${esc(x.n)} <span class="muted">(${esc(x.g)})</span></label>`).join('');
}
function collectDisabledRules() {
  state.config.disabledRules = [...$('disabledRules').querySelectorAll('.r-off')].filter((c) => c.checked).map((c) => c.value);
}

// --- KI-Auswahl: Lokal (Ollama) oder Cloud ------------------------------
const CLOUD_IDS = ['anthropic', 'openai', 'gemini', 'compat'];
const MODEL_CACHE = {};
const CUSTOM = '__custom__'; // Sentinel fuer „eigenes Modell eingeben"
const ai = { mode: 'local', ollama: null, recommended: [], pulling: null, busy: false };

const pcfg = (id) => state.config.providers[id] || (state.config.providers[id] = {});
const providerMeta = (id) => state.providers.find((p) => p.id === id) || {};
const saveCfg = () => window.vigil.saveConfig(state.config);
const fmtSize = (b) => (b >= 1e9 ? (b / 1e9).toFixed(1) + ' GB' : Math.max(1, Math.round(b / 1e6)) + ' MB').replace('.', ',');

function pickPreferred(id, models, current) {
  if (current && models.includes(current)) return current;
  const pref = {
    anthropic: [/sonnet/i, /opus/i, /haiku/i],
    openai: [/^gpt-4\.1-mini/i, /4o-mini/i, /mini/i, /^gpt-4o/i, /gpt/i],
    gemini: [/flash/i, /pro/i],
    ollama: [/coder/i, /qwen/i, /llama/i],
    compat: [],
  }[id] || [];
  for (const re of pref) { const m = models.find((x) => re.test(x)); if (m) return m; }
  return models[0] || current || '';
}

function aiReady() {
  if (!state.config) return { ok: false, why: '' };
  if (ai.mode === 'local') {
    const s = ai.ollama;
    if (!s) return { ok: false, why: 'Prüfe Ollama …' };
    if (!s.installed) return { ok: false, why: 'Installiere zuerst Ollama (Schritt 2) – oder wähle „Cloud“.' };
    if (!s.running) return { ok: false, why: 'Starte Ollama in Schritt 2.' };
    if (!s.models.length) return { ok: false, why: 'Lade in Schritt 2 ein Modell herunter, z. B. Qwen 2.5 Coder 7B.' };
    return { ok: true, label: pcfg('ollama').model || 'Ollama' };
  }
  const id = state.config.cloudProvider;
  if (!cloudHasAccess(id)) return { ok: false, why: id === 'compat' ? 'Trage in den Einstellungen die Server-Adresse des Dienstes ein.' : 'Füge in Schritt 2 deinen API-Schlüssel ein.' };
  if (!pcfg(id).model) return { ok: false, why: 'Wähle in Schritt 2 ein Modell.' };
  return { ok: true, label: pcfg(id).model };
}

function setMode(mode) {
  ai.mode = mode;
  state.config.selected = mode === 'local' ? 'ollama' : state.config.cloudProvider;
  saveCfg();
  for (const b of [$('modeLocal'), $('modeCloud')]) {
    const on = b.dataset.mode === mode;
    b.classList.toggle('active', on); b.setAttribute('aria-selected', on ? 'true' : 'false');
  }
  $('localPane').hidden = mode !== 'local';
  $('cloudPane').hidden = mode !== 'cloud';
  if (mode === 'local') refreshOllama(); else refreshCloud();
  updateRunState();
}

// --- Ollama ---------------------------------------------------------------
async function refreshOllama() {
  try { ai.ollama = await window.vigil.ollama.status(); } catch { ai.ollama = { installed: false, running: false, models: [] }; }
  renderOllama(); updateRunState();
}
function setOllamaCard(kind, title, sub, action) {
  $('ollamaDot').className = 'dot ' + kind;
  $('ollamaTitle').textContent = title;
  $('ollamaSub').textContent = sub || '';
  const b = $('ollamaAction');
  b.hidden = !action;
  if (action) { b.textContent = action.label; b.onclick = action.run; b.disabled = false; }
}
function renderOllama() {
  const s = ai.ollama || {};
  if (!s.installed) setOllamaCard('err', 'Ollama ist noch nicht installiert', 'Ollama führt KI-Modelle direkt auf deinem Rechner aus. Die Installation dauert ein, zwei Minuten.', { label: 'Ollama installieren', run: installOllama });
  else if (!s.running) setOllamaCard('wait', 'Ollama ist installiert, läuft aber nicht', 'Vigil kann den Dienst für dich starten.', { label: 'Ollama starten', run: startOllama });
  else setOllamaCard('ok', `Ollama läuft${s.version ? ' · Version ' + s.version : ''}`, s.models.length ? `${s.models.length} ${s.models.length === 1 ? 'Modell' : 'Modelle'} installiert` : 'Noch kein Modell installiert – lade unten eins herunter.', null);
  $('localModelRow').hidden = !(s.running && s.models.length);
  $('modelShop').hidden = !s.running;
  // Mit installiertem Modell ist die Download-Liste Nebensache – eingeklappt, bis man sie oeffnet.
  const shopOpen = ai.shopOpen ?? !(s.models && s.models.length);
  $('modelShop').classList.toggle('collapsed', !shopOpen && !ai.pulling);
  $('shopToggle').setAttribute('aria-expanded', shopOpen ? 'true' : 'false');
  if (s.running) { renderLocalModels(); renderRecommended(); }
}
function renderLocalModels() {
  const models = ai.ollama.models;
  const p = pcfg('ollama');
  const names = models.map((m) => m.name);
  if (!names.includes(p.model)) { p.model = pickPreferred('ollama', names, ''); saveCfg(); }
  $('localModel').innerHTML = models.map((m) => `<option value="${esc(m.name)}"${m.name === p.model ? ' selected' : ''}>${esc(m.name)}${m.size ? ' · ' + fmtSize(m.size) : ''}</option>`).join('');
}
const fullTag = (n) => (n.includes(':') ? n : n + ':latest');
const isInstalled = (n) => ai.ollama.models.some((m) => m.name === n || m.name === fullTag(n));
function renderRecommended() {
  $('recList').innerHTML = ai.recommended.map((r) => {
    const have = isInstalled(r.name);
    const action = have ? '<span class="rec-ok">✓ installiert</span>'
      : `<button class="btn small rec-pull" data-m="${esc(r.name)}"${ai.pulling ? ' disabled' : ''}>Laden</button>`;
    return `<div class="rec${have ? ' have' : ''}">
      <div class="rec-main"><b>${esc(r.label)}</b><span class="muted small">${esc(r.note)}</span></div>
      <span class="rec-meta">${esc(r.size)} · ${esc(r.ram)}</span>${action}</div>`;
  }).join('');
  $('recList').querySelectorAll('.rec-pull').forEach((b) => b.onclick = () => pullModel(b.dataset.m));
  $('customPullBtn').disabled = !!ai.pulling;
}

async function installOllama() {
  ai.busy = true;
  const btn = $('ollamaAction');
  btn.disabled = true; btn.textContent = 'Installiere …';
  $('ollamaSub').textContent = 'Installation über winget (offizielles Paket Ollama.Ollama). Bitte warten …';
  const log = $('ollamaLog'); log.hidden = false; log.textContent = '';
  const lines = [];
  const unsub = window.vigil.ollama.onLog((l) => { lines.push(l); log.textContent = lines.slice(-6).join('\n'); });
  const r = await window.vigil.ollama.install();
  unsub(); ai.busy = false;
  if (r.ok) {
    log.hidden = true;
    ai.ollama = r.status; renderOllama(); updateRunState();
    return;
  }
  setOllamaCard('err', 'Installation hat nicht geklappt', r.error, r.fallback
    ? { label: 'Download-Seite öffnen', run: () => { window.vigil.ollama.openDownload(); $('ollamaSub').textContent = 'Nach der Installation hier einfach weitermachen – Vigil erkennt Ollama automatisch.'; } }
    : { label: 'Erneut versuchen', run: installOllama });
}
async function startOllama() {
  ai.busy = true;
  const btn = $('ollamaAction');
  btn.disabled = true; btn.textContent = 'Starte …';
  const r = await window.vigil.ollama.start();
  ai.busy = false;
  if (r.ok) { ai.ollama = r.status; renderOllama(); updateRunState(); }
  else setOllamaCard('err', 'Ollama ließ sich nicht starten', r.error, { label: 'Erneut versuchen', run: startOllama });
}

const PULL_STATUS = { 'pulling manifest': 'Lade Modell-Infos …', 'verifying sha256 digest': 'Prüfe den Download …', 'writing manifest': 'Schließe ab …', 'removing any unused layers': 'Räume auf …', success: 'Fertig.' };
async function pullModel(name) {
  name = String(name || '').trim();
  if (!name || ai.pulling) return;
  ai.pulling = name; renderRecommended();
  $('pullBox').hidden = false; $('pullName').textContent = name; $('pullPct').textContent = '';
  $('pullFill').style.width = '0%'; $('pullText').textContent = 'Starte Download …'; $('pullCancel').hidden = false;
  const unsub = window.vigil.ollama.onProgress((p) => {
    if (p.model !== name) return;
    if (p.percent != null && p.total) {
      $('pullFill').style.width = p.percent + '%';
      $('pullPct').textContent = p.percent + ' %';
      $('pullText').textContent = `${fmtSize(p.completed)} von ${fmtSize(p.total)}`;
    } else $('pullText').textContent = PULL_STATUS[p.status] || p.status;
  });
  const r = await window.vigil.ollama.pull(name);
  unsub(); ai.pulling = null; $('pullCancel').hidden = true;
  if (r.ok) {
    $('pullFill').style.width = '100%'; $('pullPct').textContent = '100 %';
    $('pullText').textContent = '✓ Installiert und ausgewählt.';
    pcfg('ollama').model = fullTag(name); saveCfg();
    $('customPull').value = '';
    await refreshOllama();
    setTimeout(() => { if (!ai.pulling) $('pullBox').hidden = true; }, 2500);
  } else {
    $('pullText').textContent = '✕ ' + r.error;
    renderRecommended();
  }
}

// --- Cloud ----------------------------------------------------------------
function cloudHasAccess(id) {
  const c = pcfg(id);
  if (id === 'compat') return !!c.baseUrl;
  return !!(providerMeta(id).envKeyPresent || c.apiKey);
}
function setCloudStatus(kind, msg) {
  $('cloudStatus').textContent = msg;
  $('cloudStatus').className = 'model-status small ' + (kind === 'ok' ? 'ok' : kind === 'err' ? 'err' : 'muted');
}
function buildCloudSelect(id) {
  const c = pcfg(id);
  const list = MODEL_CACHE[id] || [];
  const custom = !!(c.model && list.length && !list.includes(c.model));
  let opts = list.map((m) => `<option value="${esc(m)}"${m === c.model ? ' selected' : ''}>${esc(m)}</option>`).join('');
  if (!list.length) opts = c.model ? `<option value="${esc(c.model)}" selected>${esc(c.model)}</option>` : '<option value="" disabled selected>– zuerst Schlüssel eingeben –</option>';
  opts += `<option value="${CUSTOM}"${custom ? ' selected' : ''}>Anderes Modell eingeben …</option>`;
  $('cloudModel').innerHTML = opts;
  $('cloudModelManual').hidden = !custom;
  if (custom) $('cloudModelManual').value = c.model;
}
function refreshCloud() {
  const id = state.config.cloudProvider;
  const meta = providerMeta(id), c = pcfg(id);
  $('cloudProvider').value = id;
  $('cloudKey').value = c.apiKey || '';
  $('cloudKey').placeholder = meta.envKeyPresent ? 'aus .env erkannt – hier überschreibbar' : (id === 'compat' ? 'optional – nur falls der Dienst einen verlangt' : 'API-Schlüssel einfügen');
  $('cloudKeyBadge').hidden = !meta.envKeyPresent;
  buildCloudSelect(id);
  if (cloudHasAccess(id)) loadCloudModels(id);
  else setCloudStatus('muted', id === 'compat' ? 'Für OpenAI-kompatible Dienste die Server-Adresse in den Einstellungen eintragen.' : 'Schlüssel eingeben – die Modelle laden dann automatisch.');
}
async function loadCloudModels(id) {
  const c = pcfg(id);
  setCloudStatus('muted', 'Lade Modelle …');
  const r = await window.vigil.loadModels({ providerId: id, apiKey: c.apiKey || '', baseUrl: c.baseUrl || '' });
  if (id !== state.config.cloudProvider) return; // inzwischen gewechselt
  if (!r.ok) { buildCloudSelect(id); setCloudStatus('err', '✕ ' + r.error + (id === 'anthropic' ? ' (Schlüssel korrekt? Guthaben vorhanden?)' : '')); updateRunState(); return; }
  MODEL_CACHE[id] = r.models;
  if (!c.model || r.models.includes(c.model) || !r.models.length) {
    const picked = pickPreferred(id, r.models, c.model || '');
    if (picked !== c.model) { c.model = picked; saveCfg(); }
  }
  buildCloudSelect(id);
  setCloudStatus(r.models.length ? 'ok' : 'err', r.models.length ? `✓ Verbunden · ${r.models.length} Modelle verfügbar` : 'Keine Modelle gefunden – Namen über „Anderes Modell eingeben“ eintragen.');
  updateRunState();
}

// --- Uebersicht (Dashboard über alle Läufe) ------------------------------
const dash = { status: 'OPEN,IN_PROGRESS', severity: '', targetId: '', q: '', newSinceBaseline: false, toxic: false };
const gradeOf = (score) => (score >= 92 ? 'A' : score >= 78 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : score >= 20 ? 'E' : 'F');
const RUN_LABEL = { QUEUED: 'wartet', RUNNING: 'läuft', COMPLETED: 'fertig', FAILED: 'fehlgeschlagen' };
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }) : '–');

function showView(v) {
  $('checkView').hidden = v !== 'check';
  $('dashView').hidden = v !== 'dash';
  for (const [id, name] of [['tabCheck', 'check'], ['tabDash', 'dash']]) {
    $(id).classList.toggle('active', v === name);
    $(id).setAttribute('aria-selected', v === name ? 'true' : 'false');
  }
  if (v === 'dash') loadDashboard();
}

async function loadDashboard() {
  const { stats, findings } = await window.vigil.dashboard({ ...dash, limit: 500 });
  // Kennzahlen: offene + in Arbeit befindliche Befunde nach Schweregrad
  $('dashStats').innerHTML = SEV_ORDER.map((s) => `<div class="stat c-${SEV_CLS[s]}${s === 'critical' && stats.open[s] ? ' alarm' : ''}"><span class="stat-n">${stats.open[s] || 0}</span><span class="stat-l">${SEV_LABEL[s]}</span></div>`).join('');
  $('dashSummary').textContent = stats.openTotal
    ? `${stats.openTotal} ${stats.openTotal === 1 ? 'Befund ist' : 'Befunde sind'} offen über ${stats.targets.length} ${stats.targets.length === 1 ? 'Ziel' : 'Ziele'}. ${stats.byStatus.RESOLVED || 0} behoben, ${(stats.byStatus.FALSE_POSITIVE || 0) + (stats.byStatus.ACCEPTED_RISK || 0)} als Fehlalarm oder akzeptiertes Risiko markiert.`
    : (stats.targets.length ? 'Keine offenen Befunde – alles im grünen Bereich.' : 'Noch keine Prüfungen gespeichert. Starte unter „Prüfen“ deinen ersten Lauf.');
  $('dashStatus').querySelectorAll('.fbtn').forEach((b) => b.classList.toggle('active', b.dataset.s === dash.status));
  // Sicherheitswert, Angriffspfade, Threat-Intel
  const sc = $('dashScore');
  sc.style.setProperty('--p', stats.posture);
  sc.style.setProperty('--tone', stats.posture >= 78 ? 'var(--low)' : stats.posture >= 50 ? 'var(--med)' : 'var(--crit)');
  $('dashGrade').textContent = stats.targets.length ? gradeOf(stats.posture) : '–';
  $('dashScoreLabel').textContent = stats.targets.length ? `${stats.posture} / 100` : 'Sicherheitswert';
  $('dashToxic').innerHTML = stats.toxic.length ? `<div class="toxic-banner" role="alert"><div class="toxic-ico">⚠</div><div><b>${stats.toxic.length} ${stats.toxic.length === 1 ? 'Angriffspfad' : 'Angriffspfade'} offen</b><ul>${stats.toxic.map((t) => `<li>${esc(t.title.replace(/^Angriffspfad:\s*/, ''))} <span class="muted small">· ${esc(t.targetName)}</span></li>`).join('')}</ul></div></div>` : '';
  try {
    const it = await window.vigil.intelStatus();
    $('intelLine').textContent = `${stats.kev ? `${stats.kev} offene Lücke(n) werden aktiv ausgenutzt (CISA KEV). ` : ''}${stats.newSinceBaseline} offen seit Baseline · Threat-Intel ${it.updatedAt ? 'vom ' + fmtDate(it.updatedAt) + ` (${it.kev} KEV, ${it.epss} EPSS)` : 'noch nicht geladen'}`;
  } catch { /* Vorschau */ }
  $('dashToggles').querySelectorAll('.fbtn').forEach((b) => b.classList.toggle('active', !!dash[b.dataset.t]));
  renderDashTargets(stats.targets);
  renderDashRuns(stats.runs);
  renderDashTable(findings, stats.targets);
}

function renderDashTargets(targets) {
  const box = $('dashTargets');
  if (!targets.length) { box.innerHTML = '<p class="muted small">Noch keine Ziele.</p>'; return; }
  box.innerHTML = targets.map((t) => {
    const o = t.open;
    const pills = SEV_ORDER.filter((s) => o[s]).map((s) => `<span class="mini-pill c-${SEV_CLS[s]}">${o[s]}</span>`).join('') || '<span class="ok-text">✓ nichts offen</span>';
    return `<div class="tgt-row${dash.targetId === t.id ? ' active' : ''}" data-id="${esc(t.id)}">
      <span class="t-kind ${t.type}">${KIND_LABEL[t.type] || t.type}</span>
      <button class="tgt-name" data-filter="${esc(t.id)}" title="${esc(t.identifier)}">${esc(t.name)}</button>
      ${t.type === 'url' || t.type === 'endpoint' ? `<span class="verified${t.verified ? '' : ' no'}" title="${t.verified ? 'Freigegeben' : 'Nicht freigegeben'}">${t.verified ? 'freigegeben' : 'nicht freigegeben'}</span>` : ''}
      <span class="tgt-pills">${pills}</span>
      <span class="muted small tgt-when">${fmtDate(t.lastScanAt)}</span>
      <span class="tgt-actions">
        ${(t.type === 'url' || t.type === 'endpoint') && !t.ownershipVerified ? `<button class="btn tiny verify" data-id="${esc(t.id)}" title="Für tiefe Prüfungen (offene Dateien, SourceMaps, Browser, API) Domain-Besitz nachweisen">Verifizieren</button>` : ''}
        ${t.ownershipVerified ? '<span class="verified" title="Domain-Besitz nachgewiesen">✓ verifiziert</span>' : ''}
        <button class="btn tiny baseline" data-id="${esc(t.id)}" title="Alle derzeit offenen Befunde als bekannt markieren – danach zeigt „Nur neu seit Baseline“ nur Neues">Baseline</button>
        <button class="btn tiny rescan" data-id="${esc(t.id)}">Erneut prüfen</button>
      </span>
      <div class="verify-box" id="vb-${esc(t.id)}" hidden></div>
    </div>`;
  }).join('');
  box.querySelectorAll('.tgt-name').forEach((b) => b.onclick = () => { dash.targetId = dash.targetId === b.dataset.filter ? '' : b.dataset.filter; loadDashboard(); });
  box.querySelectorAll('.baseline').forEach((b) => b.onclick = async () => {
    const r = await window.vigil.setBaseline(b.dataset.id);
    b.textContent = r.ok ? `✓ ${r.count} gemerkt` : 'Fehler';
    setTimeout(loadDashboard, 900);
  });
  box.querySelectorAll('.verify').forEach((b) => b.onclick = async () => {
    const vb = $('vb-' + b.dataset.id);
    const info = await window.vigil.targetInfo(b.dataset.id);
    const t = info.target;
    let host = t.identifier; try { host = new URL(t.identifier).hostname; } catch { /* Server */ }
    const dom = host.split('.').slice(-2).join('.');
    vb.hidden = false;
    vb.innerHTML = `Lege <b>eine</b> der beiden Varianten an und klicke dann auf „Jetzt prüfen“:<br>
      1. DNS-TXT-Eintrag <code>_sec-audit-verify.${esc(dom)}</code> mit dem Wert <code>${esc(t.verificationToken)}</code><br>
      2. Datei <code>https://${esc(host)}/.well-known/sec-audit.txt</code> mit dem Inhalt <code>${esc(t.verificationToken)}</code><br>
      <button class="btn tiny" id="vbtn-${esc(t.id)}" style="margin-top:8px">Jetzt prüfen</button> <span id="vst-${esc(t.id)}"></span>`;
    $('vbtn-' + t.id).onclick = async () => {
      $('vst-' + t.id).textContent = 'Prüfe …';
      const r = await window.vigil.verifyTarget(t.id);
      $('vst-' + t.id).textContent = r.ok ? `✓ Verifiziert (${r.method})` : r.error;
      if (r.ok) setTimeout(loadDashboard, 800);
    };
  });
  box.querySelectorAll('.rescan').forEach((b) => b.onclick = () => {
    const t = targets.find((x) => x.id === b.dataset.id);
    if (!t) return;
    state.targets = [{ type: t.type, value: t.identifier, authorized: t.verified }];
    renderTargets();
    showView('check');
    if ($('runBtn').disabled) { flash($('runHint').textContent || 'Ziel übernommen – wähle eine KI und starte.'); return; }
    runAudit();
  });
}

function renderDashRuns(runs) {
  $('dashRuns').innerHTML = runs.length ? runs.slice(0, 8).map((r) => `<div class="run-row-item">
    <span class="run-st st-${r.status}">${RUN_LABEL[r.status] || r.status}</span>
    <span class="run-tgt" title="${esc(r.targets.map((t) => t.value).join(', '))}">${esc(r.targets.map((t) => t.value).join(', ') || '–')}</span>
    <span class="muted small">${r.summary ? `${r.summary.total ?? 0} Befunde · ${r.summary.created || 0} neu · ${r.summary.resolved || 0} behoben` : (r.errorLog ? esc(r.errorLog) : '')}</span>
    <span class="muted small">${r.origin === 'api' ? 'API · ' : ''}${fmtDate(r.finishedAt || r.startedAt || r.createdAt)}</span>
  </div>`).join('') : '<p class="muted small">Noch keine Läufe.</p>';
}

function renderDashTable(findings, targets) {
  const tgt = targets.find((t) => t.id === dash.targetId);
  $('dashTargetFilter').hidden = !tgt;
  if (tgt) $('dashTargetName').textContent = tgt.name;
  const box = $('dashTable');
  if (!findings.length) { box.innerHTML = '<div class="empty"><b>Keine Befunde</b>In dieser Ansicht gibt es nichts – Filter anpassen.</div>'; return; }
  box.innerHTML = `<table class="ftable"><thead><tr><th>Schwere</th><th>Befund</th><th>Ziel</th><th>Zuletzt gesehen</th><th>Status</th></tr></thead><tbody>${findings.map((f) => `
    <tr class="sev-${f.severity}">
      <td><span class="sev-tag">${SEV_LABEL[f.severity]}</span></td>
      <td class="ft-main"><b title="${esc(f.title)}">${esc(cleanTitle(f.title))}</b><span class="f-loc" title="${esc(f.location)}">${esc(f.location)}</span>${f.statusNote ? `<span class="muted small">${esc(f.statusNote)}</span>` : ''}</td>
      <td class="ft-tgt" title="${esc(f.targetName)}">${esc(f.targetName)}</td>
      <td class="muted small ft-when" title="Zuerst gesehen: ${esc(fmtDate(f.firstSeenAt))}">${fmtDate(f.lastSeenAt)}</td>
      <td>${statusSelect(f.id, f.status)}</td>
    </tr>`).join('')}</tbody></table>`;
  bindStatusSelects(box, () => loadDashboard());
}

// --- Einstellungen ------------------------------------------------------
function tempText(v) {
  if (v <= 0.2) return 'Niedrig – genaue, nachvollziehbare Ergebnisse (empfohlen).';
  if (v <= 0.5) return 'Mittel – etwas freier formuliert.';
  return 'Hoch – kreativer, aber weniger zuverlässig. Für Sicherheitsprüfungen nicht ideal.';
}
function renderSettings() {
  const t = state.config.temperature ?? 0.1;
  $('tempRange').value = t; $('tempVal').textContent = t; $('tempDesc').textContent = tempText(t);
  $('cveChk').checked = state.config.cveLookup !== false;
  $('depthSelect').value = state.config.analysisDepth === 'standard' ? 'standard' : 'thorough';
  $('activeChk').checked = !!state.config.activeScan;
  $('validateChk').checked = state.config.aiValidation !== false;
  $('redactChk').checked = state.config.redactSecrets !== false;
  $('domChk').checked = state.config.domAudit !== false;
  window.vigil.intelStatus().then((it) => { $('intelSettings').textContent = it.updatedAt ? `Stand ${fmtDate(it.updatedAt)} · ${it.kev} aktiv ausgenutzte CVEs · ${it.epss} EPSS-Werte` : 'Noch nicht geladen – wird automatisch täglich aktualisiert.'; }).catch(() => {});
  window.vigil.apiMatrixGet().then((list) => {
    const m = list[0] || {};
    $('amHost').value = m.host || ''; $('amResource').value = m.resourceIdA || ''; $('amEndpoints').value = (m.endpoints || []).join('\n');
    $('amTokenA').value = ''; $('amTokenB').value = '';
    $('amStatus').textContent = m.host ? `Gespeichert für ${m.host}: Token A ${m.hasTokenA ? '✓' : '–'}, Token B ${m.hasTokenB ? '✓' : '–'}` : 'Noch nicht eingerichtet.';
  }).catch(() => {});
  $('allowlistInput').value = (state.config.allowlist || []).join('\n');
  $('apiChk').checked = !!state.config.apiEnabled;
  $('apiPort').value = state.config.apiPort || 7811;
  refreshApiInfo();

  $('proxyInput').value = state.config.proxyUrl || '';
  $('proxyTestStatus').textContent = '';
  $('proxyTestBtn').onclick = async () => {
    const st = $('proxyTestStatus'); const url = $('proxyInput').value.trim();
    state.config.proxyUrl = url; saveCfg();
    st.textContent = 'Teste Verbindung …'; st.className = 'muted small';
    const r = await window.vigil.testProxy(url);
    if (r.ok) { st.textContent = (r.usingProxy ? '✔ Proxy aktiv. ' : 'Direktverbindung (kein Proxy gesetzt). ') + 'Nach außen sichtbare IP: ' + r.ip; st.className = 'model-status ok small'; }
    else { st.textContent = '✕ Proxy nicht nutzbar: ' + r.error; st.className = 'model-status err small'; }
  };

  renderCustomRules();
  renderDisabledRules();

  // Nur Server-Adressen – Schluessel und Modelle werden direkt auf dem Hauptschirm gewaehlt.
  $('providerSettings').innerHTML = state.providers.map((p) => `
    <label class="url-row"><span>${esc(p.label)}</span>
      <input type="text" data-p="${p.id}" data-k="baseUrl" placeholder="${esc(p.defaultBaseUrl || 'https://…/v1')}" value="${esc(pcfg(p.id).baseUrl || '')}" />
    </label>`).join('');
}
function collectSettings() {
  state.config.temperature = parseFloat($('tempRange').value) || 0;
  state.config.cveLookup = $('cveChk').checked;
  state.config.analysisDepth = $('depthSelect').value;
  state.config.activeScan = $('activeChk').checked;
  state.config.aiValidation = $('validateChk').checked;
  state.config.redactSecrets = $('redactChk').checked;
  state.config.domAudit = $('domChk').checked;
  // API-Rechtematrix separat speichern – Tokens gehen verschluesselt in den Main-Prozess
  if ($('amHost').value.trim() || $('amEndpoints').value.trim()) {
    window.vigil.apiMatrixSave([{ host: $('amHost').value, resourceIdA: $('amResource').value, endpoints: $('amEndpoints').value, tokenA: $('amTokenA').value, tokenB: $('amTokenB').value }]);
  }
  state.config.allowlist = $('allowlistInput').value.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
  state.config.apiEnabled = $('apiChk').checked;
  state.config.apiPort = Math.min(65535, Math.max(1024, parseInt($('apiPort').value, 10) || 7811));
  state.config.proxyUrl = $('proxyInput').value.trim();
  $('providerSettings').querySelectorAll('input[data-k="baseUrl"]').forEach((inp) => { pcfg(inp.dataset.p).baseUrl = inp.value.trim(); });
  collectCustomRules();
  collectDisabledRules();
}
async function refreshApiInfo() {
  const info = await window.vigil.apiInfo();
  $('apiToken').value = info.token || '';
  $('apiStatus').textContent = info.running ? `✓ Läuft auf http://127.0.0.1:${info.port}` : (info.enabled ? 'Aktiviert, aber nicht gestartet – ist der Port belegt?' : 'Aus.');
  $('apiStatus').className = 'small ' + (info.running ? 'model-status ok' : 'muted');
  $('apiExample').textContent = `curl -H "Authorization: Bearer <Token>" http://127.0.0.1:${info.port || 7811}/api/findings?status=OPEN`;
}
function openSettings() { renderSettings(); $('settingsOverlay').hidden = false; }
function closeSettings() { $('settingsOverlay').hidden = true; }

// --- Init ---------------------------------------------------------------
async function init() {
  state.providers = await window.vigil.getProviders();
  state.config = await window.vigil.getConfig();
  state.config.providers = state.config.providers || {};
  try { ai.recommended = await window.vigil.ollama.recommended(); } catch { ai.recommended = []; }

  const sel = state.config.selected || 'ollama';
  if (!CLOUD_IDS.includes(state.config.cloudProvider)) state.config.cloudProvider = CLOUD_IDS.includes(sel) ? sel : 'anthropic';

  // Schritt 1: Ziele
  setupDropzone();
  $('pickFilesBtn').onclick = async (e) => { e.stopPropagation(); (await window.vigil.pickFiles()).forEach((p) => addTarget('path', p)); };
  $('pickFolderBtn').onclick = async (e) => { e.stopPropagation(); (await window.vigil.pickFolder()).forEach((p) => addTarget('path', p)); };
  $('targetInput').addEventListener('input', onTargetInput);
  $('targetInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') addTypedTarget(); });
  $('addTargetBtn').onclick = addTypedTarget;
  $('clearBtn').onclick = () => { state.targets = []; renderTargets(); };

  // Schritt 2: KI
  $('modeLocal').onclick = () => setMode('local');
  $('modeCloud').onclick = () => setMode('cloud');
  $('localModel').onchange = () => { pcfg('ollama').model = $('localModel').value; saveCfg(); updateRunState(); };
  $('customPullBtn').onclick = () => pullModel($('customPull').value);
  $('customPull').addEventListener('keydown', (e) => { if (e.key === 'Enter') pullModel($('customPull').value); });
  $('pullCancel').onclick = () => window.vigil.ollama.cancelPull();
  $('shopToggle').onclick = () => { ai.shopOpen = $('modelShop').classList.contains('collapsed'); renderOllama(); };

  $('cloudProvider').innerHTML = CLOUD_IDS.map((id) => `<option value="${id}">${esc(providerMeta(id).label || id)}</option>`).join('');
  $('cloudProvider').onchange = () => { state.config.cloudProvider = $('cloudProvider').value; state.config.selected = state.config.cloudProvider; saveCfg(); refreshCloud(); updateRunState(); };
  $('cloudKey').onchange = () => { const id = state.config.cloudProvider; pcfg(id).apiKey = $('cloudKey').value.trim(); saveCfg(); refreshCloud(); updateRunState(); };
  $('cloudKeyToggle').onclick = () => {
    const i = $('cloudKey'); i.type = i.type === 'password' ? 'text' : 'password';
    $('cloudKeyToggle').textContent = i.type === 'password' ? 'anzeigen' : 'verbergen';
  };
  $('cloudLoadBtn').onclick = () => { const id = state.config.cloudProvider; if (cloudHasAccess(id)) loadCloudModels(id); else refreshCloud(); };
  $('cloudModel').onchange = () => {
    const id = state.config.cloudProvider;
    if ($('cloudModel').value === CUSTOM) { $('cloudModelManual').hidden = false; $('cloudModelManual').focus(); return; }
    $('cloudModelManual').hidden = true;
    pcfg(id).model = $('cloudModel').value; saveCfg(); updateRunState();
  };
  $('cloudModelManual').onchange = () => { const v = $('cloudModelManual').value.trim(); if (v) { pcfg(state.config.cloudProvider).model = v; saveCfg(); updateRunState(); } };

  setMode(sel === 'ollama' ? 'local' : 'cloud');
  // Ollama nachtraeglich erkennen (z. B. von Hand gestartet oder installiert).
  setInterval(() => { if (ai.mode === 'local' && !ai.busy && !ai.pulling && !(ai.ollama && ai.ollama.running)) refreshOllama(); }, 4000);

  // Schritt 3 + Ergebnis
  $('runBtn').onclick = runAudit;
  $('findingSearch').addEventListener('input', () => { state.query = $('findingSearch').value; renderFindings(); });
  $('cancelBtn').onclick = async () => { $('cancelBtn').disabled = true; $('progressTitle').textContent = 'Wird abgebrochen …'; await window.vigil.cancelAudit(); };
  $('logToggle').onclick = () => {
    const log = $('log'); log.hidden = !log.hidden;
    $('logToggle').setAttribute('aria-expanded', log.hidden ? 'false' : 'true');
    $('logToggle').textContent = (log.hidden ? '▸' : '▾') + ' Technische Details';
  };
  const exportAs = (fmt) => async () => {
    if (fmt === 'pdf') flash('Erzeuge PDF …');
    const r = await window.vigil.saveReport(fmt);
    flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error));
  };
  $('exportHtmlBtn').onclick = exportAs('html');
  $('exportMdBtn').onclick = exportAs('md');
  $('exportSarifBtn').onclick = exportAs('sarif');
  $('exportPdfBtn').onclick = exportAs('pdf');
  // Ansichten: Pruefen | Uebersicht
  $('tabCheck').onclick = () => showView('check');
  $('tabDash').onclick = () => showView('dash');
  $('dashStatus').querySelectorAll('.fbtn').forEach((b) => b.onclick = () => { dash.status = b.dataset.s; loadDashboard(); });
  $('dashSeverity').onchange = () => { dash.severity = $('dashSeverity').value; loadDashboard(); };
  let dashTimer = null;
  $('dashSearch').addEventListener('input', () => { clearTimeout(dashTimer); dashTimer = setTimeout(() => { dash.q = $('dashSearch').value; loadDashboard(); }, 200); });
  $('dashTargetClear').onclick = () => { dash.targetId = ''; loadDashboard(); };
  $('dashToggles').querySelectorAll('.fbtn').forEach((b) => b.onclick = () => { dash[b.dataset.t] = !dash[b.dataset.t]; loadDashboard(); });
  let sbomTimer = null;
  $('sbomSearch').addEventListener('input', () => {
    clearTimeout(sbomTimer);
    sbomTimer = setTimeout(async () => {
      const q = $('sbomSearch').value.trim();
      if (q.length < 2) { $('sbomResults').innerHTML = ''; return; }
      const hits = await window.vigil.searchSbom(q);
      $('sbomResults').innerHTML = hits.length
        ? hits.map((h) => `<div class="sbom-hit"><code>${esc(h.name)}@${esc(h.version || '?')}</code><span class="muted small">${esc(h.ecosystem || '')}</span><span>${esc(h.targetName)}</span></div>`).join('')
        : '<p class="muted small">Nicht gefunden – in keinem geprüften Projekt im Einsatz.</p>';
    }, 180);
  });
  $('exportJsonBtn').onclick = exportAs('json');
  $('intelSyncBtn').onclick = async () => { $('intelSettings').textContent = 'Lade CISA KEV und EPSS …'; const r = await window.vigil.syncIntel(); $('intelSettings').textContent = r.ok ? (r.notes || []).join(' · ') || 'Aktuell.' : 'Fehler: ' + r.error; };
  $('apiRegen').onclick = async () => { await window.vigil.regenerateApiToken(); refreshApiInfo(); };
  $('apiCopy').onclick = async () => { try { await navigator.clipboard.writeText($('apiToken').value); $('apiStatus').textContent = 'Token kopiert.'; } catch { $('apiToken').select(); } };
  $('apiTokenToggle').onclick = () => { const i = $('apiToken'); i.type = i.type === 'password' ? 'text' : 'password'; };
  $('clearStoreBtn').onclick = async () => {
    if (!confirm('Alle gespeicherten Befunde, Status und Läufe löschen? Das lässt sich nicht rückgängig machen.')) return;
    await window.vigil.clearStore();
    $('clearStoreStatus').textContent = 'Befund-Speicher geleert.';
  };

  // Verlauf + Einstellungen
  $('historyBtn').onclick = openHistory;
  $('historyClose').onclick = () => { $('historyOverlay').hidden = true; };
  $('historyOverlay').addEventListener('click', (e) => { if (e.target === $('historyOverlay')) $('historyOverlay').hidden = true; });
  $('historyClearBtn').onclick = async () => { await window.vigil.historyClear(); renderHistory([]); $('historyStatus').textContent = 'Verlauf geleert.'; setTimeout(() => { $('historyStatus').textContent = ''; }, 1200); };
  $('addRuleBtn').onclick = () => { collectCustomRules(); state.config.customRules.push({ name: '', regex: '', severity: 'medium' }); renderCustomRules(); };
  $('settingsBtn').onclick = openSettings;
  $('settingsClose').onclick = closeSettings;
  $('settingsOverlay').addEventListener('click', (e) => { if (e.target === $('settingsOverlay')) closeSettings(); });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    if (!$('settingsOverlay').hidden) closeSettings();
    if (!$('historyOverlay').hidden) $('historyOverlay').hidden = true;
  });
  $('tempRange').addEventListener('input', () => { $('tempVal').textContent = $('tempRange').value; $('tempDesc').textContent = tempText(parseFloat($('tempRange').value)); });
  $('settingsSave').onclick = async () => {
    collectSettings();
    const r = await saveCfg();
    $('settingsStatus').textContent = r && r.ok ? 'Gespeichert.' : 'Fehler beim Speichern.';
    if (ai.mode === 'cloud') refreshCloud(); else refreshOllama();
    setTimeout(() => { $('settingsStatus').textContent = ''; closeSettings(); }, 600);
  };

  renderTargets();
}
function flash(msg) { $('runHint').textContent = msg; }

init();
