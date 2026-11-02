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
const KIND_LABEL = { path: 'Datei/Ordner', url: 'Webadresse', endpoint: 'Server', image: 'Container-Image', system: 'System' };
const SYSTEM_LABEL = { windows: 'Dieser Windows-PC', docker: 'Laufende Docker-Container', aws: 'AWS-Konto', azure: 'Azure-Abonnement', gcp: 'Google-Cloud-Projekt' };
function addTarget(type, value, authorized = false) {
  if (!value) return;
  if (state.targets.some((t) => t.type === type && t.value === value)) return;
  state.targets.push({ type, value, authorized });
  renderTargets();
}
// --- Bekannte & vertraute Ziele ---------------------------------------------
// Quelle: alle bisher geprueften Ziele (Befund-Speicher) plus die Freigabeliste.
// "Vertraut" = Host steht auf der Freigabeliste -> Pruefung ohne erneute Rueckfrage.
const known = { list: [], open: false, filter: 'all', q: '' };
const allowMatches = (e, host) => (e.startsWith('*.') ? host === e.slice(2) || host.endsWith(e.slice(1)) : host === e || host.endsWith('.' + e));
async function loadKnown() {
  let targets = [];
  try { targets = ((await window.vigil.dashboard({ limit: 1 })).stats || {}).targets || []; } catch { /* Vorschau */ }
  const items = targets.filter((t) => !t.hiddenFromPicker).map((t) => {
    const host = t.type === 'url' || t.type === 'endpoint' ? hostOfTarget({ type: t.type, value: t.identifier }) : '';
    return { id: t.id, type: t.type, value: t.identifier, name: t.type === 'system' ? SYSTEM_LABEL[t.identifier] || t.name : t.type === 'url' ? String(t.identifier).replace(/^https?:\/\//, '').replace(/\/$/, '') : t.name, host, trusted: !!host && isAllowlisted(host), verified: !!t.ownershipVerified, lastScanAt: t.lastScanAt, open: t.open ? t.open.total : 0 };
  });
  // Freigaben, zu denen es noch keinen Lauf gibt
  for (const e of state.config.allowlist || []) {
    if (items.some((i) => i.host && allowMatches(e, i.host))) continue;
    const h = e.replace(/^\*\./, '');
    items.push({ id: null, type: 'url', value: 'https://' + h, name: e, host: h, trusted: true, verified: false, lastScanAt: null, open: 0, allowOnly: true });
  }
  known.list = items;
  renderKnown();
}
function renderKnown() {
  const box = $('knownBox');
  box.hidden = known.list.length === 0;
  $('knownCount').textContent = known.list.length;
  const nTrusted = known.list.filter((k) => k.trusted).length;
  $('knownHint').textContent = nTrusted ? `${nTrusted} vertraut` : '';
  $('knownToggle').setAttribute('aria-expanded', String(known.open));
  $('knownPanel').hidden = !known.open;
  box.classList.toggle('open', known.open);
  $('knownPanel').querySelectorAll('[data-kf]').forEach((b) => b.classList.toggle('active', b.dataset.kf === known.filter));
  const q = known.q.toLowerCase();
  const rows = known.list.filter((k) => (known.filter === 'all' || k.trusted) && (!q || `${k.name} ${k.value}`.toLowerCase().includes(q)));
  const inList = (k) => state.targets.some((t) => t.type === k.type && t.value === k.value);
  $('knownList').innerHTML = rows.length ? rows.map((k) => {
    const i = known.list.indexOf(k);
    const added = inList(k);
    return `<li class="known-row${added ? ' added' : ''}">
      <button type="button" class="known-main" data-add="${i}" ${added ? 'disabled' : ''} title="${esc(k.value)}">
        <span class="t-kind ${k.type}">${KIND_LABEL[k.type] || k.type}</span>
        <span class="known-name">${esc(k.name)}</span>
        ${k.trusted ? '<span class="badge trust" title="Wird ohne erneute Rückfrage geprüft">✓ vertraut</span>' : ''}
        ${k.verified ? '<span class="badge verified" title="Domain-Besitz nachgewiesen – tiefe Prüfungen erlaubt">Domain nachgewiesen</span>' : ''}
        <span class="known-meta muted small">${added ? 'in der Prüfliste' : k.lastScanAt ? `zuletzt ${esc(fmtDate(k.lastScanAt))}${k.open ? ` · ${k.open} offen` : ''}` : 'noch nicht geprüft'}</span>
      </button>
      <span class="known-actions">
        ${k.trusted || k.verified ? `<button type="button" class="btn tiny ghost" data-untrust="${i}">Vertrauen entziehen</button>` : ''}
        ${k.id ? `<button type="button" class="btn tiny ghost" data-hide="${i}" title="Nur aus dieser Liste entfernen">Ausblenden</button>` : ''}
      </span>
    </li>`;
  }).join('') : `<li class="muted small known-empty">${known.filter === 'trusted' ? 'Keine vertrauten Ziele.' : 'Nichts gefunden.'}</li>`;
}
async function untrustKnown(k) {
  const entries = (state.config.allowlist || []).filter((e) => k.host && allowMatches(e, k.host));
  const what = entries.length ? `Freigabe ${entries.join(', ')}` : 'Domain-Nachweis';
  if (!confirm(`${k.name} nicht mehr vertrauen?\n\nEntfernt: ${what}.${k.verified ? '\nDer Domain-Nachweis wird ebenfalls zurückgenommen – tiefe Prüfungen brauchen dann einen neuen Nachweis.' : ''}\nBeim nächsten Prüfen fragt Vigil wieder nach der Berechtigung.`)) return;
  state.config.allowlist = (state.config.allowlist || []).filter((e) => !entries.includes(e));
  await saveCfg();
  if (k.id && k.verified) { try { await window.vigil.setTargetMeta(k.id, { ownershipVerified: false }); } catch { /* egal */ } }
  // Bereits in der Pruefliste: herausnehmen – zum Pruefen muss die Berechtigung neu bestaetigt werden
  const before = state.targets.length;
  state.targets = state.targets.filter((t) => !((t.type === 'url' || t.type === 'endpoint') && hostOfTarget(t) === k.host));
  renderTargets();
  toast(`${k.name} wird nicht mehr automatisch vertraut${state.targets.length < before ? ' – aus der Prüfliste genommen' : ''}`, 'ok');
  loadKnown();
}
function setupKnown() {
  $('knownToggle').onclick = () => { known.open = !known.open; renderKnown(); if (known.open) $('knownSearch').focus(); };
  $('knownSearch').addEventListener('input', () => { known.q = $('knownSearch').value; renderKnown(); });
  $('knownPanel').querySelectorAll('[data-kf]').forEach((b) => b.onclick = () => { known.filter = b.dataset.kf; renderKnown(); });
  $('knownList').addEventListener('click', async (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const k = known.list[Number(b.dataset.add ?? b.dataset.untrust ?? b.dataset.hide)];
    if (!k) return;
    if (b.dataset.add != null) { addTarget(k.type, k.value, k.trusted); toast(`${k.name} zur Prüfliste hinzugefügt`, 'ok'); }
    else if (b.dataset.untrust != null) untrustKnown(k);
    else if (b.dataset.hide != null) { await window.vigil.setTargetMeta(k.id, { hiddenFromPicker: true }); toast(`${k.name} ausgeblendet`, 'ok'); loadKnown(); }
  });
  loadKnown();
}

function renderTargets() {
  const ul = $('targetList');
  ul.innerHTML = '';
  state.targets.forEach((t, i) => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="t-kind ${t.type}">${KIND_LABEL[t.type]}</span><span class="t-val" title="${esc(t.value)}">${esc(t.type === 'system' ? SYSTEM_LABEL[t.value] || t.value : t.value)}</span>`;
    const rm = document.createElement('button');
    rm.className = 't-rm'; rm.textContent = '✕'; rm.setAttribute('aria-label', 'Entfernen');
    rm.onclick = () => { state.targets.splice(i, 1); renderTargets(); };
    li.appendChild(rm);
    ul.appendChild(li);
  });
  document.querySelectorAll('.sys-chip').forEach((b) => b.classList.toggle('on', state.targets.some((t) => t.type === 'system' && t.value === b.dataset.system)));
  $('targetCount').textContent = state.targets.length;
  $('targets').hidden = state.targets.length === 0;
  if (known.list.length) renderKnown();
  updateRunState();
}

// Freitext deuten: lokaler Pfad, Webadresse, Container-Image oder Server (IP/Host).
function classifyInput(v) {
  if (/^image:/i.test(v)) return { type: 'image', value: v.slice(6).trim() };
  if (/^system:(windows|docker|aws|azure|gcp)$/i.test(v)) return { type: 'system', value: v.slice(7).toLowerCase() };
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
  const t = v && !/^(https?:\/\/|image:)$/i.test(v) ? classifyInput(v) : null;
  $('targetKind').hidden = !t;
  if (t) $('targetKind').textContent = 'Erkannt: ' + KIND_LABEL[t.type];
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
  else $('runHint').textContent = `Bereit – ${state.targets.length} ${state.targets.length === 1 ? 'Ziel' : 'Ziele'} mit ${ready.label}.`;
  scheduleEstimate(ready.ok && state.targets.length > 0);
  setRunEta();
  updateReady(ready);
  updateStatusBar();
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
  // Schnellstart-Kacheln fuer Webseite/Image: Eingabefeld mit passendem Anfang fuellen
  // System-Pruefungen direkt zur Liste hinzufuegen bzw. wieder entfernen
  document.querySelectorAll('.sys-chip').forEach((b) => b.addEventListener('click', () => {
    const v = b.dataset.system;
    const i = state.targets.findIndex((t) => t.type === 'system' && t.value === v);
    if (i >= 0) state.targets.splice(i, 1); else state.targets.push({ type: 'system', value: v });
    renderTargets();
  }));
  dz.querySelectorAll('.quick-tile[data-fill]').forEach((b) => b.addEventListener('click', () => {
    const inp = $('targetInput');
    if (!inp.value.trim()) inp.value = b.dataset.fill;
    inp.placeholder = b.dataset.hint;
    inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length);
    onTargetInput();
  }));
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
// --- Kosten-/Token-Vorschau vor dem Start -----------------------------------
const fmtDur = (s) => (s < 90 ? `≈ ${Math.max(1, Math.round(s / 10) * 10)} Sek.` : s < 3600 ? `≈ ${Math.round(s / 60)} Min.` : `≈ ${(s / 3600).toFixed(1).replace('.', ',')} Std.`);
const fmtK = (n) => (n >= 1e6 ? (n / 1e6).toFixed(2).replace('.', ',') + ' Mio.' : n >= 1000 ? Math.round(n / 1000).toLocaleString('de-DE') + ' Tsd.' : String(n));
let estTimer = null;
let estSeq = 0;
function scheduleEstimate(show) {
  clearTimeout(estTimer);
  if (!show) { $('estimateCard').hidden = true; state.estimate = null; setRunEta(); return; }
  estTimer = setTimeout(refreshEstimate, 350);
}
// Dauer kommt komplett aus der Vorschau des Hauptprozesses (lernt aus echten Laeufen mit).
function expectedSeconds() {
  return state.targets.length && state.estimate ? state.estimate.seconds : null;
}
// Restzeit waehrend des Laufs: Plan minus verbrauchte Zeit, ab dem ersten KI-Aufruf
// hochgerechnet aus dem tatsaechlichen Tempo (die KI ist fast immer der groesste Teil).
function remainingSeconds(elapsedS) {
  const live = state.live || {};
  const est = state.estimate;
  if (live.aiDone > 0 && live.aiTotal) {
    const rate = (Date.now() - live.aiStart) / 1000 / live.aiDone;
    const left = live.aiTotal - live.aiDone;
    const validate = est && est.calls ? Math.ceil(live.aiTotal / 4) : 0;
    return rate * (left + (live.phase === 'validate' ? Math.max(0, (live.valTotal || validate) - (live.valDone || 0)) : validate));
  }
  const exp = expectedSeconds();
  return exp == null ? null : exp - elapsedS;
}
// Checkliste "Startklar?" neben dem Start-Button
function updateReady(ready) {
  const n = state.targets.length;
  const set = (id, ok, text) => { const li = $(id); li.classList.toggle('ok', ok); li.querySelector('.ready-text').textContent = text; };
  set('readyTarget', n > 0, n ? `${n} ${n === 1 ? 'Ziel' : 'Ziele'} in der Prüfliste` : 'Ziel hinzufügen');
  set('readyAi', ready.ok, !needsAi() && n ? 'Keine KI nötig für diese Ziele' : ready.ok ? `KI bereit: ${ready.label}` : (ready.why || 'KI wählen'));
  const s = expectedSeconds();
  const est = state.estimate;
  const costText = !n ? 'Kosten und Dauer prüfen'
    : !needsAi() ? `Kostenlos · ${s ? fmtDur(s) : 'kurz'}`
      : est ? `${est.local ? 'Kostenlos' : est.priced ? '≈ ' + fmtUsd(est.usd) : 'Preis unbekannt'} · ${fmtDur(s)}` : 'Schätzung wird berechnet …';
  set('readyCost', n > 0 && (!needsAi() || !!est), costText);
}
// Voraussichtliche Zeit direkt im Start-Button
function setRunEta() {
  const s = state.running ? null : expectedSeconds();
  $('runEta').hidden = s == null;
  if (s != null) $('runEta').textContent = fmtDur(s);
}
async function refreshEstimate() {
  const seq = ++estSeq;
  const card = $('estimateCard');
  // Ohne KI (nur Webadressen/Images) keine Karte, aber trotzdem die Dauer schaetzen
  const showCard = needsAi();
  card.hidden = !showCard;
  card.classList.add('loading');
  card.innerHTML = '<div class="est-head"><span>Vorschau dieses Laufs</span><span class="muted small">rechne …</span></div>';
  let r;
  try { r = await window.vigil.estimateAudit({ targets: state.targets, providerId: state.config.selected }); } catch (e) { r = { ok: false, error: e.message }; }
  if (seq !== estSeq) return; // inzwischen geaendert
  card.classList.remove('loading');
  if (!showCard) { state.estimate = r && r.ok ? r.current : null; setRunEta(); updateReady({ ok: true }); return; }
  if (!r || !r.ok) { card.innerHTML = `<div class="est-head"><span>Vorschau</span></div><p class="muted small">Keine Schätzung möglich${r && r.error ? ': ' + esc(r.error) : ''}.</p>`; return; }
  const c = r.current, o = r.other;
  state.estimate = c;
  setRunEta();
  updateReady(needsAi() ? aiReady() : { ok: true });
  const total = c.inputTokens + c.outputTokens;
  const price = c.local ? '<b class="est-price free">Kostenlos</b><span class="muted small">läuft lokal auf deinem Rechner</span>'
    : c.priced ? `<b class="est-price">≈ ${esc(fmtUsd(c.usd))}</b><span class="muted small">${esc(r.model || '')}</span>`
      : `<b class="est-price">${fmtK(total)} Tokens</b><span class="muted small">kein Preis für „${esc(r.model || '?')}“ hinterlegt</span>`;
  const modeName = (d) => (d === 'thorough' ? 'Gründlich' : 'Schnell');
  const otherPrice = o.local ? fmtDur(o.seconds) : o.priced ? `≈ ${fmtUsd(o.usd)} · ${fmtDur(o.seconds)}` : `${fmtK(o.inputTokens + o.outputTokens)} Tokens`;
  const warn = !c.local && c.priced && c.usd > (state.config.costWarnUsd ?? 2);
  card.innerHTML = `
    <div class="est-head"><span>Vorschau dieses Laufs</span><span class="est-mode">${modeName(c.depth)}</span></div>
    <div class="est-main">${price}</div>
    <div class="est-grid">
      <div><span class="est-n">${fmtK(total)}</span><span class="est-l">Tokens</span></div>
      <div><span class="est-n">${c.calls}</span><span class="est-l">KI-Aufrufe</span></div>
      <div><span class="est-n">${c.files}</span><span class="est-l">Dateien</span></div>
      <div><span class="est-n">${fmtDur(c.seconds).replace('≈ ', '')}</span><span class="est-l">Dauer</span></div>
    </div>
    <div class="est-split muted small">${fmtK(c.inputTokens)} Eingang · ${fmtK(c.outputTokens)} Ausgang${c.truncated ? ' · große Projekte werden gekürzt' : ''}</div>
    <div class="est-split muted small">${c.timeMeasured ? 'Dauer aus deinen bisherigen Läufen gelernt' : 'Dauer vorsichtig geschätzt – wird nach dem ersten Lauf mit diesem Modell genauer'}</div>
    ${warn ? `<div class="est-warn">Über deiner Kostengrenze von ${fmtUsd(state.config.costWarnUsd ?? 2)} – Vigil fragt vor dem Start nach.</div>` : ''}
    <button type="button" class="est-switch" id="estSwitch">${modeName(o.depth)}-Modus: ${esc(otherPrice)} – umstellen</button>`;
  $('estSwitch').onclick = () => { state.config.analysisDepth = o.depth; saveCfg(); refreshEstimate(); toast(`${modeName(o.depth)}-Modus aktiv`, 'ok'); };
}

async function runAudit() {
  if (state.running || !state.targets.length) return;
  // Kostenbremse: teure Cloud-Laeufe vorher bestaetigen lassen
  const est = state.estimate;
  if (needsAi() && est && !est.local && est.priced && est.usd > (state.config.costWarnUsd ?? 2)
    && !confirm(`Dieser Lauf kostet voraussichtlich ${fmtUsd(est.usd)} (${fmtK(est.inputTokens + est.outputTokens)} Tokens, ${est.calls} KI-Aufrufe).\n\nTrotzdem starten?`)) return;
  state.runStartedAt = Date.now();
  state.running = true; updateRunState();
  $('cancelBtn').hidden = false; $('cancelBtn').disabled = false;
  $('progressPanel').hidden = false;
  $('emptyState').hidden = true;
  $('resultPanel').hidden = true;
  $('resultActions').hidden = true;
  $('log').textContent = '';
  $('costPanel').hidden = true; $('costPanel').innerHTML = '';
  $('barFill').style.width = '0%';
  $('progressTitle').textContent = 'Prüfung läuft …';
  $('progressPanel').classList.remove('done', 'failed');
  renderStepper('ingest');
  resetStage();
  $('baselineStatus').textContent = 'Prüfung läuft – die Befunde erscheinen hier, sobald sie fertig ist.';
  showView('results');
  // Laufzeit und Restzeit live mitzaehlen
  const expected = expectedSeconds();
  const tick = () => {
    const ms = Date.now() - state.runStartedAt;
    $('progressSub').textContent = `${state.targets.map((t) => t.value).join(', ')} · ${fmtElapsed(ms)}`;
    $('stageElapsed').textContent = fmtElapsed(ms);
    const left = remainingSeconds(ms / 1000);
    if (left == null) $('stageEta').textContent = '–';
    else $('stageEta').textContent = left > 5 ? fmtDur(left).replace('≈ ', '') : expected != null && ms / 1000 > expected * 1.15 ? 'dauert länger als geplant' : 'gleich';
  };
  tick();
  clearInterval(state.elapsedTimer);
  state.elapsedTimer = setInterval(tick, 1000);

  state.live = {};
  const unsub = window.vigil.onProgress((p) => {
    const live = state.live;
    live.phase = p.phase;
    if (p.phase === 'analyze' && p.total) { if (!live.aiStart) live.aiStart = Date.now(); live.aiTotal = p.total; live.aiDone = p.done || 0; }
    if (p.phase === 'validate' && p.total) { live.valTotal = p.total; live.valDone = p.done || 0; }
    renderStepper(p.phase);
    updateStage(p);
    $('log').textContent += `[${p.phase}]${p.total ? ` ${p.done}/${p.total}` : ''} ${p.message}\n`;
    $('log').scrollTop = $('log').scrollHeight;
    if (p.total) $('barFill').style.width = Math.round((p.done / p.total) * 100) + '%';
    if (p.cost) updateCost(p.cost, false);
  });

  const res = await window.vigil.runAudit({ targets: state.targets, providerId: state.config.selected });
  // Bestaetigte Hosts hat der Main-Prozess auf die Freigabeliste gesetzt.
  try { state.config.allowlist = (await window.vigil.getConfig()).allowlist || []; } catch { /* egal */ }
  loadKnown();
  unsub();
  clearInterval(state.elapsedTimer);
  state.running = false; updateRunState(); setRunEta();
  $('cancelBtn').hidden = true;
  const took = fmtElapsed(Date.now() - state.runStartedAt);

  if (!res.ok) {
    $('progressTitle').textContent = 'Prüfung fehlgeschlagen';
    $('progressSub').textContent = res.error;
    $('progressPanel').classList.add('failed');
    renderStepper('');
    $('log').hidden = false; $('logToggle').setAttribute('aria-expanded', 'true');
    $('log').textContent += '\nFEHLER: ' + res.error + '\n';
    toast('Prüfung fehlgeschlagen: ' + res.error, 'err');
    return;
  }
  $('barFill').style.width = '100%';
  $('progressTitle').textContent = res.canceled ? 'Abgebrochen – Teilergebnis' : 'Prüfung abgeschlossen';
  $('progressSub').textContent = `${state.targets.map((t) => t.value).join(', ')} · Dauer ${took}`;
  $('progressPanel').classList.add('done');
  renderStepper(res.canceled ? '' : 'done');
  if (res.result) {
    if (res.result.meta && res.result.meta.usage) updateCost(res.result.meta.usage, true);
    renderResult(res.result);
    const n = (res.result.findings || []).filter((f) => !f.suppressed).length;
    toast(res.canceled ? 'Abgebrochen – Teilergebnis geladen' : `Fertig: ${n} ${n === 1 ? 'Befund' : 'Befunde'} in ${took}`, 'ok');
  }
}
// Radar-Buehne: Phase, Meldung, Fortschritt und ein Leuchtpunkt je Ereignis
function resetStage() {
  state.stagePhase = null;
  $('radarBlips').innerHTML = '';
  $('stagePhase').textContent = PHASES[0].label;
  $('stageStep').textContent = `Schritt 1 von ${PHASES.length}`;
  $('stageMsg').textContent = 'Starte …';
  $('stagePct').textContent = '0 %';
}
function updateStage(p) {
  const i = PHASES.findIndex((x) => x.key === p.phase);
  if (i >= 0 && p.phase !== state.stagePhase) {
    state.stagePhase = p.phase;
    const el = $('stagePhase');
    el.textContent = PHASES[i].label;
    el.classList.remove('swap'); void el.offsetWidth; el.classList.add('swap');
    $('stageStep').textContent = `Schritt ${i + 1} von ${PHASES.length}`;
  }
  if (p.message) $('stageMsg').textContent = p.message;
  $('stagePct').textContent = p.total ? Math.round((p.done / p.total) * 100) + ' %' : '–';
  // Leuchtpunkt an zufaelliger Stelle im Radar (hoechstens 14 sichtbar)
  const box = $('radarBlips');
  const a = Math.random() * Math.PI * 2, r = 40 + Math.random() * 50;
  const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  c.setAttribute('cx', (100 + Math.cos(a) * r).toFixed(1));
  c.setAttribute('cy', (100 + Math.sin(a) * r).toFixed(1));
  c.setAttribute('r', '3');
  c.setAttribute('fill', Math.random() < 0.2 ? '#f4f1ea' : '#f2b23a');
  c.setAttribute('class', 'blip');
  box.appendChild(c);
  while (box.childNodes.length > 14) box.firstChild.remove();
}
const fmtElapsed = (ms) => { const s = Math.round(ms / 1000); return s < 60 ? `${s} s` : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} min`; };

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
  const label = cost.estimate ? 'Geschätzt' : (done ? 'Kosten gesamt' : 'Bisher');
  const usd = cost.priced ? `≈ ${esc(fmtUsd(cost.usd || 0))}` : `${esc(totalT)} Tokens`;
  const was = done && state.estimate && state.estimate.priced && !cost.estimate ? ` · Vorschau ≈ ${esc(fmtUsd(state.estimate.usd))}` : '';
  el.title = `${totalT} Tokens · ${inT} Eingang · ${outT} Ausgang${cost.priced ? '' : ' · Modell nicht in der Preisliste'}`;
  el.innerHTML = `<span class="cost-label">${esc(label)}</span><span class="cost-usd">${usd}</span>` +
    `<span class="cost-tok">${cost.priced ? esc(totalT) + ' Tokens' : 'kein Preis hinterlegt'}${was}</span>`;
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
  const noteHtml = notes.map((n) => `<span class="merge-note">${esc(n)}</span>`).join('') +
    (unverified ? `<span class="merge-note warn">${unverified} ${plural(unverified, 'Befund ist', 'Befunde sind')} nur von der KI gemeldet und unbestätigt – bitte selbst prüfen.</span>` : '');
  const mergeNote = noteHtml ? `<div class="merge-notes">${noteHtml}</div>` : '';

  const v = $('verdict');
  v.className = 'verdict card v-' + kind;
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
  state.selected = null;
  $('findingSearch').value = '';
  $('resultPanel').hidden = false;
  $('resultActions').hidden = false;
  $('emptyState').hidden = true;
  const open = state.lastFindings.filter((f) => !f.suppressed);
  const badge = $('navResultsCount');
  badge.hidden = !open.length;
  badge.textContent = open.length;
  badge.classList.toggle('alarm', open.some((f) => f.severity === 'critical' || f.severity === 'high'));

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

const riskOf = (f) => (f.contextualRiskScore != null ? f.contextualRiskScore : (f.cvss != null ? f.cvss * 10 : null));
const riskCls = (r) => (r >= 85 ? 'crit' : r >= 65 ? 'high' : r >= 40 ? 'med' : 'low');
const findingKey = (f, i) => f.id || 'i' + i;

// Kategorien in Alltagssprache
const CATEGORY_LABEL = {
  Other: 'Sonstiges', Config: 'Konfiguration', Transport: 'Verschlüsselung', Dependencies: 'Abhängigkeiten', Secrets: 'Zugangsdaten',
  AccessControl: 'Zugriffsrechte', Auth: 'Anmeldung', Injection: 'Einschleusen von Befehlen', XSS: 'Einschleusen von Skripten',
  Crypto: 'Verschlüsselung', SSRF: 'Server-Anfragen von außen', PathTraversal: 'Dateizugriff', Deserialization: 'Datenverarbeitung',
  Logic: 'Programmlogik', DoS: 'Überlastung', Supply: 'Lieferkette', SupplyChain: 'Lieferkette', Container: 'Container', Host: 'Server',
  DNS: 'DNS & E-Mail', LLM: 'KI-Sicherheit', Logging: 'Protokollierung', License: 'Lizenz', AttackPath: 'Angriffsweg',
};
// Beteiligte Befunde eines Angriffswegs (verknuepft ueber ruleId@location)
function linkedOf(f) {
  if (!Array.isArray(f.linkedKeys) || !f.linkedKeys.length) return [];
  const want = new Set(f.linkedKeys);
  return state.lastFindings.map((x, i) => ({ x, k: findingKey(x, i) })).filter(({ x }) => want.has(`${x.ruleId}@${x.location}`));
}

// Kompakte Zeile in der Befundliste (links).
function findingRow(f, key) {
  const risk = riskOf(f);
  const flags = `${f.inCisaKev ? '<span class="fr-flag kev" title="Aktiv ausgenutzt (CISA KEV)"></span>' : ''}${f.isNew && state.lastResult && state.lastResult.hasBaseline ? '<span class="fr-flag new" title="Neu seit dem letzten Lauf"></span>' : ''}`;
  return `<button type="button" class="frow sev-${f.severity}${state.selected === key ? ' active' : ''}${f.suppressed ? ' is-suppressed' : ''}" role="option" aria-selected="${state.selected === key}" data-key="${esc(key)}">
      <span class="fr-main">
        <span class="fr-title" title="${esc(cleanTitle(f.title))}">${esc(cleanTitle(f.title))}</span>
        <span class="fr-sub"><span class="fr-loc">${esc(f.location || f.category || '')}</span></span>
      </span>
      <span class="fr-side">${flags}${risk != null ? `<span class="risk risk-${riskCls(risk)}" title="Kontext-Risiko 0–100">${Math.round(risk)}</span>` : ''}</span>
    </button>`;
}

// Volle Detailansicht eines Befunds (rechts).
function findingDetail(f) {
  const srcs = findingSources(f);
  const srcNames = srcs.map(sourceLabel).join(', ');
  const ev = EVIDENCE[f.assurance];
  const risk = riskOf(f);
  const chips = [
    `<span class="sev-tag sev-${f.severity}" title="${esc(SEV_HELP[f.severity])}">${SEV_LABEL[f.severity]}</span>`,
    risk != null ? `<span class="risk risk-${riskCls(risk)}" title="Kontext-Risiko 0–100${f.cvss != null ? ' · CVSS ' + Number(f.cvss).toFixed(1) : ''}">Risiko ${Math.round(risk)}</span>` : '',
    ev ? `<span class="chip ${ev.cls}" title="${esc(ev.help)}">${ev.label}</span>` : '',
    f.inCisaKev ? '<span class="chip badge-kev" title="Steht im CISA-Katalog aktiv ausgenutzter Lücken">aktiv ausgenutzt</span>' : '',
    f.epssScore >= 0.1 ? `<span class="chip badge-epss" title="Wahrscheinlichkeit einer Ausnutzung in 30 Tagen">EPSS ${Math.round(f.epssScore * 100)} %</span>` : '',
    f.isNew && state.lastResult && state.lastResult.hasBaseline ? '<span class="chip badge-new">neu</span>' : '',
    f.regression ? '<span class="chip badge-reg" title="War als behoben markiert und ist wieder da">wieder da</span>' : '',
    `<span class="chip">${esc(CATEGORY_LABEL[f.category] || f.category)}</span>`,
  ].filter(Boolean).join('');
  const ctx = (f.context || []).filter((c) => CONTEXT[c]);
  const danger = [f.impact, f.reachability].filter(Boolean).join(' ');
  const secs = [
    f.description && `<div class="f-sec${danger ? '' : ' full'}"><h4>Was ist los?</h4><p>${esc(f.description)}</p></div>`,
    danger && `<div class="f-sec${f.description ? '' : ' full'}"><h4>Was kann passieren?</h4><p>${esc(danger)}</p></div>`,
  ].filter(Boolean).join('');
  const check = f.validation && f.validation.reason
    ? `<div class="f-sec check-sec"><h4>Gegenprüfung: ${f.validation.verdict === 'confirmed' ? 'bestätigt' : 'nicht eindeutig'}</h4><p>${esc(f.validation.reason)}</p></div>` : '';
  // Angriffsweg: die beteiligten Einzelbefunde zum Anklicken
  const linked = linkedOf(f);
  const linkedHtml = linked.length ? `<div class="f-sec linked-sec"><h4>Beteiligte Befunde</h4><div class="linked-list">${linked.map(({ x, k }) => `<button type="button" class="linked-row sev-${x.severity}" data-key="${esc(k)}"><span class="sev-tag">${SEV_LABEL[x.severity]}</span><span class="linked-title">${esc(cleanTitle(x.title))}</span><span class="linked-go" aria-hidden="true">›</span></button>`).join('')}</div></div>` : '';
  return `
    <header class="fd-head">
      <div class="fd-top">${chips}</div>
      <h2 class="fd-title">${esc(cleanTitle(f.title))}</h2>
      ${f.location ? `<div class="fd-loc">${esc(f.location)}</div>` : ''}
      <div class="fd-meta">
        <span class="meta-text"${f.ruleId ? ` title="Regel: ${esc(f.ruleId)}"` : ''}>${srcs.length > 1 ? 'Gefunden von' : 'Erkannt durch'}: ${esc(srcNames)}${f.confidence ? ' · Verlässlichkeit ' + esc(CONF_LABEL[f.confidence] || f.confidence) : ''}</span>
        ${f.id ? statusSelect(f.id, f.status || 'OPEN') : ''}
      </div>
    </header>
    <div class="fd-body">
      ${f.locationDetail ? `<p class="loc-detail"><span>Fundort</span>${esc(f.locationDetail)}</p>` : ''}
      ${ctx.length ? `<div class="ctx-row">${ctx.map((c) => `<span class="ctx-chip ctx-${c}">${CONTEXT[c]}</span>`).join('')}</div>` : ''}
      ${secs ? `<div class="f-cols">${secs}</div>` : ''}
      ${linkedHtml}
      ${check}
      ${f.evidence ? `<div class="f-sec evidence"><h4>Fundstelle</h4><code>${esc(f.evidence)}</code></div>` : ''}
      ${solutionBlock(f)}
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
  if (steps.length) parts.push(`<div class="sol-steps"><h4>So behebst du es</h4><ol>${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>${f.remediation && f.steps && f.steps.length && !f.steps.includes(f.remediation) && !/^Siehe /.test(f.remediation) ? `<p class="muted small">Für diesen Fund: ${esc(f.remediation)}</p>` : ''}</div>`);
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
  return parts.length ? `<div class="solution"><div class="sol-title">Lösung</div>${parts.join('')}</div>` : '';
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
  return `<div class="toxic-banner" role="alert"><div class="toxic-ico">⚠</div><div><b>${toxic.length} ${toxic.length === 1 ? 'Angriffsweg' : 'Angriffswege'} erkannt</b><ul>${toxic.map((t) => `<li>${esc(t.title.replace(/^(Möglicher )?Angriffsweg:\s*/, ''))}</li>`).join('')}</ul><span class="muted small">Mehrere Schwächen ergeben zusammen einen kompletten Weg für einen Angriff. Schon eine einzige Behebung unterbricht ihn.</span></div></div>`;
}

function visibleList() {
  const q = state.query.trim().toLowerCase();
  let list = state.filter === 'all' ? state.lastFindings : state.lastFindings.filter((f) => f.severity === state.filter);
  if (!state.showSuppressed) list = list.filter((f) => !f.suppressed);
  if (state.onlyNew) list = list.filter((f) => f.isNew);
  if (state.onlyProven) list = list.filter((f) => f.assurance !== 'unverified');
  return list.filter((f) => matchesQuery(f, q));
}
function renderFindings() {
  const box = $('findings');
  const list = visibleList();
  const keyed = list.map((f) => ({ f, key: findingKey(f, state.lastFindings.indexOf(f)) }));
  if (!keyed.length) {
    box.innerHTML = state.lastFindings.length
      ? '<div class="empty"><b>Keine Treffer</b>Filter oder Suche anpassen.</div>'
      : '<div class="empty"><b>Alles sauber</b>Vigil hat in diesem Lauf nichts gefunden.</div>';
    state.selected = null;
    renderDetail();
    return;
  }
  // Auswahl behalten, sonst den dringendsten Befund zeigen
  if (!keyed.some((x) => x.key === state.selected)) state.selected = keyed[0].key;
  box.innerHTML = toxicBanner(state.lastFindings) + SEV_ORDER.map((s) => {
    const items = keyed.filter((x) => x.f.severity === s);
    if (!items.length) return '';
    return `<div class="group-head sev-${s}">${SEV_LABEL[s]} <span class="gcount">${items.length}</span></div>` + items.map((x) => findingRow(x.f, x.key)).join('');
  }).join('');
  box.querySelectorAll('.frow').forEach((r) => r.onclick = () => selectFinding(r.dataset.key));
  renderDetail();
}
function selectFinding(key, focus) {
  state.selected = key;
  $('findings').querySelectorAll('.frow').forEach((r) => {
    const on = r.dataset.key === key;
    r.classList.toggle('active', on); r.setAttribute('aria-selected', on ? 'true' : 'false');
    if (on) { r.scrollIntoView({ block: 'nearest' }); if (focus) r.focus(); }
  });
  renderDetail();
}
function renderDetail() {
  const pane = $('findingDetail');
  const f = state.lastFindings.find((x, i) => findingKey(x, i) === state.selected);
  if (!f) { pane.innerHTML = '<div class="fd-empty">Wähle links einen Befund, um Details und Lösung zu sehen.</div>'; return; }
  pane.innerHTML = findingDetail(f);
  pane.scrollTop = 0;
  bindSolutionControls(pane);
  pane.querySelectorAll('.linked-row').forEach((b) => b.onclick = () => {
    // Ausgeblendeter Teilbefund? Filter zuruecksetzen, damit er in der Liste auftaucht.
    if (!visibleList().some((x) => findingKey(x, state.lastFindings.indexOf(x)) === b.dataset.key)) { state.filter = 'all'; state.query = ''; $('findingSearch').value = ''; state.onlyNew = false; state.onlyProven = false; refreshResultView(); }
    selectFinding(b.dataset.key);
  });
  bindStatusSelects(pane, (id, status) => {
    state.lastFindings.forEach((x) => { if (x.id === id) { x.status = status; x.suppressed = HIDDEN_STATUS.has(status); } });
    toast(`Status: ${STATUS_LABEL[status]}`, 'ok');
    refreshResultView();
  });
}
// Pfeiltasten in der Befundliste
function moveSelection(delta) {
  const rows = [...$('findings').querySelectorAll('.frow')];
  if (!rows.length) return;
  const i = rows.findIndex((r) => r.dataset.key === state.selected);
  const next = rows[Math.min(rows.length - 1, Math.max(0, (i < 0 ? 0 : i + delta)))];
  selectFinding(next.dataset.key, true);
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
function sourceLabel(s) { return ({ osv: 'Schwachstellen-DB (OSV)', prescan: 'statische Prüfung', webscan: 'Server-Check', nmap: 'nmap', nuclei: 'nuclei', gitleaks: 'gitleaks', trufflehog: 'trufflehog', trivy: 'trivy', grype: 'grype', semgrep: 'semgrep', bandit: 'bandit', checkov: 'checkov', retire: 'retire.js', hadolint: 'hadolint', 'osv-scanner': 'osv-scanner', binary: 'Binary-Analyse', ai: 'KI', 'supply-chain-audit': 'Lieferkette', 'container-host-audit': 'Container-Prüfung', 'semgrep-custom-sast': 'Code-Regeln', 'llm-prompt-security': 'KI-Sicherheit', 'linux-host-audit': 'Server-Konfig', 'web-exposure-audit': 'Web-Exposure', 'web-tls-posture': 'Web/TLS', 'dns-mail-drift': 'DNS & Mail', 'headless-dom-audit': 'Browser-Prüfung', 'api-auth-matrix': 'API-Rechtematrix', correlator: 'Angriffsweg-Analyse' })[s] || s || 'KI'; }

// --- Scan-Verlauf -------------------------------------------------------
async function loadHistory() {
  renderHistory(await window.vigil.historyList());
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
    if (!res.ok) return;
    $('progressPanel').hidden = true;
    renderResult(res.result);
    showView('results');
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
const ai = { mode: 'local', ollama: null, recommended: [], pulling: null, busy: false, localList: [] };

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
  if (ai.mode === 'local' && localSourceId() !== 'ollama') {
    const src = ai.localList.find((x) => x.id === localSourceId());
    if (!src) return { ok: false, why: 'Die gewählte lokale KI antwortet gerade nicht – starte sie oder wähle eine andere.' };
    if (!pcfg('compat').model) return { ok: false, why: `Wähle ein Modell von ${src.name}.` };
    return { ok: true, label: `${pcfg('compat').model} (${src.name})` };
  }
  if (ai.mode === 'local') {
    const s = ai.ollama;
    if (!s) return { ok: false, why: 'Prüfe Ollama …' };
    if (!s.installed) return { ok: false, why: 'Installiere zuerst Ollama (unter „KI“) – oder wähle „Cloud“.' };
    if (!s.running) return { ok: false, why: 'Starte Ollama unter „KI“.' };
    if (!s.models.length) return { ok: false, why: 'Lade unter „KI“ ein Modell herunter, z. B. Qwen 2.5 Coder 7B.' };
    return { ok: true, label: pcfg('ollama').model || 'Ollama' };
  }
  const id = state.config.cloudProvider;
  if (!cloudHasAccess(id)) return { ok: false, why: id === 'compat' ? 'Trage in den Einstellungen die Server-Adresse des Dienstes ein.' : 'Füge unter „KI“ deinen API-Schlüssel ein.' };
  if (!pcfg(id).model) return { ok: false, why: 'Wähle unter „KI“ ein Modell.' };
  return { ok: true, label: pcfg(id).model };
}

// --- Lokale KI-Quelle: Ollama oder ein bereits laufender OpenAI-kompatibler Server -------
const localSourceId = () => state.config.localSource || 'ollama';
async function scanLocal(manual) {
  if (manual) $('localSources').classList.add('scanning');
  try { ai.localList = await window.vigil.ollama.detectLocal(); } catch { ai.localList = []; }
  $('localSources').classList.remove('scanning');
  renderLocalSources();
  if (manual) toast(ai.localList.length ? `${ai.localList.length} lokale KI gefunden` : 'Keine laufende lokale KI gefunden', ai.localList.length ? 'ok' : 'info');
  updateRunState();
}
function renderLocalSources() {
  const sel = localSourceId();
  const list = [...ai.localList];
  if (!list.some((x) => x.id === 'ollama')) list.unshift({ id: 'ollama', name: 'Ollama', port: 11434, kind: 'ollama', models: null });
  $('localSources').innerHTML = list.map((s) => {
    const state2 = s.models == null ? 'nicht aktiv' : s.models.length ? `${s.models.length} ${s.models.length === 1 ? 'Modell' : 'Modelle'}` : 'läuft, kein Modell';
    return `<button type="button" class="ls-card${s.id === sel ? ' active' : ''}" role="radio" aria-checked="${s.id === sel}" data-id="${esc(s.id)}">
      <span class="dot ${s.models == null ? '' : s.models.length ? 'ok' : 'wait'}"></span>
      <span class="ls-main"><b>${esc(s.name)}</b><span class="muted small">Port ${s.port} · ${state2}</span></span></button>`;
  }).join('');
  $('localSources').querySelectorAll('.ls-card').forEach((b) => b.onclick = () => selectLocalSource(b.dataset.id));
  const other = sel !== 'ollama' ? ai.localList.find((x) => x.id === sel) : null;
  $('ollamaBlock').hidden = sel !== 'ollama';
  $('localOtherRow').hidden = sel === 'ollama';
  if (sel !== 'ollama') {
    const models = (other && other.models) || [];
    const c = pcfg('compat');
    if (other) c.baseUrl = other.baseUrl;
    if (!models.includes(c.model)) c.model = models[0] || '';
    $('localOtherModel').innerHTML = models.length ? models.map((m) => `<option value="${esc(m)}"${m === c.model ? ' selected' : ''}>${esc(m)}</option>`).join('') : '<option value="" disabled selected>– kein Modell geladen –</option>';
    $('localOtherHint').textContent = other ? `${other.name} unter ${other.baseUrl} – läuft lokal, kostenlos, deine Daten bleiben auf dem PC.` : 'Diese KI antwortet gerade nicht.';
    saveCfg();
  }
}
function selectLocalSource(id) {
  state.config.localSource = id;
  state.config.selected = id === 'ollama' ? 'ollama' : 'compat';
  saveCfg();
  renderLocalSources();
  if (id === 'ollama') refreshOllama();
  updateRunState();
}

function setMode(mode) {
  ai.mode = mode;
  state.config.selected = mode === 'local' ? (localSourceId() === 'ollama' ? 'ollama' : 'compat') : state.config.cloudProvider;
  saveCfg();
  for (const b of [$('modeLocal'), $('modeCloud')]) {
    const on = b.dataset.mode === mode;
    b.classList.toggle('active', on); b.setAttribute('aria-selected', on ? 'true' : 'false');
  }
  $('localPane').hidden = mode !== 'local';
  $('cloudPane').hidden = mode !== 'cloud';
  if (mode === 'local') { scanLocal(); refreshOllama(); } else refreshCloud();
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

// Seiten: Neue Pruefung | Ergebnis | Uebersicht | Verlauf | Einstellungen
const VIEWS = { scan: 'scanView', results: 'resultsView', dash: 'dashView', history: 'historyView', settings: 'settingsView' };
function showView(v) {
  if (!VIEWS[v]) return;
  if (v !== 'dash' && state.dashOpen) closeDashDetail();
  state.view = v;
  for (const [name, id] of Object.entries(VIEWS)) $(id).hidden = name !== v;
  document.querySelectorAll('.nav-item[data-view]').forEach((b) => {
    const on = b.dataset.view === v;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  closeMenus();
  document.querySelector('.main').scrollTop = 0;
  if (v === 'dash') loadDashboard();
  if (v === 'history') loadHistory();
  if (v === 'settings') {
    renderSettings();
    $('setNav').querySelectorAll('a').forEach((a, i) => a.classList.toggle('active', i === 0));
  }
}
function closeMenus() {
  $('exportMenu').hidden = true;
  $('exportBtn').setAttribute('aria-expanded', 'false');
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
  $('dashToxic').innerHTML = stats.toxic.length ? `<div class="toxic-banner" role="alert"><div class="toxic-ico">⚠</div><div><b>${stats.toxic.length} ${stats.toxic.length === 1 ? 'Angriffsweg' : 'Angriffswege'} offen</b><ul>${stats.toxic.map((t) => `<li>${esc(t.title.replace(/^(Möglicher )?Angriffsweg:\s*/, ''))} <span class="muted small">· ${esc(t.targetName)}</span></li>`).join('')}</ul></div></div>` : '';
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
    showView('scan');
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
  state.dashFindings = findings;
  box.innerHTML = `<table class="ftable"><thead><tr><th>Schwere</th><th>Befund</th><th>Ziel</th><th>Zuletzt gesehen</th><th>Status</th></tr></thead><tbody>${findings.map((f, i) => `
    <tr class="sev-${f.severity} clickable${state.dashOpen === f.id ? ' active' : ''}" data-i="${i}" tabindex="0" role="button" aria-label="Details zu ${esc(cleanTitle(f.title))}">
      <td><span class="sev-tag">${SEV_LABEL[f.severity]}</span></td>
      <td class="ft-main"><b title="${esc(f.title)}">${esc(cleanTitle(f.title))}</b><span class="f-loc" title="${esc(f.location)}">${esc(f.location)}</span>${f.statusNote ? `<span class="muted small">${esc(f.statusNote)}</span>` : ''}</td>
      <td class="ft-tgt" title="${esc(f.targetName)}">${esc(f.targetName)}</td>
      <td class="muted small ft-when" title="Zuerst gesehen: ${esc(fmtDate(f.firstSeenAt))}">${fmtDate(f.lastSeenAt)}</td>
      <td>${statusSelect(f.id, f.status)}</td>
    </tr>`).join('')}</tbody></table>`;
  bindStatusSelects(box, () => loadDashboard());
  box.querySelectorAll('tr.clickable').forEach((tr) => {
    tr.onclick = () => openDashDetail(Number(tr.dataset.i));
    tr.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDashDetail(Number(tr.dataset.i)); } };
  });
  // Nach Statusaenderung o. ae. den offenen Befund weiter anzeigen
  if (state.dashOpen) { const i = findings.findIndex((f) => f.id === state.dashOpen); if (i >= 0) openDashDetail(i, true); else closeDashDetail(); }
}

// Detail-Ansicht fuer einen gespeicherten Befund der Uebersicht (seitliches Fenster).
// Gespeichert ist der vollstaendige Befund (Erklaerung, Loesung, Links) unter rec.finding.
function dashFindingFull(rec) {
  return { ...rec, ...(rec.finding || {}), id: rec.id, status: rec.status, severity: rec.severity, title: rec.title, location: rec.location, statusNote: rec.statusNote, firstSeenAt: rec.firstSeenAt, lastSeenAt: rec.lastSeenAt, contextualRiskScore: rec.contextualRiskScore ?? (rec.finding && rec.finding.contextualRiskScore), linkedKeys: [] };
}
function openDashDetail(i, keepScroll) {
  const list = state.dashFindings || [];
  const rec = list[i];
  if (!rec) return;
  state.dashOpen = rec.id; state.dashIndex = i;
  const body = $('dashDrawerBody');
  const top = body.scrollTop;
  const f = dashFindingFull(rec);
  const linked = (rec.linkedFindingIds || []).map((id) => list.findIndex((x) => x.id === id)).filter((k) => k >= 0);
  body.innerHTML = `<div class="muted small drawer-meta">Ziel: <b>${esc(rec.targetName)}</b> · zuerst gesehen ${esc(fmtDate(rec.firstSeenAt))} · zuletzt ${esc(fmtDate(rec.lastSeenAt))}</div>`
    + findingDetail(f)
    + (linked.length ? `<div class="f-sec"><h4>Beteiligte Befunde</h4>${linked.map((k) => `<button type="button" class="linked-row" data-i="${k}"><span class="sev-tag sev-${list[k].severity}">${SEV_LABEL[list[k].severity]}</span> ${esc(cleanTitle(list[k].title))}</button>`).join('')}</div>` : '');
  bindSolutionControls(body);
  body.querySelectorAll('.linked-row').forEach((b) => b.onclick = () => openDashDetail(Number(b.dataset.i)));
  bindStatusSelects(body, (id, status) => { toast(`Status: ${STATUS_LABEL[status]}`, 'ok'); loadDashboard(); });
  $('dashDrawerPos').textContent = `Befund ${i + 1} von ${list.length}`;
  $('dashDrawerPrev').disabled = i <= 0;
  $('dashDrawerNext').disabled = i >= list.length - 1;
  $('dashDrawer').hidden = false; $('dashDrawerBg').hidden = false;
  body.scrollTop = keepScroll ? top : 0;
  $('dashTable').querySelectorAll('tr.clickable').forEach((tr) => tr.classList.toggle('active', Number(tr.dataset.i) === i));
  if (!keepScroll) $('dashDrawerClose').focus();
}
function closeDashDetail() {
  state.dashOpen = null;
  $('dashDrawer').hidden = true; $('dashDrawerBg').hidden = true;
  $('dashTable').querySelectorAll('tr.clickable.active').forEach((tr) => tr.classList.remove('active'));
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
  $('incrChk').checked = state.config.incremental !== false;
  $('gitHistChk').checked = state.config.gitHistory !== false;
  $('triageModelInput').value = pcfg(state.config.selected || 'ollama').triageModel || '';
  $('consensusModelInput').value = pcfg(state.config.selected || 'ollama').consensusModel || '';
  if (window.vigil.aiCacheInfo) window.vigil.aiCacheInfo().then((c) => { $('cacheInfo').textContent = c.entries ? `Derzeit ${c.entries} Dateien gemerkt.` : ''; }).catch(() => {});
  $('redactChk').checked = state.config.redactSecrets !== false;
  $('domChk').checked = state.config.domAudit !== false;
  $('costWarnInput').value = state.config.costWarnUsd ?? 2;
  renderPresets();
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
  state.config.incremental = $('incrChk').checked;
  state.config.gitHistory = $('gitHistChk').checked;
  pcfg(state.config.selected || 'ollama').triageModel = $('triageModelInput').value.trim();
  pcfg(state.config.selected || 'ollama').consensusModel = $('consensusModelInput').value.trim();
  state.config.redactSecrets = $('redactChk').checked;
  state.config.domAudit = $('domChk').checked;
  state.config.costWarnUsd = Math.max(0, parseFloat($('costWarnInput').value) || 0);
  // API-Rechtematrix separat speichern – Tokens gehen verschluesselt in den Main-Prozess
  if ($('amHost').value.trim() || $('amEndpoints').value.trim()) {
    window.vigil.apiMatrixSave([{ host: $('amHost').value, resourceIdA: $('amResource').value, endpoints: $('amEndpoints').value, tokenA: $('amTokenA').value, tokenB: $('amTokenB').value }]);
  }
  state.config.allowlist = $('allowlistInput').value.split(/[\s,]+/).map((x) => x.trim().toLowerCase()).filter(Boolean);
  setTimeout(loadKnown, 0);
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
function openSettings() { showView('settings'); }

// Profile: setzen die wichtigsten Schalter auf einmal und speichern sofort.
const PRESETS = {
  fast: { analysisDepth: 'standard', aiValidation: false, cveLookup: true, activeScan: false, domAudit: false },
  balanced: { analysisDepth: 'thorough', aiValidation: true, cveLookup: true, activeScan: false, domAudit: true },
  max: { analysisDepth: 'thorough', aiValidation: true, cveLookup: true, activeScan: true, domAudit: true },
};
const PRESET_NAME = { fast: 'Schnell & günstig', balanced: 'Ausgewogen', max: 'Maximal gründlich' };
function currentPreset() {
  const c = state.config;
  const val = { analysisDepth: c.analysisDepth === 'standard' ? 'standard' : 'thorough', aiValidation: c.aiValidation !== false, cveLookup: c.cveLookup !== false, activeScan: !!c.activeScan, domAudit: c.domAudit !== false };
  return Object.keys(PRESETS).find((k) => Object.entries(PRESETS[k]).every(([key, v]) => val[key] === v)) || null;
}
function renderPresets() {
  const cur = currentPreset();
  document.querySelectorAll('#presetGrid .preset').forEach((b) => { b.classList.toggle('active', b.dataset.preset === cur); b.setAttribute('aria-pressed', String(b.dataset.preset === cur)); });
}
async function applyPreset(name) {
  collectSettings();
  Object.assign(state.config, PRESETS[name]);
  await saveCfg();
  renderSettings();
  updateRunState();
  toast(`Profil „${PRESET_NAME[name]}“ übernommen und gespeichert`, 'ok');
}

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
  setupKnown();

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

  const localOther = sel === 'compat' && state.config.localSource && state.config.localSource !== 'ollama';
  setMode(sel === 'ollama' || localOther ? 'local' : 'cloud');
  // Ollama nachtraeglich erkennen (z. B. von Hand gestartet oder installiert).
  // Nur nachsehen (nie starten), ob Ollama inzwischen laeuft – alle 6 s, solange "Lokal · Ollama" gewaehlt ist.
  setInterval(() => { if (ai.mode === 'local' && localSourceId() === 'ollama' && !ai.busy && !ai.pulling && !(ai.ollama && ai.ollama.running)) refreshOllama(); }, 6000);
  $('localScan').onclick = () => scanLocal(true);
  $('localOtherModel').onchange = () => { pcfg('compat').model = $('localOtherModel').value; saveCfg(); updateRunState(); };

  // Schritt 3 + Ergebnis
  $('runBtn').onclick = runAudit;
  $('findingSearch').addEventListener('input', () => { state.query = $('findingSearch').value; renderFindings(); });
  $('cancelBtn').onclick = async () => { $('cancelBtn').disabled = true; $('progressTitle').textContent = 'Wird abgebrochen …'; await window.vigil.cancelAudit(); };
  $('logToggle').onclick = () => {
    const log = $('log'); log.hidden = !log.hidden;
    $('logToggle').setAttribute('aria-expanded', log.hidden ? 'false' : 'true');
  };
  const exportAs = (fmt) => async () => {
    closeMenus();
    if (fmt === 'pdf') flash('Erzeuge PDF …');
    const r = await window.vigil.saveReport(fmt);
    flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error));
  };
  $('exportHtmlBtn').onclick = exportAs('html');
  $('exportMdBtn').onclick = exportAs('md');
  $('exportSarifBtn').onclick = exportAs('sarif');
  $('exportPdfBtn').onclick = exportAs('pdf');
  $('exportBtn').onclick = (e) => {
    e.stopPropagation();
    const open = $('exportMenu').hidden;
    $('exportMenu').hidden = !open;
    $('exportBtn').setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) $('exportMenu').querySelector('button').focus();
  };
  document.addEventListener('click', (e) => { if (!e.target.closest('.menu-wrap')) closeMenus(); });
  $('findings').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); moveSelection(1); }
    else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); moveSelection(-1); }
  });

  // Seitenleiste
  document.querySelectorAll('.nav-item[data-view]').forEach((b) => b.onclick = () => showView(b.dataset.view));
  $('aiPill').onclick = () => { showView('scan'); setTimeout(() => $('aiCard').scrollIntoView({ behavior: 'smooth', block: 'start' }), 30); };
  $('newScanBtn').onclick = () => showView('scan');
  $('emptyScanBtn').onclick = () => showView('scan');
  $('sbMode').onclick = () => {
    state.config.analysisDepth = state.config.analysisDepth === 'standard' ? 'thorough' : 'standard';
    saveCfg(); updateRunState();
    toast(state.config.analysisDepth === 'standard' ? 'Schnell-Modus aktiv' : 'Gründlich-Modus aktiv', 'ok');
  };
  document.querySelectorAll('#presetGrid .preset').forEach((b) => b.onclick = () => applyPreset(b.dataset.preset));
  // Schalter, die zu einem Profil gehoeren: Profil-Markierung sofort mitziehen
  $('cacheClearBtn').onclick = async () => { await window.vigil.aiCacheClear(); $('cacheInfo').textContent = ''; toast('KI-Zwischenspeicher geleert – der nächste Lauf prüft alles neu', 'ok'); };
  ['depthSelect', 'validateChk', 'cveChk', 'activeChk', 'domChk'].forEach((id) => $(id).addEventListener('change', () => { collectSettings(); renderPresets(); }));
  // Einstellungen: Unternavigation folgt dem Scrollen
  $('setNav').querySelectorAll('a').forEach((a) => a.onclick = (e) => {
    e.preventDefault();
    document.querySelector(a.getAttribute('href')).scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
  document.querySelector('.main').addEventListener('scroll', () => {
    if (state.view !== 'settings') return;
    let current = null;
    document.querySelectorAll('.set-block').forEach((sec) => { if (sec.getBoundingClientRect().top < 140) current = sec.id; });
    $('setNav').querySelectorAll('a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === '#' + (current || 'set-analyse')));
  }, { passive: true });
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
  $('historyClearBtn').onclick = async () => { await window.vigil.historyClear(); renderHistory([]); $('historyStatus').textContent = 'Verlauf geleert.'; setTimeout(() => { $('historyStatus').textContent = ''; }, 1200); };
  $('addRuleBtn').onclick = () => { collectCustomRules(); state.config.customRules.push({ name: '', regex: '', severity: 'medium' }); renderCustomRules(); };
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { if (!$('dashDrawer').hidden) closeDashDetail(); closeMenus(); }
    // Im offenen Detail-Fenster der Uebersicht mit Pfeiltasten blaettern
    if (!$('dashDrawer').hidden && (e.key === 'ArrowDown' || e.key === 'ArrowUp') && !/SELECT|INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
      e.preventDefault(); openDashDetail((state.dashIndex || 0) + (e.key === 'ArrowDown' ? 1 : -1));
    }
  });
  $('dashDrawerClose').onclick = closeDashDetail;
  $('dashDrawerBg').onclick = closeDashDetail;
  $('dashDrawerPrev').onclick = () => openDashDetail((state.dashIndex || 0) - 1);
  $('dashDrawerNext').onclick = () => openDashDetail((state.dashIndex || 0) + 1);
  $('tempRange').addEventListener('input', () => { $('tempVal').textContent = $('tempRange').value; $('tempDesc').textContent = tempText(parseFloat($('tempRange').value)); });
  $('settingsSave').onclick = async () => {
    collectSettings();
    const r = await saveCfg();
    toast(r && r.ok ? 'Einstellungen gespeichert' : 'Fehler beim Speichern', r && r.ok ? 'ok' : 'err');
    if (ai.mode === 'cloud') refreshCloud(); else refreshOllama();
    updateRunState();
  };

  showView('scan');
  renderTargets();
}
// Meldungen als Toast (oben rechts) – nichts geht mehr in einer Statuszeile unter.
function toast(msg, kind = 'info') {
  if (!msg) return;
  const box = $('toasts');
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.setAttribute('role', kind === 'err' ? 'alert' : 'status');
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => el.classList.add('out'), 3800);
  setTimeout(() => el.remove(), 4300);
}
function flash(msg) {
  if (!msg) return;
  toast(msg, /^Fehler|nicht|✕/.test(msg) ? 'err' : /^Gespeichert|✓/.test(msg) ? 'ok' : 'info');
}

// Seitenleiste + Zusammenfassung: aktive KI, Ziele, Modus, Threat-Intel
async function updateStatusBar() {
  if (!state.config) return;
  const sel = state.config.selected;
  const name = sel === 'ollama' ? (pcfg('ollama').model || 'Ollama – kein Modell')
    : (pcfg(sel).model || providerMeta(sel).label || sel);
  const where = ai.mode === 'local' ? 'Lokal' : String(providerMeta(sel).label || 'Cloud').replace(/\s*\(.*\)/, '');
  $('sbAi').textContent = name;
  $('sumAi').textContent = !state.targets.length || needsAi() ? `${where} · ${name}` : 'nicht nötig';
  $('sumAi').title = `${where} · ${name}`;
  $('sbDot').className = 'dot ' + (aiReady().ok ? 'ok' : 'wait');
  $('sbTargets').textContent = state.targets.length;
  $('sbMode').textContent = state.config.analysisDepth === 'standard' ? 'Schnell' : 'Gründlich';
  if (!updateStatusBar.intelLoaded) {
    updateStatusBar.intelLoaded = true;
    try { const it = await window.vigil.intelStatus(); $('sbIntel').textContent = it.updatedAt ? `Threat-Intel ${fmtDate(it.updatedAt)}` : 'Threat-Intel lädt …'; } catch { $('sbIntel').textContent = ''; }
  }
}

// Tastenkuerzel
document.addEventListener('keydown', (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (mod && e.key === 'Enter') { e.preventDefault(); if (!$('runBtn').disabled) runAudit(); }
  else if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); const s = state.view === 'dash' ? $('dashSearch') : $('findingSearch'); if (s && s.offsetParent) s.focus(); }
  else if (mod && e.key === ',') { e.preventDefault(); openSettings(); }
  else if (mod && ['1', '2', '3', '4'].includes(e.key)) { e.preventDefault(); showView(['scan', 'results', 'dash', 'history'][+e.key - 1]); }
});

init();
