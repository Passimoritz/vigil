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
const SYSTEM_LABEL = { windows: 'Dieser Windows-PC', docker: 'Laufende Docker-Container', aws: 'AWS-Konto', azure: 'Azure-Abonnement', gcp: 'Google-Cloud-Projekt',
  winapps: 'Installierte Programme', browserext: 'Browser-Erweiterungen', backup: 'Datensicherung (Windows)', macos: 'Dieser Mac', router: 'Router (Standard-Gateway)', lan: 'Geräte im lokalen Netz', linuxssh: 'Linux-Server (SSH)', dbdirect: 'Datenbanken', k8s: 'Kubernetes-Cluster (kubectl)', iam: 'Cloud-Berechtigungen (IAM)', cicd: 'GitHub / GitLab / Azure DevOps', m365: 'Microsoft 365 / Google Workspace', hosting: 'Cloudflare, Hetzner, DigitalOcean, Vercel, Netlify', hibp: 'Datenlecks der Domain (HIBP)' };
const SYSTEM_RE = new RegExp(`^system:(${Object.keys(SYSTEM_LABEL).join('|')})$`, 'i');
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
  if (SYSTEM_RE.test(v)) return { type: 'system', value: v.slice(7).toLowerCase() };
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
  if (needsConfirm(t) && !$('authChk').checked) {
    // Bestaetigung direkt unter dem Feld hervorheben – ein Klick auf „Ja – hinzufügen“ genuegt
    const bar = $('authRow'); bar.hidden = false;
    bar.classList.remove('attention'); void bar.offsetWidth; bar.classList.add('attention');
    $('authYes').focus();
    return;
  }
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
  // macOS-Pruefung nur auf einem Mac anbieten
  const macChip = document.querySelector('.sys-chip[data-system="macos"]');
  if (macChip) macChip.hidden = !/Mac/i.test(navigator.platform || navigator.userAgent || '');
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
  // Monatliches KI-Budget: erreicht oder durch diesen Lauf ueberschritten -> ausdruecklich bestaetigen
  let budgetConfirmed = false;
  const localRun = (est && est.local) || state.config.selected === 'ollama';
  if (needsAi() && !localRun && (state.config.monthlyBudgetUsd || 0) > 0 && window.vigil.budgetStats) {
    let b = null;
    try { b = await window.vigil.budgetStats(); } catch { /* ohne Budget-Info */ }
    const add = est && est.priced ? est.usd : 0;
    if (b && b.budget && (b.exceeded || b.spent + add > b.budget)) {
      if (!confirm(`Monatliches KI-Budget: ${fmtUsd(b.spent)} von ${fmtUsd(b.budget)} ausgegeben.\n${add ? `Dieser Lauf kostet voraussichtlich weitere ${fmtUsd(add)}.\n` : ''}\nTrotzdem starten?`)) return;
      budgetConfirmed = true;
    }
  }
  state.runStartedAt = Date.now();
  state.running = true; updateRunState();
  $('cancelBtn').hidden = false; $('cancelBtn').disabled = false;
  setPaused(false); $('pauseBtn').hidden = false; $('pauseBtn').disabled = false;
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

  const res = await window.vigil.runAudit({ targets: state.targets, providerId: state.config.selected, ...(budgetConfirmed ? { budgetConfirmed: true } : {}) });
  // Bestaetigte Hosts hat der Main-Prozess auf die Freigabeliste gesetzt.
  try { state.config.allowlist = (await window.vigil.getConfig()).allowlist || []; } catch { /* egal */ }
  loadKnown();
  unsub();
  clearInterval(state.elapsedTimer);
  state.running = false; updateRunState(); setRunEta();
  $('cancelBtn').hidden = true;
  $('pauseBtn').hidden = true; setPaused(false);
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

// Befundtexte kommen deutsch aus den Pruefmodulen; in der englischen Oberflaeche uebersetzen
const wantEnglish = () => state.config && state.config.lang !== 'de' && !!window.VigilFindingsI18n;
function renderResult(result) {
  state.rawResult = result;
  if (wantEnglish()) result = window.VigilFindingsI18n.localizeResult(result);
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
  renderVerdict(); renderRunSummary(); renderThreatModel(); renderFilters(); updateBaselineStatus(); renderViewToggles(); renderFindings();
}

// Zusammenfassung des Laufs (KI oder regelbasiert, aus result.meta.runSummary)
function renderRunSummary() {
  const el = $('runSummary'); if (!el) return;
  const s = state.lastResult && state.lastResult.meta && state.lastResult.meta.runSummary;
  el.hidden = !(s && s.text);
  if (!s || !s.text) return;
  el.innerHTML = `<h3>Zusammenfassung</h3><p>${esc(s.text)}</p><span class="muted small">${s.source === 'ai' ? `von der KI geschrieben${s.model ? ' (' + esc(s.model) + ')' : ''}` : 'regelbasiert erstellt'}</span>`;
}

// --- STRIDE-Bedrohungsmodell ---------------------------------------------------
const STRIDE_ORDER = ['S', 'T', 'R', 'I', 'D', 'E'];
const LEVEL_DE = { high: 'hoch', medium: 'mittel', low: 'niedrig' };
function renderThreatModel() {
  const el = $('threatPanel'); if (!el) return;
  const tm = state.threatBusy ? { pending: true } : state.lastResult && state.lastResult.meta && state.lastResult.meta.threatModel;
  el.hidden = !tm;
  if (!tm) return;
  if (tm.pending) { el.innerHTML = `<h3>Bedrohungsmodell (STRIDE)</h3><p class="muted small">Wird erstellt …</p>${dots}`; return; }
  const groups = STRIDE_ORDER.map((s) => ({ s, list: (tm.threats || []).filter((t) => t.stride === s) })).filter((g) => g.list.length);
  el.innerHTML = `<div class="tm-head"><h3>Bedrohungsmodell (STRIDE)</h3><span class="muted small">${tm.source === 'ai' ? `KI${tm.model ? ' · ' + esc(tm.model) : ''}` : 'aus den Befunden abgeleitet'} · ${esc(fmtDate(tm.at))} · auch im Bericht enthalten</span><button type="button" class="btn tiny ghost tm-close">Ausblenden</button></div>
    ${tm.summary ? `<p>${esc(tm.summary)}</p>` : ''}
    ${tm.error ? `<p class="muted small">${esc(tm.error)}</p>` : ''}
    ${(tm.assets || []).length || (tm.entryPoints || []).length ? `<div class="tm-facts">${tm.assets.length ? `<div><h4>Schützenswert</h4><ul>${tm.assets.map((a) => `<li>${esc(a)}</li>`).join('')}</ul></div>` : ''}${tm.entryPoints.length ? `<div><h4>Eingänge</h4><ul>${tm.entryPoints.map((a) => `<li>${esc(a)}</li>`).join('')}</ul></div>` : ''}</div>` : ''}
    <div class="tm-grid">${groups.map((g) => g.list.map((t) => `<article class="tm-card stride-${g.s}">
      <div class="tm-cat"><b>${g.s}</b> ${esc(t.category)}</div>
      <h4 class="tm-title">${esc(t.title)}</h4>
      ${t.asset ? `<p class="muted small">Betrifft: ${esc(t.asset)}</p>` : ''}
      ${t.description ? `<p>${esc(t.description)}</p>` : ''}
      <p class="small">Wahrscheinlichkeit <b>${esc(LEVEL_DE[t.likelihood] || t.likelihood)}</b> · Auswirkung <b>${esc(LEVEL_DE[t.impact] || t.impact)}</b></p>
      ${t.mitigations.length ? `<ul class="tm-mit">${t.mitigations.map((m) => `<li>${esc(m)}</li>`).join('')}</ul>` : ''}
      ${t.findings.length ? `<div class="tm-links">${t.findings.map((x) => `<button type="button" class="chip-btn tm-f" data-id="${esc(x.id || '')}" data-title="${esc(x.title)}">#${x.n} ${esc(x.title.slice(0, 60))}</button>`).join('')}</div>` : ''}
    </article>`).join('')).join('')}</div>
    ${(tm.assumptions || []).length ? `<p class="muted small">Annahmen: ${esc(tm.assumptions.join(' · '))}</p>` : ''}`;
  el.querySelector('.tm-close').onclick = () => { el.hidden = true; };
  el.querySelectorAll('.tm-f').forEach((b) => b.onclick = () => {
    const i = state.lastFindings.findIndex((x) => (b.dataset.id && x.id === b.dataset.id) || x.title === b.dataset.title);
    if (i >= 0) selectFinding(findingKey(state.lastFindings[i], i));
  });
}
async function buildThreatModel() {
  if (state.threatBusy || !state.lastResult) return;
  state.threatBusy = true; renderThreatModel();
  $('threatPanel').scrollIntoView({ block: 'nearest' });
  const r = await window.vigil.threatModel();
  state.threatBusy = false;
  if (r && r.ok) {
    for (const res of [state.lastResult, state.rawResult]) if (res) res.meta = { ...(res.meta || {}), threatModel: r.threatModel };
    toast('Bedrohungsmodell erstellt', 'ok');
  } else flash('Bedrohungsmodell nicht erstellt: ' + ((r && r.error) || 'unbekannter Fehler'));
  renderThreatModel();
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
const OWASP_LABEL = { A01: 'Fehlerhafte Zugriffskontrolle', A02: 'Kryptografische Fehler', A03: 'Injection', A04: 'Unsicheres Design', A05: 'Fehlkonfiguration', A06: 'Veraltete und verwundbare Komponenten', A07: 'Fehler bei Anmeldung', A08: 'Fehlende Integrität von Software und Daten', A09: 'Unzureichendes Protokollieren', A10: 'Server-Side Request Forgery' };
const REACH_LABEL = { used: 'Paket wird genutzt', 'function-used': 'betroffene Funktion wird aufgerufen', 'function-unused': 'betroffene Funktion ungenutzt', unused: 'Paket ungenutzt', transitive: 'nur indirekt enthalten' };
const REACH_HELP = { 'function-used': 'Die Lücke ist sehr wahrscheinlich erreichbar.', 'function-unused': 'Risiko deutlich geringer – trotzdem aktualisieren.', unused: 'Am einfachsten: Paket entfernen.', transitive: 'Kommt über ein anderes Paket mit.' };
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
    f.owasp ? `<span class="chip" title="${esc(OWASP_LABEL[f.owasp] || f.owasp)} – Einordnung nach OWASP Top 10">OWASP ${esc(f.owasp)}</span>` : '',
    f.cwe ? `<span class="chip" title="Schwachstellen-Typ nach der CWE-Liste">${esc(f.cwe)}</span>` : '',
    f.reach ? `<span class="chip reach-${esc(f.reach)}" title="${esc(REACH_HELP[f.reach] || '')}">${esc(REACH_LABEL[f.reach] || f.reach)}</span>` : '',
    f.consensus === 'both' ? '<span class="chip ev-multi" title="Beide KI-Modelle haben diesen Befund unabhängig gefunden">von 2 Modellen bestätigt</span>' : '',
  ].filter(Boolean).join('');
  const ctx = (f.context || []).filter((c) => CONTEXT[c]);
  const danger = [f.impact, f.reachability].filter(Boolean).join(' ');
  const secs = [
    f.description && `<div class="f-sec${danger ? '' : ' full'}"><h4>Was ist los?</h4><p>${glossify(esc(f.description))}</p></div>`,
    danger && `<div class="f-sec${f.description ? '' : ' full'}"><h4>Was kann passieren?</h4><p>${glossify(esc(danger))}</p></div>`,
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
      ${/:\d+(:\d+)?$/.test(f.location || '') && !/^https?:/i.test(f.location || '') ? '<div class="f-sec code-sec" hidden><h4>Betroffener Code</h4><div class="code-view"></div></div>' : ''}
      ${solutionBlock(f)}
      ${aiHelpBlock(f)}
      ${noteBlock(f)}
      <div class="f-sec ask-sec">
        <h4>Rückfrage an die KI</h4>
        <div class="ask-log" aria-live="polite"></div>
        <div class="ask-quick">
          <button type="button" class="chip-btn" data-q="Ist das bei mir wirklich ausnutzbar? Was müsste dafür gegeben sein?">Wirklich ausnutzbar?</button>
          <button type="button" class="chip-btn" data-q="Wie behebe ich das genau in meinem Code? Bitte mit konkretem Beispiel.">Wie genau beheben?</button>
          <button type="button" class="chip-btn" data-q="Kann das ein Fehlalarm sein? Woran erkenne ich das?">Fehlalarm?</button>
        </div>
        <form class="ask-form"><input type="text" class="ask-input" placeholder="Eigene Frage zu diesem Befund …" aria-label="Frage zu diesem Befund" maxlength="2000" /><button type="submit" class="btn primary tiny">Fragen</button></form>
      </div>
    </div>`;
}

// Kleines, sicheres Markdown fuer KI-Antworten: Absaetze, Ueberschriften, Listen, **fett**, *kursiv*,
// `Code`, Codebloecke und https-Links. Alles wird zuerst maskiert – die KI kann kein HTML einschleusen.
function mdInline(t) {
  return esc(t)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s.,;:!?)]|$)/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https:\/\/[^)\s]+)\)/g, '<a href="#" class="md-link" data-url="$2">$1</a>');
}
function miniMarkdown(src) {
  const parts = String(src || '').replace(/\r/g, '').split('```');
  let html = '';
  parts.forEach((part, i) => {
    if (i % 2) { html += `<pre class="md-code"><code>${esc(part.replace(/^[\w+.-]*\n/, '').replace(/\n$/, ''))}</code></pre>`; return; }
    let list = null;
    const close = () => { if (list) { html += `</${list}>`; list = null; } };
    for (const raw of part.split('\n')) {
      const l = raw.trimEnd();
      let m;
      if (!l.trim()) { close(); continue; }
      if ((m = l.match(/^\s*#{1,4}\s+(.*)$/))) { close(); html += `<p class="md-h">${mdInline(m[1])}</p>`; continue; }
      if ((m = l.match(/^\s*[-*•]\s+(.*)$/))) { if (list !== 'ul') { close(); html += '<ul>'; list = 'ul'; } html += `<li>${mdInline(m[1])}</li>`; continue; }
      if ((m = l.match(/^\s*\d+[.)]\s+(.*)$/))) { if (list !== 'ol') { close(); html += '<ol>'; list = 'ol'; } html += `<li>${mdInline(m[1])}</li>`; continue; }
      close();
      html += `<p>${mdInline(l)}</p>`;
    }
    close();
  });
  return html;
}

// Nach dem Einfuegen der Detailansicht: Code-Ausschnitt laden und Rueckfragen verdrahten.
// Gespraeche bleiben je Befund erhalten, solange die App laeuft.
state.chats = state.chats || {};
function hydrateDetail(root, f) {
  const codeSec = root.querySelector('.code-sec');
  if (codeSec && window.vigil.findingSnippet) {
    window.vigil.findingSnippet(f.location).then((s) => {
      if (!s || !s.ok || !root.contains(codeSec)) return;
      codeSec.hidden = false;
      codeSec.querySelector('.code-view').innerHTML = `<div class="code-file">${esc(s.file)}</div><pre>${s.lines.map((l, i) => { const n = s.from + i; return `<span class="cl${n === s.line ? ' hit' : ''}"><i>${n}</i>${esc(l) || ' '}</span>`; }).join('')}</pre>`;
    }).catch(() => {});
  }
  const sec = root.querySelector('.ask-sec');
  if (!sec) return;
  const key = f.id || `${f.ruleId}@${f.location}`;
  const chat = state.chats[key] || (state.chats[key] = []);
  const log = sec.querySelector('.ask-log');
  const paint = () => {
    log.innerHTML = chat.map((m) => `<div class="ask-msg ${m.role}"><span class="ask-who">${m.role === 'user' ? 'Du' : esc(m.model || 'KI')}</span><div class="${m.role === 'ai' ? 'ask-md' : ''}">${m.pending ? '<span class="ask-dots"><i></i><i></i><i></i></span>' : m.role === 'ai' ? miniMarkdown(m.text) : esc(m.text)}</div></div>`).join('');
    log.querySelectorAll('.md-link').forEach((a) => a.onclick = (e) => { e.preventDefault(); window.vigil.openLink(a.dataset.url); });
    log.hidden = !chat.length;
  };
  paint();
  const ask = async (q) => {
    q = String(q || '').trim();
    if (!q || chat.some((m) => m.pending)) return;
    const history = chat.filter((m) => !m.pending).map((m) => ({ role: m.role, text: m.text }));
    chat.push({ role: 'user', text: q }, { role: 'ai', pending: true });
    paint();
    const r = await window.vigil.askFinding({ question: q, history, finding: { title: f.title, severity: f.severity, location: f.location, category: f.category, description: f.description, impact: f.impact, reachability: f.reachability, remediation: f.remediation } });
    chat.pop();
    chat.push({ role: 'ai', text: r && r.ok ? r.answer : `Keine Antwort: ${(r && r.error) || 'unbekannter Fehler'}`, model: r && r.model });
    if (root.contains(sec)) paint();
  };
  sec.querySelectorAll('[data-q]').forEach((b) => b.onclick = () => ask(b.dataset.q));
  sec.querySelector('.ask-form').onsubmit = (e) => { e.preventDefault(); const inp = sec.querySelector('.ask-input'); ask(inp.value); inp.value = ''; };
  hydrateAiHelp(root, f);
}

// --- KI-Hilfe im Detail: Erklaerstufen, Fix als Diff, Upgrade-Hinweise ------------------
// Alles sind Vorschlaege: Vigil aendert keine Datei – Kopieren und Uebernehmen macht der Nutzer.
const LEVEL_LABEL = { lay: 'Laie', dev: 'Entwickler', expert: 'Experte' };
state.aiHelp = state.aiHelp || {};
const findingPayload = (f) => ({ id: f.id, title: f.title, severity: f.severity, location: f.location, category: f.category, cwe: f.cwe, description: f.description, impact: f.impact, reachability: f.reachability, remediation: f.remediation });
function aiHelpBlock(f) {
  const pkg = f.package && f.package.name ? f.package : null;
  const codeFix = /:\d+(:\d+)?$/.test(f.location || '') && !/^https?:/i.test(f.location || '');
  return `<div class="f-sec ai-help">
    <h4>KI-Hilfe</h4>
    <div class="lvl-row"><span class="muted small">Erklärung für</span>
      <span class="seg lvl-seg" role="radiogroup" aria-label="Erklärstufe">${Object.entries(LEVEL_LABEL).map(([k, v]) => `<button type="button" role="radio" aria-checked="false" data-level="${k}">${v}</button>`).join('')}</span>
    </div>
    <div class="explain-out ask-md" aria-live="polite" hidden></div>
    <div class="patch-row">
      ${codeFix ? '<button type="button" class="btn small gen-patch">Fix generieren</button>' : ''}
      ${pkg ? '<button type="button" class="btn small upg-btn">Upgrade-Hinweise</button>' : ''}
      ${codeFix || pkg ? '<span class="muted small">Nur Vorschläge – Vigil ändert keine Datei.</span>' : ''}
    </div>
    <div class="patch-out" aria-live="polite" hidden></div>
    <div class="upg-out" aria-live="polite" hidden></div>
  </div>`;
}
const dots = '<span class="ask-dots"><i></i><i></i><i></i></span>';
function diffHtml(d) {
  return `<pre class="diff-view">${String(d).split('\n').map((l) => `<span class="${/^(\+\+\+|---)/.test(l) ? 'd-file' : /^@@/.test(l) ? 'd-hunk' : /^\+/.test(l) ? 'd-add' : /^-/.test(l) ? 'd-del' : 'd-ctx'}">${esc(l) || ' '}</span>`).join('')}</pre>`;
}
function hydrateAiHelp(root, f) {
  const box = root.querySelector('.ai-help');
  if (!box) return;
  const key = f.id || `${f.ruleId}@${f.location}`;
  const mem = state.aiHelp[key] || (state.aiHelp[key] = { explain: {} });
  const out = box.querySelector('.explain-out');
  const paintExplain = () => {
    box.querySelectorAll('.lvl-seg button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.level === mem.level)));
    const e = mem.level && mem.explain[mem.level];
    out.hidden = !e;
    if (!e) return;
    out.innerHTML = e.pending ? dots : e.error ? `<p class="err small">${esc(e.error)}</p>`
      : `${miniMarkdown(e.text)}<p class="muted small">${esc(e.model || 'KI')}${e.cached ? ' · aus dem Zwischenspeicher' : ''} · <a href="#" class="re-explain">neu erklären</a></p>`;
    const re = out.querySelector('.re-explain');
    if (re) re.onclick = (ev) => { ev.preventDefault(); explain(mem.level, true); };
  };
  const explain = async (level, refresh) => {
    mem.level = level;
    if (mem.explain[level] && !refresh && !mem.explain[level].error) { paintExplain(); return; }
    mem.explain[level] = { pending: true };
    paintExplain();
    const r = await window.vigil.explainFinding(findingPayload(f), level, refresh);
    mem.explain[level] = r && r.ok ? { text: r.text, model: r.model, cached: r.cached } : { error: `Keine Antwort: ${(r && r.error) || 'unbekannter Fehler'}` };
    if (root.contains(box)) paintExplain();
  };
  box.querySelectorAll('.lvl-seg button').forEach((b) => b.onclick = () => explain(b.dataset.level));
  paintExplain();

  const pout = box.querySelector('.patch-out');
  const paintPatch = () => {
    const p = mem.patch;
    pout.hidden = !p;
    if (!p) return;
    if (p.pending) { pout.innerHTML = `<p class="muted small">Die KI schreibt einen Fix-Vorschlag …</p>${dots}`; return; }
    if (p.error) { pout.innerHTML = `<p class="err small">${esc(p.error)}</p>`; return; }
    const chk = p.check && p.check.checked ? (p.check.applies ? '<span class="chip ev-ok">passt zum aktuellen Code</span>' : '<span class="chip ev-weak">passt nicht exakt – vor dem Übernehmen prüfen</span>') : '';
    pout.innerHTML = `${p.summary ? `<p>${esc(p.summary)}</p>` : ''}
      ${p.diff ? `<div class="sol-head"><span class="muted small">+${p.stats.added} / −${p.stats.removed} Zeilen · ${esc(p.model || '')}${p.confidence ? ' · Verlässlichkeit ' + esc(CONF_LABEL[p.confidence] || p.confidence) : ''}</span>${chk}${copyBtn(p.diff)}</div>${diffHtml(p.diff)}<p class="muted small">Nichts wurde angewendet. Kopieren und z. B. mit <code>git apply</code> übernehmen – vorher lesen und testen.</p>` : '<p class="muted small">Kein Diff möglich.</p>'}
      ${p.notes ? `<div class="ask-md">${miniMarkdown(p.notes)}</div>` : ''}`;
    bindSolutionControls(pout);
  };
  const pb = box.querySelector('.gen-patch');
  if (pb) pb.onclick = async () => {
    if (mem.patch && mem.patch.pending) return;
    mem.patch = { pending: true }; paintPatch(); pb.disabled = true;
    const r = await window.vigil.patchFinding(findingPayload(f));
    mem.patch = r && r.ok ? r : { error: `Kein Vorschlag: ${(r && r.error) || 'unbekannter Fehler'}` };
    pb.disabled = false;
    if (root.contains(box)) paintPatch();
  };
  paintPatch();

  const uout = box.querySelector('.upg-out');
  const paintUpg = () => {
    const u = mem.upgrade;
    uout.hidden = !u;
    if (!u) return;
    if (u.pending) { uout.innerHTML = `<p class="muted small">Suche Changelog und Release Notes …</p>${dots}`; return; }
    if (u.error && !u.links) { uout.innerHTML = `<p class="err small">${esc(u.error)}</p>`; return; }
    const j = u.jump || {};
    const warn = j.breaking ? `<p class="upg-warn">⚠ ${j.kind === 'major' ? `Sprung über ${j.majors || 1} Hauptversion(en)` : 'Versionssprung in 0.x'} (${esc(j.from)} → ${esc(j.to)}) – brechende Änderungen sind wahrscheinlich.</p>`
      : j.kind === 'unknown' ? '<p class="muted small">Versionssprung nicht bestimmbar.</p>' : `<p class="muted small">${j.kind === 'minor' ? 'Kleiner Versionssprung' : 'Fehlerbehebungs-Version'} (${esc(j.from)} → ${esc(j.to)}) – nach semver ohne brechende Änderungen.</p>`;
    uout.innerHTML = warn
      + (u.aiSummary ? `<div class="ask-md">${miniMarkdown(u.aiSummary)}</div>` : '')
      + (u.hints && u.hints.length ? `<h4>Hinweise aus den Release Notes</h4><ul class="upg-hints">${u.hints.map((h) => `<li><b>${esc(h.tag)}</b> ${esc(h.text)}</li>`).join('')}</ul>` : '')
      + (u.links && u.links.length ? `<div class="link-row">${u.links.map((l) => `<button type="button" class="link-chip kind-${esc(l.kind || 'doc')}" data-url="${esc(l.url)}" title="${esc(l.url)}">${LINK_ICON[l.kind] || '🔗'} ${esc(l.label)}</button>`).join('')}</div>` : '<p class="muted small">Keine Changelog-Links in den Paket-Metadaten gefunden.</p>')
      + (u.error ? `<p class="muted small">Hinweis: ${esc(u.error)}</p>` : '');
    bindSolutionControls(uout);
  };
  const ub = box.querySelector('.upg-btn');
  if (ub) ub.onclick = async () => {
    if (mem.upgrade && mem.upgrade.pending) return;
    mem.upgrade = { pending: true }; paintUpg(); ub.disabled = true;
    const r = await window.vigil.upgradeGuide(f.package);
    mem.upgrade = r && r.ok ? r : { error: `Keine Hinweise: ${(r && r.error) || 'unbekannter Fehler'}` };
    ub.disabled = false;
    if (root.contains(box)) paintUpg();
  };
  paintUpg();
}

// --- Loesungsteil: Warum, Schritte, Versions-Patch, Schnipsel, Links -------
const LINK_ICON = { doc: '📘', news: '📰', video: '▶' };
const SNIP_LABEL = { nginx: 'nginx', apache: 'Apache', caddy: 'Caddy', express: 'Node/Express', node: 'Node.js', php: 'PHP', compose: 'docker-compose', dockerfile: 'Dockerfile', yaml: 'GitHub Actions', sshd_config: 'sshd_config', shell: 'Shell', ufw: 'ufw', fail2ban: 'fail2ban', dns: 'DNS-Eintrag', prisma: 'Prisma', sql: 'SQL', html: 'HTML', vite: 'Vite', webpack: 'webpack', npmrc: '.npmrc', ci: 'CI', certbot: 'certbot', csp: 'CSP', http: 'HTTP', apollo: 'Apollo', yoga: 'GraphQL Yoga', terser: 'terser' };
function copyBtn(text) { return `<button type="button" class="btn tiny copy-btn" data-copy="${esc(text)}">Kopieren</button>`; }
function solutionBlock(f) {
  const parts = [];
  if (f.explanation) parts.push(`<div class="sol-why"><h4>Warum das wichtig ist</h4><p>${glossify(esc(f.explanation))}</p></div>`);
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
  box.innerHTML = toxicBanner(state.lastFindings) + groupFindings(keyed).map((g) => `<div class="group-head${g.sev ? ' sev-' + g.sev : ' gb'}" title="${esc(g.label)}">${esc(g.label)} <span class="gcount">${g.items.length}</span></div>` + g.items.map((x) => findingRow(x.f, x.key)).join('')).join('');
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
  hydrateDetail(pane, f);
  pane.querySelectorAll('.linked-row').forEach((b) => b.onclick = () => {
    // Ausgeblendeter Teilbefund? Filter zuruecksetzen, damit er in der Liste auftaucht.
    if (!visibleList().some((x) => findingKey(x, state.lastFindings.indexOf(x)) === b.dataset.key)) { state.filter = 'all'; state.query = ''; $('findingSearch').value = ''; state.onlyNew = false; state.onlyProven = false; refreshResultView(); }
    selectFinding(b.dataset.key);
  });
  bindNote(pane, f, (note) => { state.lastFindings.forEach((x) => { if (x.id === f.id) x.note = note; }); if (state.rawResult) (state.rawResult.findings || []).forEach((x) => { if (x.id === f.id) x.note = note; }); });
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
// "Risiko akzeptiert" ist befristet: Frist (Standard 90 Tage) und Begruendung abfragen.
// Liefert { days, note } oder null (abgebrochen).
function askAcceptance() {
  return new Promise((resolve) => {
    const dlg = document.createElement('dialog');
    dlg.className = 'accept-dlg';
    dlg.innerHTML = `<form method="dialog">
      <h3>Risiko akzeptieren</h3>
      <p class="muted small">Die Akzeptanz läuft ab – danach ist der Befund wieder offen und wird neu bewertet.</p>
      <label class="field"><span>Gültig für</span><select class="acc-days">${[[30, '30 Tage'], [90, '90 Tage (Standard)'], [180, '180 Tage'], [365, '1 Jahr']].map(([d, l]) => `<option value="${d}"${d === 90 ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
      <label class="field"><span>Begründung (optional)</span><input type="text" class="acc-note" maxlength="500" placeholder="z. B. nur intern erreichbar, Behebung im nächsten Release" /></label>
      <div class="dlg-actions"><button type="button" class="btn ghost acc-cancel">Abbrechen</button><button type="submit" class="btn primary acc-ok">Akzeptieren</button></div>
    </form>`;
    document.body.appendChild(dlg);
    const done = (v) => { try { dlg.close(); } catch { /* egal */ } dlg.remove(); resolve(v); };
    dlg.querySelector('.acc-cancel').onclick = () => done(null);
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); done(null); });
    dlg.querySelector('form').onsubmit = (e) => { e.preventDefault(); done({ days: Number(dlg.querySelector('.acc-days').value) || 90, note: dlg.querySelector('.acc-note').value.trim() }); };
    try { dlg.showModal(); } catch { dlg.setAttribute('open', ''); }
    dlg.querySelector('.acc-days').focus();
  });
}
function bindStatusSelects(root, onChanged) {
  root.querySelectorAll('.status-select').forEach((sel) => {
    sel.onclick = (e) => e.stopPropagation();
    let prev = sel.value;
    sel.onfocus = () => { prev = sel.value; };
    sel.onchange = async () => {
      let r;
      if (sel.value === 'ACCEPTED_RISK') {
        const a = await askAcceptance();
        if (!a) { sel.value = prev; return; }
        r = await window.vigil.setFindingStatus(sel.dataset.id, sel.value, a.note, a.days);
        if (r.ok && r.acceptedUntil) toast(`Akzeptiert bis ${new Date(r.acceptedUntil).toLocaleDateString(state.config && state.config.lang === 'de' ? 'de-DE' : 'en-GB')}`, 'ok');
      } else r = await window.vigil.setFindingStatus(sel.dataset.id, sel.value);
      if (r.ok) { prev = sel.value; onChanged(sel.dataset.id, r.status); }
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

// Details eines Laufs: Modell, Kosten, Zusammenfassung und (falls aufgezeichnet) das
// Reproduzierbarkeits-Protokoll mit Prompt- und Antwort-Pruefsummen.
const REPRO_KIND = { analyze: 'Analyse', triage: 'Vorsortierung', validate: 'Gegenprüfung', summary: 'Zusammenfassung' };
function historyDetailsHtml(d) {
  const u = d.usage || {};
  const facts = [
    d.provider && `${esc(d.provider)} / ${esc(d.model || '–')}`,
    u.inputTokens || u.outputTokens ? `${fmtK((u.inputTokens || 0) + (u.outputTokens || 0))} Tokens` : '',
    u.priced ? fmtUsd(u.usd || 0) : u.local ? 'Lokal' : '',
    d.lookups != null ? `${d.lookups} Nachschlage-Abfragen` : '',
    d.privacyMode ? 'strenger Datenschutz' : '',
    d.skippedByBudget ? `${d.skippedByBudget} Dateien wegen Budget übersprungen` : '',
  ].filter(Boolean).map((x) => '<span>' + x + '</span>').join(' · ');
  const r = d.repro;
  const repro = r ? `<h4>Protokoll für Reproduzierbarkeit</h4>
    <p class="muted small"><span>${r.calls} KI-Aufruf(e)</span> · <span>Prompt-Version ${esc(r.promptVersion || '–')}</span> · <span>${r.integrity && r.integrity.ok ? 'Prüfsummen stimmen' : 'Prüfsummen weichen ab: ' + esc((r.integrity && r.integrity.bad || []).join(', '))}</span>${r.truncated ? ' · <span>Prompts teilweise nur als Prüfsumme (Größenlimit)</span>' : ''}</p>
    <div class="repro-list">${(r.entries || []).slice(0, 200).map((e) => `<details class="repro-item"><summary><b>#${e.n}</b> <span>${esc(REPRO_KIND[e.kind] || e.kind)}</span> · ${esc(e.model || '')} · T=${esc(String(e.params && e.params.temperature != null ? e.params.temperature : '–'))} · max ${esc(String((e.params && e.params.maxTokens) || '–'))} <code title="SHA-256 des Prompts">${esc(String(e.promptSha256).slice(0, 12))}</code> → <code title="SHA-256 der Antwort">${esc(String(e.responseSha256).slice(0, 12))}</code></summary>
      <p class="muted small">Prompt-SHA-256: <code>${esc(e.promptSha256)}</code><br>Antwort-SHA-256: <code>${esc(e.responseSha256)}</code></p>
      ${e.prompt ? `<pre class="repro-pre">${esc([e.prompt.system, e.prompt.prefix, e.prompt.user].filter(Boolean).join('\n\n').slice(0, 20000))}</pre><h4>Antwort</h4><pre class="repro-pre">${esc(String(e.response || '').slice(0, 8000))}</pre>` : '<p class="muted small">Nur Prüfsummen gespeichert.</p>'}
    </details>`).join('')}</div>` : '<p class="muted small">Kein Reproduzierbarkeits-Protokoll (in den Einstellungen unter „Belastbarkeit &amp; Datenschutz“ einschaltbar).</p>';
  return `${facts ? `<p class="small">${facts}</p>` : ''}${d.runSummary && d.runSummary.text ? `<p>${esc(d.runSummary.text)}</p>` : ''}${repro}`;
}

// --- Scan-Verlauf -------------------------------------------------------
async function loadHistory() {
  renderHistory(await window.vigil.historyList());
}
function renderHistory(runs) {
  const box = $('historyList');
  if (!runs || !runs.length) { box.innerHTML = '<p class="muted">Noch keine Läufe gespeichert.</p>'; state.histSel = []; updateCompareBar(); return; }
  state.histRuns = runs;
  state.histSel = (state.histSel || []).filter((id) => runs.some((r) => r.id === id));
  box.innerHTML = runs.map((r) => {
    const c = r.counts || {};
    const when = new Date(r.at).toLocaleString('de-DE');
    const tgt = (r.targets || []).join(', ');
    return `<div class="hist-item"><input type="checkbox" class="hist-sel" data-id="${esc(r.id)}" aria-label="Für den Vergleich auswählen"${state.histSel.includes(r.id) ? ' checked' : ''}><button type="button" class="hist-row" data-id="${esc(r.id)}">
      <span class="hist-when">${esc(when)}</span>
      <span class="hist-tgt" title="${esc(tgt)}">${esc(tgt || '—')}</span>
      <span class="hist-counts">${r.total || 0} Befund(e)${c.critical ? ` · ${c.critical} kritisch` : ''}${c.high ? ` · ${c.high} hoch` : ''}</span>
    </button><button type="button" class="btn tiny ghost hist-det" data-id="${esc(r.id)}" aria-expanded="false">Details</button><div class="hist-details" hidden></div></div>`;
  }).join('');
  box.querySelectorAll('.hist-det').forEach((b) => b.onclick = async () => {
    const pane = b.parentElement.querySelector('.hist-details');
    if (!pane.hidden) { pane.hidden = true; b.setAttribute('aria-expanded', 'false'); return; }
    pane.hidden = false; b.setAttribute('aria-expanded', 'true');
    pane.innerHTML = dots;
    const d = await window.vigil.historyDetails(b.dataset.id);
    pane.innerHTML = d && d.ok ? historyDetailsHtml(d) : `<p class="err small">${esc((d && d.error) || 'Nicht lesbar.')}</p>`;
  });
  box.querySelectorAll('.hist-sel').forEach((c) => c.onchange = () => toggleHistSel(c.dataset.id, c.checked));
  updateCompareBar();
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
const CLOUD_IDS = ['anthropic', 'openai', 'gemini', 'mistral', 'deepseek', 'groq', 'openrouter', 'azure', 'bedrock', 'vertex', 'compat'];
// Anbieter, die zwingend eine eigene Basis-URL brauchen (Einstellungen > Server-Adressen)
const NEEDS_URL = new Set(['compat', 'azure', 'vertex']);
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
  if (!cloudHasAccess(id)) return { ok: false, why: NEEDS_URL.has(id) && !pcfg(id).baseUrl ? 'Trage in den Einstellungen die Server-Adresse des Dienstes ein.' : 'Füge unter „KI“ deinen API-Schlüssel ein.' };
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
  if (!names.includes(p.model)) {
    // Passt ein installiertes Modell zur Ausstattung des PCs? Dann dieses vorauswaehlen.
    const hw = ai.hardware && ai.hardware.recommendation;
    p.model = (hw && hw.installedChoice && names.includes(hw.installedChoice)) ? hw.installedChoice : pickPreferred('ollama', names, '');
    saveCfg();
  }
  $('localModel').innerHTML = models.map((m) => `<option value="${esc(m.name)}"${m.name === p.model ? ' selected' : ''}>${esc(m.name)}${m.size ? ' · ' + fmtSize(m.size) : ''}</option>`).join('');
}
const fullTag = (n) => (n.includes(':') ? n : n + ':latest');
const isInstalled = (n) => ai.ollama.models.some((m) => m.name === n || m.name === fullTag(n));
// Hinweis: erkannte Grafikkarte/RAM und das dazu passende Modell
function renderHwRec() {
  const el = $('hwRec'); if (!el) return;
  const h = ai.hardware;
  el.hidden = !(h && h.recommendation);
  if (!h || !h.recommendation) return;
  const r = h.recommendation;
  const g = (h.gpus || [])[0];
  const have = ai.ollama && ai.ollama.models && isInstalled(r.name);
  el.innerHTML = `<span class="hw-ico" aria-hidden="true">⚙</span><div><b>Empfohlen für deinen PC: ${esc(r.label)}</b><span class="muted small">${g ? esc(g.name) + (g.vramGB ? ' · ' + String(g.vramGB).replace('.', ',') + ' GB Grafikspeicher' : '') + ' · ' : ''}${String(h.ramGB).replace('.', ',')} GB RAM – ${r.mode === 'gpu' ? 'läuft auf der Grafikkarte' : 'läuft auf dem Prozessor (langsamer)'}</span></div>${have ? '<span class="rec-ok">✓ installiert</span>' : ai.ollama && ai.ollama.running ? `<button class="btn small hw-pull" data-m="${esc(r.name)}"${ai.pulling ? ' disabled' : ''}>Laden</button>` : ''}`;
  const b = el.querySelector('.hw-pull'); if (b) b.onclick = () => pullModel(b.dataset.m);
}
function renderRecommended() {
  renderHwRec();
  const best = ai.hardware && ai.hardware.recommendation && ai.hardware.recommendation.name;
  $('recList').innerHTML = ai.recommended.map((r) => {
    const have = isInstalled(r.name);
    const action = have ? '<span class="rec-ok">✓ installiert</span>'
      : `<button class="btn small rec-pull" data-m="${esc(r.name)}"${ai.pulling ? ' disabled' : ''}>Laden</button>`;
    return `<div class="rec${have ? ' have' : ''}">
      <div class="rec-main"><b>${esc(r.label)}${r.name === best ? ' <span class="chip ev-ok">passt zu deinem PC</span>' : ''}</b><span class="muted small">${esc(r.note)}</span></div>
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
  if (id === 'vertex') return !!c.baseUrl; // Token optional (gcloud)
  if (id === 'azure') return !!c.baseUrl && !!(providerMeta(id).envKeyPresent || c.apiKey);
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
  else setCloudStatus('muted', NEEDS_URL.has(id) && !c.baseUrl ? (id === 'compat' ? 'Für OpenAI-kompatible Dienste die Server-Adresse in den Einstellungen eintragen.' : 'Die Server-Adresse (Basis-URL) des Dienstes in den Einstellungen eintragen.') : 'Schlüssel eingeben – die Modelle laden dann automatisch.');
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
const RUN_LABEL = { QUEUED: 'wartet', RUNNING: 'läuft', COMPLETED: 'fertig', FAILED: 'fehlgeschlagen', PARTIAL_FAILURE: 'teilweise', THROTTLED_ABORTED: 'gedrosselt' };
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
    setGroup(state.setGroup || 'general');
  }
}
function closeMenus() {
  $('exportMenu').hidden = true;
  $('exportBtn').setAttribute('aria-expanded', 'false');
}

async function loadDashboard() {
  const res = await window.vigil.dashboard({ ...dash, limit: 5000 });
  const stats = res.stats;
  const findings = wantEnglish() ? res.findings.map(window.VigilFindingsI18n.localizeFinding) : res.findings;
  state.dashStats = stats;
  const open = stats.open || {};
  const total = stats.openTotal || 0;
  // Kopfzeile
  $('dashSummary').textContent = !stats.targets.length ? 'Noch keine Prüfungen gespeichert. Starte unter „Neue Prüfung“ deinen ersten Lauf.'
    : total ? `${total} ${total === 1 ? 'Befund ist' : 'Befunde sind'} offen – über ${stats.targets.length} ${stats.targets.length === 1 ? 'Ziel' : 'Ziele'}. ${stats.byStatus.RESOLVED || 0} behoben, ${(stats.byStatus.FALSE_POSITIVE || 0) + (stats.byStatus.ACCEPTED_RISK || 0)} als Fehlalarm oder akzeptiert.`
      : 'Keine offenen Befunde – alles im grünen Bereich.';
  // Sicherheitswert
  const sc = $('dashScore');
  const tone = stats.posture >= 78 ? 'var(--low)' : stats.posture >= 50 ? 'var(--med)' : 'var(--crit)';
  sc.style.setProperty('--p', stats.posture); sc.style.setProperty('--tone', tone);
  $('dashGrade').textContent = stats.targets.length ? gradeOf(stats.posture) : '–';
  $('dashScoreLabel').textContent = stats.targets.length ? `${stats.posture} / 100` : 'noch kein Wert';
  $('dashVerdict').textContent = !stats.targets.length ? 'Noch nichts geprüft' : stats.posture >= 90 ? 'Sehr gut aufgestellt' : stats.posture >= 78 ? 'Gut – kleinere Baustellen' : stats.posture >= 60 ? 'Ordentlich, aber mit Lücken' : stats.posture >= 40 ? 'Deutlicher Handlungsbedarf' : 'Dringend handeln';
  const tr = stats.trend || [];
  const delta = tr.length >= 2 ? tr[tr.length - 1].posture - tr[tr.length - 2].posture : null;
  $('dashDelta').textContent = delta == null ? '' : delta === 0 ? 'unverändert seit dem letzten Lauf' : `${delta > 0 ? '▲ +' : '▼ '}${delta} seit dem letzten Lauf`;
  $('dashDelta').className = 'small ' + (delta > 0 ? 'up' : delta < 0 ? 'down' : 'muted');
  $('dashSpark').innerHTML = sparkline(tr.slice(-20).map((t) => t.posture), 100);
  // Schwere-Verteilung als Balken + Legende (anklickbar = Filter)
  $('dashOpenTotal').textContent = total;
  $('dashSevBar').innerHTML = total ? SEV_ORDER.filter((s) => open[s]).map((s) => `<span class="sb-${SEV_CLS[s]}" style="flex:${open[s]}" title="${SEV_LABEL[s]}: ${open[s]}"></span>`).join('') : '<span class="sb-none"></span>';
  $('dashStats').innerHTML = SEV_ORDER.map((s) => `<button type="button" class="sev-chip c-${SEV_CLS[s]}${dash.severity === s ? ' on' : ''}" data-sev="${s}" aria-pressed="${dash.severity === s}"><i></i><b>${open[s] || 0}</b> ${SEV_LABEL[s]}</button>`).join('');
  $('dashStats').querySelectorAll('[data-sev]').forEach((b) => b.onclick = () => { dash.severity = dash.severity === b.dataset.sev ? '' : b.dataset.sev; $('dashSeverity').value = dash.severity; dashTab('findings'); loadDashboard(); });
  // Kennzahlen rechts
  const k = stats.last30 || { created: 0, resolved: 0 };
  $('dashTrendKpis').innerHTML = `
    <div><span class="kpi-n">${stats.mttrDays != null ? String(stats.mttrDays).replace('.', ',') : '–'}</span><span class="kpi-l">Tage bis zur Behebung (Ø)</span></div>
    <div><span class="kpi-n">${k.resolved}</span><span class="kpi-l">behoben (30 Tage)</span></div>
    <div><span class="kpi-n">${k.created}</span><span class="kpi-l">neu gefunden (30 Tage)</span></div>
    <div><span class="kpi-n${stats.toxic.length ? ' warn' : ''}">${stats.toxic.length}</span><span class="kpi-l">offene Angriffswege</span></div>`;
  renderWatch();
  $('dashToxic').innerHTML = stats.toxic.length ? `<div class="toxic-banner" role="alert"><div class="toxic-ico">⚠</div><div><b>${stats.toxic.length} ${stats.toxic.length === 1 ? 'Angriffsweg' : 'Angriffswege'} offen</b><ul>${stats.toxic.map((t) => `<li>${esc(t.title.replace(/^(Möglicher )?Angriffsweg:\s*/, ''))} <span class="muted small">· ${esc(t.targetName)}</span></li>`).join('')}</ul></div></div>` : '';
  try {
    const it = await window.vigil.intelStatus();
    $('intelLine').textContent = `${stats.kev ? `${stats.kev} offene Lücke(n) werden aktiv ausgenutzt (CISA KEV) · ` : ''}${stats.newSinceBaseline} offen seit Baseline · Gefahrenlage ${it.updatedAt ? 'vom ' + fmtDate(it.updatedAt) : 'noch nicht geladen'}`;
  } catch { /* Vorschau */ }
  // Filterzustand
  $('dashStatus').querySelectorAll('.fbtn').forEach((b) => b.classList.toggle('active', b.dataset.s === dash.status));
  $('dashToggles').querySelectorAll('.fbtn').forEach((b) => b.classList.toggle('active', !!dash[b.dataset.t]));
  const sel = $('dashTargetSelect');
  sel.innerHTML = '<option value="">Alle Ziele</option>' + stats.targets.map((t) => `<option value="${esc(t.id)}"${dash.targetId === t.id ? ' selected' : ''}>${esc(t.name)}</option>`).join('');
  $('tabCountFindings').textContent = findings.length;
  $('tabCountTargets').textContent = stats.targets.length;
  renderDashTargets(stats.targets);
  renderDashRuns(stats.runs);
  renderDashTrend(stats);
  renderDashTable(findings, stats.targets);
}

function sparkline(values, max) {
  if (values.length < 2) return '';
  const W = 160, H = 34, m = Math.max(max || 0, ...values, 1);
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * (W - 4) + 2).toFixed(1)},${(H - 3 - (v / m) * (H - 6)).toFixed(1)}`).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linejoin="round"/></svg>`;
}

// Reiter der Uebersicht
function dashTab(name) {
  state.dashTabName = name;
  document.querySelectorAll('.dash-tab').forEach((b) => { const on = b.dataset.tab === name; b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on)); });
  document.querySelectorAll('.dash-pane').forEach((p) => { p.hidden = p.dataset.pane !== name; });
}

// Bestaetigungsdialog (statt confirm): Promise<boolean>
function askConfirm(title, text, yes = 'Löschen') {
  return new Promise((resolve) => {
    $('confirmTitle').textContent = title; $('confirmText').textContent = text; $('confirmYes').textContent = yes;
    $('confirmBg').hidden = false;
    const done = (v) => { $('confirmBg').hidden = true; $('confirmYes').onclick = $('confirmNo').onclick = null; document.removeEventListener('keydown', key, true); resolve(v); };
    const key = (e) => { if (e.key === 'Escape') { e.stopPropagation(); done(false); } };
    document.addEventListener('keydown', key, true);
    $('confirmYes').onclick = () => done(true);
    $('confirmNo').onclick = () => done(false);
    setTimeout(() => $('confirmNo').focus(), 30);
  });
}
const REAPPEAR_NOTE = 'Ist die Lücke noch vorhanden, taucht sie beim nächsten Lauf wieder auf. Zum dauerhaften Ausblenden besser „Fehlalarm“ oder „Risiko akzeptiert“ wählen.';
async function deleteDashFindings(ids, label) {
  if (!ids.length) return;
  if (!(await askConfirm(ids.length === 1 ? 'Befund löschen?' : `${ids.length} Befunde löschen?`, `${label ? `„${label}“ wird` : 'Die ausgewählten Befunde werden'} aus der Übersicht entfernt. ${REAPPEAR_NOTE}`))) return;
  const r = await window.vigil.deleteFindings(ids);
  for (const id of ids) state.dashSelected.delete(id);
  if (ids.includes(state.dashOpen)) closeDashDetail();
  undoToast(`${r.deleted} ${r.deleted === 1 ? 'Befund' : 'Befunde'} gelöscht`, r.undoToken, loadDashboard);
  loadDashboard();
}

function renderDashTargets(targets) {
  const box = $('dashTargets');
  if (!targets.length) { box.innerHTML = '<div class="empty"><b>Noch keine Ziele</b>Sobald du etwas prüfst, erscheint es hier.</div>'; return; }
  box.innerHTML = targets.map((t) => {
    const o = t.open;
    const bar = o.total ? SEV_ORDER.filter((s) => o[s]).map((s) => `<span class="sb-${SEV_CLS[s]}" style="flex:${o[s]}"></span>`).join('') : '<span class="sb-ok"></span>';
    const web = t.type === 'url' || t.type === 'endpoint';
    return `<article class="tgt-card${dash.targetId === t.id ? ' active' : ''}" data-id="${esc(t.id)}">
      <header><span class="t-kind ${t.type}">${KIND_LABEL[t.type] || t.type}</span>${t.ownershipVerified ? '<span class="badge verified" title="Domain-Besitz nachgewiesen">nachgewiesen</span>' : ''}</header>
      <button type="button" class="tgt-title" data-filter="${esc(t.id)}" title="${esc(t.identifier)} – Befunde dieses Ziels zeigen">${esc(t.name)}</button>
      <div class="sev-bar mini">${bar}</div>
      <div class="tgt-meta"><span>${o.total ? `<b>${o.total}</b> offen` : '<span class="ok-text">✓ nichts offen</span>'}</span><span class="muted small">geprüft ${esc(fmtDate(t.lastScanAt))}</span></div>
      <footer>
        <button type="button" class="btn tiny" data-act="rescan">Erneut prüfen</button>
        <button type="button" class="btn tiny ghost" data-act="baseline" title="Alle derzeit offenen Befunde als bekannt markieren – danach zeigt „Neu seit Baseline“ nur Neues">Baseline</button>
        ${web && !t.ownershipVerified ? '<button type="button" class="btn tiny ghost" data-act="verify" title="Für tiefe Prüfungen Domain-Besitz nachweisen">Nachweisen</button>' : ''}
        <button type="button" class="btn tiny ghost danger icon-del" data-act="delete" aria-label="Ziel ${esc(t.name)} löschen" title="Ziel mit allen Befunden löschen">Löschen</button>
      </footer>
      <div class="verify-box" id="vb-${esc(t.id)}" hidden></div>
    </article>`;
  }).join('');
  box.querySelectorAll('.tgt-title').forEach((b) => b.onclick = () => { dash.targetId = b.dataset.filter; dashTab('findings'); loadDashboard(); });
  box.querySelectorAll('[data-act]').forEach((b) => b.onclick = async () => {
    const id = b.closest('.tgt-card').dataset.id;
    const t = targets.find((x) => x.id === id);
    if (!t) return;
    if (b.dataset.act === 'delete') {
      if (!(await askConfirm('Ziel löschen?', `„${t.name}“ wird mit allen gespeicherten Befunden aus der Übersicht entfernt. Freigaben und Domain-Nachweis in den Einstellungen bleiben unberührt. Prüfst du das Ziel erneut, erscheint es wieder.`))) return;
      const r = await window.vigil.deleteTarget(id);
      if (dash.targetId === id) dash.targetId = '';
      if (r.ok) undoToast(`„${t.name}“ gelöscht (${r.deletedFindings} Befunde)`, r.undoToken, () => { loadDashboard(); loadKnown(); });
      else toast('Löschen fehlgeschlagen: ' + r.error, 'err');
      loadDashboard(); loadKnown();
    } else if (b.dataset.act === 'baseline') {
      const r = await window.vigil.setBaseline(id);
      toast(r.ok ? `${r.count} Befunde als bekannt gemerkt` : 'Fehler', r.ok ? 'ok' : 'err');
      loadDashboard();
    } else if (b.dataset.act === 'rescan') {
      state.targets = [{ type: t.type, value: t.identifier, authorized: t.verified }];
      renderTargets(); showView('scan');
      if ($('runBtn').disabled) { flash($('runHint').textContent || 'Ziel übernommen – wähle eine KI und starte.'); return; }
      runAudit();
    } else if (b.dataset.act === 'verify') {
      const vb = $('vb-' + id);
      const info = await window.vigil.targetInfo(id);
      const tt = info.target;
      let host = tt.identifier; try { host = new URL(tt.identifier).hostname; } catch { /* Server */ }
      const dom = host.split('.').slice(-2).join('.');
      vb.hidden = false;
      vb.innerHTML = `Lege <b>eine</b> der beiden Varianten an und klicke dann auf „Jetzt prüfen“:<br>
        1. DNS-TXT-Eintrag <code>_sec-audit-verify.${esc(dom)}</code> mit dem Wert <code>${esc(tt.verificationToken)}</code><br>
        2. Datei <code>https://${esc(host)}/.well-known/sec-audit.txt</code> mit dem Inhalt <code>${esc(tt.verificationToken)}</code><br>
        <button class="btn tiny" id="vbtn-${esc(id)}" style="margin-top:8px">Jetzt prüfen</button> <span id="vst-${esc(id)}"></span>`;
      $('vbtn-' + id).onclick = async () => {
        $('vst-' + id).textContent = 'Prüfe …';
        const r = await window.vigil.verifyTarget(id);
        $('vst-' + id).textContent = r.ok ? `✓ Nachgewiesen (${r.method})` : r.error;
        if (r.ok) setTimeout(loadDashboard, 800);
      };
    }
  });
}

// Entwicklung ueber die Zeit: Sicherheitswert und offene Befunde je Lauf
function renderDashTrend(stats) {
  const tr = stats.trend || [];
  const box = $('dashTrend');
  if (tr.length < 2) { box.innerHTML = '<p class="muted small">Die Grafik erscheint ab dem zweiten Lauf.</p>'; $('dashTrendNote').textContent = ''; return; }
  $('dashTrendNote').textContent = `letzte ${tr.length} Läufe`;
  const W = 640, H = 160, P = 26;
  const maxOpen = Math.max(1, ...tr.map((t) => t.open));
  const x = (i) => P + (i / (tr.length - 1)) * (W - 2 * P);
  const yP = (v) => H - P - (v / 100) * (H - 2 * P);
  const yO = (v) => H - P - (v / maxOpen) * (H - 2 * P);
  const line = (fn, key) => tr.map((t, i) => `${x(i).toFixed(1)},${fn(t[key]).toFixed(1)}`).join(' ');
  const area = `${x(0).toFixed(1)},${H - P} ${line(yP, 'posture')} ${x(tr.length - 1).toFixed(1)},${H - P}`;
  box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Sicherheitswert und offene Befunde im Verlauf">
    <defs><linearGradient id="trFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="var(--accent)" stop-opacity=".25"/><stop offset="1" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>
    ${[0, 50, 100].map((v) => `<line x1="${P}" x2="${W - P}" y1="${yP(v)}" y2="${yP(v)}" class="tr-grid"/><text x="4" y="${yP(v) + 4}" class="tr-ax">${v}</text>`).join('')}
    <polygon points="${area}" fill="url(#trFill)"/>
    <polyline points="${line(yO, 'open')}" class="tr-open"/>
    <polyline points="${line(yP, 'posture')}" class="tr-post"/>
    ${tr.map((t, i) => `<circle cx="${x(i).toFixed(1)}" cy="${yP(t.posture).toFixed(1)}" r="3.2" class="tr-dot"><title>${esc(fmtDate(t.at))}: Sicherheitswert ${t.posture}, ${t.open} offen (${t.created} neu, ${t.resolved} behoben)</title></circle>`).join('')}
    <text x="${P}" y="${H - 6}" class="tr-ax">${esc(fmtDate(tr[0].at))}</text><text x="${W - P}" y="${H - 6}" class="tr-ax" text-anchor="end">${esc(fmtDate(tr[tr.length - 1].at))}</text>
  </svg>
  <div class="tr-legend"><span><i class="lg-post"></i>Sicherheitswert (0–100)</span><span><i class="lg-open"></i>offene Befunde (max. ${maxOpen})</span></div>`;
}

function renderDashRuns(runs) {
  const box = $('dashRuns');
  box.innerHTML = runs.length ? runs.slice(0, 20).map((r) => `<div class="run-card">
    <span class="run-st st-${r.status}">${RUN_LABEL[r.status] || r.status}</span>
    <div class="run-main"><span class="run-tgt" title="${esc(r.targets.map((t) => t.value).join(', '))}">${esc(r.targets.map((t) => t.value).join(', ') || '–')}</span>
      <span class="muted small">${r.summary ? `${r.summary.total ?? 0} Befunde · ${r.summary.created || 0} neu · ${r.summary.resolved || 0} behoben` : (r.errorLog ? esc(r.errorLog) : '')}${r.durationMs ? ` · ${fmtElapsed(r.durationMs)}` : ''}</span></div>
    <span class="muted small run-when">${r.origin === 'api' ? 'API · ' : ''}${fmtDate(r.finishedAt || r.startedAt || r.createdAt)}</span>
    ${r.status === 'RUNNING' || r.status === 'QUEUED' ? '' : `<button type="button" class="btn tiny ghost danger" data-run="${esc(r.id)}" aria-label="Lauf löschen">Löschen</button>`}
  </div>`).join('') : '<p class="muted small">Noch keine Läufe.</p>';
  box.querySelectorAll('[data-run]').forEach((b) => b.onclick = async () => {
    if (!(await askConfirm('Lauf löschen?', 'Der Eintrag verschwindet aus dem Verlauf. Die Befunde dieses Laufs bleiben erhalten.'))) return;
    const r = await window.vigil.deleteRun(b.dataset.run);
    if (r.ok) undoToast('Lauf gelöscht', r.undoToken, loadDashboard); else toast(r.error, 'err');
    loadDashboard();
  });
}

state.dashSelected = new Set();
function renderDashTable(findings, targets) {
  const tgt = targets.find((t) => t.id === dash.targetId);
  $('dashTargetFilter').hidden = !tgt;
  if (tgt) $('dashTargetName').textContent = tgt.name;
  state.dashFindings = findings;
  // Auswahl nur fuer noch sichtbare Befunde behalten
  const visibleIds = new Set(findings.map((f) => f.id));
  for (const id of [...state.dashSelected]) if (!visibleIds.has(id)) state.dashSelected.delete(id);
  const box = $('dashTable');
  if (!findings.length) { box.innerHTML = `<div class="empty"><b>${stateEmptyTitle()}</b>${dash.status === 'OPEN,IN_PROGRESS' && !dash.q && !dash.severity ? 'Starte eine Prüfung oder schau unter „Alle“ nach.' : 'Filter anpassen, um mehr zu sehen.'}</div>`; updateBulk(); return; }
  const all = findings.every((f) => state.dashSelected.has(f.id));
  box.innerHTML = `<table class="ftable"><thead><tr>
      <th class="sel"><input type="checkbox" id="dashSelAll" aria-label="Alle auswählen"${all ? ' checked' : ''}></th>
      <th>Schwere</th><th>Befund</th><th>Ziel</th><th>Zuletzt gesehen</th><th>Status</th><th class="act"><span class="sr-only">Aktionen</span></th></tr></thead><tbody>${findings.map((f, i) => `
    <tr class="sev-${f.severity} clickable${state.dashOpen === f.id ? ' active' : ''}${state.dashSelected.has(f.id) ? ' selected' : ''}" data-i="${i}" tabindex="0" aria-label="Details zu ${esc(cleanTitle(f.title))}">
      <td class="sel"><input type="checkbox" class="row-sel" data-id="${esc(f.id)}" aria-label="Auswählen"${state.dashSelected.has(f.id) ? ' checked' : ''}></td>
      <td><span class="sev-tag">${SEV_LABEL[f.severity]}</span></td>
      <td class="ft-main"><b title="${esc(f.title)}">${esc(cleanTitle(f.title))}</b><span class="f-loc" title="${esc(f.location)}">${esc(f.location)}</span>${f.statusNote ? `<span class="muted small">${esc(f.statusNote)}</span>` : ''}</td>
      <td class="ft-tgt" title="${esc(f.targetName)}">${esc(f.targetName)}</td>
      <td class="muted small ft-when" title="Zuerst gesehen: ${esc(fmtDate(f.firstSeenAt))}">${fmtDate(f.lastSeenAt)}</td>
      <td>${statusSelect(f.id, f.status)}</td>
      <td class="act"><button type="button" class="row-del" data-del="${esc(f.id)}" aria-label="Befund löschen" title="Löschen">✕</button></td>
    </tr>`).join('')}</tbody></table>`;
  bindStatusSelects(box, () => loadDashboard());
  box.querySelectorAll('tr.clickable').forEach((tr) => {
    tr.onclick = (e) => { if (e.target.closest('.sel, .act, select')) return; openDashDetail(Number(tr.dataset.i)); };
    tr.onkeydown = (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === tr) { e.preventDefault(); openDashDetail(Number(tr.dataset.i)); } if (e.key === 'Delete' && e.target === tr) { const f = findings[Number(tr.dataset.i)]; deleteDashFindings([f.id], cleanTitle(f.title)); } };
  });
  box.querySelectorAll('.row-sel').forEach((c) => c.onchange = () => { if (c.checked) state.dashSelected.add(c.dataset.id); else state.dashSelected.delete(c.dataset.id); c.closest('tr').classList.toggle('selected', c.checked); updateBulk(); });
  box.querySelectorAll('[data-del]').forEach((b) => b.onclick = () => { const f = findings.find((x) => x.id === b.dataset.del); deleteDashFindings([b.dataset.del], f && cleanTitle(f.title)); });
  $('dashSelAll').onchange = () => { for (const f of findings) { if ($('dashSelAll').checked) state.dashSelected.add(f.id); else state.dashSelected.delete(f.id); } renderDashTable(findings, targets); };
  updateBulk();
  if (state.dashOpen) { const i = findings.findIndex((f) => f.id === state.dashOpen); if (i >= 0) openDashDetail(i, true); else closeDashDetail(); }
}
function stateEmptyTitle() { return dash.status === 'RESOLVED' ? 'Noch nichts behoben' : dash.status.startsWith('FALSE') ? 'Keine Fehlalarme oder akzeptierten Risiken' : 'Keine Befunde in dieser Ansicht'; }
function updateBulk() {
  const n = state.dashSelected.size;
  $('dashBulk').hidden = n === 0;
  $('dashBulkCount').textContent = `${n} ausgewählt`;
}

// Detail-Ansicht fuer einen gespeicherten Befund der Uebersicht (seitliches Fenster).
function dashFindingFull(rec) {
  const full = dashFindingMerge(rec);
  return wantEnglish() ? window.VigilFindingsI18n.localizeFinding(full) : full;
}
function dashFindingMerge(rec) {
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
  hydrateDetail(body, f);
  // Zweispaltig: links Befund, Code, Fundstelle – rechts Loesung und Rueckfrage (bleiben beim Scrollen sichtbar)
  const fd = body.querySelector('.fd-body');
  if (fd) {
    const main = document.createElement('div'); main.className = 'dd-main';
    const side = document.createElement('aside'); side.className = 'dd-side';
    [fd.querySelector('.solution'), fd.querySelector('.ask-sec')].forEach((n) => n && side.appendChild(n));
    while (fd.firstChild) main.appendChild(fd.firstChild);
    const linkedSec = body.querySelector(':scope > .f-sec');
    if (linkedSec) main.appendChild(linkedSec);
    fd.append(main, side);
    fd.classList.add('dd-grid');
  }
  body.querySelectorAll('.linked-row').forEach((b) => b.onclick = () => openDashDetail(Number(b.dataset.i)));
  bindNote(body, f, (note) => { rec.note = note; });
  bindStatusSelects(body, (id, status) => { toast(`Status: ${STATUS_LABEL[status]}`, 'ok'); loadDashboard(); });
  $('dashDrawerPos').textContent = `Befund ${i + 1} von ${list.length}`;
  $('dashDrawerPrev').disabled = i <= 0;
  $('dashDrawerNext').disabled = i >= list.length - 1;
  $('dashDrawerDelete').onclick = () => deleteDashFindings([rec.id], cleanTitle(rec.title));
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

function setupDashboard() {
  document.querySelectorAll('.dash-tab').forEach((b) => b.onclick = () => dashTab(b.dataset.tab));
  $('dashRefresh').onclick = () => loadDashboard();
  $('dashCleanBtn').onclick = (e) => { e.stopPropagation(); const m = $('dashCleanMenu'); m.hidden = !m.hidden; $('dashCleanBtn').setAttribute('aria-expanded', String(!m.hidden)); };
  document.addEventListener('click', (e) => { if (!e.target.closest('#dashCleanMenu, #dashCleanBtn')) { $('dashCleanMenu').hidden = true; $('dashCleanBtn').setAttribute('aria-expanded', 'false'); } });
  $('dashPurgeResolved').onclick = async () => {
    $('dashCleanMenu').hidden = true;
    const n = (state.dashStats && state.dashStats.byStatus && state.dashStats.byStatus.RESOLVED) || 0;
    if (!n) { toast('Es gibt keine behobenen Befunde zum Löschen', 'ok'); return; }
    if (!(await askConfirm('Behobene Befunde löschen?', `${n} als behoben markierte Befunde werden endgültig aus der Übersicht entfernt. Taucht eine Lücke wieder auf, erscheint sie als neu statt als „wieder da“.`))) return;
    const r = await window.vigil.purgeResolved(dash.targetId || '');
    toast(`${r.deleted} behobene Befunde gelöscht`, 'ok'); loadDashboard();
  };
  $('dashPurgeFiltered').onclick = () => { $('dashCleanMenu').hidden = true; deleteDashFindings((state.dashFindings || []).map((f) => f.id)); };
  $('dashStatus').querySelectorAll('.fbtn').forEach((b) => b.onclick = () => { dash.status = b.dataset.s; loadDashboard(); });
  $('dashSeverity').onchange = () => { dash.severity = $('dashSeverity').value; loadDashboard(); };
  $('dashTargetSelect').onchange = () => { dash.targetId = $('dashTargetSelect').value; loadDashboard(); };
  let dashTimer = null;
  $('dashSearch').addEventListener('input', () => { clearTimeout(dashTimer); dashTimer = setTimeout(() => { dash.q = $('dashSearch').value; loadDashboard(); }, 200); });
  $('dashTargetClear').onclick = () => { dash.targetId = ''; loadDashboard(); };
  $('dashToggles').querySelectorAll('.fbtn').forEach((b) => b.onclick = () => { dash[b.dataset.t] = !dash[b.dataset.t]; loadDashboard(); });
  $('dashBulkClear').onclick = () => { state.dashSelected.clear(); renderDashTable(state.dashFindings || [], (state.dashStats && state.dashStats.targets) || []); };
  $('dashBulkDelete').onclick = () => deleteDashFindings([...state.dashSelected]);
  $('dashBulkStatus').onchange = async () => {
    const st = $('dashBulkStatus').value;
    if (!st) return;
    const ids = [...state.dashSelected];
    for (const id of ids) await window.vigil.setFindingStatus(id, st);
    $('dashBulkStatus').value = '';
    toast(`${ids.length} ${ids.length === 1 ? 'Befund' : 'Befunde'}: ${STATUS_LABEL[st]}`, 'ok');
    state.dashSelected.clear(); loadDashboard();
  };
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
}

// --- Einstellungen ------------------------------------------------------
// Barrierefreiheit: Eingabefelder ohne eigene Beschriftung bekommen den Namen ihrer Zeile
// (Einstellungen: fettgedruckter Titel links) bzw. ihren Platzhalter als Namen fuer Bildschirmleser.
function labelOrphans(root = document) {
  root.querySelectorAll('input, select, textarea').forEach((i) => {
    if (i.type === 'hidden' || (i.labels && i.labels.length) || i.getAttribute('aria-label') || i.closest('label')) return;
    const row = i.closest('.set-row');
    const name = (row && row.querySelector('.set-label b') && row.querySelector('.set-label b').textContent) || i.getAttribute('placeholder') || i.getAttribute('title');
    if (name) i.setAttribute('aria-label', name.trim());
  });
}

// --- Darstellung: Farbschema, Schriftgroesse ------------------------------------
const SCALES = [0.9, 1, 1.12, 1.25];
function applyAppearance() {
  const t = state.config.theme;
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  const z = Number(state.config.uiScale) || 1;
  document.documentElement.style.zoom = z === 1 ? '' : String(z);
  const mark = (id, attr, val) => document.querySelectorAll('#' + id + ' button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset[attr] === String(val))));
  mark('themeSeg', 'theme', t === 'light' || t === 'dark' ? t : 'system');
  mark('scaleSeg', 'scale', z);
  mark('langSeg', 'lang', state.config.lang === 'de' ? 'de' : 'en');
}
function setScale(z) { state.config.uiScale = z; saveCfg(); applyAppearance(); }
function setupAppearance() {
  document.querySelectorAll('#themeSeg button').forEach((b) => b.onclick = () => { state.config.theme = b.dataset.theme; saveCfg(); applyAppearance(); });
  document.querySelectorAll('#scaleSeg button').forEach((b) => b.onclick = () => setScale(Number(b.dataset.scale)));
  document.querySelectorAll('#langSeg button').forEach((b) => b.onclick = () => { state.config.lang = b.dataset.lang; saveCfg(); applyAppearance(); if (window.applyLanguage) window.applyLanguage(state.config.lang); if (state.rawResult) renderResult(state.rawResult); loadDashboard().catch(() => {}); });
  document.addEventListener('keydown', (e) => {
    if (!e.ctrlKey || e.altKey) return;
    const cur = SCALES.indexOf(Number(state.config.uiScale) || 1);
    if (e.key === '+' || e.key === '=') { e.preventDefault(); setScale(SCALES[Math.min(SCALES.length - 1, (cur < 0 ? 1 : cur) + 1)]); }
    else if (e.key === '-') { e.preventDefault(); setScale(SCALES[Math.max(0, (cur < 0 ? 1 : cur) - 1)]); }
    else if (e.key === '0') { e.preventDefault(); setScale(1); }
  });
  $('crashOpenBtn').onclick = () => window.vigil.crashOpen();
  applyAppearance();
  // Englisch ist Standard; Deutsch nur, wenn ausdruecklich gewaehlt
  if (state.config.lang !== 'de' && window.applyLanguage) window.applyLanguage('en');
}
// Erkennungsquellen: was ist wie aktuell? (live, taeglich, von Windows)
function renderFeeds() {
  if (!window.vigil.feedsStatus) return;
  window.vigil.feedsStatus().then((s) => {
    const age = (iso) => { if (!iso) return null; const h = (Date.now() - Date.parse(iso)) / 36e5; return h < 1 ? 'vor weniger als einer Stunde' : h < 48 ? `vor ${Math.round(h)} Std.` : `vor ${Math.round(h / 24)} Tagen`; };
    const row = (name, desc, when, ok, extra = '') => `<li class="feed-row"><span class="feed-dot ${ok === true ? 'ok' : ok === false ? 'bad' : 'live'}" aria-hidden="true"></span><div><b>${esc(name)}</b><span class="muted small">${esc(desc)}</span></div><span class="small feed-when">${esc(when)}${extra}</span></li>`;
    const fresh = (iso) => !!iso && Date.now() - Date.parse(iso) < 30 * 36e5;
    const rows = [
      row('Paket-Schwachstellen (OSV.dev)', 'npm, PyPI, Maven, Go, Cargo, NuGet, RubyGems … – wird bei jedem Lauf live abgefragt', 'immer aktuell', null),
      row('Aktiv ausgenutzte Lücken (CISA KEV)', `${s.intel.kev || 0} Einträge`, s.intel.updatedAt ? age(s.intel.updatedAt) : 'noch nicht geladen', fresh(s.intel.updatedAt)),
      row('Ausnutzungs-Wahrscheinlichkeit (EPSS)', `${s.intel.epss || 0} Werte`, s.intel.updatedAt ? age(s.intel.updatedAt) : 'noch nicht geladen', fresh(s.intel.updatedAt)),
      ...s.feeds.map((f) => (f.inactive ? row(f.label, 'Werkzeug nicht installiert', 'nicht aktiv', null)
        : row(f.label, f.count ? `${f.count} ${f.unit || (f.id === 'retirejs' ? 'Bibliotheken' : 'Regeln')}` : f.fetchedAt ? 'aktualisiert' : 'noch nicht geladen', f.fetchedAt ? age(f.fetchedAt) : 'noch nicht geladen', f.fetchedAt ? fresh(f.fetchedAt) && !f.lastError : false, f.lastError ? ` · letzter Versuch fehlgeschlagen: ${esc(f.lastError)}` : ''))),
      row('Schadsoftware-Signaturen (Microsoft Defender)', 'aktualisiert Windows selbst mehrmals täglich', 'von Windows', null),
    ];
    $('feedList').innerHTML = rows.join('');
  }).catch(() => {});
  if (window.vigil.osvOfflineStatus) window.vigil.osvOfflineStatus().then((o) => {
    $('osvOfflineStatus').textContent = o.ecosystems.length ? `Vorrat: ${o.ecosystems.map((e) => `${e.eco} (${e.count})`).join(', ')}` : o.enabled ? 'Wird beim nächsten Abgleich geladen.' : '';
  }).catch(() => {});
  if (window.vigil.yaraInfo) window.vigil.yaraInfo().then((y) => {
    $('yaraStatus').textContent = `${y.installed ? 'YARA ist installiert.' : 'YARA ist nicht installiert – die Regeln werden übersprungen.'} ${y.rules} eigene Regeldatei(en).`;
  }).catch(() => {});
}
// Hinweise aus der Hintergrund-Ueberwachung (neue CVEs, BSI-Hinweise, neue Zertifikate)
function renderWatch() {
  if (!window.vigil.watchAlerts) return;
  window.vigil.watchAlerts().then((list) => {
    const box = $('dashWatch');
    if (!list.length) { box.innerHTML = ''; return; }
    const tr = (s) => (wantEnglish() && window.VigilFindingsI18n ? window.VigilFindingsI18n.translate(s) : s);
    const kind = { newcve: 'Neue Lücke', advisory: 'BSI-Hinweis', ct: 'Zertifikat' };
    box.innerHTML = `<section class="watch-box" aria-label="Hinweise aus der Überwachung"><h3>Neu seit der letzten Prüfung (${list.length})</h3><p class="hint small">Ohne neuen Scan erkannt: neue Schwachstellen in Paketen aus gespeicherten Prüfungen, passende BSI-Sicherheitshinweise und neue Zertifikate für deine Domains.</p><ul class="watch-list">${list.slice(0, 20).map((a, i) => `<li class="watch-item"><span class="feed-dot ${esc(a.severity || '')}" aria-hidden="true"></span><div><b>${esc(tr(a.title))}</b><span class="muted small">${esc(kind[a.type] || '')} · ${esc(fmtDate(a.at))}</span><span class="small">${esc(tr(a.detail || ''))}</span></div><span class="acts">${a.link ? `<button type="button" class="btn ghost tiny" data-watch-link="${i}">Details</button>` : ''}<button type="button" class="btn ghost tiny" data-watch-dismiss="${i}">Ausblenden</button></span></li>`).join('')}</ul>${list.length > 1 ? '<button type="button" class="btn ghost tiny" data-watch-dismiss="*">Alle ausblenden</button>' : ''}</section>`;
    box.querySelectorAll('[data-watch-link]').forEach((b) => { b.onclick = () => window.vigil.openLink(list[Number(b.dataset.watchLink)].link); });
    box.querySelectorAll('[data-watch-dismiss]').forEach((b) => { b.onclick = () => { const k = b.dataset.watchDismiss; window.vigil.watchDismiss(k === '*' ? '*' : list[Number(k)].key).then(renderWatch); }; });
  }).catch(() => {});
}
// Einstellungs-Bereiche: welche Karten gehoeren wohin (Reihenfolge = Anzeige)
const SET_GROUPS = {
  general: ['presets', 'set-app', 'set-report'],
  checks: ['set-analyse', 'set-privacy', 'set-malware', 'set-feeds', 'set-tools', 'set-systems'],
  web: ['set-scope', 'set-deep', 'set-login', 'set-matrix'],
  advanced: ['set-rules', 'set-network', 'set-providers', 'set-rest', 'set-data'],
};
function setGroup(name) {
  state.setGroup = SET_GROUPS[name] ? name : 'general';
  const body = document.querySelector('#settingsView .set-body');
  const show = new Set(SET_GROUPS[state.setGroup]);
  body.querySelectorAll(':scope > section').forEach((sec) => { const id = sec.id || (sec.classList.contains('presets') ? 'presets' : ''); sec.hidden = !show.has(id); });
  // Karten in der festgelegten Reihenfolge anordnen
  for (const id of SET_GROUPS[state.setGroup]) { const el = id === 'presets' ? body.querySelector(':scope > .presets') : $(id); if (el) body.appendChild(el); }
  $('setNav').querySelectorAll('[data-group]').forEach((b) => { const on = b.dataset.group === state.setGroup; b.classList.toggle('active', on); b.setAttribute('aria-selected', String(on)); });
  document.querySelector('.main').scrollTop = 0;
}
function renderLoginStatus() {
  if (!window.vigil.webLoginGet) return;
  window.vigil.webLoginGet().then((list) => {
    const m = list[0] || {};
    state.hadLogin = !!m.host;
    $('wlUrl').value = m.loginUrl || ''; $('wlUser').value = m.username || ''; $('wlUserField').value = m.userField || ''; $('wlPassField').value = m.passField || '';
    $('wlStatus').textContent = m.host ? `Gespeichert für ${m.host}: Passwort ${m.hasPassword ? '✓ verschlüsselt hinterlegt' : 'fehlt'}. Zum Entfernen die Anmelde-Adresse leeren und speichern.` : 'Noch kein Testkonto hinterlegt.';
  }).catch(() => {});
}
function renderMalwareStatus() {
  if (!window.vigil.malwareKeyInfo) return;
  window.vigil.malwareKeyInfo().then((k) => { $('mbStatus').textContent = k.hasKey ? 'Schlüssel ✓ hinterlegt.' : 'Kein Schlüssel hinterlegt – dieser Abgleich wird übersprungen.'; }).catch(() => {});
}
// Zugaenge fuer System-Pruefungen (Server, Datenbanken, Online-Konten). Geheimnisse gehen nur in den
// Main-Prozess (verschluesselt) und kommen nie zurueck – angezeigt wird nur, ob etwas hinterlegt ist.
const SYS_FIELDS_UI = [
  { k: 'sshTarget', ph: 'Linux-Server: benutzer@server oder benutzer@server:port' },
  { k: 'sshKeyPath', ph: 'Pfad zum privaten SSH-Schlüssel, z. B. C:\\Users\\du\\.ssh\\id_ed25519' },
  { k: 'dbUrls', n: 'Datenbank-Verbindungen', ph: 'Datenbanken, eine Verbindung pro Zeile: postgres://, mysql://, mongodb://, redis:// (leer = unverändert)', secret: true, area: true },
  { k: 'githubToken', n: 'GitHub-Token', ph: 'GitHub-Token mit Leserechten (leer = unverändert)', secret: true },
  { k: 'githubOrg', ph: 'GitHub-Organisation (optional)' },
  { k: 'gitlabToken', n: 'GitLab-Token', ph: 'GitLab-Token mit read_api (leer = unverändert)', secret: true },
  { k: 'gitlabUrl', ph: 'GitLab-Server (leer = gitlab.com)' },
  { k: 'gitlabGroup', ph: 'GitLab-Gruppe (optional)' },
  { k: 'adoOrg', ph: 'Azure-DevOps-Organisation' },
  { k: 'adoToken', n: 'Azure-DevOps-Token', ph: 'Azure-DevOps-Token mit Leserechten (leer = unverändert)', secret: true },
  { k: 'm365Tenant', ph: 'Microsoft 365: Tenant-ID' },
  { k: 'm365ClientId', ph: 'Microsoft 365: App-ID (Client-ID)' },
  { k: 'm365Secret', n: 'Microsoft-365-App-Schlüssel', ph: 'Microsoft 365: geheimer App-Schlüssel (leer = unverändert)', secret: true },
  { k: 'gwsAdmin', ph: 'Google Workspace: E-Mail eines Admins' },
  { k: 'gwsServiceAccount', n: 'Google-Workspace-Dienstkonto', ph: 'Google Workspace: Dienstkonto-Schlüssel als JSON (leer = unverändert)', secret: true, area: true },
  { k: 'cloudflareToken', n: 'Cloudflare-Token', ph: 'Cloudflare-API-Token mit Leserechten (leer = unverändert)', secret: true },
  { k: 'hetznerToken', n: 'Hetzner-Token', ph: 'Hetzner-Cloud-Token, nur lesen (leer = unverändert)', secret: true },
  { k: 'digitaloceanToken', n: 'DigitalOcean-Token', ph: 'DigitalOcean-Token, nur lesen (leer = unverändert)', secret: true },
  { k: 'vercelToken', n: 'Vercel-Token', ph: 'Vercel-Token (leer = unverändert)', secret: true },
  { k: 'netlifyToken', n: 'Netlify-Token', ph: 'Netlify-Token (leer = unverändert)', secret: true },
  { k: 'hibpDomain', ph: 'Have I Been Pwned: eigene, dort verifizierte Domain' },
  { k: 'hibpKey', n: 'HIBP-Schlüssel', ph: 'Have I Been Pwned: API-Schlüssel (leer = unverändert)', secret: true },
];
function renderSystems() {
  if (!window.vigil.systemsGet || !$('sysFields')) return;
  const box = $('sysFields');
  if (!box.children.length) {
    box.innerHTML = SYS_FIELDS_UI.map((f) => (f.area
      ? `<textarea id="sys_${f.k}" rows="2" spellcheck="false" placeholder="${esc(f.ph)}" aria-label="${esc(f.ph)}"></textarea>`
      : `<input id="sys_${f.k}" type="${f.secret ? 'password' : 'text'}" placeholder="${esc(f.ph)}" aria-label="${esc(f.ph)}" autocomplete="off" />`)).join('');
  }
  window.vigil.systemsGet().then((s) => {
    for (const f of SYS_FIELDS_UI) $('sys_' + f.k).value = f.secret ? '' : s[f.k] || '';
    $('lanPortChk').checked = !!s.lanPortCheck;
    const stored = SYS_FIELDS_UI.filter((f) => f.secret && s['has_' + f.k]).map((f) => f.n);
    $('sysStatus').textContent = stored.length ? `Verschlüsselt hinterlegt: ${stored.join(' · ')}` : 'Noch keine Zugänge hinterlegt.';
  }).catch(() => {});
}
function saveSystems() {
  if (!window.vigil.systemsSave || !$('sysFields') || !$('sysFields').children.length) return;
  const patch = { lanPortCheck: $('lanPortChk').checked };
  for (const f of SYS_FIELDS_UI) patch[f.k] = $('sys_' + f.k).value;
  window.vigil.systemsSave(patch).then(renderSystems).catch(() => {});
}
function renderReportLogo() {
  const has = /^data:image\//.test(state.config.reportLogo || '');
  $('reportLogoPreview').hidden = !has; $('reportLogoClear').hidden = !has;
  if (has) $('reportLogoPreview').src = state.config.reportLogo;
}
// Ausgaben dieses Monats (lokal geschaetzt) neben der Budget-Einstellung
function renderBudgetInfo() {
  if (!window.vigil.budgetStats || !$('budgetInfo')) return;
  window.vigil.budgetStats().then((s) => {
    const last = (s.recentRuns || [])[0];
    $('budgetInfo').textContent = `Diesen Monat: ${fmtUsd(s.spent || 0)}${s.budget ? ` von ${fmtUsd(s.budget)} (${s.percent} %)` : ''} · ${s.runs || 0} Läufe${s.avgRunUsd ? ` · Ø ${fmtUsd(s.avgRunUsd)} je Lauf` : ''}${last ? ` · letzter Lauf ${fmtUsd(last.usd)}` : ''}.`;
  }).catch(() => {});
}
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
  $('secretLiveChk').checked = state.config.secretLiveCheck === true;
  // KI & Datenschutz: eigene Vorgaben, Nachschlagen, Datei-Budget, Budget, strenger Datenschutz, Protokoll
  $('aiFocusInput').value = state.config.aiFocus || '';
  $('lookupChk').checked = !!state.config.aiLookup;
  $('lookupMaxInput').value = state.config.aiLookupMax || 4;
  $('fileBudgetInput').value = state.config.aiFileBudget || 0;
  $('embedModelInput').value = state.config.embedModel || '';
  $('runSumChk').checked = state.config.aiRunSummary !== false;
  $('monthlyBudgetInput').value = state.config.monthlyBudgetUsd || 0;
  $('privacyChk').checked = !!state.config.privacyMode;
  $('privacyTermsInput').value = (state.config.privacyTerms || []).join('\n');
  $('privacyHostsInput').value = (state.config.privacyHosts || []).join('\n');
  $('reproChk').checked = !!state.config.aiRepro;
  renderBudgetInfo();
  $('domChk').checked = state.config.domAudit !== false;
  $('costWarnInput').value = state.config.costWarnUsd ?? 2;
  $('reportCompanyInput').value = state.config.reportCompany || '';
  $('malwareChk').checked = state.config.malwareScan !== false;
  $('crawlChk').checked = state.config.webCrawl !== false;
  $('usbChk').checked = !!state.config.usbAutoScan;
  $('watchCvesChk').checked = state.config.watchCves !== false;
  $('watchCtChk').checked = state.config.watchCt !== false;
  $('osvOfflineChk').checked = !!state.config.osvOffline;
  renderLoginStatus(); renderMalwareStatus(); renderFeeds(); renderSystems();
  applyAppearance();
  if (window.vigil.crashInfo) window.vigil.crashInfo().then((c) => { $('crashInfo').textContent = c.count ? `Bisher ${c.count} Bericht(e) gespeichert.` : 'Bisher keine Abstürze.'; }).catch(() => {});
  renderReportLogo();
  renderReportBranding();
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
  state.config.secretLiveCheck = $('secretLiveChk').checked;
  state.config.aiFocus = $('aiFocusInput').value.trim().slice(0, 2000);
  state.config.aiLookup = $('lookupChk').checked;
  state.config.aiLookupMax = Math.min(10, Math.max(1, parseInt($('lookupMaxInput').value, 10) || 4));
  state.config.aiFileBudget = Math.max(0, parseInt($('fileBudgetInput').value, 10) || 0);
  state.config.embedModel = $('embedModelInput').value.trim();
  state.config.aiRunSummary = $('runSumChk').checked;
  state.config.monthlyBudgetUsd = Math.max(0, parseFloat($('monthlyBudgetInput').value) || 0);
  state.config.privacyMode = $('privacyChk').checked;
  const lines = (id) => $(id).value.split(/\n/).map((x) => x.trim()).filter(Boolean).slice(0, 200);
  state.config.privacyTerms = lines('privacyTermsInput');
  state.config.privacyHosts = lines('privacyHostsInput');
  state.config.aiRepro = $('reproChk').checked;
  setTimeout(renderBudgetInfo, 200);
  state.config.domAudit = $('domChk').checked;
  state.config.costWarnUsd = Math.max(0, parseFloat($('costWarnInput').value) || 0);
  state.config.malwareScan = $('malwareChk').checked;
  state.config.webCrawl = $('crawlChk').checked;
  state.config.usbAutoScan = $('usbChk').checked;
  state.config.watchCves = $('watchCvesChk').checked;
  state.config.watchCt = $('watchCtChk').checked;
  state.config.osvOffline = $('osvOfflineChk').checked;
  // Testkonto und Schadsoftware-Schluessel separat – Geheimnisse gehen verschluesselt in den Main-Prozess
  if ($('wlUrl').value.trim()) {
    window.vigil.webLoginSave([{ loginUrl: $('wlUrl').value, username: $('wlUser').value, password: $('wlPass').value, userField: $('wlUserField').value, passField: $('wlPassField').value }]).then(() => { $('wlPass').value = ''; renderLoginStatus(); });
  } else if (state.hadLogin) window.vigil.webLoginSave([]).then(renderLoginStatus);
  saveSystems();
  if ($('mbKey').value.trim()) window.vigil.malwareSetKey($('mbKey').value.trim()).then(() => { $('mbKey').value = ''; renderMalwareStatus(); });
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
  // Ausstattung des PCs erkennen (im Hintergrund) -> passendes lokales Modell empfehlen
  if (window.vigil.ollama.hardware) window.vigil.ollama.hardware().then((h) => { ai.hardware = h && h.ok ? h : null; if (ai.ollama && ai.ollama.running) { renderLocalModels(); renderRecommended(); } renderHwRec(); }).catch(() => {});
  if ($('threatBtn')) $('threatBtn').onclick = buildThreatModel;

  const sel = state.config.selected || 'ollama';
  if (!CLOUD_IDS.includes(state.config.cloudProvider)) state.config.cloudProvider = CLOUD_IDS.includes(sel) ? sel : 'anthropic';

  // Schritt 1: Ziele
  setupDropzone();
  $('pickFilesBtn').onclick = async (e) => { e.stopPropagation(); (await window.vigil.pickFiles()).forEach((p) => addTarget('path', p)); };
  $('pickFolderBtn').onclick = async (e) => { e.stopPropagation(); (await window.vigil.pickFolder()).forEach((p) => addTarget('path', p)); };
  $('targetInput').addEventListener('input', onTargetInput);
  $('targetInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') addTypedTarget(); });
  $('addTargetBtn').onclick = addTypedTarget;
  $('authYes').onclick = () => { $('authChk').checked = true; addTypedTarget(); };
  $('clearBtn').onclick = () => { state.targets = []; renderTargets(); };
  setupKnown();
  setupAppearance();
  setupDashboard();
  labelOrphans();

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
    if (fmt === 'pdf' || fmt === 'auditzip') flash(fmt === 'pdf' ? 'Erzeuge PDF …' : 'Erzeuge Audit-Paket …');
    const r = await window.vigil.saveReport(fmt);
    if (r.ok && r.markdown) { try { await navigator.clipboard.writeText(r.markdown); } catch { /* egal */ } toast('Abzeichen gespeichert – Markdown-Schnipsel kopiert: ' + r.markdown, 'ok'); return; }
    flash(r.ok ? (r.signature || r.signed ? 'Gespeichert und signiert: ' : 'Gespeichert: ') + r.path : (r.canceled ? '' : 'Fehler: ' + r.error));
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
  $('feedsSyncBtn').onclick = async () => {
    $('feedsSyncBtn').disabled = true; $('feedsSyncStatus').textContent = 'Lade die neuesten Erkennungsdaten …';
    const r = await window.vigil.feedsSync();
    $('feedsSyncBtn').disabled = false;
    $('feedsSyncStatus').textContent = r.ok ? '✓ Alles aktuell.' : 'Teilweise fehlgeschlagen – die letzte gute Fassung bleibt aktiv.';
    renderFeeds();
  };
  $('yaraFolderBtn').onclick = () => window.vigil.yaraOpenFolder();
  // Hintergrund-Ueberwachung und USB-Laufwerke (Benachrichtigung -> Klick -> Pruefliste)
  if (window.vigil.onWatchUpdate) window.vigil.onWatchUpdate(() => { renderWatch(); });
  if (window.vigil.onUsbScan) window.vigil.onUsbScan((drive) => { if (!/^[A-Z]:\\$/.test(drive)) return; addTarget('path', drive); showView('scan'); toast(`${drive} zur Prüfliste hinzugefügt`, 'ok'); });
  $('cacheClearBtn').onclick = async () => { await window.vigil.aiCacheClear(); $('cacheInfo').textContent = ''; toast('KI-Zwischenspeicher geleert – der nächste Lauf prüft alles neu', 'ok'); };
  // Port-Pruefung im lokalen Netz nur nach ausdruecklicher Bestaetigung einschalten
  if ($('lanPortChk')) $('lanPortChk').addEventListener('change', (e) => {
    if (e.target.checked && !confirm('Vigil baut dann zu jedem gefundenen Gerät im eigenen Netz kurze Verbindungen zu wenigen Verwaltungs-Ports auf (z. B. Telnet, Weboberfläche, Fernwartung).\nNur private Adressen im eigenen Subnetz, keine Anmeldeversuche, kein Port-Scan. Prüfe nur Netze, die dir gehören.\nEinschalten?')) e.target.checked = false;
  });
  ['depthSelect', 'validateChk', 'cveChk', 'activeChk', 'domChk', 'malwareChk', 'crawlChk'].forEach((id) => $(id).addEventListener('change', () => { collectSettings(); renderPresets(); }));
  // Einstellungen: vier Bereiche statt einer langen Seite
  $('setNav').querySelectorAll('[data-group]').forEach((b) => b.onclick = () => setGroup(b.dataset.group));
  $('exportJsonBtn').onclick = exportAs('json');
  $('exportCdxBtn').onclick = exportAs('cyclonedx');
  $('exportSpdxBtn').onclick = exportAs('spdx');
  $('exportMenu').querySelectorAll('[data-fmt]').forEach((b) => b.onclick = exportAs(b.dataset.fmt));
  $('verifyReportBtn').onclick = () => { closeMenus(); verifyReportUi(); };
  setupExtras();
  $('exportExecBtn').onclick = exportAs('execpdf');
  $('reportCompanyInput').addEventListener('change', () => { state.config.reportCompany = $('reportCompanyInput').value.trim(); saveCfg(); });
  $('reportLogoFile').addEventListener('change', () => {
    const file = $('reportLogoFile').files[0];
    if (!file) return;
    if (file.size > 300 * 1024) { toast('Logo zu groß – höchstens 300 KB', 'err'); return; }
    const rd = new FileReader();
    rd.onload = () => { state.config.reportLogo = String(rd.result); saveCfg(); renderReportLogo(); toast('Logo gespeichert', 'ok'); };
    rd.readAsDataURL(file);
  });
  $('reportLogoClear').onclick = () => { state.config.reportLogo = ''; saveCfg(); renderReportLogo(); };
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
    if (e.key === 'Escape') { if (!$('palette').hidden) { closePalette(); return; } if (!$('glossaryBg').hidden) { $('glossaryBg').hidden = true; return; } if (!$('dashDrawer').hidden) closeDashDetail(); closeMenus(); closeLayoutMenu(); }
    // Im offenen Detail-Fenster der Uebersicht mit Pfeiltasten blaettern
    if (!$('dashDrawer').hidden && (e.key === 'ArrowDown' || e.key === 'ArrowUp') && !/SELECT|INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
      e.preventDefault(); openDashDetail((state.dashIndex || 0) + (e.key === 'ArrowDown' ? 1 : -1));
    }
  });
  $('dashDrawerClose').onclick = closeDashDetail;
  // Breite des Detail-Fensters ziehen bzw. mit Pfeiltasten aendern; wird gemerkt
  const setDrawerW = (px) => { const w = Math.round(Math.max(520, Math.min(window.innerWidth - 80, px))); $('dashDrawer').style.setProperty('--drawer-w', w + 'px'); try { localStorage.setItem('vigil.drawerW', String(w)); } catch { /* egal */ } };
  try { const w = Number(localStorage.getItem('vigil.drawerW')); if (w) $('dashDrawer').style.setProperty('--drawer-w', w + 'px'); } catch { /* egal */ }
  $('dashDrawerResize').addEventListener('pointerdown', (e) => {
    e.preventDefault();
    const h = $('dashDrawerResize'); h.setPointerCapture(e.pointerId);
    const move = (ev) => setDrawerW(window.innerWidth - ev.clientX);
    const up = () => { h.removeEventListener('pointermove', move); h.removeEventListener('pointerup', up); };
    h.addEventListener('pointermove', move); h.addEventListener('pointerup', up);
  });
  $('dashDrawerResize').addEventListener('keydown', (e) => { if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') { e.preventDefault(); e.stopPropagation(); setDrawerW($('dashDrawer').getBoundingClientRect().width + (e.key === 'ArrowLeft' ? 60 : -60)); } });
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
  else if (mod && (e.key.toLowerCase() === 'k' || (e.shiftKey && e.key.toLowerCase() === 'p'))) { e.preventDefault(); if ($('palette').hidden) openPalette(); else closePalette(); }
  else if (mod && e.key.toLowerCase() === 'f') { e.preventDefault(); const s = state.view === 'dash' ? $('dashSearch') : $('findingSearch'); if (s && s.offsetParent) s.focus(); }
  else if (mod && e.key === ',') { e.preventDefault(); openSettings(); }
  else if (mod && ['1', '2', '3', '4'].includes(e.key)) { e.preventDefault(); showView(['scan', 'results', 'dash', 'history'][+e.key - 1]); }
});

// --- Begleitung beim ersten Start --------------------------------------------------
const ob = { step: 0 };
function showOnboarding() {
  ob.step = 0;
  $('onboard').hidden = false;
  paintOnboarding();
  window.vigil.ollama.status().then((s) => { $('obLocalState').textContent = s && s.running ? '✓ Ollama läuft bereits' : s && s.installed ? 'Ollama ist installiert' : 'Ollama wird bei Bedarf eingerichtet'; }).catch(() => {});
  setTimeout(() => $('obNext').focus(), 50);
}
function paintOnboarding() {
  document.querySelectorAll('#onboard .ob-step').forEach((s) => { s.hidden = Number(s.dataset.step) !== ob.step; });
  document.querySelectorAll('#onboard .ob-steps i').forEach((d, i) => d.classList.toggle('on', i <= ob.step));
  $('obBack').hidden = ob.step === 0;
  $('obNext').textContent = ob.step === 2 ? 'Fertig' : 'Weiter';
}
function finishOnboarding() {
  $('onboard').hidden = true;
  state.config.onboarded = true;
  saveCfg();
}
function setupOnboarding() {
  $('obNext').onclick = () => { if (ob.step >= 2) finishOnboarding(); else { ob.step++; paintOnboarding(); } };
  $('obBack').onclick = () => { ob.step = Math.max(0, ob.step - 1); paintOnboarding(); };
  $('obSkip').onclick = finishOnboarding;
  document.querySelectorAll('#onboard [data-mode]').forEach((b) => b.onclick = () => { setMode(b.dataset.mode); document.querySelectorAll('#onboard [data-mode]').forEach((x) => x.classList.toggle('picked', x === b)); setTimeout(() => { ob.step = 2; paintOnboarding(); }, 250); });
  $('obFolder').onclick = async () => { const p = await window.vigil.pickFolder(); if (p && p.length) { p.forEach((x) => addTarget('path', x)); finishOnboarding(); showView('scan'); toast('Ordner übernommen – jetzt „Prüfung starten“', 'ok'); } };
  $('obDemo').onclick = async () => {
    $('obDemo').disabled = true;
    const r = await window.vigil.sampleDemo();
    $('obDemo').disabled = false;
    if (!r || !r.ok) { toast('Beispiel-Lauf nicht möglich: ' + ((r && r.error) || '?'), 'err'); return; }
    finishOnboarding();
    showView('results');
    $('emptyState').hidden = true; $('progressPanel').hidden = true;
    renderResult(r.result);
    toast(`Beispiel-Lauf: ${r.result.summary.total} Befunde im Übungsprojekt`, 'ok');
  };
  $('onboard').addEventListener('keydown', (e) => { if (e.key === 'Escape') finishOnboarding(); });
  $('onboardAgainBtn').onclick = showOnboarding;
  if (!state.config.onboarded) showOnboarding();
}

// ==========================================================================================
// Erweiterungen: Glossar, Notizen, Rueckgaengig, Pause, Gruppierung, Befehlspalette,
// Layout der Uebersicht, Vergleich zweier Laeufe, Berichts-Branding und Signatur, Browser-Eingang
// ==========================================================================================

// --- Glossar: Fachbegriffe mit Erklaerung (Deutsch, Englisch) --------------------------------
const GLOSSARY = {
  CSP: ['Content Security Policy – legt fest, aus welchen Quellen eine Seite Skripte, Bilder und Styles laden darf.', 'Content Security Policy – defines which sources a page may load scripts, images and styles from.'],
  CVE: ['Common Vulnerabilities and Exposures – weltweit eindeutige Nummer einer bekannten Schwachstelle.', 'Common Vulnerabilities and Exposures – a globally unique ID of a known vulnerability.'],
  CVSS: ['Common Vulnerability Scoring System – Schweregrad einer Schwachstelle von 0 bis 10.', 'Common Vulnerability Scoring System – severity of a vulnerability from 0 to 10.'],
  CWE: ['Common Weakness Enumeration – Katalog typischer Schwachstellen-Arten (z. B. CWE-89 = SQL-Injection).', 'Common Weakness Enumeration – catalogue of weakness types (e.g. CWE-89 = SQL injection).'],
  EPSS: ['Exploit Prediction Scoring System – Wahrscheinlichkeit, dass eine Lücke in den nächsten 30 Tagen ausgenutzt wird.', 'Exploit Prediction Scoring System – probability that a vulnerability is exploited in the next 30 days.'],
  KEV: ['Known Exploited Vulnerabilities – Liste der US-Behörde CISA mit Lücken, die nachweislich aktiv ausgenutzt werden.', 'Known Exploited Vulnerabilities – CISA list of vulnerabilities that are known to be actively exploited.'],
  IDOR: ['Insecure Direct Object Reference – fremde Datensätze lassen sich durch Ändern einer ID abrufen.', 'Insecure Direct Object Reference – other users’ records can be fetched by changing an ID.'],
  XSS: ['Cross-Site Scripting – eingeschleuster Skriptcode läuft im Browser anderer Nutzer.', 'Cross-site scripting – injected script code runs in other users’ browsers.'],
  SSRF: ['Server-Side Request Forgery – der Server lässt sich dazu bringen, Anfragen an interne Adressen zu schicken.', 'Server-side request forgery – the server can be made to send requests to internal addresses.'],
  CSRF: ['Cross-Site Request Forgery – eine fremde Seite löst Aktionen im Namen eines angemeldeten Nutzers aus.', 'Cross-site request forgery – another site triggers actions on behalf of a logged-in user.'],
  SBOM: ['Software Bill of Materials – Stückliste aller Pakete und Versionen eines Projekts.', 'Software bill of materials – list of all packages and versions in a project.'],
  VEX: ['Vulnerability Exploitability eXchange – maschinenlesbare Aussage, ob eine Lücke ein Produkt wirklich betrifft.', 'Vulnerability Exploitability eXchange – machine-readable statement whether a vulnerability really affects a product.'],
  OWASP: ['Open Worldwide Application Security Project – gemeinnützige Organisation, bekannt für die Top 10 der Web-Risiken.', 'Open Worldwide Application Security Project – non-profit known for the Top 10 web risks.'],
  CORS: ['Cross-Origin Resource Sharing – regelt, welche fremden Webseiten Daten per Browser abrufen dürfen.', 'Cross-origin resource sharing – controls which other websites may fetch data via the browser.'],
  HSTS: ['HTTP Strict Transport Security – zwingt Browser, eine Seite nur noch per HTTPS aufzurufen.', 'HTTP Strict Transport Security – forces browsers to use HTTPS only for a site.'],
  TLS: ['Transport Layer Security – Verschlüsselung der Verbindung (das „S“ in HTTPS).', 'Transport Layer Security – encryption of the connection (the “S” in HTTPS).'],
  JWT: ['JSON Web Token – signiertes Anmelde-Token; unsicher, wenn die Signatur nicht geprüft wird.', 'JSON Web Token – signed login token; unsafe if the signature is not verified.'],
  RCE: ['Remote Code Execution – Angreifer können aus der Ferne eigenen Code ausführen.', 'Remote code execution – attackers can run their own code remotely.'],
  XXE: ['XML External Entity – ein XML-Parser lädt auf Anweisung fremde Dateien oder Adressen.', 'XML external entity – an XML parser loads external files or URLs on request.'],
  MFA: ['Multi-Faktor-Authentifizierung – Anmeldung mit einem zweiten Faktor zusätzlich zum Passwort.', 'Multi-factor authentication – login with a second factor in addition to the password.'],
  SARIF: ['Static Analysis Results Interchange Format – Austauschformat für Prüfergebnisse (VS Code, GitHub).', 'Static Analysis Results Interchange Format – exchange format for findings (VS Code, GitHub).'],
  ReDoS: ['Regular Expression Denial of Service – ein regulärer Ausdruck braucht bei bestimmten Eingaben extrem lange.', 'Regular expression denial of service – a regex takes extremely long on crafted input.'],
};
const glossText = (term) => { const g = GLOSSARY[term]; return g ? g[state.config && state.config.lang === 'de' ? 0 : 1] : ''; };
const GLOSS_RE = new RegExp(`\\b(${Object.keys(GLOSSARY).join('|')})\\b`, 'g');
// Erstes Vorkommen jedes Begriffs in einem (bereits maskierten) Text als Erklaerung markieren
function glossify(html) {
  const seen = new Set();
  return String(html || '').replace(GLOSS_RE, (m) => { if (seen.has(m)) return m; seen.add(m); return `<abbr class="gloss" tabindex="0" title="${esc(glossText(m))}">${m}</abbr>`; });
}
function openGlossary() {
  $('glossaryList').innerHTML = Object.keys(GLOSSARY).sort((a, b) => a.localeCompare(b)).map((k) => `<dt>${esc(k)}</dt><dd>${esc(glossText(k))}</dd>`).join('');
  $('glossaryBg').hidden = false;
  setTimeout(() => $('glossaryClose').focus(), 30);
}

// --- Notizen je Befund ------------------------------------------------------------------------
function noteBlock(f) {
  if (!f.id) return '';
  return `<div class="f-sec note-sec"><h4>Notiz</h4><textarea class="note-input" rows="2" maxlength="4000" aria-label="Notiz zu diesem Befund" placeholder="Eigene Notiz – erscheint auch im Bericht (Strg + Enter speichert)">${esc(f.note || '')}</textarea><div class="note-foot"><span class="muted small note-state" aria-live="polite">${f.note ? 'gespeichert' : ''}</span><button type="button" class="btn tiny note-save">Notiz speichern</button></div></div>`;
}
function bindNote(root, f, onSaved) {
  const sec = root.querySelector('.note-sec');
  if (!sec || !f.id) return;
  const inp = sec.querySelector('.note-input'), st = sec.querySelector('.note-state');
  const save = async () => {
    const r = await window.vigil.setFindingNote(f.id, inp.value);
    if (r && r.ok) { f.note = r.note || ''; st.textContent = r.note ? 'gespeichert' : 'entfernt'; if (onSaved) onSaved(f.note); toast(r.note ? 'Notiz gespeichert' : 'Notiz entfernt', 'ok'); }
    else { st.textContent = ''; toast('Notiz nicht gespeichert: ' + ((r && r.error) || '?'), 'err'); }
  };
  sec.querySelector('.note-save').onclick = save;
  inp.addEventListener('input', () => { st.textContent = inp.value.trim() !== String(f.note || '').trim() ? 'nicht gespeichert' : (f.note ? 'gespeichert' : ''); });
  inp.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); e.stopPropagation(); save(); } });
}

// --- Rueckgaengig: Toast mit Knopf, ca. 10 Sekunden ----------------------------------------------
function undoToast(msg, token, after) {
  if (!token) { toast(msg, 'ok'); if (after) after(); return; }
  if (after) after();
  const el = document.createElement('div');
  el.className = 'toast ok has-action';
  el.setAttribute('role', 'status');
  el.innerHTML = `<span class="toast-msg"></span><button type="button" class="btn tiny toast-undo">Rückgängig</button><i class="toast-timer" aria-hidden="true"></i>`;
  el.querySelector('.toast-msg').textContent = msg;
  $('toasts').appendChild(el);
  let gone = false;
  const close = () => { if (gone) return; gone = true; el.classList.add('out'); setTimeout(() => el.remove(), 400); };
  const timer = setTimeout(close, 10000);
  el.querySelector('.toast-undo').onclick = async () => {
    clearTimeout(timer); close();
    const r = await window.vigil.undoDelete(token);
    toast(r && r.ok ? 'Wiederhergestellt' : 'Nicht mehr rückgängig zu machen', r && r.ok ? 'ok' : 'err');
    if (after) after();
  };
  return el;
}

// --- Pause / Fortsetzen ---------------------------------------------------------------------------
function setPaused(on) {
  state.paused = !!on;
  const b = $('pauseBtn');
  b.textContent = on ? 'Fortsetzen' : 'Pausieren';
  b.setAttribute('aria-pressed', String(!!on));
  $('progressPanel').classList.toggle('paused', !!on);
}
async function togglePause() {
  if (!state.running) return;
  $('pauseBtn').disabled = true;
  const r = state.paused ? await window.vigil.resumeAudit() : await window.vigil.pauseAudit();
  $('pauseBtn').disabled = false;
  if (!r || !r.ok) return;
  setPaused(r.paused);
  $('progressTitle').textContent = r.paused ? 'Pausiert – hält am nächsten Zwischenschritt' : 'Prüfung läuft …';
  toast(r.paused ? 'Prüfung pausiert' : 'Prüfung fortgesetzt', 'ok');
}

// --- Gruppierung der Ergebnisliste --------------------------------------------------------------
const GROUP_BY = ['severity', 'file', 'category', 'target'];
const fileOf = (f) => { const l = String(f.location || '').replace(/\\/g, '/'); if (/^https?:\/\//i.test(l)) { try { return new URL(l).host; } catch { return l; } } return l.replace(/:\d+(:\d+)?$/, '') || '–'; };
function targetLabel(f) {
  if (f.targetId && state.targetNames && state.targetNames[f.targetId]) return state.targetNames[f.targetId];
  const l = String(f.location || '').replace(/\\/g, '/');
  if (/^https?:\/\//i.test(l)) { try { return new URL(l).host; } catch { /* weiter */ } }
  return l.split('/').filter(Boolean)[0] || 'Unbekanntes Ziel';
}
function groupFindings(keyed) {
  const by = GROUP_BY.includes(state.groupBy) ? state.groupBy : 'severity';
  if (by === 'severity') return SEV_ORDER.map((s) => ({ sev: s, label: SEV_LABEL[s], items: keyed.filter((x) => x.f.severity === s) })).filter((g) => g.items.length);
  const keyOf = by === 'file' ? fileOf : by === 'category' ? (f) => CATEGORY_LABEL[f.category] || f.category || 'Sonstiges' : targetLabel;
  const map = new Map();
  for (const x of keyed) { const k = keyOf(x.f); if (!map.has(k)) map.set(k, []); map.get(k).push(x); }
  const rank = (f) => SEV_ORDER.indexOf(f.severity);
  return [...map].map(([label, items]) => ({ label, items: items.sort((a, b) => rank(a.f) - rank(b.f)), worst: Math.min(...items.map((x) => rank(x.f))) }))
    .sort((a, b) => a.worst - b.worst || b.items.length - a.items.length || a.label.localeCompare(b.label));
}
async function setGroupBy(v) {
  state.groupBy = GROUP_BY.includes(v) ? v : 'severity';
  $('groupBySelect').value = state.groupBy;
  if (state.config) { state.config.resultsGroupBy = state.groupBy; saveCfg(); }
  if (state.groupBy === 'target' && !state.targetNames) {
    try { const d = await window.vigil.dashboard({ limit: 1 }); state.targetNames = Object.fromEntries(d.stats.targets.map((t) => [t.id, t.name])); } catch { state.targetNames = {}; }
  }
  if (state.lastResult) renderFindings();
}

// --- Befehlspalette (Strg K) ----------------------------------------------------------------------
const pal = { items: [], active: 0, prevFocus: null };
const trT = (s) => (window.translateText ? window.translateText(s) : s);
function paletteCommands() {
  const has = !!state.lastResult;
  const run = !!state.running;
  const C = [];
  const add = (group, label, act, keys = '', hint = '') => C.push({ group, label, act, keys, hint });
  add('Gehe zu', 'Neue Prüfung', () => showView('scan'), 'scan start ziel', 'Strg 1');
  add('Gehe zu', 'Ergebnis', () => showView('results'), 'results befunde', 'Strg 2');
  add('Gehe zu', 'Übersicht', () => showView('dash'), 'dashboard overview', 'Strg 3');
  add('Gehe zu', 'Verlauf', () => showView('history'), 'history runs', 'Strg 4');
  add('Gehe zu', 'Einstellungen', () => showView('settings'), 'settings options', 'Strg ,');
  for (const [g, l] of [['general', 'Einstellungen: Allgemein'], ['checks', 'Einstellungen: Prüfungen'], ['web', 'Einstellungen: Web & Server'], ['advanced', 'Einstellungen: Erweitert']]) add('Gehe zu', l, () => { showView('settings'); setGroup(g); }, 'settings ' + g);
  if (!run && !$('runBtn').disabled) add('Prüfung', 'Prüfung starten', () => { showView('scan'); runAudit(); }, 'run scan start', 'Strg Enter');
  if (run) add('Prüfung', state.paused ? 'Prüfung fortsetzen' : 'Prüfung pausieren', togglePause, 'pause resume');
  if (run) add('Prüfung', 'Prüfung abbrechen', () => $('cancelBtn').click(), 'cancel stop');
  add('Prüfung', 'Ordner zur Prüfliste hinzufügen …', () => { showView('scan'); $('pickFolderBtn').click(); }, 'folder add');
  add('Prüfung', 'Beispiel-Lauf zeigen', async () => { const r = await window.vigil.sampleDemo(); if (r && r.ok) { showView('results'); $('emptyState').hidden = true; $('progressPanel').hidden = true; renderResult(r.result); } }, 'demo sample');
  if (has) {
    for (const [fmt, label] of [['pdf', 'Exportieren: PDF'], ['execpdf', 'Exportieren: Kurzbericht (PDF)'], ['html', 'Exportieren: HTML'], ['md', 'Exportieren: Markdown'], ['docx', 'Exportieren: Word (.docx)'], ['xlsx', 'Exportieren: Excel (.xlsx)'], ['csv', 'Exportieren: CSV'], ['sarif', 'Exportieren: SARIF'], ['json', 'Exportieren: JSON'], ['auditzip', 'Exportieren: Audit-Paket (ZIP)'], ['openvex', 'Exportieren: OpenVEX'], ['cdxvex', 'Exportieren: CycloneDX VEX'], ['badge', 'Exportieren: Abzeichen (SVG)']]) {
      add('Export', label, () => { const b = document.querySelector(`#exportMenu [data-fmt="${fmt}"]`) || { execpdf: $('exportExecBtn'), pdf: $('exportPdfBtn'), html: $('exportHtmlBtn'), md: $('exportMdBtn'), sarif: $('exportSarifBtn'), json: $('exportJsonBtn') }[fmt]; if (b) b.click(); }, 'export ' + fmt);
    }
    for (const g of GROUP_BY) add('Ansicht', `Gruppieren: ${{ severity: 'nach Schwere', file: 'nach Datei', category: 'nach Bereich', target: 'nach Ziel' }[g]}`, () => { showView('results'); setGroupBy(g); }, 'group ' + g);
  }
  add('Export', 'Bericht prüfen …', verifyReportUi, 'verify signature');
  add('Ansicht', 'Übersicht anpassen', () => { showView('dash'); setTimeout(openLayoutMenu, 50); }, 'layout widgets cards');
  add('Ansicht', 'Glossar anzeigen', openGlossary, 'glossary terms');
  add('Ansicht', 'Farbschema: Hell', () => { state.config.theme = 'light'; saveCfg(); applyAppearance(); }, 'theme light');
  add('Ansicht', 'Farbschema: Dunkel', () => { state.config.theme = 'dark'; saveCfg(); applyAppearance(); }, 'theme dark');
  add('Ansicht', 'Farbschema: Wie Windows', () => { state.config.theme = 'system'; saveCfg(); applyAppearance(); }, 'theme system');
  add('Ansicht', 'Sprache: Deutsch', () => document.querySelector('#langSeg [data-lang="de"]').click(), 'language german');
  add('Ansicht', 'Sprache: English', () => document.querySelector('#langSeg [data-lang="en"]').click(), 'language english');
  return C;
}
function paletteItems(q) {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean);
  const hit = (s) => words.every((w) => s.includes(w));
  const items = paletteCommands().map((c) => ({ ...c, shown: trT(c.label), groupShown: trT(c.group) })).filter((c) => !words.length || hit(`${c.label} ${c.shown} ${c.group} ${c.groupShown} ${c.keys}`.toLowerCase()));
  if (q.trim().length >= 2 && state.lastFindings.length) {
    const qq = q.trim().toLowerCase();
    const found = state.lastFindings.map((f, i) => ({ f, key: findingKey(f, i) })).filter(({ f }) => !f.suppressed && matchesQuery(f, qq)).slice(0, 8);
    for (const { f, key } of found) items.push({ group: 'Befunde', groupShown: trT('Befunde'), shown: cleanTitle(f.title), hint: SEV_LABEL[f.severity], sev: f.severity, act: () => { showView('results'); state.filter = 'all'; state.query = ''; $('findingSearch').value = ''; state.showSuppressed = false; state.onlyNew = false; state.onlyProven = false; refreshResultView(); selectFinding(key, true); } });
    items.push({ group: 'Befunde', groupShown: trT('Befunde'), shown: `${trT('In Befunden suchen')}: „${q.trim()}“`, act: () => { showView('results'); $('findingSearch').value = q.trim(); state.query = q.trim(); renderFindings(); $('findingSearch').focus(); } });
  }
  return items;
}
function renderPalette() {
  const q = $('palInput').value;
  pal.items = paletteItems(q);
  pal.active = Math.min(pal.active, Math.max(0, pal.items.length - 1));
  let last = '';
  $('palList').innerHTML = pal.items.length ? pal.items.map((it, i) => {
    const head = it.groupShown !== last ? `<li class="pal-group" role="presentation">${esc(it.groupShown)}</li>` : '';
    last = it.groupShown;
    return `${head}<li id="pal-${i}" role="option" class="pal-item${i === pal.active ? ' active' : ''}" aria-selected="${i === pal.active}" data-i="${i}">${it.sev ? `<span class="sev-dot sev-${it.sev}" aria-hidden="true"></span>` : ''}<span class="pal-label">${esc(it.shown)}</span>${it.hint ? `<span class="pal-hint">${esc(trT(it.hint))}</span>` : ''}</li>`;
  }).join('') : `<li class="pal-empty" role="presentation">${esc(trT('Nichts gefunden'))}</li>`;
  $('palInput').setAttribute('aria-activedescendant', pal.items.length ? `pal-${pal.active}` : '');
  const a = $('palList').querySelector('.pal-item.active'); if (a) a.scrollIntoView({ block: 'nearest' });
  $('palList').querySelectorAll('.pal-item').forEach((li) => { li.onmousemove = () => { if (pal.active !== Number(li.dataset.i)) { pal.active = Number(li.dataset.i); renderPalette(); } }; li.onclick = () => runPaletteItem(Number(li.dataset.i)); });
}
function openPalette(q = '') {
  pal.prevFocus = document.activeElement;
  closeMenus(); closeLayoutMenu();
  $('palette').hidden = false;
  $('palInput').value = q; pal.active = 0;
  renderPalette();
  setTimeout(() => $('palInput').focus(), 0);
}
function closePalette() {
  $('palette').hidden = true;
  if (pal.prevFocus && pal.prevFocus.isConnected && pal.prevFocus.focus) pal.prevFocus.focus();
}
function runPaletteItem(i) {
  const it = pal.items[i];
  if (!it) return;
  closePalette();
  try { it.act(); } catch (e) { console.error(e); }
}

// --- Layout der Uebersicht: Karten zeigen/ausblenden und anordnen ---------------------------------
const WIDGETS = [['score', 'Sicherheitswert'], ['sev', 'Offene Befunde nach Schwere'], ['kpis', 'Kennzahlen'], ['toxic', 'Angriffswege'], ['intel', 'Gefahrenlage']];
function widgetState() {
  const saved = Array.isArray(state.config && state.config.dashWidgets) ? state.config.dashWidgets.filter((w) => w && WIDGETS.some(([id]) => id === w.id)) : [];
  for (const [id] of WIDGETS) if (!saved.some((w) => w.id === id)) saved.push({ id, on: true });
  return saved.map((w) => ({ id: w.id, on: w.on !== false }));
}
function applyWidgets() {
  const ws = widgetState();
  const hero = document.querySelector('#dashView .dash-hero'), low = $('dashLow');
  for (const w of ws) {
    const el = document.querySelector(`#dashView [data-widget="${w.id}"]`);
    if (!el) continue;
    el.hidden = !w.on;
    (el.parentElement === hero ? hero : low).appendChild(el);
  }
  const vis = [...hero.children].filter((c) => !c.hidden).length;
  hero.hidden = vis === 0;
  hero.style.gridTemplateColumns = vis && vis < 3 ? `repeat(${vis}, minmax(0, 1fr))` : '';
}
function renderLayoutMenu() {
  const ws = widgetState();
  const name = Object.fromEntries(WIDGETS);
  $('dashLayoutMenu').innerHTML = `<div class="lm-head">Karten der Übersicht</div>${ws.map((w, i) => `<div class="lm-row" data-id="${w.id}">
    <label><input type="checkbox" data-act="toggle"${w.on ? ' checked' : ''}> ${esc(name[w.id])}</label>
    <span><button type="button" class="btn tiny ghost" data-act="up" aria-label="${esc(name[w.id])} nach oben"${i ? '' : ' disabled'}>↑</button><button type="button" class="btn tiny ghost" data-act="down" aria-label="${esc(name[w.id])} nach unten"${i < ws.length - 1 ? '' : ' disabled'}>↓</button></span>
  </div>`).join('')}<button type="button" class="btn tiny ghost lm-reset" data-act="reset">Zurücksetzen</button>`;
  $('dashLayoutMenu').querySelectorAll('[data-act]').forEach((b) => {
    const ev = b.type === 'checkbox' ? 'onchange' : 'onclick';
    b[ev] = (e) => {
      e.stopPropagation();
      const list = widgetState();
      const row = b.closest('.lm-row');
      const i = row ? list.findIndex((w) => w.id === row.dataset.id) : -1;
      if (b.dataset.act === 'toggle') list[i].on = b.checked;
      else if (b.dataset.act === 'up' && i > 0) [list[i - 1], list[i]] = [list[i], list[i - 1]];
      else if (b.dataset.act === 'down' && i < list.length - 1) [list[i + 1], list[i]] = [list[i], list[i + 1]];
      state.config.dashWidgets = b.dataset.act === 'reset' ? WIDGETS.map(([id]) => ({ id, on: true })) : list;
      saveCfg(); applyWidgets(); renderLayoutMenu();
      const again = $('dashLayoutMenu').querySelector(row ? `.lm-row[data-id="${row.dataset.id}"] [data-act="${b.dataset.act}"]` : '[data-act="reset"]');
      if (again && !again.disabled) again.focus();
    };
  });
}
function openLayoutMenu() {
  renderLayoutMenu();
  $('dashLayoutMenu').hidden = false; $('dashLayoutBtn').setAttribute('aria-expanded', 'true');
  const first = $('dashLayoutMenu').querySelector('input'); if (first) first.focus();
}
function closeLayoutMenu() { if (!$('dashLayoutMenu')) return; $('dashLayoutMenu').hidden = true; $('dashLayoutBtn').setAttribute('aria-expanded', 'false'); }

// --- Verlauf: zwei Laeufe vergleichen (nebeneinander) ------------------------------------------
function toggleHistSel(id, on) {
  state.histSel = (state.histSel || []).filter((x) => x !== id);
  if (on) state.histSel.push(id);
  if (state.histSel.length > 2) state.histSel = state.histSel.slice(-2);
  document.querySelectorAll('#historyList .hist-sel').forEach((c) => { c.checked = state.histSel.includes(c.dataset.id); });
  updateCompareBar();
}
function updateCompareBar() {
  const n = (state.histSel || []).length;
  $('histCompareBtn').disabled = n !== 2;
  $('histCompareInfo').textContent = n === 2 ? '2 Läufe ausgewählt' : n === 1 ? '1 Lauf ausgewählt – noch einen ankreuzen' : 'Zwei Läufe ankreuzen, um sie zu vergleichen.';
}
async function showCompare() {
  const [a, b] = state.histSel || [];
  if (!a || !b) return;
  const r = await window.vigil.historyCompare(a, b);
  if (!r.ok) { toast(r.error, 'err'); return; }
  state.compare = { a: r.a.id, b: r.b.id };
  const d = r.diff;
  const when = (m) => `${fmtDate(m.at)}${m.targets && m.targets.length ? ' · ' + m.targets.join(', ') : ''}`;
  const col = (title, list, cls, empty) => `<div class="hc-col ${cls}"><h3>${title} <span class="gcount">${list.length}</span></h3>${list.length ? list.map((f) => `<div class="hc-item sev-${f.severity}"><span class="sev-tag">${SEV_LABEL[f.severity]}</span><div><b>${esc(cleanTitle(f.title))}</b>${f.previousSeverity ? `<span class="muted small hc-chg">${SEV_LABEL[f.previousSeverity]} → ${SEV_LABEL[f.severity]}</span>` : ''}<span class="f-loc">${esc(f.location || '')}</span></div></div>`).join('') : `<p class="muted small">${empty}</p>`}</div>`;
  $('histCompareBody').innerHTML = `<div class="hc-runs"><div><span class="eyebrow">Vorher</span><b>${esc(when(r.a))}</b><span class="muted small">${d.totals.before} offen</span></div><div><span class="eyebrow">Nachher</span><b>${esc(when(r.b))}</b><span class="muted small">${d.totals.after} offen</span></div></div>
    <div class="hc-grid">${col('Neu', d.added, 'added', 'Nichts Neues.')}${col('Behoben', d.fixed, 'fixed', 'Nichts behoben.')}${col('Unverändert', d.unchanged, 'same', 'Keine gemeinsamen Befunde.')}</div>`;
  $('histCompare').hidden = false;
  $('histCompare').scrollIntoView({ block: 'start', behavior: 'smooth' });
  $('histCompareClose').focus();
}

// --- Berichts-Branding, Normen-Auswahl, Signatur -------------------------------------------------
const FRAMEWORKS = [['iso27001', 'ISO 27001'], ['bsi', 'BSI IT-Grundschutz'], ['nis2', 'NIS2'], ['dsgvo', 'DSGVO'], ['cra', 'Cyber Resilience Act'], ['soc2', 'SOC 2'], ['pcidss', 'PCI DSS 4.0'], ['asvs', 'OWASP ASVS 4.0'], ['hipaa', 'HIPAA']];
function renderReportBranding() {
  const c = state.config;
  $('reportAccentInput').value = /^#[0-9a-f]{6}$/i.test(c.reportAccent || '') ? c.reportAccent : '#b7791f';
  $('reportCoverInput').value = c.reportCoverText || '';
  $('reportFooterInput').value = c.reportFooterText || '';
  const on = Array.isArray(c.reportFrameworks) && c.reportFrameworks.length ? new Set(c.reportFrameworks) : null;
  $('reportFrameworks').innerHTML = FRAMEWORKS.map(([k, l]) => `<label class="fw-chip"><input type="checkbox" data-fw="${k}"${!on || on.has(k) ? ' checked' : ''}> ${esc(l)}</label>`).join('');
  $('reportFrameworks').querySelectorAll('[data-fw]').forEach((b) => b.onchange = () => {
    const sel = [...$('reportFrameworks').querySelectorAll('[data-fw]:checked')].map((x) => x.dataset.fw);
    if (!sel.length) { b.checked = true; toast('Mindestens eine Norm muss gewählt bleiben', 'err'); return; }
    state.config.reportFrameworks = sel.length === FRAMEWORKS.length ? [] : sel; saveCfg();
  });
  $('signChk').checked = !!c.signReports;
  if (window.vigil.signingInfo) window.vigil.signingInfo().then((s) => { $('signInfo').textContent = s.hasKey ? `Schlüssel ${s.keyId}.` : s.encryption ? 'Noch kein Schlüssel – entsteht beim ersten signierten Export.' : 'Verschlüsselung nicht verfügbar – Signieren nicht möglich.'; }).catch(() => {});
}
async function verifyReportUi() {
  const r = await window.vigil.verifyReport();
  if (!r || r.canceled) return;
  const name = String(r.path || '').split(/[\\/]/).pop();
  let msg;
  if (r.ok) msg = r.signed === false ? `✓ ${name}: Prüfsummen stimmen (ohne Signatur).` : `✓ ${name}: Signatur gültig${r.trusted ? ' – eigener Schlüssel' : ' – fremder Schlüssel'} (${r.keyId}).`;
  else msg = `✕ ${name}: ${(r.errors || []).slice(0, 3).join(' ') || 'Prüfung fehlgeschlagen.'}`;
  if ($('verifyResult')) $('verifyResult').textContent = msg;
  toast(msg, r.ok ? 'ok' : 'err');
}

// --- Einrichtung (aus init) ----------------------------------------------------------------------
function setupExtras() {
  // Gruppierung
  state.groupBy = GROUP_BY.includes(state.config.resultsGroupBy) ? state.config.resultsGroupBy : 'severity';
  $('groupBySelect').value = state.groupBy;
  $('groupBySelect').onchange = () => setGroupBy($('groupBySelect').value);
  // Pause
  $('pauseBtn').onclick = togglePause;
  // Glossar
  $('glossaryClose').onclick = () => { $('glossaryBg').hidden = true; };
  $('glossaryBtn').onclick = openGlossary;
  $('glossaryBg').addEventListener('click', (e) => { if (e.target === $('glossaryBg')) $('glossaryBg').hidden = true; });
  // Befehlspalette
  $('palInput').addEventListener('input', () => { pal.active = 0; renderPalette(); });
  $('palInput').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const n = pal.items.length; if (n) { pal.active = (pal.active + (e.key === 'ArrowDown' ? 1 : -1) + n) % n; renderPalette(); } }
    else if (e.key === 'Home' || e.key === 'End') { if (pal.items.length) { e.preventDefault(); pal.active = e.key === 'Home' ? 0 : pal.items.length - 1; renderPalette(); } }
    else if (e.key === 'Enter') { e.preventDefault(); runPaletteItem(pal.active); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closePalette(); }
    else if (e.key === 'Tab') e.preventDefault(); // Fokus bleibt in der Palette
  });
  $('palette').addEventListener('mousedown', (e) => { if (e.target === $('palette')) closePalette(); });
  // Layout der Uebersicht
  applyWidgets();
  $('dashLayoutBtn').onclick = (e) => { e.stopPropagation(); if ($('dashLayoutMenu').hidden) openLayoutMenu(); else closeLayoutMenu(); };
  document.addEventListener('click', (e) => { if (!e.target.closest('#dashLayoutMenu, #dashLayoutBtn')) closeLayoutMenu(); });
  // Vergleich im Verlauf
  $('histCompareBtn').onclick = showCompare;
  $('histCompareClose').onclick = () => { $('histCompare').hidden = true; };
  document.querySelectorAll('#histCompare [data-cmp]').forEach((b) => b.onclick = async () => {
    if (!state.compare) return;
    const r = await window.vigil.historyCompareSave(state.compare.a, state.compare.b, b.dataset.cmp);
    flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error));
  });
  // Berichts-Branding und Signatur
  $('reportAccentInput').addEventListener('change', () => { state.config.reportAccent = $('reportAccentInput').value; saveCfg(); });
  $('reportAccentReset').onclick = () => { state.config.reportAccent = ''; saveCfg(); renderReportBranding(); };
  $('reportCoverInput').addEventListener('change', () => { state.config.reportCoverText = $('reportCoverInput').value.trim(); saveCfg(); });
  $('reportFooterInput').addEventListener('change', () => { state.config.reportFooterText = $('reportFooterInput').value.trim(); saveCfg(); });
  $('signChk').addEventListener('change', async () => {
    state.config.signReports = $('signChk').checked; await saveCfg();
    if (state.config.signReports) { const r = await window.vigil.signingCreate(); if (!r.ok) { state.config.signReports = false; $('signChk').checked = false; saveCfg(); toast(r.error, 'err'); } renderReportBranding(); }
  });
  $('verifyBtn').onclick = verifyReportUi;
  // Browser-Erweiterung: vorgemerkte Adresse erst nach Rueckfrage in das Eingabefeld uebernehmen
  if (window.vigil.onInbox) window.vigil.onInbox(async (url) => {
    if (!/^https?:\/\//i.test(url)) return;
    const ok = await askConfirm('Adresse aus dem Browser übernehmen?', `Die Browser-Erweiterung schlägt „${url}“ zur Prüfung vor. Übernehmen? Vor dem Start bestätigst du wie gewohnt, dass du die Seite prüfen darfst.`, 'Übernehmen');
    if (!ok) return;
    showView('scan');
    $('targetInput').value = url; onTargetInput(); $('targetInput').focus();
    toast('Adresse übernommen – bitte Berechtigung bestätigen und hinzufügen', 'ok');
  });
}
init().then(setupOnboarding).catch((e) => console.error(e));
