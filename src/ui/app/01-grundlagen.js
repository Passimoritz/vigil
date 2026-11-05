'use strict';

// Vigil-Oberfläche, Teil 1/9: Zustand, Hilfsfunktionen, Ziele, bekannte Ziele, Drag & Drop, Start der Analyse.
// Die Oberfläche ist auf mehrere klassische Skripte in src/ui/app/ verteilt (Reihenfolge siehe index.html).

const $ = (id) => document.getElementById(id);
const uiLocale = () => (typeof state !== 'undefined' && state.config && state.config.lang === 'de' ? 'de-DE' : 'en-GB');
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
  { const n = state.targets.filter((t) => t.type === 'system').length; const c = $('sysCount'); if (c) { c.textContent = n; c.hidden = !n; } }
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
