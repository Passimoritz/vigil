'use strict';

// Vigil-Oberfläche, Teil 5/9: KI-Auswahl: lokal (Ollama/kompatibel) und Cloud.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

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
