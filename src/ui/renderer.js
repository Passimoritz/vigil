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
  { key: 'done', label: 'Fertig' },
];

const state = { targets: [], providers: [], config: null, lastFindings: [], lastResult: null, filter: 'all', onlyNew: false, showSuppressed: false, running: false };
let RULE_NAMES = null; // Namen der eingebauten Regeln (lazy via IPC)

// --- Ziele --------------------------------------------------------------
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
    const kind = t.type === 'path' ? 'Datei/Ordner' : t.type === 'url' ? 'Webadresse' : 'Server';
    const li = document.createElement('li');
    li.innerHTML = `<span class="t-kind ${t.type}">${kind}</span><span class="t-val" title="${esc(t.value)}">${esc(t.value)}</span>`;
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
function updateRunState() {
  $('runBtn').disabled = state.running || state.targets.length === 0;
  if (!state.running) $('runHint').textContent = state.targets.length ? 'Bereit. Die Prüfung kann je nach Menge ein paar Minuten dauern.' : 'Füge oben zuerst etwas zur Prüfliste hinzu.';
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
    if (!added) $('runHint').textContent = 'Konnte die Pfade nicht lesen – nutze die Auswahl-Buttons.';
  });
  dz.addEventListener('click', () => $('pickFilesBtn').click());
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('pickFilesBtn').click(); } });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());
}

// --- Anbieter / Status --------------------------------------------------
function describeProvider(id) {
  return {
    ollama: 'Läuft lokal auf deinem Rechner – kostenlos, offline, deine Daten bleiben bei dir.',
    anthropic: 'Claude von Anthropic – sehr stark bei Code. Braucht einen API-Schlüssel.',
    openai: 'ChatGPT-Modelle von OpenAI. Braucht einen API-Schlüssel.',
    gemini: 'Gemini von Google. Braucht einen API-Schlüssel.',
    compat: 'Beliebiger OpenAI-kompatibler Dienst (Mistral, DeepSeek, Groq, LM Studio …). Basis-URL in den Einstellungen setzen.',
  }[id] || '';
}
function setStatus(kind, text) {
  $('statusDot').className = 'dot ' + kind;
  $('statusText').textContent = text;
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
  $('resultPanel').hidden = true;
  $('log').textContent = '';
  $('costPanel').hidden = true; $('costPanel').innerHTML = '';
  $('barFill').style.width = '0%';
  $('progressTitle').textContent = 'Prüfung läuft …';
  renderStepper('ingest');
  $('progressPanel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  const unsub = window.vigil.onProgress((p) => {
    renderStepper(p.phase);
    $('log').textContent += `[${p.phase}]${p.total ? ` ${p.done}/${p.total}` : ''} ${p.message}\n`;
    $('log').scrollTop = $('log').scrollHeight;
    if (p.total) $('barFill').style.width = Math.round((p.done / p.total) * 100) + '%';
    if (p.cost) updateCost(p.cost, false);
  });

  const res = await window.vigil.runAudit({ targets: state.targets, providerId: $('providerSelect').value });
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

function renderVerdict(summary) {
  const c = summary.counts;
  let kind = 'ok', head = 'Keine Probleme gefunden.', sub = 'Vigil hat nichts Auffälliges entdeckt.';
  if (summary.total > 0) {
    sub = 'Klick ein Problem an, um Details und die Lösung zu sehen.';
    if (c.critical) { kind = 'crit'; head = `${c.critical} kritische und ${c.high || 0} hohe Probleme gefunden.`; }
    else if (c.high) { kind = 'high'; head = `${c.high} hohe Probleme gefunden.`; }
    else if (c.medium) { kind = 'med'; head = `${c.medium} Problem(e) mittleren Risikos gefunden.`; }
    else { kind = 'low'; head = `${summary.total} kleinere Hinweise gefunden.`; }
  }
  $('verdict').className = 'verdict v-' + kind;
  $('verdict').innerHTML = `<div class="v-head">${esc(head)}</div><div class="v-sub">${esc(sub)}</div>`;
}

function renderResult(result) {
  state.lastFindings = result.findings || [];
  state.lastResult = result;
  state.filter = 'all'; state.onlyNew = false; state.showSuppressed = false;
  $('resultPanel').hidden = false;
  renderVerdict(result.summary);

  const c = result.summary.counts;
  $('legend').innerHTML = SEV_ORDER.map((s) => `<span class="pill ${SEV_CLS[s]}" title="${esc(SEV_HELP[s])}">${SEV_LABEL[s]}: ${c[s] || 0}</span>`).join('');

  const filters = $('filters');
  filters.innerHTML = `<button class="fbtn active" data-f="all">Alle (${result.summary.total})</button>` +
    SEV_ORDER.filter((s) => c[s]).map((s) => `<button class="fbtn" data-f="${s}">${SEV_LABEL[s]} (${c[s]})</button>`).join('');
  filters.querySelectorAll('.fbtn').forEach((b) => b.onclick = () => {
    filters.querySelectorAll('.fbtn').forEach((x) => x.classList.remove('active'));
    b.classList.add('active'); state.filter = b.dataset.f; renderFindings();
  });

  if (result.errors && result.errors.length) {
    $('log').hidden = false; $('logToggle').setAttribute('aria-expanded', 'true');
    $('log').textContent += '\nHinweise:\n' + result.errors.map((e) => '  - ' + e).join('\n') + '\n';
  }
  updateBaselineStatus();
  renderViewToggles();
  renderFindings();
}

function renderFindings() {
  const box = $('findings');
  let list = state.filter === 'all' ? state.lastFindings : state.lastFindings.filter((f) => f.severity === state.filter);
  if (!state.showSuppressed) list = list.filter((f) => !f.suppressed);
  if (state.onlyNew) list = list.filter((f) => f.isNew);
  if (!list.length) { box.innerHTML = '<p class="muted">Keine Einträge in dieser Ansicht.</p>'; return; }
  box.innerHTML = list.map((f) => {
    const danger = [f.impact, f.reachability].filter(Boolean).join(' ');
    const badges = `${f.isNew ? '<span class="badge-new" title="Seit der gespeicherten Baseline neu">neu</span>' : ''}${f.suppressed ? '<span class="badge-supp" title="Dauerhaft ausgeblendet">ausgeblendet</span>' : ''}`;
    return `
    <div class="card finding sev-${f.severity}${f.suppressed ? ' is-suppressed' : ''}">
      <button class="card-head" aria-expanded="false">
        <span class="sev-tag" title="${esc(SEV_HELP[f.severity])}">${SEV_LABEL[f.severity]}</span>
        <span class="f-title">${esc(f.title)}</span>${badges}
        <span class="cvss" title="CVSS: standardisierter Schweregrad 0–10">${f.cvss != null ? 'CVSS ' + f.cvss : ''}</span>
        <span class="chev">▸</span>
      </button>
      <div class="card-body">
        <div class="f-meta">${esc(f.category)}${f.location ? ` · <code>${esc(f.location)}</code>` : ''} · Quelle: ${esc(sourceLabel(f.source))}</div>
        ${f.description ? `<div class="f-sec"><h4>Das Problem</h4><p>${esc(f.description)}</p></div>` : ''}
        ${danger ? `<div class="f-sec"><h4>Wie gefährlich ist das?</h4><p>${esc(danger)}</p></div>` : ''}
        ${f.remediation ? `<div class="f-sec fix"><h4>✔ So behebst du es</h4><p>${esc(f.remediation)}</p></div>` : ''}
        ${f.patch ? `<pre>${esc(f.patch)}</pre>` : ''}
        <div class="f-actions"><button type="button" class="btn tiny supp-toggle" data-fp="${esc(f.id || '')}">${f.suppressed ? 'Wieder einblenden' : 'Diesen Befund ausblenden'}</button></div>
      </div>
    </div>`;
  }).join('');
  box.querySelectorAll('.card-head').forEach((h) => h.onclick = () => {
    const open = h.parentElement.classList.toggle('open');
    h.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  box.querySelectorAll('.supp-toggle').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    const fp = b.dataset.fp; if (!fp) return;
    const r = await window.vigil.toggleSuppress(fp);
    if (r.ok) {
      state.lastFindings.forEach((f) => { if ((f.id || '') === fp) f.suppressed = r.suppressed; });
      updateBaselineStatus(); renderViewToggles(); renderFindings();
    }
  });
}
// Baseline-Status + Ansichts-Umschalter (nur neue / ausgeblendete zeigen).
function updateBaselineStatus() {
  const el = $('baselineStatus'); if (!el) return;
  const r = state.lastResult;
  const newCount = state.lastFindings.filter((f) => f.isNew).length;
  if (r && r.hasBaseline) {
    const when = r.baselineAt ? ' (von ' + new Date(r.baselineAt).toLocaleString('de-DE') + ')' : '';
    el.textContent = `Baseline aktiv${when} · ${newCount} neue Befund(e) seit der Baseline.`;
  } else {
    el.textContent = 'Keine Baseline gesetzt – „Als Baseline merken" hebt beim nächsten Lauf nur neue Befunde hervor.';
  }
}
function renderViewToggles() {
  const box = $('viewToggles'); if (!box) return;
  const r = state.lastResult;
  const newCount = state.lastFindings.filter((f) => f.isNew).length;
  const suppCount = state.lastFindings.filter((f) => f.suppressed).length;
  let html = '';
  if (r && r.hasBaseline) html += `<button class="fbtn toggle${state.onlyNew ? ' active' : ''}" data-t="onlyNew">Nur neue (${newCount})</button>`;
  if (suppCount || state.showSuppressed) html += `<button class="fbtn toggle${state.showSuppressed ? ' active' : ''}" data-t="showSupp">Ausgeblendete zeigen (${suppCount})</button>`;
  box.innerHTML = html;
  box.querySelectorAll('.fbtn').forEach((b) => b.onclick = () => {
    if (b.dataset.t === 'onlyNew') state.onlyNew = !state.onlyNew;
    else state.showSuppressed = !state.showSuppressed;
    renderViewToggles(); renderFindings();
  });
}
function sourceLabel(s) { return ({ osv: 'Schwachstellen-DB (OSV)', prescan: 'statische Prüfung', webscan: 'Server-Check', nmap: 'nmap', nuclei: 'nuclei', gitleaks: 'gitleaks', trufflehog: 'trufflehog', trivy: 'trivy', grype: 'grype', semgrep: 'semgrep', bandit: 'bandit', checkov: 'checkov', retire: 'retire.js', hadolint: 'hadolint', 'osv-scanner': 'osv-scanner', binary: 'Binary-Analyse', ai: 'KI' })[s] || 'KI'; }

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

// --- Einstellungen ------------------------------------------------------
function tempText(v) {
  if (v <= 0.2) return 'Niedrig – genaue, nachvollziehbare Ergebnisse (empfohlen).';
  if (v <= 0.5) return 'Mittel – etwas freier formuliert.';
  return 'Hoch – kreativer, aber weniger zuverlässig. Für Sicherheitsprüfungen nicht ideal.';
}
// Modelle automatisch ziehen + sinnvolles Modell vorauswaehlen.
const MODEL_CACHE = {};
const CUSTOM = '__custom__'; // Sentinel fuer „eigenes Modell eingeben"
// Ist das aktuell gespeicherte Modell NICHT in der geladenen Liste? -> manuelle Eingabe.
function isCustomModel(p, pc) {
  const list = MODEL_CACHE[p.id];
  return !!(pc.model && list && list.length && !list.includes(pc.model));
}
// Baut die <option>-Liste fuer das Modell-Dropdown eines Anbieters.
function modelOptions(p, pc) {
  const list = MODEL_CACHE[p.id] || [];
  const picked = pickPreferred(p.id, list, pc.model || '');
  let opts = '';
  if (list.length) {
    opts = list.map((m) => `<option value="${esc(m)}"${m === picked && !isCustomModel(p, pc) ? ' selected' : ''}>${esc(m)}</option>`).join('');
  } else if (pc.model) {
    // Noch keine Liste geladen: aktuelles Modell trotzdem zeigen.
    opts = `<option value="${esc(pc.model)}" selected>${esc(pc.model)}</option>`;
  } else {
    opts = `<option value="" disabled selected>— „Modelle laden" klicken —</option>`;
  }
  opts += `<option value="${CUSTOM}"${isCustomModel(p, pc) ? ' selected' : ''}>✏️ Eigenes Modell eingeben …</option>`;
  return opts;
}
function providerReady(p) {
  const pc = state.config.providers[p.id] || {};
  return p.id === 'ollama' || p.id === 'compat' || p.envKeyPresent || !!pc.apiKey;
}
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
async function pullModels(id, { silent } = {}) {
  const pc = state.config.providers[id] || (state.config.providers[id] = {});
  const keyEl = document.querySelector(`#providerSettings input[data-p="${id}"][data-k="apiKey"]`);
  const baseEl = document.querySelector(`#providerSettings input[data-p="${id}"][data-k="baseUrl"]`);
  const apiKey = keyEl ? keyEl.value.trim() : (pc.apiKey || '');
  const baseUrl = baseEl ? baseEl.value.trim() : (pc.baseUrl || '');
  const ms = document.querySelector(`[data-ms="${id}"]`);
  if (ms && !silent) { ms.textContent = 'Lade Modelle …'; ms.className = 'model-status muted small'; }
  const r = await window.vigil.loadModels({ providerId: id, apiKey, baseUrl });
  if (!r.ok) {
    if (ms && !silent) { ms.textContent = r.error + (id === 'anthropic' ? '  (Schlüssel korrekt? Guthaben vorhanden?)' : ''); ms.className = 'model-status err small'; }
    return [];
  }
  MODEL_CACHE[id] = r.models;
  const p = state.providers.find((x) => x.id === id);
  // Dropdown neu aufbauen (alle geladenen Modelle + „eigenes Modell").
  const sel = document.querySelector(`#providerSettings select[data-p="${id}"][data-k="model"]`);
  const man = document.querySelector(`#providerSettings input[data-p="${id}"][data-k="modelManual"]`);
  const custom = isCustomModel(p, pc);
  if (!custom) {
    const picked = pickPreferred(id, r.models, pc.model || '');
    if (picked && picked !== pc.model) { pc.model = picked; window.vigil.saveConfig(state.config); }
  }
  if (sel) { sel.innerHTML = modelOptions(p, pc); sel.value = custom ? CUSTOM : (pc.model || ''); }
  if (man) { man.hidden = !custom; if (custom) man.value = pc.model || ''; }
  if (ms) {
    if (r.models.length) { ms.textContent = `${r.models.length} Modelle geladen · ausgewählt: ${pc.model || '—'}`; ms.className = 'model-status ok small'; }
    else if (id === 'ollama') { ms.textContent = 'Verbindung ok, aber kein Modell installiert. Lade z. B. „ollama pull qwen2.5-coder".'; ms.className = 'model-status err small'; }
    else { ms.textContent = 'Keine Modelle gefunden – Modellname unten manuell eingeben.'; ms.className = 'model-status err small'; }
  }
  return r.models;
}
// Beim Start/Anbieterwechsel still sicherstellen, dass ein gueltiges Modell gesetzt ist.
async function ensureModel(id) {
  const p = state.providers.find((x) => x.id === id);
  if (p && providerReady(p)) await pullModels(id, { silent: true });
}

function renderSettings() {
  const t = state.config.temperature ?? 0.1;
  $('tempRange').value = t; $('tempVal').textContent = t; $('tempDesc').textContent = tempText(t);
  $('cveChk').checked = state.config.cveLookup !== false;
  $('depthSelect').value = state.config.analysisDepth === 'standard' ? 'standard' : 'thorough';
  $('activeChk').checked = !!state.config.activeScan;

  // Proxy / VPN
  $('proxyInput').value = state.config.proxyUrl || '';
  $('proxyTestStatus').textContent = '';
  $('proxyInput').onchange = () => { state.config.proxyUrl = $('proxyInput').value.trim(); window.vigil.saveConfig(state.config); };
  $('proxyTestBtn').onclick = async () => {
    const st = $('proxyTestStatus'); const url = $('proxyInput').value.trim();
    state.config.proxyUrl = url; window.vigil.saveConfig(state.config);
    st.textContent = 'Teste Verbindung …'; st.className = 'muted small';
    const r = await window.vigil.testProxy(url);
    if (r.ok) { st.textContent = (r.usingProxy ? '✔ Proxy aktiv. ' : 'Direktverbindung (kein Proxy gesetzt). ') + 'Nach außen sichtbare IP: ' + r.ip; st.className = 'model-status ok small'; }
    else { st.textContent = '✕ Proxy nicht nutzbar: ' + r.error; st.className = 'model-status err small'; }
  };

  renderCustomRules();
  renderDisabledRules();

  $('providerSettings').innerHTML = state.providers.map((p) => {
    const pc = state.config.providers[p.id] || {};
    const envBadge = p.envKeyPresent ? '<span class="env-badge" title="Ein Schlüssel wurde in der .env gefunden">.env erkannt</span>' : '';
    const keyRow = p.id === 'ollama' ? '' : `
      <label>Schlüssel</label>
      <input type="password" data-p="${p.id}" data-k="apiKey" placeholder="${p.envKeyPresent ? '(aus .env – hier überschreibbar)' : 'API-Schlüssel'}" value="${esc(pc.apiKey || '')}" />`;
    return `
    <div class="prov-block">
      <h4>${esc(p.label)} ${envBadge}</h4>
      <div class="grid">
        <label>Modell</label>
        <div class="model-row">
          <select class="model-select" data-p="${p.id}" data-k="model">${modelOptions(p, pc)}</select>
          <button type="button" class="btn small load-models" data-p="${p.id}">Modelle laden</button>
        </div>
        <input type="text" class="model-manual" data-p="${p.id}" data-k="modelManual" placeholder="z. B. ${esc(p.defaultModel || 'modell-name')}" value="${esc(isCustomModel(p, pc) ? pc.model : '')}" ${isCustomModel(p, pc) ? '' : 'hidden'} />
        <div class="model-status muted small" data-ms="${p.id}">Tipp: „Modelle laden" holt die verfügbaren Namen direkt vom Anbieter.</div>
        <label>Basis-URL</label>
        <input type="text" data-p="${p.id}" data-k="baseUrl" placeholder="${esc(p.defaultBaseUrl || 'https://…')}" value="${esc(pc.baseUrl || '')}" />
        ${keyRow}
      </div>
    </div>`;
  }).join('');

  // „Modelle laden"-Buttons
  $('providerSettings').querySelectorAll('.load-models').forEach((btn) => btn.onclick = () => pullModels(btn.dataset.p));
  // Modell-Dropdown: bei „eigenes Modell" das Textfeld zeigen, sonst Auswahl speichern.
  $('providerSettings').querySelectorAll('select[data-k="model"]').forEach((sel) => sel.onchange = () => {
    const id = sel.dataset.p;
    const pc = state.config.providers[id] || (state.config.providers[id] = {});
    const man = document.querySelector(`#providerSettings input[data-p="${id}"][data-k="modelManual"]`);
    if (sel.value === CUSTOM) { if (man) { man.hidden = false; man.focus(); } }
    else {
      if (man) man.hidden = true;
      pc.model = sel.value; window.vigil.saveConfig(state.config);
      const ms = document.querySelector(`[data-ms="${id}"]`);
      if (ms) { ms.textContent = 'Ausgewählt: ' + (pc.model || '—'); ms.className = 'model-status ok small'; }
    }
  });
  // Bei Key-/URL-Eingabe automatisch neu laden
  $('providerSettings').querySelectorAll('input[data-k="apiKey"], input[data-k="baseUrl"]').forEach((inp) =>
    inp.addEventListener('change', () => pullModels(inp.dataset.p)));
  // Automatisch fuer alle bereiten Anbieter ziehen
  state.providers.forEach((p) => {
    const ms = document.querySelector(`[data-ms="${p.id}"]`);
    if (providerReady(p)) pullModels(p.id);
    else if (ms) ms.textContent = p.id === 'ollama' ? 'Ollama starten – dann lädt die Liste automatisch.' : 'Schlüssel eingeben – die Liste lädt dann automatisch.';
  });
}
function collectSettings() {
  state.config.temperature = parseFloat($('tempRange').value) || 0;
  state.config.cveLookup = $('cveChk').checked;
  state.config.analysisDepth = $('depthSelect').value;
  state.config.activeScan = $('activeChk').checked;
  state.config.proxyUrl = $('proxyInput').value.trim();
  // Modell je Anbieter: aus Dropdown bzw. aus dem manuellen Feld, wenn „eigenes Modell" gewählt ist.
  $('providerSettings').querySelectorAll('select[data-k="model"]').forEach((sel) => {
    const id = sel.dataset.p;
    state.config.providers[id] = state.config.providers[id] || {};
    const man = document.querySelector(`#providerSettings input[data-p="${id}"][data-k="modelManual"]`);
    const model = sel.value === CUSTOM ? (man ? man.value.trim() : '') : sel.value;
    if (model) state.config.providers[id].model = model;
  });
  // Schlüssel + Basis-URL (das manuelle Modell-Feld wird oben separat behandelt).
  $('providerSettings').querySelectorAll('input[data-p]').forEach((inp) => {
    const id = inp.dataset.p, k = inp.dataset.k;
    if (k === 'modelManual') return;
    state.config.providers[id] = state.config.providers[id] || {};
    state.config.providers[id][k] = inp.value.trim();
  });
  collectCustomRules();
  collectDisabledRules();
  state.config.selected = $('providerSelect').value;
}
function openSettings() { renderSettings(); $('settingsOverlay').hidden = false; }
function closeSettings() { $('settingsOverlay').hidden = true; }

// --- Init ---------------------------------------------------------------
async function init() {
  state.providers = await window.vigil.getProviders();
  state.config = await window.vigil.getConfig();

  const sel = $('providerSelect');
  sel.innerHTML = state.providers.map((p) => `<option value="${p.id}">${esc(p.label)}</option>`).join('');
  sel.value = state.config.selected || 'ollama';
  const refreshDesc = () => { $('providerDesc').textContent = describeProvider(sel.value); setStatus('', 'noch nicht getestet'); };
  sel.onchange = () => { state.config.selected = sel.value; window.vigil.saveConfig(state.config); refreshDesc(); ensureModel(sel.value); };
  refreshDesc();
  ensureModel(sel.value); // beim Start still ein gueltiges Modell sicherstellen

  setupDropzone();

  $('pickFilesBtn').onclick = async () => { (await window.vigil.pickFiles()).forEach((p) => addTarget('path', p)); };
  $('pickFolderBtn').onclick = async () => { (await window.vigil.pickFolder()).forEach((p) => addTarget('path', p)); };

  $('advToggle').onclick = () => {
    const panel = $('advPanel'); const open = panel.hidden;
    panel.hidden = !open;
    $('advToggle').setAttribute('aria-expanded', open ? 'true' : 'false');
    $('advToggle').textContent = (open ? '▾' : '▸') + ' Webseite oder Server prüfen (für Fortgeschrittene)';
  };
  $('addUrlBtn').onclick = () => { addTarget('url', $('urlInput').value.trim()); $('urlInput').value = ''; };
  $('addIpBtn').onclick = () => {
    const v = $('ipInput').value.trim(); if (!v) return;
    if (!$('authChk').checked) { $('runHint').textContent = 'Bitte zuerst bestätigen, dass du das Ziel prüfen darfst.'; return; }
    addTarget('endpoint', v, true); $('ipInput').value = ''; $('authChk').checked = false;
  };
  $('clearBtn').onclick = () => { state.targets = []; renderTargets(); };
  $('runBtn').onclick = runAudit;
  $('cancelBtn').onclick = async () => { $('cancelBtn').disabled = true; $('progressTitle').textContent = 'Wird abgebrochen …'; await window.vigil.cancelAudit(); };

  $('logToggle').onclick = () => {
    const log = $('log'); log.hidden = !log.hidden;
    $('logToggle').setAttribute('aria-expanded', log.hidden ? 'false' : 'true');
    $('logToggle').textContent = (log.hidden ? '▸' : '▾') + ' Technische Details';
  };

  $('exportHtmlBtn').onclick = async () => { const r = await window.vigil.saveReport('html'); flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error)); };
  $('exportMdBtn').onclick = async () => { const r = await window.vigil.saveReport('md'); flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error)); };
  $('exportSarifBtn').onclick = async () => { const r = await window.vigil.saveReport('sarif'); flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error)); };
  $('baselineBtn').onclick = async () => {
    const r = await window.vigil.saveBaseline();
    if (r.ok) {
      if (state.lastResult) { state.lastResult.hasBaseline = true; state.lastResult.baselineAt = r.at; }
      state.lastFindings.forEach((f) => { f.isNew = false; });
      updateBaselineStatus(); renderViewToggles(); renderFindings();
      flash(`Baseline gesetzt (${r.count} Befund(e) als bekannt gemerkt).`);
    } else flash('Fehler: ' + (r.error || 'unbekannt'));
  };

  $('pingBtn').onclick = async () => {
    setStatus('wait', 'teste …');
    const r = await window.vigil.pingProvider(sel.value);
    if (r.ok) setStatus('ok', 'Verbindung ok');
    else setStatus('err', 'Fehler: ' + r.error);
  };

  $('exportPdfBtn').onclick = async () => { flash('Erzeuge PDF …'); const r = await window.vigil.saveReport('pdf'); flash(r.ok ? 'Gespeichert: ' + r.path : (r.canceled ? '' : 'Fehler: ' + r.error)); };
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
    const r = await window.vigil.saveConfig(state.config);
    $('settingsStatus').textContent = r.ok ? 'Gespeichert.' : 'Fehler beim Speichern.';
    setTimeout(() => { $('settingsStatus').textContent = ''; closeSettings(); }, 600);
  };

  renderTargets();
}
function flash(msg) { $('runHint').textContent = msg; }

init();
