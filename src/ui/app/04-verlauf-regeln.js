'use strict';

// Vigil-Oberfläche, Teil 4/9: Verlauf und eigene Regeln.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

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
    const when = new Date(r.at).toLocaleString(uiLocale());
    const systemName = (v) => { const c = document.querySelector(`.sys-chip[data-system="${CSS.escape(v)}"]`); return c ? c.textContent : v; };
    const tgt = (r.targets || []).map(systemName).join(', ');
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
