'use strict';

// Vigil-Oberfläche, Teil 6/9: Übersicht über alle Läufe.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

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
