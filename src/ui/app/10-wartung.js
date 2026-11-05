'use strict';

// Vigil-Oberfläche, Teil 10/10: Geplante Prüfungen, Greenbone-Anbindung, Zustand der aktiven Werkzeuge.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

// --- Zustand der Werkzeuge -----------------------------------------------------------
function renderToolHealth() {
  const box = $('toolHealth');
  if (!box || !window.vigil.toolHealth) return;
  box.innerHTML = '<div class="muted small">Prüfe Werkzeuge …</div>';
  window.vigil.toolHealth().then((items) => {
    box.innerHTML = (items || []).map((h) => `<div class="health-row health-${esc(h.state)}"><span class="health-dot" aria-hidden="true"></span><div><b>${esc(h.tool)}</b> <span class="muted small">${esc(h.detail || '')}</span>${h.fix ? `<div class="small">${esc(h.fix)}</div>` : ''}</div></div>`).join('');
  }).catch(() => { box.innerHTML = ''; });
}

// --- Automatische Updates der Werkzeuge -----------------------------------------------
function renderToolUpdates() {
  if (!$('toolUpdateChk') || !window.vigil.toolUpdateInfo) return;
  window.vigil.toolUpdateInfo().then((u) => {
    $('toolUpdateChk').checked = u.enabled;
    $('toolUpdateNow').disabled = u.running;
    const out = $('toolUpdateStatus');
    if (u.running) { out.textContent = 'Prüfe auf neue Versionen …'; return; }
    if (!u.lastCheck) { out.textContent = 'Noch nicht geprüft.'; return; }
    const res = u.results || [];
    const done = res.filter((r) => r.status === 'updated').map((r) => `${r.id} ${r.to}`);
    const bad = res.filter((r) => r.status === 'failed' || r.status === 'rolled-back').map((r) => `${r.id}: ${r.error || ''}`);
    const when = new Date(u.lastCheck).toLocaleString(uiLocale());
    out.textContent = [`Zuletzt geprüft: ${when}`, done.length ? `Aktualisiert: ${done.join(', ')}` : 'Alles aktuell', ...bad].join(' · ');
  });
}
function bindToolUpdates() {
  if (!$('toolUpdateChk')) return;
  $('toolUpdateChk').onchange = () => window.vigil.toolUpdateSet($('toolUpdateChk').checked);
  $('toolUpdateNow').onclick = async () => { await window.vigil.toolUpdateNow(); renderToolUpdates(); };
  if (window.vigil.onToolsUpdated) window.vigil.onToolsUpdated(() => { renderToolUpdates(); renderToolHealth(); });
}

// --- Greenbone ------------------------------------------------------------------------
// Gesamtfortschritt: Der Download zaehlt nach Paketen; andere Schritte haben kein bekanntes Ende (dann ohne Prozent).
function gbPercent(p) {
  return p && p.step === 'pull' && p.total ? Math.round((p.done || 0) / p.total * 100) : null;
}
function gbElapsed(iso) {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  const m = Math.floor(s / 60);
  return m >= 60 ? `${Math.floor(m / 60)} Std. ${m % 60} Min.` : `${m} Min.`;
}
function renderGbProgress(g) {
  const box = $('gbProgress');
  const st = g.setup || {};
  const running = st.state === 'running';
  box.hidden = !running;
  $('gbChip').hidden = !running;
  if (!running) return;
  const p = st.progress;
  const idx = p ? g.steps.findIndex((s) => s.id === p.step) : -1;
  const pct = gbPercent(p);
  const detail = !p ? 'Einrichtung startet …' : p.step === 'pull' ? `${p.done || 0} von ${p.total} Paketen${p.size ? ` · ${p.size} geladen` : ''}` : p.step === 'sync' && p.count ? `${p.count} Tests bisher. ${p.message}` : p.message;
  box.innerHTML = `<ol class="gb-steps-list">${g.steps.map((s, i) => `<li class="${i < idx ? 'done' : i === idx ? 'now' : ''}"${i === idx ? ' aria-current="step"' : ''}><span class="gb-mark" aria-hidden="true">${i < idx ? '✓' : i + 1}</span>${esc(s.label)}</li>`).join('')}</ol>
    <div class="gb-bar big${pct == null ? ' busy' : ''}" role="progressbar" aria-valuemin="0" aria-valuemax="100"${pct == null ? '' : ` aria-valuenow="${pct}"`}><span style="width:${pct == null ? 100 : pct}%"></span></div>
    <div class="gb-detail"><span>${esc(detail)}</span><span class="muted">${pct == null ? '' : `${pct} % · `}läuft seit ${esc(gbElapsed(st.startedAt || new Date().toISOString()))}</span></div>`;
  $('gbChipLabel').textContent = idx >= 0 ? g.steps[idx].label : 'Greenbone';
  $('gbChipPct').textContent = pct == null ? '' : `${pct} %`;
  const fill = $('gbChipFill');
  fill.parentElement.classList.toggle('busy', pct == null);
  fill.style.width = `${pct == null ? 100 : pct}%`;
}
let gbAsked = false;
function renderGreenbone() {
  if (!$('gbEnabled') || !window.vigil.greenboneGet) return;
  window.vigil.greenboneGet().then((g) => {
    const st = g.setup || {};
    const running = st.state === 'running', ready = st.state === 'ready';
    $('gbEnabled').checked = !!g.enabled;
    $('gbEnabled').disabled = !ready;
    $('gbAuto').hidden = running;
    $('gbCancel').hidden = !running;
    $('gbAuto').textContent = ready ? 'Einrichtung wiederholen' : st.state === 'error' || st.state === 'needs_wsl' ? 'Einrichtung fortsetzen' : 'Einrichten';
    $('gbTest').disabled = !ready;
    const out = $('gbAutoStatus');
    out.className = st.state === 'error' || st.state === 'needs_wsl' ? 'small err' : 'small muted';
    out.textContent = running ? '' : ready ? 'Eingerichtet.' : st.error || (st.state === 'declined' ? 'Nicht eingerichtet.' : '');
    renderGbProgress(g);
    if (g.needsAnswer && !$('gbAsk').open && !gbAsked && $('onboard').hidden) { gbAsked = true; $('gbAsk').showModal(); }
  });
}
function bindGreenbone() {
  if (!$('gbAuto')) return;
  const answer = async (yes) => { $('gbAsk').close(); await window.vigil.greenboneAnswer(yes); renderGreenbone(); };
  $('gbAskYes').onclick = () => answer(true);
  $('gbAskNo').onclick = () => answer(false);
  $('gbAsk').addEventListener('cancel', (e) => { e.preventDefault(); answer(false); });
  $('gbChip').onclick = () => { showView('settings'); setGroup('checks'); $('set-greenbone').scrollIntoView({ block: 'start' }); };
  $('gbAuto').onclick = async () => { await window.vigil.greenboneSetupRun(); renderGreenbone(); };
  $('gbCancel').onclick = async () => { await window.vigil.greenboneSetupCancel(); renderGreenbone(); };
  $('gbRemove').onclick = async () => {
    if (!confirm('Greenbone entfernen? Die WSL-Umgebung von Vigil wird gelöscht und der Speicher freigegeben. Andere WSL-Umgebungen bleiben unberührt.')) return;
    const r = await window.vigil.greenboneRemove();
    toast(r && r.ok ? 'Greenbone entfernt.' : (r && r.error) || 'Nicht entfernt.', r && r.ok ? 'ok' : 'err');
    renderGreenbone();
  };
  $('gbEnabled').onchange = async () => {
    const r = await window.vigil.greenboneSetEnabled($('gbEnabled').checked);
    if (!r || !r.ok) { toast((r && r.error) || 'Nicht gespeichert.', 'err'); renderGreenbone(); }
  };
  $('gbTest').onclick = async () => {
    const out = $('gbResult');
    out.className = 'small muted';
    out.textContent = 'Starte Greenbone, das kann einige Minuten dauern …';
    const r = await window.vigil.greenboneTest();
    if (!r || !r.ok) { out.textContent = `Keine Verbindung: ${(r && r.error) || 'unbekannter Fehler'}`; out.className = 'small err'; return; }
    out.className = 'small';
    out.textContent = `Verbunden: GMP ${r.version || '?'}${r.nvts ? `, ${r.nvts} Tests` : ''}${r.syncing ? ' – Tests werden gerade abgeglichen, Scans erst danach möglich.' : ''}`;
  };
  if (window.vigil.onGreenboneSetup) window.vigil.onGreenboneSetup(renderGreenbone);
  // Laufzeit aktuell halten und nach der Einfuehrung fragen
  setInterval(() => { if (!document.hidden) renderGreenbone(); }, 30000);
}

// --- Geplante Prüfungen --------------------------------------------------------------
const SCHED_DAYS = ['Sonntag', 'Montag', 'Dienstag', 'Mittwoch', 'Donnerstag', 'Freitag', 'Samstag'];
const schedWhen = (s) => (s.freq === 'weekly' ? `${SCHED_DAYS[s.weekday]}s, ${s.time} Uhr` : `Täglich, ${s.time} Uhr`);
function schedLast(s) {
  const st = s.lastStatus;
  if (!st) return 'Noch nicht gelaufen';
  const at = new Date(st.at).toLocaleString();
  if (!st.ok) return `${at}: nicht gelaufen – ${st.error || ''}`;
  return `${at}: ${st.total} Befund(e), ${st.alerts} neu${st.webhookError ? ` – Webhook: ${st.webhookError}` : ''}`;
}
function renderSchedules() {
  const box = $('schedList');
  if (!box || !window.vigil.schedulesList) return;
  window.vigil.schedulesList().then((d) => {
    $('schedBackground').checked = !!d.runInBackground;
    $('schedLogin').checked = !!d.startAtLogin;
    box.innerHTML = d.items.length ? d.items.map((s) => `<div class="sched-row" data-id="${esc(s.id)}">
      <div class="sched-main"><b>${esc(s.name)}</b>${s.enabled ? '' : ' <span class="muted small">(pausiert)</span>'}<div class="small">${esc(schedWhen(s))} · ${s.targets.length} Ziel(e) · meldet ab ${esc(SEV_LABEL[s.minSeverity] || s.minSeverity)}${s.hasWebhook ? ' · Webhook' : ''}</div><div class="muted small" title="${esc(s.targets.map((t) => t.value).join('\n'))}">${esc(schedLast(s))}</div></div>
      <div class="sched-actions"><button type="button" class="btn tiny" data-act="run">Jetzt prüfen</button><button type="button" class="btn tiny" data-act="toggle">${s.enabled ? 'Pausieren' : 'Fortsetzen'}</button><button type="button" class="btn tiny danger" data-act="del">Löschen</button></div>
    </div>`).join('') : '<div class="muted small">Noch keine geplanten Prüfungen.</div>';
    box.querySelectorAll('.sched-row').forEach((row) => {
      const s = d.items.find((x) => x.id === row.dataset.id);
      row.querySelector('[data-act="run"]').onclick = async () => { toast('Geplante Prüfung gestartet.', 'info'); const r = await window.vigil.schedulesRun(s.id); if (r && !r.ok) toast(r.error || 'Nicht gestartet.', 'err'); renderSchedules(); };
      row.querySelector('[data-act="toggle"]').onclick = async () => { await window.vigil.schedulesSave({ ...s, enabled: !s.enabled }); renderSchedules(); };
      row.querySelector('[data-act="del"]').onclick = async () => { if (!confirm('Geplante Prüfung löschen?')) return; await window.vigil.schedulesDelete(s.id); renderSchedules(); };
    });
  });
}
function schedTargets(text) {
  return text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((value) => {
    if (/^https?:\/\//i.test(value)) return { type: 'url', value };
    if (/^[a-z]:[\\/]|^[\\/]/i.test(value)) return { type: 'path', value };
    return { type: 'endpoint', value };
  });
}
function bindSchedules() {
  if (!$('schedAdd')) return;
  $('schedFreq').onchange = () => { $('schedDay').hidden = $('schedFreq').value !== 'weekly'; };
  $('schedAdd').onclick = async () => {
    const r = await window.vigil.schedulesSave({ name: $('schedName').value, targets: schedTargets($('schedTargets').value), freq: $('schedFreq').value, weekday: Number($('schedDay').value), time: $('schedTime').value, minSeverity: $('schedMin').value, webhook: $('schedHook').value.trim() });
    if (!r || !r.ok) { toast((r && r.error) || 'Nicht gespeichert.', 'err'); return; }
    ['schedName', 'schedTargets', 'schedHook'].forEach((id) => { $(id).value = ''; });
    toast('Geplante Prüfung gespeichert.', 'ok');
    renderSchedules();
  };
  const saveBg = () => window.vigil.schedulesBackground({ runInBackground: $('schedBackground').checked, startAtLogin: $('schedLogin').checked });
  $('schedBackground').onchange = saveBg;
  $('schedLogin').onchange = saveBg;
  if (window.vigil.onSchedulesUpdate) window.vigil.onSchedulesUpdate(renderSchedules);
}

bindToolUpdates();
renderToolUpdates();
bindGreenbone();
bindSchedules();
renderToolHealth();
renderGreenbone();
renderSchedules();

if ($('dashEmptyScan')) $('dashEmptyScan').onclick = () => showView('scan');
