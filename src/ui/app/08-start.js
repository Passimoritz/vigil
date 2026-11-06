'use strict';

// Vigil-Oberfläche, Teil 8/9: Init, Tastenkürzel, Einführung.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

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
  setInterval(() => { if (!document.hidden && ai.mode === 'local' && localSourceId() === 'ollama' && !ai.busy && !ai.pulling && !(ai.ollama && ai.ollama.running)) refreshOllama(); }, 6000);
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
  bindDashExport();
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
