'use strict';

// Vigil-Oberfläche, Teil 7/9: Einstellungen und Darstellung.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

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
  checks: ['set-analyse', 'set-privacy', 'set-malware', 'set-feeds', 'set-schedules', 'set-tools', 'set-greenbone', 'set-systems'],
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
