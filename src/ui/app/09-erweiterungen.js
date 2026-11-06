'use strict';

// Vigil-Oberfläche, Teil 9/9: Glossar, Notizen, Rückgängig, Pause, Gruppierung, Befehlspalette, Layout, Vergleich, Branding, Einrichtung.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

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
  $('progressTitle').textContent = r.paused ? 'Pausiert – Stand gespeichert, Vigil darf geschlossen werden' : 'Prüfung läuft …';
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
