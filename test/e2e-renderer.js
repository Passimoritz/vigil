// Laeuft IM App-Fenster (executeJavaScript). Spielt die wichtigsten Klickwege durch und prueft
// die Barrierefreiheit (Namen fuer Bedienelemente, Beschriftungen, Kontrast der Haupttexte).
// Ergebnis: { ok, results: [{ name, ok, info }] }
(async () => {
  const results = [];
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, ms = 6000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (fn()) return true; } catch { /* weiter */ } await wait(80); } return false; };
  const $ = (id) => document.getElementById(id);
  const t = async (name, fn) => { try { const r = await fn(); results.push({ name, ok: r === true || r === undefined, info: typeof r === 'string' ? r : '' }); } catch (e) { results.push({ name, ok: false, info: e.message }); } };
  const visible = (el) => !!el && el.offsetParent !== null;

  await until(() => window.state && state.config && $('runBtn'));
  await t('Start: Englisch ist die Standardsprache', async () => { await wait(300); return (document.documentElement.lang === 'en' && /Settings/.test(document.querySelector('.sidebar').textContent)) || document.documentElement.lang; });
  // Die folgenden Klickwege pruefen deutsche Texte – dafuer auf Deutsch umschalten
  state.config.lang = 'de'; window.applyLanguage('de'); await wait(100);
  await t('Start: Einführung erscheint beim ersten Start', async () => (await until(() => !$('onboard').hidden, 3000)) || 'nicht angezeigt');
  await t('Einführung: weiter und überspringen', async () => { $('obNext').click(); await wait(50); const two = !document.querySelector('#onboard [data-step="1"]').hidden; $('obSkip').click(); await wait(50); return (two && $('onboard').hidden && state.config.onboarded === true) || 'Ablauf gestört'; });

  await t('Prüfen: Webadresse wird erkannt', async () => { $('targetInput').value = 'https://example.org'; $('targetInput').dispatchEvent(new Event('input')); return (/Webadresse/.test($('targetKind').textContent) && !$('authRow').hidden) || $('targetKind').textContent; });
  await t('Prüfen: Ziel hinzufügen und entfernen', async () => {
    $('targetInput').value = 'C:\\Projekte\\demo'; $('targetInput').dispatchEvent(new Event('input')); $('addTargetBtn').click(); await wait(50);
    const added = state.targets.length === 1 && state.targets[0].type === 'path';
    document.querySelector('#targetList .t-rm').click(); await wait(30);
    return (added && state.targets.length === 0) || 'Prüfliste stimmt nicht';
  });
  await t('Prüfen: System-Chip schaltet ein und aus', async () => { const c = document.querySelector('.sys-chip[data-system="windows"]'); c.click(); const on = state.targets.some((x) => x.type === 'system'); c.click(); return (on && !state.targets.length && !c.classList.contains('on')) || 'Chip reagiert nicht'; });
  await t('Prüfen: Zeit-Schätzung im Start-Knopf', async () => {
    state.targets.push({ type: 'url', value: 'https://example.org', authorized: true }); renderTargets();
    const ok = await until(() => !$('runEta').hidden && /Sek|Min/.test($('runEta').textContent), 6000);
    state.targets = []; renderTargets();
    return ok || 'keine Schätzung angezeigt';
  });

  for (const [v, id] of [['results', 'resultsView'], ['dash', 'dashView'], ['history', 'historyView'], ['settings', 'settingsView'], ['scan', 'scanView']]) {
    await t(`Navigation: ${v}`, async () => { document.querySelector(`.nav-item[data-view="${v}"]`).click(); await wait(150); return !$(id).hidden || 'Seite nicht sichtbar'; });
  }
  await t('Beispiel-Lauf: Befunde, Detail und Rückfrage-Feld', async () => {
    const r = await window.vigil.sampleDemo();
    if (!r.ok) return r.error;
    showView('results'); $('emptyState').hidden = true; renderResult(r.result);
    await wait(100);
    const rows = document.querySelectorAll('#findings .frow');
    if (rows.length < 10) return `nur ${rows.length} Befunde`;
    rows[1].click(); await wait(100);
    return (!!document.querySelector('#findingDetail .ask-sec') && !!document.querySelector('#findingDetail .fd-title')) || 'Detail unvollständig';
  });
  await t('Ergebnis: Suche filtert die Liste', async () => { $('findingSearch').value = 'AWS'; $('findingSearch').dispatchEvent(new Event('input')); await wait(80); const n = document.querySelectorAll('#findings .frow').length; $('findingSearch').value = ''; $('findingSearch').dispatchEvent(new Event('input')); return (n >= 1 && n < 10) || `${n} Treffer`; });
  await t('Ergebnis: Exportmenü öffnet und schließt', async () => { $('exportBtn').click(); const open = !$('exportMenu').hidden; document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); await wait(30); return (open && $('exportMenu').hidden) || 'Menü reagiert nicht'; });
  await t('Einstellungen: Profil anwenden', async () => { showView('settings'); document.querySelector('#presetGrid [data-preset="fast"]').click(); await wait(100); return state.config.analysisDepth === 'standard' || state.config.analysisDepth; });
  await t('Einstellungen: Hell/Dunkel und Schriftgröße', async () => {
    document.querySelector('#themeSeg [data-theme="light"]').click(); const light = document.documentElement.dataset.theme === 'light';
    document.querySelector('#scaleSeg [data-scale="1.25"]').click(); const big = document.documentElement.style.zoom === '1.25';
    document.querySelector('#themeSeg [data-theme="system"]').click(); document.querySelector('#scaleSeg [data-scale="1"]').click();
    return (light && big && !document.documentElement.dataset.theme) || `hell ${light}, groß ${big}`;
  });
  await t('Einstellungen: Englisch umschalten und zurück', async () => {
    if (!window.applyLanguage) return 'keine Übersetzung geladen';
    document.querySelector('#langSeg [data-lang="en"]').click(); await wait(80);
    const en = /Settings/.test(document.querySelector('.sidebar').textContent);
    document.querySelector('#langSeg [data-lang="de"]').click(); await wait(80);
    return (en && /Einstellungen/.test(document.querySelector('.sidebar').textContent)) || 'Umschalten fehlgeschlagen';
  });
  await t('Übersicht: Detail-Fenster öffnet und schließt', async () => {
    showView('dash'); await wait(400);
    const row = document.querySelector('#dashTable tr.clickable');
    if (!row) return true; // leerer Speicher im Test – nichts zu klicken
    row.click(); const open = !$('dashDrawer').hidden; $('dashDrawerClose').click();
    return (open && $('dashDrawer').hidden) || 'Detail-Fenster reagiert nicht';
  });

  // --- Barrierefreiheit ---
  for (const v of ['scan', 'settings', 'dash']) {
    await t(`Barrierefreiheit (${v}): jeder sichtbare Knopf hat einen Namen`, async () => {
      showView(v); await wait(120);
      const nameOf = (el) => (el.getAttribute('aria-label') || el.getAttribute('title') || el.textContent || '').trim();
      const bad = [...document.querySelectorAll('button, [role="button"]')].filter((b) => visible(b) && !nameOf(b));
      return bad.length ? `ohne Namen: ${bad.slice(0, 5).map((b) => b.id || b.className).join(', ')}` : true;
    });
    await t(`Barrierefreiheit (${v}): Eingabefelder sind beschriftet`, () => {
      const bad = [...document.querySelectorAll('input, select, textarea')].filter((i) => visible(i) && i.type !== 'hidden' && i.type !== 'file' && !(i.labels && i.labels.length) && !i.getAttribute('aria-label') && !i.closest('label') && !i.getAttribute('title'));
      return bad.length ? `ohne Beschriftung: ${bad.slice(0, 8).map((i) => i.id || i.name || i.type).join(', ')}` : true;
    });
  }
  await t('Barrierefreiheit: Bilder haben Alternativtext', () => { const bad = [...document.querySelectorAll('img')].filter((i) => !i.hasAttribute('alt')); return bad.length ? `${bad.length} ohne alt` : true; });
  await t('Barrierefreiheit: Sprache und Seitentitel gesetzt', () => (!!document.documentElement.lang && !!document.title) || 'fehlt');
  const lum = (rgb) => { const [r, g, b] = rgb.match(/\d+(\.\d+)?/g).slice(0, 3).map(Number).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  for (const theme of ['dark', 'light']) {
    await t(`Barrierefreiheit: Textkontrast ${theme === 'dark' ? 'dunkel' : 'hell'} mindestens 4,5 : 1`, async () => {
      document.documentElement.dataset.theme = theme; await wait(60);
      const cs = getComputedStyle(document.documentElement);
      const probe = document.createElement('div'); document.body.appendChild(probe);
      const col = (v) => { probe.style.color = cs.getPropertyValue(v).trim(); return getComputedStyle(probe).color; };
      const pairs = [['--text', '--panel'], ['--text', '--bg'], ['--muted', '--panel'], ['--muted', '--panel-2'], ['--accent', '--panel'], ['--accent-ink', '--accent-strong']];
      const low = pairs.map(([f, b]) => [f, b, ratio(col(f), col(b))]).filter((p) => p[2] < 4.5);
      probe.remove(); delete document.documentElement.dataset.theme;
      return low.length ? low.map((p) => `${p[0]} auf ${p[1]}: ${p[2].toFixed(2)}`).join('; ') : true;
    });
  }
  await t('Barrierefreiheit: Tastaturfokus sichtbar', () => { showView('scan'); const b = $('addTargetBtn'); b.focus(); const s = getComputedStyle(b); return (document.activeElement === b && (s.outlineStyle !== 'none' || s.boxShadow !== 'none')) || 'kein sichtbarer Fokusrahmen'; });


  // --- Erweiterungen: Palette, Gruppierung, Layout, Notizen, Rueckgaengig, Glossar, Vergleich, Branding ---
  await t('Befehlspalette: Strg K öffnet, Suche filtert, Enter führt aus, Esc schließt', async () => {
    showView('scan');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true })); await wait(60);
    if ($('palette').hidden) return 'nicht geöffnet';
    const focused = document.activeElement === $('palInput');
    $('palInput').value = 'verlauf'; $('palInput').dispatchEvent(new Event('input')); await wait(30);
    const opts = document.querySelectorAll('#palList [role="option"]').length;
    $('palInput').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })); await wait(150);
    const nav = !$('historyView').hidden && $('palette').hidden;
    openPalette(); await wait(30); $('palInput').dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); await wait(30);
    return (focused && opts >= 1 && nav && $('palette').hidden && $('palInput').getAttribute('role') === 'combobox') || `Fokus ${focused}, Treffer ${opts}, Navigation ${nav}`;
  });
  await t('Befehlspalette: Pfeiltasten wählen, Befunde sind auffindbar', async () => {
    const r = await window.vigil.sampleDemo(); showView('results'); $('emptyState').hidden = true; renderResult(r.result);
    openPalette('aws'); await wait(40);
    const before = $('palInput').getAttribute('aria-activedescendant');
    $('palInput').dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true })); await wait(20);
    const after = $('palInput').getAttribute('aria-activedescendant');
    const hasFinding = [...document.querySelectorAll('#palList .pal-item')].some((li) => li.querySelector('.sev-dot'));
    closePalette();
    return (before !== after && hasFinding) || `aktiv ${before}→${after}, Befund ${hasFinding}`;
  });
  await t('Ergebnis: Gruppieren nach Datei und zurück nach Schwere', async () => {
    $('groupBySelect').value = 'file'; $('groupBySelect').dispatchEvent(new Event('change')); await wait(80);
    const fileHeads = document.querySelectorAll('#findings .group-head.gb').length;
    const cfg = state.config.resultsGroupBy;
    $('groupBySelect').value = 'severity'; $('groupBySelect').dispatchEvent(new Event('change')); await wait(80);
    const sevHeads = document.querySelectorAll('#findings .group-head[class*="sev-"]').length;
    return (fileHeads >= 2 && cfg === 'file' && sevHeads >= 1 && state.config.resultsGroupBy === 'severity') || `Datei ${fileHeads}, Schwere ${sevHeads}`;
  });
  await t('Glossar: Fachbegriffe im Befundtext erklärt, Glossar öffnet', async () => {
    renderResult({ findings: [{ title: 'Fehlende CSP', severity: 'medium', category: 'Config', location: 'https://example.org', description: 'Ohne CSP kann XSS leichter ausgenutzt werden.' }], summary: { total: 1, counts: {} }, meta: {} });
    await wait(60);
    const abbr = document.querySelectorAll('#findingDetail abbr.gloss');
    openGlossary(); await wait(30);
    const open = !$('glossaryBg').hidden && $('glossaryList').querySelectorAll('dt').length >= 15;
    $('glossaryClose').click();
    return (abbr.length >= 2 && !!abbr[0].title && open && $('glossaryBg').hidden) || `${abbr.length} Begriffe, Glossar ${open}`;
  });
  await t('Notiz: Feld im Detail, Speichern meldet das Ergebnis', async () => {
    renderResult({ findings: [{ id: 'abcdef1234567890', title: 'Testbefund', severity: 'high', category: 'Other', location: 'a.js:1', note: 'alt' }], summary: { total: 1, counts: {} }, meta: {} });
    await wait(60);
    const inp = document.querySelector('#findingDetail .note-input');
    if (!inp || inp.value !== 'alt') return 'Notizfeld fehlt';
    inp.value = 'neu'; inp.dispatchEvent(new Event('input'));
    const dirty = /nicht gespeichert/.test(document.querySelector('#findingDetail .note-state').textContent);
    const n = $('toasts').children.length;
    document.querySelector('#findingDetail .note-save').click();
    const toasted = await until(() => $('toasts').children.length > n, 3000); // leerer Speicher: Fehler-Toast
    return (dirty && toasted) || 'kein Feedback';
  });
  await t('Rückgängig: Toast mit Knopf, ungültiges Token wird gemeldet', async () => {
    const el = undoToast('1 Befund gelöscht', 'deadbeefdeadbeef', () => {});
    const btn = el && el.querySelector('.toast-undo');
    if (!btn) return 'kein Rückgängig-Knopf';
    const n = $('toasts').querySelectorAll('.toast.err').length;
    btn.click();
    const ok = await until(() => $('toasts').querySelectorAll('.toast.err').length > n, 3000);
    return ok || 'keine Rückmeldung';
  });
  await t('Übersicht: Karte ausblenden, verschieben und zurücksetzen', async () => {
    showView('dash'); await wait(200);
    $('dashLayoutBtn').click(); await wait(30);
    if ($('dashLayoutMenu').hidden) return 'Menü öffnet nicht';
    const cb = $('dashLayoutMenu').querySelector('.lm-row[data-id="kpis"] input'); cb.checked = false; cb.dispatchEvent(new Event('change'));
    const hidden = $('dashTrendKpis').hidden && state.config.dashWidgets.find((w) => w.id === 'kpis').on === false;
    $('dashLayoutMenu').querySelector('.lm-row[data-id="sev"] [data-act="up"]').click();
    const first = document.querySelector('#dashView .dash-hero').firstElementChild.dataset.widget;
    $('dashLayoutMenu').querySelector('[data-act="reset"]').click();
    const reset = !$('dashTrendKpis').hidden && document.querySelector('#dashView .dash-hero').firstElementChild.dataset.widget === 'score';
    closeLayoutMenu();
    return (hidden && first === 'sev' && reset) || `ausgeblendet ${hidden}, erste Karte ${first}, zurück ${reset}`;
  });
  await t('Verlauf: zwei Läufe ankreuzen aktiviert den Vergleich', async () => {
    showView('history'); await wait(150);
    renderHistory([{ id: 'aaa111', at: '2026-11-01T10:00:00Z', targets: ['x'], total: 2, counts: {} }, { id: 'bbb222', at: '2026-11-02T10:00:00Z', targets: ['x'], total: 1, counts: {} }, { id: 'ccc333', at: '2026-11-03T10:00:00Z', targets: ['x'], total: 0, counts: {} }]);
    const boxes = document.querySelectorAll('#historyList .hist-sel');
    const click = (i) => { boxes[i].checked = true; boxes[i].dispatchEvent(new Event('change')); };
    click(0); const one = $('histCompareBtn').disabled;
    click(1); const two = !$('histCompareBtn').disabled;
    click(2); const still2 = state.histSel.length === 2 && !boxes[0].checked;
    state.histSel = []; loadHistory();
    return (one && two && still2) || `eins ${one}, zwei ${two}, max zwei ${still2}`;
  });
  await t('Prüfung: Pause-Knopf nur während eines Laufs', () => (!!$('pauseBtn') && $('pauseBtn').hidden && $('pauseBtn').textContent.trim() === 'Pausieren') || 'Pause-Knopf falsch');
  await t('Export: neue Formate im Menü', () => { const f = [...$('exportMenu').querySelectorAll('[data-fmt]')].map((b) => b.dataset.fmt).join(); return f === 'docx,xlsx,csv,auditzip,openvex,cdxvex,badge' || f; });
  await t('Einstellungen: Branding und Normen-Auswahl werden gespeichert', async () => {
    showView('settings'); setGroup('general'); await wait(80);
    const fw = $('reportFrameworks').querySelectorAll('[data-fw]');
    if (fw.length !== 9) return `${fw.length} Normen`;
    $('reportFooterInput').value = 'Nur intern'; $('reportFooterInput').dispatchEvent(new Event('change'));
    fw[4].checked = false; fw[4].dispatchEvent(new Event('change'));
    const ok = state.config.reportFooterText === 'Nur intern' && state.config.reportFrameworks.length === 8 && !state.config.reportFrameworks.includes('cra');
    fw[4].checked = true; fw[4].dispatchEvent(new Event('change'));
    $('reportFooterInput').value = ''; $('reportFooterInput').dispatchEvent(new Event('change'));
    return (ok && Array.isArray(state.config.reportFrameworks) && !state.config.reportFrameworks.length && !!$('signChk') && !!$('verifyBtn')) || 'nicht gespeichert';
  });

  await t('Englisch: Befundtexte im Ergebnis übersetzt', async () => {
    const r = await window.vigil.sampleDemo();
    state.config.lang = 'en'; window.applyLanguage('en');
    showView('results'); renderResult(r.result); await wait(100);
    document.querySelector('#findings .frow').click(); await wait(100);
    const txt = document.querySelector('#findingDetail').textContent;
    state.config.lang = 'de'; window.applyLanguage('de');
    return (!!window.VigilFindingsI18n && /What is wrong\?/.test(txt) && !/Im Code steht|Wer den Code sieht/.test(txt)) || txt.slice(0, 160);
  });

  return { ok: results.every((r) => r.ok), results };
})();
