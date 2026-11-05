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
  // KI & Behebung: ohne echte KI-Aufrufe (nur Darstellung und Bedienung)
  await t('Ergebnis: Zusammenfassung des Laufs sichtbar', async () => (!$('runSummary').hidden && $('runSummary').textContent.length > 60) || 'keine Zusammenfassung');
  await t('KI-Hilfe: Erklärstufen und Fix-Knopf im Detail', async () => {
    const row = [...document.querySelectorAll('#findings .frow')].find((r) => { r.click(); return !!document.querySelector('#findingDetail .gen-patch'); });
    const lv = document.querySelectorAll('#findingDetail .lvl-seg button').length;
    return (row && lv === 3 && /Vigil ändert keine Datei/.test(document.querySelector('#findingDetail .ai-help').textContent)) || `Stufen ${lv}, Fix-Knopf ${!!row}`;
  });
  await t('Bedrohungsmodell: STRIDE-Karten werden angezeigt', async () => {
    state.lastResult.meta = { ...(state.lastResult.meta || {}), threatModel: { source: 'rules', at: new Date().toISOString(), summary: 'Test', assets: ['Daten'], entryPoints: [], assumptions: [], threats: [{ stride: 'T', category: 'Manipulation', title: 'SQL', asset: '', description: 'd', likelihood: 'high', impact: 'high', mitigations: ['Parameter binden'], findings: [] }] } };
    renderThreatModel();
    const ok = !$('threatPanel').hidden && document.querySelectorAll('#threatPanel .tm-card').length === 1;
    $('threatPanel').querySelector('.tm-close').click();
    return (ok && $('threatPanel').hidden) || 'Karten fehlen';
  });
  await t('Risiko akzeptieren: Frist-Dialog mit 90 Tagen als Standard', async () => {
    const p = askAcceptance(); await wait(50);
    const dlg = document.querySelector('.accept-dlg');
    const def = dlg && dlg.querySelector('.acc-days').value;
    dlg.querySelector('.acc-cancel').click();
    const r = await p;
    return (def === '90' && r === null && !document.querySelector('.accept-dlg')) || `Standard ${def}`;
  });
  await t('Einstellungen: Budget, Datenschutz, Protokoll, Vorgaben vorhanden', async () => (['monthlyBudgetInput', 'aiFocusInput', 'lookupChk', 'fileBudgetInput', 'privacyChk', 'reproChk', 'runSumChk'].every((id) => $(id))) || 'Felder fehlen');
  await t('Einstellungen: Profil anwenden', async () => { showView('settings'); document.querySelector('#presetGrid [data-preset="fast"]').click(); await wait(100); return state.config.analysisDepth === 'standard' || state.config.analysisDepth; });
  await t('Einstellungen: Zugänge für System-Prüfungen (Geheimnisse leer, Status sichtbar)', async () => {
    showView('settings'); setGroup('checks'); renderSettings(); await until(() => $('sysStatus').textContent, 3000);
    const f = $('sysFields');
    const secretsEmpty = [...f.querySelectorAll('input[type="password"], textarea')].every((x) => !x.value);
    return (f.children.length >= 20 && secretsEmpty && !!$('sysStatus').textContent && !!document.querySelector('.sys-chip[data-system="lan"]')) || `${f.children.length} Felder, Status „${$('sysStatus').textContent}“`;
  });
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
