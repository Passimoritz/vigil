// Laeuft IM App-Fenster: echte Mausrad-Ereignisse an vielen Stellen jeder Ansicht. Ergebnis fuer test/scroll-audit.js.
(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const $ = (id) => document.getElementById(id);
  for (let i = 0; i < 150 && !(window.state && state.config && $('runBtn')); i++) await wait(80);
  await wait(300);
  try { if ($('obSkip') && !$('onboard').hidden) $('obSkip').click(); } catch { /* keine Einfuehrung */ }
  const scrolled = () => [...document.querySelectorAll('*')].some((e) => e.scrollTop > 0);
  const reset = () => document.querySelectorAll('*').forEach((e) => { if (e.scrollTop > 0) e.scrollTop = 0; });
  const dead = [];
  const sweep = async (name) => {
    await wait(300);
    document.querySelectorAll('.main details').forEach((d) => { d.open = true; });
    await wait(100);
    if (document.querySelector('.main').scrollHeight <= document.querySelector('.main').clientHeight + 40) return;
    for (let x = 300; x < innerWidth - 20; x += 300) for (let y = 60; y < innerHeight - 20; y += 170) {
      reset(); await wait(20);
      await window.vigil.e2eWheel(x, y, 240);
      await wait(180);
      if (!scrolled()) { const e = document.elementFromPoint(x, y); dead.push(name + ' @' + x + ',' + y + ' ' + (e ? e.tagName + '#' + e.id : '')); }
    }
  };
  for (const g of ['general', 'checks', 'web', 'advanced']) { showView('settings'); setGroup(g); await sweep('Einstellungen ' + g); }
  showView('results'); $('emptyState').hidden = true; renderResult((await window.vigil.sampleDemo()).result); await sweep('Ergebnis');
  showView('scan'); await sweep('Neue Prüfung');
  // Fokussiertes Auswahlfeld: Das Rad scrollt die Seite und aendert den Wert nicht
  showView('settings'); setGroup('checks'); await wait(300); reset();
  const sel = [...document.querySelectorAll('#settingsView select')].find((e) => { const r = e.getBoundingClientRect(); return e.offsetParent && r.top > 60 && r.bottom < innerHeight - 30; });
  sel.focus(); const before = sel.value; const box = sel.getBoundingClientRect();
  await window.vigil.e2eWheel(box.left + box.width / 2, box.top + box.height / 2, 240); await wait(250);
  const focusOk = scrolled() && sel.value === before;
  // Protokoll: Wer nach oben gescrollt hat, bleibt dort, auch wenn neue Zeilen kommen
  const log = $('log'); $('progressPanel').hidden = false; log.hidden = false; showView('results');
  log.textContent = Array.from({ length: 300 }, (_, i) => 'Zeile ' + i).join('\n') + '\n';
  log.scrollTop = log.scrollHeight; await wait(50);
  const follows = (() => { const t = log.scrollTop; appendRunLog('neu\n'); return log.scrollTop > t; })();
  log.scrollTop = 200; appendRunLog('noch eine\n');
  const stays = log.scrollTop === 200;
  return { ok: true, results: [{ name: 'scroll', ok: true, dead, focusOk, follows, stays }] };
})();
