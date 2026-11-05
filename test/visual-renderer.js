// Laeuft IM App-Fenster (executeJavaScript) vor den Bildschirmfotos der visuellen Regression:
// stellt einen festen, reproduzierbaren Zustand her (Englisch, dunkel, Einfuehrung zu,
// Beispiel-Lauf im Ergebnis). Die Aufnahmen macht danach electron/main.js (VIGIL_VISUAL_DIR).
(async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const until = async (fn, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { try { if (fn()) return true; } catch { /* weiter */ } await wait(80); } return false; };
  const $ = (id) => document.getElementById(id);
  await until(() => window.state && state.config && $('runBtn'));
  await wait(300);
  try { if ($('obSkip') && !$('onboard').hidden) $('obSkip').click(); } catch { /* keine Einfuehrung */ }
  document.documentElement.dataset.theme = 'dark';
  // Blinkende Schreibmarken und Animationen abschalten – sonst wackeln die Bilder
  const st = document.createElement('style');
  st.textContent = '*,*::before,*::after{animation:none!important;transition:none!important;caret-color:transparent!important}';
  document.head.appendChild(st);
  try {
    const r = await window.vigil.sampleDemo();
    if (r && r.ok) { showView('results'); if ($('emptyState')) $('emptyState').hidden = true; renderResult(r.result); }
  } catch { /* Ergebnisansicht bleibt leer */ }
  if (document.activeElement) document.activeElement.blur();
  await wait(400);
  return { ok: true, results: [] };
})();
