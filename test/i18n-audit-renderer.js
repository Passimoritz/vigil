// Laeuft IM App-Fenster: geht alle Ansichten, Einstellungsbereiche, Tabs, Dialoge und Befunde durch und
// sammelt Texte, die in der gewaehlten Sprache nicht uebersetzt sind. Ergebnis fuer test/i18n-audit.js.
(async () => {
  let stage = 'Start';
  const work = (async () => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const $ = (id) => document.getElementById(id);
  for (let i = 0; i < 150 && !(window.state && state.config && $('runBtn')); i++) await wait(80);
  await wait(300);
  try { if ($('obSkip') && !$('onboard').hidden) $('obSkip').click(); } catch { /* keine Einfuehrung */ }

  // Eigennamen und Fachbegriffe, die in beiden Sprachen gleich sind, zaehlen nicht als deutsch
  const DE = /[äöüÄÖÜß]|\b(und|oder|der|die|das|den|dem|des|ein|eine|einen|einem|einer|nicht|mit|für|von|zu|zum|zur|ist|sind|wird|werden|wurde|auf|aus|bei|nach|noch|auch|kein|keine|wenn|dann|über|unter|ohne|alle|alles|dieser|diese|dieses|hier|oben|unten|jetzt|neu|neue|neuen|Datei|Dateien|Prüfung|Prüfungen|Befund|Befunde|Ziel|Ziele|Einstellungen|Bericht|Fehler|Hinweis|Schwere|Lösung|Speichern|Abbrechen|Öffnen|Laden|Starten|läuft|Sekunden|Minuten|Stunden|Tage|gefunden|erkannt|geprüft|gespeichert|Lücke|Lücken)\b/;
  const EN = /\b(the|with|from|your|this|that|these|have|were|will|would|should|please|click|save|settings|findings?|results?|upload|error|failed|loading|checked|found)\b/i;
  // Englische Woerter in deutschen Saetzen ("VS Code", "from" im Beispiel) zaehlen nicht
  const isEnglish = { test: (t) => EN.test(t) && !DE.test(t) };
  // Bewusst nicht uebersetzt: Sprachwahl, Produktnamen, Beispiele
  const SKIP = /^(Deutsch|English|Vigil|Ollama|Greenbone OpenVAS|Docker|OWASP|SBOM|SARIF|JSON|HTML|PDF|CSV|CVE-|CWE-|DE|EN|📰|▶ Video:|Have I Been Pwned)/;
  const seen = new Map();
  let where = '';
  const inCode = (el) => el && el.closest && el.closest('code,pre,kbd,script,style,.fr-loc,.fd-loc,.evidence,.md-code,.diff-view,.log,[data-no-i18n],textarea');
  function collect(bad) {
    const check = (text, how) => {
      const t = String(text || '').replace(/`[^`]*`/g, ' ').replace(/\s+/g, ' ').trim();
      if (t.length < 3 || !/[A-Za-zÄÖÜäöü]{3}/.test(t) || SKIP.test(t) || /^https?:|^[\w./\\:-]+$/.test(t)) return;
      if (bad.test(t) && !seen.has(t)) seen.set(t, `${where}${how}`);
    };
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (w.nextNode()) { const n = w.currentNode; if (!inCode(n.parentElement)) check(n.nodeValue, ''); }
    document.querySelectorAll('[placeholder],[title],[aria-label]').forEach((el) => {
      if (inCode(el)) return;
      for (const a of ['placeholder', 'title', 'aria-label']) if (el.hasAttribute(a)) check(el.getAttribute(a), ` [${a}]`);
    });
  }
  async function sweep(bad) {
    stage = 'Beispiel-Lauf'; const r = await window.vigil.sampleDemo();
    stage = 'Ergebnis'; showView('results'); if ($('emptyState')) $('emptyState').hidden = true; renderResult(r.result);
    await wait(250);
    where = 'Ergebnis'; collect(bad);
    const keys = [...document.querySelectorAll('#findings .frow')].map((x) => x.dataset.key);
    for (const k of keys) { selectFinding(k); await wait(25); where = 'Befund'; collect(bad); }
    for (const v of ['scan', 'dash', 'history', 'settings']) { showView(v); await wait(120); where = `Ansicht ${v}`; collect(bad); }
    for (const g of ['general', 'checks', 'web', 'advanced']) { setGroup(g); await wait(120); where = `Einstellungen ${g}`; collect(bad); }
    showView('dash');
    for (const tab of document.querySelectorAll('.dash-tab')) { tab.click(); await wait(100); where = `Übersicht ${tab.dataset.tab || ''}`; collect(bad); }
    showView('scan');
    for (const m of ['cloud', 'local']) { try { setMode(m); await wait(150); where = `KI ${m}`; collect(bad); } catch { /* egal */ } }
    // Ladezustaende der Greenbone-Anzeige
    try { renderGbProgress({ steps: [{ id: 'pull', label: 'Greenbone herunterladen' }, { id: 'sync', label: 'Tests laden' }], setup: { state: 'running', startedAt: new Date(Date.now() - 4e6).toISOString(), progress: { step: 'pull', done: 7, total: 19, size: '4,6 GB' } } }); where = 'Greenbone'; await wait(80); collect(bad); renderGbProgress({ steps: [], setup: {} }); } catch { /* egal */ }
  }

  // Echter, gespeicherter Lauf, damit Uebersicht und Verlauf Inhalte haben (ohne KI)
  stage = 'gespeicherter Lauf';
  try { await window.vigil.runAudit({ targets: [{ type: 'system', value: 'browserext' }] }); } catch { /* dann ohne */ }

  state.config.lang = 'de'; window.applyLanguage('de'); await wait(150);
  await sweep(isEnglish);
  const english = [...seen].map(([text, at]) => ({ text, at }));
  seen.clear();

  state.config.lang = 'en'; window.applyLanguage('en'); await wait(150);
  await sweep(DE);
  const german = [...seen].map(([text, at]) => ({ text, at }));

  // Literale aus dem Quelltext (Meldungen, die nur in seltenen Faellen erscheinen)
  state.config.lang = 'en'; window.applyLanguage('en'); await wait(50);
  // Beispiele mit echten Werten fuer Meldungen, die nur in seltenen Faellen erscheinen
  const SAMPLES = ['example.org wird nicht mehr automatisch vertraut', 'Bereit – 2 Ziele mit qwen.', '3 Ziele in der Prüfliste', '5 Befunde sind offen – über 2 Ziele. 1 behoben, 0 als Fehlalarm oder akzeptiert.', '4 offen seit Baseline', '2 behobene Befunde gelöscht', 'Beispiel-Lauf: 60 Befunde im Übungsprojekt', 'Prüfung fehlgeschlagen: x', 'Bedrohungsmodell nicht erstellt: x', 'Status nicht gespeichert: x', 'Prüfsummen weichen ab: x', 'Löschen fehlgeschlagen: x', 'Nach außen sichtbare IP: 1.2.3.4', '✕ Proxy nicht nutzbar: x', 'Gespeichert und signiert: x', 'Gruppieren: nach Datei', 'Version 7.80 ist veraltet', 'Wird automatisch aktualisiert, sobald du die Windows-Abfrage bestätigst. Ältere Versionen erkennen viele Dienste nicht mehr.', 'Zuletzt geprüft: 06.11.2026, 10:00 · Alles aktuell', 'Greenbone wird heruntergeladen …', '7 von 19 Paketen · 4,6 GB geladen', 'Heute: nicht gelaufen – x', 'Heute: 3 Befund(e), 1 neu', 'Keine Verbindung: x', 'Täglich, 03:00 Uhr'];
  const stat = SAMPLES.filter((s) => { const t = window.translateText(s); return t === s || /[äöüß]/i.test(t); });
  return { ok: true, results: [{ name: 'audit', ok: true, german, english, stat }] };
  })();
  const limit = new Promise((r) => setTimeout(() => r({ ok: false, results: [{ name: 'audit', ok: false, info: 'hängt bei: ' + stage }] }), 100000));
  return Promise.race([work, limit]);
})();
