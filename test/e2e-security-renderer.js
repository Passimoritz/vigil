// Laeuft IM App-Fenster (executeJavaScript): App-Sperre und Verschluesselung von aussen pruefen.
// Ergebnis: { ok, results: [{ name, ok, info }] }
(async () => {
  const results = [];
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const t = async (name, fn) => { try { const r = await fn(); results.push({ name, ok: r === true || r === undefined, info: typeof r === 'string' ? r : '' }); } catch (e) { results.push({ name, ok: false, info: e.message }); } };
  const L = window.vigil.appLock;
  const until = async (fn, ms = 6000) => { const s = Date.now(); while (Date.now() - s < ms) { try { if (fn()) return true; } catch { /* weiter */ } await wait(80); } return false; };
  await until(() => window.state && state.config);

  await t('App-Sperre: standardmäßig aus', async () => { const s = await L.status(); return (!s.enabled && !s.locked) || JSON.stringify(s); });
  await t('App-Sperre: zu kurzes Passwort abgelehnt', async () => { const r = await L.configure({ password: 'kurz', idleMinutes: 5 }); return (!r.ok && /mindestens/.test(r.error)) || JSON.stringify(r); });
  await t('App-Sperre: einschalten', async () => { const r = await L.configure({ password: 'geheim-123', idleMinutes: 5 }); const s = await L.status(); return (r.ok && s.enabled && s.idleMinutes === 5) || JSON.stringify(r); });
  await t('App-Sperre: Passwort-Hash erreicht das Fenster nicht', async () => { const c = await window.vigil.getConfig(); return (c.appLock && c.appLock.enabled && !c.appLock.secret && !JSON.stringify(c).includes('scrypt')) || JSON.stringify(c.appLock); });
  await t('App-Sperre: Speichern der Einstellungen schaltet sie nicht ab', async () => { const c = await window.vigil.getConfig(); c.appLock = { enabled: false }; await window.vigil.saveConfig(c); return (await L.status()).enabled || 'abgeschaltet'; });
  await t('App-Sperre: gesperrt blockiert der Main-Prozess Datenanfragen', async () => {
    await L.lock();
    const d = await window.vigil.dashboard({});
    const ov = await until(() => document.getElementById('appLockOverlay'), 2000);
    return (d && d.locked && ov) || 'nicht gesperrt: ' + JSON.stringify(d).slice(0, 80);
  });
  await t('App-Sperre: falsches Passwort bleibt gesperrt', async () => { const r = await L.unlock('falsch-123'); return (!r.ok && (await L.status()).locked) || JSON.stringify(r); });
  await t('App-Sperre: richtiges Passwort entsperrt', async () => {
    const r = await L.unlock('geheim-123');
    const d = await window.vigil.dashboard({});
    const gone = await until(() => !document.getElementById('appLockOverlay'), 2000);
    return (r.ok && d && d.stats && gone) || JSON.stringify(r);
  });
  await t('App-Sperre: Ausschalten nur mit aktuellem Passwort', async () => {
    const bad = await L.configure({ enabled: false, current: 'falsch' });
    const good = await L.configure({ enabled: false, current: 'geheim-123' });
    return (!bad.ok && good.ok && !(await L.status()).enabled) || JSON.stringify({ bad, good });
  });
  await t('Verschlüsselung: im Fenster als aktiv gemeldet', async () => { const e = await window.vigil.dataEncryption(); return e.encrypted || 'nicht verschlüsselt'; });
  return { ok: results.every((r) => r.ok), results };
})();
