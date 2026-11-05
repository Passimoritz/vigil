'use strict';

// App-Sperre im Fenster: Sperrbildschirm (Overlay) und die Einstellungen unter
// Einstellungen → Erweitert → Gespeicherte Befunde. Die eigentliche Sperre sitzt im
// Main-Prozess (electron/applock.js): gesperrt beantwortet er keine Datenanfragen.
(() => {
  const api = window.vigil && window.vigil.appLock;
  if (!api) return;
  let overlay = null;
  let lockedAtLoad = false;

  const el = (tag, css, text) => { const e = document.createElement(tag); if (css) e.style.cssText = css; if (text != null) e.textContent = text; return e; };

  function showOverlay(st) {
    if (overlay) return;
    overlay = el('div', 'position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;background:rgba(6,9,14,.97);');
    overlay.id = 'appLockOverlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    const box = el('div', 'width:min(360px,90vw);padding:28px;border-radius:14px;background:#111722;border:1px solid #263042;color:#e6e9ef;font:14px "Segoe UI",sans-serif;display:flex;flex-direction:column;gap:12px;');
    const h = el('h2', 'margin:0;font-size:18px;', 'Vigil ist gesperrt');
    const p = el('p', 'margin:0;color:#8b919d;', 'Passwort eingeben, um fortzufahren.');
    const input = el('input', 'padding:9px 10px;border-radius:8px;border:1px solid #2c3648;background:#0a0e15;color:inherit;font:inherit;');
    input.type = 'password'; input.id = 'appLockPw'; input.autocomplete = 'current-password'; input.setAttribute('aria-label', 'Passwort');
    const msg = el('div', 'min-height:18px;color:#f87171;font-size:13px;'); msg.setAttribute('aria-live', 'polite');
    const btn = el('button', 'padding:9px;border-radius:8px;border:0;background:#f2b23a;color:#111;font:600 14px "Segoe UI",sans-serif;cursor:pointer;', 'Entsperren');
    btn.type = 'button'; btn.id = 'appLockBtn';
    const go = async () => {
      btn.disabled = true;
      try {
        const r = await api.unlock(input.value);
        if (r && r.ok) return unlocked();
        msg.textContent = (r && r.error) || 'Falsches Passwort.';
        input.value = '';
      } finally { btn.disabled = false; input.focus(); }
    };
    btn.onclick = go;
    input.onkeydown = (e) => { if (e.key === 'Enter') go(); };
    box.append(h, p, input, msg, btn);
    if (st && st.biometric) {
      const bio = el('button', 'padding:8px;border-radius:8px;border:1px solid #2c3648;background:none;color:inherit;font:inherit;cursor:pointer;', 'Mit Touch ID entsperren');
      bio.type = 'button';
      bio.onclick = async () => { const r = await api.biometric(); if (r && r.ok) unlocked(); };
      box.append(bio);
    }
    overlay.append(box);
    document.body.append(overlay);
    setTimeout(() => input.focus(), 30);
  }
  function unlocked() {
    if (overlay) { overlay.remove(); overlay = null; }
    // Beim Start gesperrt: die Oberflaeche konnte noch keine Daten laden -> neu laden
    if (lockedAtLoad) { lockedAtLoad = false; location.reload(); }
  }

  // --- Einstellungen -------------------------------------------------------
  function renderSettings(st) {
    const host = document.getElementById('appLockBox');
    if (!host) return;
    host.textContent = '';
    const row = el('div'); row.className = 'set-row';
    const label = el('div'); label.className = 'set-label';
    label.append(el('b', null, 'App-Sperre'), el('span', null, 'Beim Start und nach Leerlauf ein Passwort verlangen. Gespeichert wird nur ein scrypt-Hash.'));
    row.append(label);
    const form = el('div', 'display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:6px;');
    const mk = (id, ph, type = 'password') => { const i = el('input'); i.type = type; i.id = id; i.placeholder = ph; i.setAttribute('aria-label', ph); i.style.cssText = 'max-width:220px;'; return i; };
    const cur = mk('alCurrent', 'Aktuelles Passwort');
    const pw = mk('alNew', st.enabled ? 'Neues Passwort (leer = unverändert)' : 'Neues Passwort');
    const idle = mk('alIdle', 'Minuten Leerlauf (0 = nur beim Start)', 'number');
    idle.min = '0'; idle.max = '240'; idle.value = String(st.idleMinutes ?? 10); idle.style.cssText = 'max-width:120px;';
    idle.title = 'Sperren nach Minuten Leerlauf (0 = nur beim Start)';
    const status = el('span'); status.className = 'hint'; status.id = 'alStatus';
    status.textContent = st.enabled ? '✓ App-Sperre aktiv.' : 'App-Sperre aus.';
    const save = el('button', null, st.enabled ? 'Speichern' : 'Sperre einschalten'); save.type = 'button'; save.className = 'btn tiny'; save.id = 'alSave';
    const done = (r) => { status.textContent = r && r.ok ? 'Gespeichert.' : ((r && r.error) || 'Nicht gespeichert.'); if (r && r.ok) setTimeout(refresh, 900); };
    save.onclick = async () => done(await api.configure({ current: cur.value, password: pw.value, idleMinutes: Number(idle.value), enabled: true }));
    if (st.enabled) form.append(cur);
    form.append(pw, idle, save);
    if (st.enabled) {
      const off = el('button', null, 'Sperre ausschalten'); off.type = 'button'; off.className = 'btn tiny'; off.id = 'alOff';
      off.onclick = async () => done(await api.configure({ current: cur.value, enabled: false, idleMinutes: Number(idle.value) }));
      const now = el('button', null, 'Jetzt sperren'); now.type = 'button'; now.className = 'btn tiny'; now.id = 'alLockNow';
      now.onclick = () => api.lock();
      form.append(off, now);
    }
    form.append(status);
    host.append(row, form);
  }
  async function refresh() {
    try { renderSettings(await api.status()); } catch { /* Fenster wird geschlossen */ }
    try {
      const enc = window.vigil.dataEncryption ? await window.vigil.dataEncryption() : null;
      const info = document.getElementById('encInfo');
      if (info && enc && !enc.locked) info.textContent = enc.encrypted ? '✓ Befunde und Verlauf werden verschlüsselt gespeichert (AES-256-GCM, Schlüssel durch Windows geschützt).' : 'Befunde und Verlauf liegen unverschlüsselt vor – die Schlüsselverwaltung des Systems ist nicht verfügbar.';
    } catch { /* egal */ }
  }

  api.onState((s) => { if (s && s.locked) api.status().then(showOverlay); else unlocked(); });
  const start = async () => {
    const st = await api.status();
    if (st && st.locked) { lockedAtLoad = true; showOverlay(st); } else refresh();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
