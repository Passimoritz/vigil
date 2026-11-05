'use strict';

// Popup: aktuelle Adresse an die lokale Vigil-REST-API schicken (POST /api/inbox).
// Vigil fragt im Fenster nach, bevor das Ziel in die Pruefliste kommt – hier wird nichts geprueft.
const $ = (id) => document.getElementById(id);
const say = (t, kind) => { $('status').textContent = t; $('status').className = kind || ''; };

async function currentUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && tab.url ? tab.url : '';
}

async function settings() {
  const s = await chrome.storage.local.get({ port: 7811, token: '' });
  return { port: Math.min(65535, Math.max(1024, Number(s.port) || 7811)), token: String(s.token || '') };
}

(async () => {
  const url = await currentUrl();
  const okUrl = /^https?:\/\//i.test(url);
  $('url').textContent = okUrl ? url : 'This page cannot be checked (only http/https).';
  $('send').disabled = !okUrl;
  $('opts').onclick = (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); };
  $('send').onclick = async () => {
    const { port, token } = await settings();
    if (!token) { say('Enter the API token from Vigil (Settings → Advanced → Local REST API) first.', 'err'); return; }
    $('send').disabled = true; say('Sending …');
    try {
      const r = await fetch(`http://127.0.0.1:${port}/api/inbox`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ url }) });
      const j = await r.json().catch(() => ({}));
      if (r.status === 202) say(`Sent to Vigil: ${j.target || url}. Please confirm it in the app.`, 'ok');
      else if (r.status === 401) say('Token rejected – copy it again from Vigil.', 'err');
      else say(`Vigil answered ${r.status}: ${j.error || 'error'}`, 'err');
    } catch {
      say('Vigil is not reachable. Is the app running and the local REST API enabled?', 'err');
    } finally { $('send').disabled = false; }
  };
})();
