'use strict';

// Einstellungen der Erweiterung: Port und API-Token der lokalen Vigil-REST-API (nur lokal gespeichert)
const $ = (id) => document.getElementById(id);
(async () => {
  const s = await chrome.storage.local.get({ port: 7811, token: '' });
  $('port').value = s.port; $('token').value = s.token;
  $('save').onclick = async () => {
    const port = Math.min(65535, Math.max(1024, Number($('port').value) || 7811));
    await chrome.storage.local.set({ port, token: $('token').value.trim() });
    $('status').textContent = 'Saved.';
  };
})();
