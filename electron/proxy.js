'use strict';

// Leitet alle ausgehenden fetch-Anfragen (KI-Anbieter, OSV, Web-Checks) ueber
// einen vom Nutzer gesetzten Proxy/VPN um. Dann sieht das Ziel die IP des
// Proxys, nicht die des Nutzers. Unterstuetzt http(s)- und socks4/5-Proxys.

const { setGlobalDispatcher, getGlobalDispatcher, ProxyAgent, Agent, buildConnector } = require('undici');

// Ursprungs-Dispatcher merken, um den Proxy wieder abschalten zu koennen.
const DIRECT = getGlobalDispatcher();

// Baut einen undici-Dispatcher fuer eine SOCKS-Verbindung (z. B. Tor 127.0.0.1:9050).
function socksDispatcher(u) {
  const { SocksClient } = require('socks'); // ist als Abhaengigkeit vorhanden
  const type = u.protocol === 'socks4:' ? 4 : 5;
  const tlsConnect = buildConnector({}); // uebernimmt bei https das TLS-Upgrade
  return new Agent({
    connect: async (opts, cb) => {
      try {
        const { socket } = await SocksClient.createConnection({
          proxy: {
            host: u.hostname,
            port: Number(u.port) || 1080,
            type,
            userId: u.username ? decodeURIComponent(u.username) : undefined,
            password: u.password ? decodeURIComponent(u.password) : undefined,
          },
          command: 'connect',
          destination: {
            host: opts.hostname,
            port: Number(opts.port) || (opts.protocol === 'https:' ? 443 : 80),
          },
          timeout: 15000,
        });
        // Vorhandenen SOCKS-Socket an undici uebergeben (TLS nur bei https).
        tlsConnect({ ...opts, httpSocket: socket }, cb);
      } catch (err) {
        cb(err);
      }
    },
  });
}

// Baut den passenden Dispatcher aus einer Proxy-URL (leer -> Direktverbindung).
function dispatcherFor(proxyUrl) {
  const raw = String(proxyUrl || '').trim();
  if (!raw) return DIRECT;
  let u;
  try { u = new URL(raw); } catch { throw new Error('Proxy-Adresse ist keine gültige URL (z. B. http://host:3128 oder socks5://127.0.0.1:9050).'); }
  const p = u.protocol;
  if (p === 'http:' || p === 'https:') return new ProxyAgent({ uri: raw });
  if (p === 'socks:' || p === 'socks5:' || p === 'socks5h:' || p === 'socks4:' || p === 'socks4a:') return socksDispatcher(u);
  throw new Error('Nicht unterstützter Proxy-Typ „' + p.replace(':', '') + '". Erlaubt: http, https, socks4, socks5.');
}

let activeUrl = '';

// Proxy anwenden (global fuer alle fetch-Aufrufe dieses Prozesses).
function applyProxy(proxyUrl) {
  const d = dispatcherFor(proxyUrl);
  setGlobalDispatcher(d);
  activeUrl = String(proxyUrl || '').trim();
  return activeUrl;
}

// Testet die Proxy-URL und meldet die nach aussen sichtbare IP zurueck.
// Setzt den vorher aktiven Proxy danach wieder.
async function testProxy(proxyUrl) {
  const prev = activeUrl;
  try {
    applyProxy(proxyUrl); // wirft bei ungueltiger URL / Typ
    const res = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(12000) });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const j = await res.json();
    return { ok: true, ip: j.ip, usingProxy: !!String(proxyUrl || '').trim() };
  } catch (e) {
    const cause = (e && e.cause && (e.cause.code || e.cause.message)) || e.message;
    return { ok: false, error: String(cause) };
  } finally {
    try { applyProxy(prev); } catch { setGlobalDispatcher(DIRECT); }
  }
}

module.exports = { applyProxy, testProxy, dispatcherFor };
