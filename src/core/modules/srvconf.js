'use strict';

// Webserver-Konfigurationen im Repository: nginx, Apache (inkl. .htaccess) und Caddy.
// Geprueft werden alte TLS-Versionen, schwache Chiffren, Verzeichnislisten, Versions-Banner und
// fehlende Sicherheits-Header. Rein statisch – es wird kein Server angesprochen.

const { base, fileName, mk, isText } = require('./rulekit');

const M = 'webserver-config-audit';

function kindOf(u) {
  const n = fileName(u);
  const p = base(u);
  const c = u.content || '';
  if (n === 'caddyfile' || /\.caddyfile$/i.test(n)) return 'caddy';
  if (n === '.htaccess' || n === 'httpd.conf' || n === 'apache2.conf' || /(^|\/)(apache2?|httpd)\//i.test(p) && /\.conf$/i.test(n)) return 'apache';
  if (/\.conf$|(^|\/)sites-(available|enabled)\//i.test(p) || n === 'nginx.conf') {
    if (/<VirtualHost\b|^\s*(ServerName|DocumentRoot|SSLProtocol|ServerTokens)\b/im.test(c)) return 'apache';
    if (/^\s*(server|http)\s*\{/m.test(c) && /^\s*(listen|server_name|location|root|proxy_pass)\b/m.test(c)) return 'nginx';
  }
  return null;
}

const OLD_TLS = { nginx: /^\s*ssl_protocols\s+([^;]+);/gm, apache: /^\s*SSLProtocol\s+(.+)$/gim, caddy: /^\s*protocols\s+(tls1\.[01])\b(.*)$/gim };
const has = (c, re) => re.test(c);

function headerCheck(u, kind, out) {
  const c = u.content;
  // Nur dort, wo dieser Server Antworten ausliefert (TLS-Server bzw. Site-Block)
  const tlsSite = kind === 'nginx' ? /^\s*listen\s+[^;]*\b443\b|^\s*ssl_certificate\s/m.test(c)
    : kind === 'apache' ? /<VirtualHost[^>]*:443>|^\s*SSLEngine\s+on/im.test(c)
      : /^\s*[\w.*-]+\.[a-z]{2,}(:\d+)?[\s,{]/m.test(c);
  if (!tlsSite) return;
  const H = kind === 'nginx' ? (h) => new RegExp(`add_header\\s+["']?${h}`, 'i') : kind === 'apache' ? (h) => new RegExp(`Header\\s+(always\\s+)?(set|append|merge)\\s+["']?${h}`, 'i') : (h) => new RegExp(`^\\s*(header\\s+)?["']?\\+?${h}\\b`, 'im');
  const missing = ['Strict-Transport-Security', 'X-Content-Type-Options', 'Content-Security-Policy', 'X-Frame-Options'].filter((h) => !(h === 'X-Frame-Options' && /frame-ancestors/i.test(c)) && !has(c, H(h)));
  if (!missing.length) return;
  out.push(mk(M, u, null, {
    ruleId: `${kind}-missing-headers`, severity: 'low', category: 'Config',
    title: `Sicherheits-Header fehlen in der Server-Konfiguration: ${missing.join(', ')}`,
    description: 'Die Konfiguration setzt diese Header nicht. Falls auch die Anwendung sie nicht setzt, fehlen Schutzschichten gegen Downgrade auf HTTP, Clickjacking und eingeschleuste Skripte.',
    remediation: kind === 'nginx' ? 'Im server-Block ergänzen, z. B.: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always; add_header X-Content-Type-Options nosniff always;'
      : kind === 'apache' ? 'In der VirtualHost ergänzen, z. B.: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" (mod_headers aktivieren).'
        : 'Im Site-Block ergänzen: header { Strict-Transport-Security "max-age=31536000; includeSubDomains" X-Content-Type-Options nosniff }',
    evidence: missing.join(', '),
  }));
}

function scan(u, kind, out) {
  const c = u.content;
  const push = (ruleId, severity, category, idx, title, description, remediation, evidence) => out.push(mk(M, u, idx, { ruleId, severity, category, title, description, remediation, ...(evidence ? { evidence } : {}), confidence: 'high' }));
  // Alte TLS-Versionen
  const re = OLD_TLS[kind]; re.lastIndex = 0; let m;
  while ((m = re.exec(c))) {
    const v = m[1];
    const bad = kind === 'nginx' ? v.split(/\s+/).filter((t) => /^(SSLv2|SSLv3|TLSv1|TLSv1\.1)$/.test(t))
      : kind === 'apache' ? [...v.split(/\s+/).filter((t) => /^\+?(SSLv2|SSLv3|TLSv1|TLSv1\.1)$/.test(t)).map((t) => t.replace('+', '')), ...(/(^|\s)\+?all\b/i.test(v) && !/-TLSv1(\s|$)/.test(v) ? ['all (inkl. TLSv1/TLSv1.1)'] : [])]
        : [m[1]];
    if (bad.length) push(`${kind}-old-tls`, 'high', 'Transport', m.index, `Veraltete TLS-Versionen erlaubt: ${bad.join(', ')}`, 'SSLv3, TLS 1.0 und TLS 1.1 gelten als unsicher und werden von aktuellen Browsern nicht mehr benötigt. Angreifer können Verbindungen auf diese Versionen herunterhandeln.', kind === 'nginx' ? 'ssl_protocols TLSv1.2 TLSv1.3;' : kind === 'apache' ? 'SSLProtocol -all +TLSv1.2 +TLSv1.3' : 'Die protocols-Zeile entfernen (Caddy nutzt standardmäßig TLS 1.2 und 1.3) oder protocols tls1.2 tls1.3 setzen.', m[0].trim().slice(0, 160));
  }
  // Schwache Chiffren (nur aktiv erlaubte, nicht per ! oder - ausgeschlossene)
  const cre = kind === 'nginx' ? /^\s*ssl_ciphers\s+["']?([^;"']+)/gm : kind === 'apache' ? /^\s*SSLCipherSuite\s+(?:SSL\s+|TLSv1\.3\s+)?["']?([^\n"']+)/gim : null;
  if (cre) while ((m = cre.exec(c))) {
    const weak = m[1].split(/[:\s]+/).filter((t) => t && !/^[!-]/.test(t) && /RC4|3DES|DES-CBC|\bDES\b|EXPORT|NULL|MD5|aNULL|eNULL|ADH|AECDH/i.test(t));
    if (weak.length) push(`${kind}-weak-ciphers`, 'medium', 'Crypto', m.index, `Schwache TLS-Chiffren erlaubt: ${weak.slice(0, 4).join(', ')}`, 'Diese Verfahren sind gebrochen oder ohne Authentisierung. Mit ihnen lässt sich verschlüsselter Verkehr unter Umständen entschlüsseln.', 'Eine aktuelle Chiffren-Liste verwenden (z. B. aus dem Mozilla SSL Configuration Generator, Profil „intermediate“).', m[0].trim().slice(0, 160));
  }
  if (kind === 'nginx') {
    const ai = c.search(/(^|[{;\s])autoindex\s+on\s*;/m);
    if (ai >= 0) push('nginx-autoindex', 'medium', 'Config', ai, 'Verzeichnislisten eingeschaltet (nginx autoindex on)', 'Für Ordner ohne Startseite zeigt der Server alle enthaltenen Dateien an – oft auch Backups, Logs oder Konfigurationsdateien.', 'autoindex off; setzen bzw. die Zeile entfernen.');
    const st = c.search(/^\s*server_tokens\s+on\s*;/m);
    if (st >= 0 || (/^\s*http\s*\{/m.test(c) && !/^\s*server_tokens\s+off\s*;/m.test(c))) push('nginx-server-tokens', 'low', 'Config', st, 'nginx verrät seine Versionsnummer (server_tokens)', 'Ohne server_tokens off steht die genaue nginx-Version im Server-Header und auf Fehlerseiten. Angreifer sehen so, welche bekannten Lücken sie ausprobieren können.', 'Im http-Block server_tokens off; setzen.');
  }
  if (kind === 'apache') {
    const idx = c.search(/^\s*Options\s+[^\n]*(?<![-\w])\+?Indexes\b/im);
    if (idx >= 0) push('apache-dir-listing', 'medium', 'Config', idx, 'Verzeichnislisten eingeschaltet (Apache Options Indexes)', 'Für Ordner ohne Startseite zeigt der Server alle enthaltenen Dateien an – oft auch Backups, Logs oder Konfigurationsdateien.', 'Options -Indexes setzen.');
    const tok = c.search(/^\s*ServerTokens\s+(Full|OS|Major|Minor|Min(imal)?)\b|^\s*ServerSignature\s+On\b/im);
    if (tok >= 0) push('apache-server-tokens', 'low', 'Config', tok, 'Apache verrät Version und System (ServerTokens/ServerSignature)', 'Die genaue Apache-Version und das Betriebssystem stehen im Server-Header bzw. auf Fehlerseiten. Angreifer sehen so, welche bekannten Lücken sie ausprobieren können.', 'ServerTokens Prod und ServerSignature Off setzen.');
    const tr = c.search(/^\s*TraceEnable\s+On\b/im);
    if (tr >= 0) push('apache-trace-enabled', 'low', 'Config', tr, 'HTTP-Methode TRACE erlaubt (Apache)', 'TRACE spiegelt die Anfrage samt Headern zurück. Zusammen mit anderen Fehlern lassen sich so Cookies auslesen (Cross-Site Tracing).', 'TraceEnable Off setzen.');
  }
  if (kind === 'caddy') {
    const br = c.search(/^\s*file_server\s+browse\b|^\s*browse\b/m);
    if (br >= 0) push('caddy-dir-listing', 'medium', 'Config', br, 'Verzeichnislisten eingeschaltet (Caddy file_server browse)', 'Für Ordner ohne Startseite zeigt der Server alle enthaltenen Dateien an – oft auch Backups, Logs oder Konfigurationsdateien.', 'file_server ohne browse verwenden.');
  }
  headerCheck(u, kind, out);
}

function runSrvConf(units) {
  const out = [];
  for (const u of units) {
    if (!isText(u)) continue;
    const kind = kindOf(u);
    if (kind) scan(u, kind, out);
  }
  return out;
}

module.exports = { runSrvConf, kindOf };
