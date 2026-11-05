'use strict';

// E-Mails pruefen (.eml = MIME, .msg = Outlook/OLE): Absender gegen Antwortadresse, gefaelschte
// Anzeigenamen, fehlgeschlagene SPF/DKIM/DMARC-Pruefung, Links, deren Text eine andere Adresse
// zeigt als das echte Ziel, und gefaehrliche Anhaenge. Anhaenge gibt der Aufrufer (ingest.js) an
// die normale Datei-Pruefung weiter. Nichts wird geoeffnet, kein Link wird aufgerufen.

const path = require('path');
const { normalizeFinding } = require('./schema');
const { readCfb } = require('./cfb');

const MAX_PARTS = 300;
const MAX_ATTACH = 60;

// --- MIME --------------------------------------------------------------------------------------
function decodeCharset(buf, charset) {
  const cs = String(charset || 'utf-8').toLowerCase().replace(/^"|"$/g, '');
  if (/^(us-ascii|ascii|utf-?8)$/.test(cs)) return buf.toString('utf8');
  if (/^(iso-8859-1|latin1|windows-1252|cp1252)$/.test(cs)) return buf.toString('latin1');
  try { return new TextDecoder(cs).decode(buf); } catch { return buf.toString('utf8'); }
}
const qpDecode = (s) => Buffer.from(String(s).replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
// RFC 2047: =?utf-8?B?…?= bzw. =?iso-8859-1?Q?…?=
function decodeWords(s) {
  return String(s || '').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=(\s+(?==\?))?/gi, (m, cs, enc, txt) => {
    try { const b = enc.toLowerCase() === 'b' ? Buffer.from(txt, 'base64') : qpDecode(txt.replace(/_/g, ' ')); return decodeCharset(b, cs); } catch { return m; }
  });
}
function parseHeaders(text) {
  const map = {};
  const unfolded = String(text).replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const m = line.match(/^([!-9;-~]+):\s*(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase();
    (map[k] = map[k] || []).push(m[2]);
  }
  return map;
}
const h1 = (h, k) => (h[k] && h[k][0]) || '';
function param(value, name) {
  const v = String(value || '');
  const star = v.match(new RegExp(`${name}\\*=([^;]+)`, 'i'));
  if (star) { const m = star[1].trim().match(/^([^']*)'[^']*'(.*)$/); try { return m ? decodeCharset(Buffer.from(decodeURIComponent(m[2]), 'latin1'), m[1]) : star[1]; } catch { return star[1]; } }
  const m = v.match(new RegExp(`${name}\\s*=\\s*("([^"]*)"|[^;\\s]+)`, 'i'));
  return m ? decodeWords(m[2] != null ? m[2] : m[1]) : '';
}

function splitHeadBody(buf) {
  const s = buf.toString('latin1');
  const m = s.match(/\r?\n\r?\n/);
  if (!m) return { head: s, body: Buffer.alloc(0) };
  return { head: s.slice(0, m.index), body: buf.subarray(Buffer.byteLength(s.slice(0, m.index + m[0].length), 'latin1')) };
}

function parseEml(buf) {
  const mail = { headers: {}, text: [], html: [], attachments: [] };
  let parts = 0;
  const walk = (b, depth, top) => {
    if (parts++ > MAX_PARTS || depth > 6) return;
    const { head, body } = splitHeadBody(b);
    const h = parseHeaders(head);
    if (top) mail.headers = h;
    const ct = h1(h, 'content-type') || 'text/plain';
    const type = ct.split(';')[0].trim().toLowerCase();
    const cte = h1(h, 'content-transfer-encoding').trim().toLowerCase();
    const disp = h1(h, 'content-disposition');
    if (/^multipart\//.test(type)) {
      const boundary = param(ct, 'boundary');
      if (!boundary) return;
      const s = body.toString('latin1');
      const sep = '--' + boundary;
      const chunks = s.split(sep).slice(1);
      for (const c of chunks) {
        if (c.startsWith('--')) break;
        walk(Buffer.from(c.replace(/^\r?\n/, '').replace(/\r?\n$/, ''), 'latin1'), depth + 1, false);
      }
      return;
    }
    let data = body;
    if (cte === 'base64') data = Buffer.from(body.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
    else if (cte === 'quoted-printable') data = qpDecode(body.toString('latin1'));
    const filename = param(disp, 'filename') || param(ct, 'name');
    if (type === 'message/rfc822' && !filename) { walk(data, depth + 1, false); return; }
    if (filename || /^attachment/i.test(disp) || !/^text\//.test(type)) {
      if (mail.attachments.length < MAX_ATTACH) mail.attachments.push({ name: filename || `anhang-${mail.attachments.length + 1}`, contentType: type, data });
      return;
    }
    const txt = decodeCharset(data, param(ct, 'charset'));
    (type === 'text/html' ? mail.html : mail.text).push(txt.slice(0, 2 * 1024 * 1024));
  };
  walk(buf, 0, true);
  return mail;
}

// --- Outlook .msg -------------------------------------------------------------------------------
function parseMsg(buf) {
  const s = readCfb(buf);
  if (!s) return null;
  const prop = (prefix, id) => {
    const u = s[`${prefix}__substg1.0_${id}001F`];
    if (u) return u.toString('utf16le').replace(/\0+$/, '');
    const a = s[`${prefix}__substg1.0_${id}001E`];
    return a ? a.toString('latin1').replace(/\0+$/, '') : '';
  };
  const bin = (prefix, id) => s[`${prefix}__substg1.0_${id}0102`] || null;
  const transport = prop('', '007D');
  const headers = transport ? parseHeaders(transport) : {};
  const senderName = prop('', '0C1A'), senderAddr = prop('', '5D01') || prop('', '0C1F') || prop('', '0065');
  if (!headers.from && (senderName || senderAddr)) headers.from = [`${senderName ? `"${senderName}" ` : ''}<${senderAddr}>`];
  if (!headers.subject) headers.subject = [prop('', '0037')];
  const mail = { headers, text: [], html: [], attachments: [] };
  const body = prop('', '1000');
  if (body) mail.text.push(body);
  const html = bin('', '1013') || null;
  if (html) mail.html.push(html.toString('utf8'));
  else { const h = prop('', '1013'); if (h) mail.html.push(h); }
  const prefixes = [...new Set(Object.keys(s).map((k) => (k.match(/^(__attach_version1\.0_#[0-9A-F]{8})\//i) || [])[1]).filter(Boolean))];
  for (const p of prefixes.slice(0, MAX_ATTACH)) {
    const data = bin(`${p}/`, '3701');
    if (!data) continue;
    mail.attachments.push({ name: prop(`${p}/`, '3707') || prop(`${p}/`, '3704') || 'anhang', contentType: prop(`${p}/`, '370E'), data });
  }
  return mail;
}

// --- Pruefung ----------------------------------------------------------------------------------
function parseAddress(v) {
  const s = decodeWords(String(v || '')).trim();
  const m = s.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>/);
  const addr = (m ? m[2] : (s.match(/[^\s<>"]+@[^\s<>"]+/) || [''])[0]).trim().toLowerCase();
  return { name: m ? m[1].trim() : '', addr, domain: (addr.split('@')[1] || '').replace(/[>\s]+$/, '') };
}
// grobe "registrierbare Domain": letzte zwei Teile (drei bei co.uk, com.au …)
function baseDomain(host) {
  const p = String(host || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (p.length <= 2) return p.join('.');
  const two = p.slice(-2).join('.');
  return /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/.test(two) ? p.slice(-3).join('.') : two;
}
const BRANDS = ['paypal', 'microsoft', 'office365', 'outlook', 'apple', 'icloud', 'amazon', 'google', 'dhl', 'ups', 'fedex', 'netflix', 'sparkasse', 'volksbank', 'commerzbank', 'deutsche bank', 'postbank', 'ing', 'n26', 'telekom', 'vodafone', '1&1', 'ebay', 'dropbox', 'docusign', 'adobe', 'linkedin', 'facebook', 'instagram', 'whatsapp', 'elster', 'finanzamt'];
const DANGEROUS_ATTACH = /\.(exe|scr|com|pif|cpl|msi|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|jar|iso|img|vhd|vhdx|reg|chm|url|library-ms|search-ms|appx|msix|one)$/i;

function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } }
function stripTags(s) { return String(s).replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim(); }
function decodeEntities(s) { return String(s).replace(/&amp;/g, '&').replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCharCode(parseInt(h, 16))).replace(/&#(\d+);/g, (m, d) => String.fromCharCode(Number(d))); }

function extractLinks(mail) {
  const links = [];
  for (const html of mail.html) {
    for (const m of html.matchAll(/<a\b[^>]*?\bhref\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi)) {
      if (links.length > 500) break;
      links.push({ href: decodeEntities(m[2]).trim(), text: stripTags(m[3]).slice(0, 200) });
    }
  }
  for (const t of [...mail.text, ...mail.html.map(stripTags)]) for (const m of t.matchAll(/https?:\/\/[^\s"'<>)\]]+/gi)) if (links.length < 800) links.push({ href: m[0].replace(/[.,;:]+$/, ''), text: '' });
  return links.filter((l) => /^https?:\/\//i.test(l.href));
}

function analyzeMail(mail, label) {
  const out = [];
  const where = String(label).replace(/\\/g, '/');
  const F = (o) => out.push(normalizeFinding({ category: 'Other', confidence: 'medium', sourceModule: 'mail-audit', location: where, ...o }, 'mail-audit'));
  const h = mail.headers || {};
  const from = parseAddress(h1(h, 'from'));
  const reply = parseAddress(h1(h, 'reply-to'));
  if (from.domain && reply.domain && baseDomain(from.domain) !== baseDomain(reply.domain)) F({
    ruleId: 'mail-replyto-mismatch', severity: 'medium',
    title: `Antworten gehen an eine fremde Domain: ${reply.domain}`,
    description: `Die E-Mail kommt angeblich von ${from.addr}, Antworten gehen aber an ${reply.addr}. So leiten Betrüger Antworten auf Rechnungs- oder Chef-Mails („CEO-Fraud“) zu sich um.`,
    remediation: 'Nicht auf „Antworten“ klicken; den Absender über einen bekannten Weg (Telefon, eigene Adressliste) kontaktieren.',
  });
  // Anzeigename enthaelt eine andere Adresse/Domain oder eine bekannte Marke
  const shown = from.name.toLowerCase();
  const shownAddr = (shown.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/) || [])[1] || (shown.match(/\b([a-z0-9-]+\.(?:com|de|net|org|io|eu|at|ch))\b/) || [])[1];
  const brand = BRANDS.find((b) => new RegExp(`(^|[^a-z])${b.replace(/[.*+?^${}()|[\]\\&]/g, '\\$&')}([^a-z]|$)`).test(shown));
  if (from.domain && shownAddr && baseDomain(shownAddr) !== baseDomain(from.domain)) F({
    ruleId: 'mail-display-name-spoof', severity: 'high', confidence: 'high',
    title: `Gefälschter Absendername: „${from.name.slice(0, 80)}“`,
    description: `Im Anzeigenamen steht ${shownAddr}, die tatsächliche Absenderadresse ist aber ${from.addr}. Viele Mail-Programme zeigen nur den Namen – so sieht die Mail aus, als käme sie von jemand anderem.`,
    remediation: 'Die Mail als Phishing behandeln: keine Links anklicken, keine Anhänge öffnen.',
  });
  else if (from.domain && brand && !baseDomain(from.domain).replace(/[^a-z0-9]/g, '').includes(brand.replace(/[^a-z0-9]/g, ''))) F({
    ruleId: 'mail-brand-impersonation', severity: 'medium',
    title: `Absendername nennt „${brand}“, Adresse passt nicht: ${from.domain}`,
    description: `Der Anzeigename „${from.name.slice(0, 80)}“ erweckt den Eindruck einer bekannten Firma, die Mail kommt aber von ${from.addr}.`,
    remediation: 'Nicht auf Links klicken; die Firma direkt über ihre bekannte Webseite kontaktieren.',
  });
  // SPF/DKIM/DMARC laut Empfangsserver
  const auth = (h['authentication-results'] || []).join(' ').toLowerCase();
  const failed = ['spf', 'dkim', 'dmarc'].filter((k) => new RegExp(`\\b${k}=(fail|softfail|permerror)`).test(auth));
  if (failed.length) F({
    ruleId: 'mail-auth-failed', severity: failed.includes('dmarc') ? 'high' : 'medium', confidence: 'high',
    title: `Absender-Prüfung fehlgeschlagen: ${failed.map((x) => x.toUpperCase()).join(', ')}`,
    description: `Der empfangende Mailserver hat vermerkt, dass ${failed.map((x) => x.toUpperCase()).join(', ')} für diese Mail fehlgeschlagen ist. Die Mail stammt dann sehr wahrscheinlich nicht vom angegebenen Absender.`,
    remediation: 'Als Fälschung behandeln. Für die eigene Domain SPF, DKIM und DMARC korrekt einrichten.',
  });
  // Links: sichtbarer Text zeigt eine andere Domain als das echte Ziel
  const links = extractLinks(mail);
  const mism = links.filter((l) => { const shownHost = hostOf(/^https?:\/\//i.test(l.text) ? l.text : /^[\w-]+(\.[\w-]+)+(\/|$)/.test(l.text) ? 'https://' + l.text : ''); return shownHost && hostOf(l.href) && baseDomain(shownHost) !== baseDomain(hostOf(l.href)); });
  if (mism.length) F({
    ruleId: 'mail-link-mismatch', severity: 'high', confidence: 'high',
    title: `Link zeigt eine andere Adresse als sein echtes Ziel (${mism.length})`,
    description: `Angezeigt wird z. B. „${mism[0].text.slice(0, 80)}“, der Link führt aber zu ${hostOf(mism[0].href)}. Das ist ein klassischer Phishing-Trick.`,
    remediation: 'Link nicht anklicken. Die Seite lieber selbst über die bekannte Adresse aufrufen.',
  });
  const ipLinks = links.filter((l) => /^\d{1,3}(\.\d{1,3}){3}$|^\[/.test(hostOf(l.href)));
  const puny = links.filter((l) => /(^|\.)xn--/.test(hostOf(l.href)));
  if (ipLinks.length || puny.length) F({
    ruleId: 'mail-suspicious-link-host', severity: 'medium',
    title: 'Links auf IP-Adressen bzw. verwechselbare Domains',
    description: `Links zu nackten IP-Adressen oder internationalisierten Domains (Punycode), die einer bekannten Adresse ähneln können: ${[...new Set([...ipLinks, ...puny].map((l) => hostOf(l.href)))].slice(0, 5).join(', ')}.`,
    remediation: 'Links nicht anklicken; seriöse Firmen verlinken auf ihre eigene Domain.',
  });
  // Anhaenge
  const bad = mail.attachments.filter((a) => DANGEROUS_ATTACH.test(a.name) || /\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.[a-z0-9]{2,4}$/i.test(a.name));
  if (bad.length) F({
    ruleId: 'mail-dangerous-attachment', severity: 'high', confidence: 'high',
    title: `Gefährlicher Anhang: ${bad.slice(0, 3).map((a) => path.basename(a.name)).join(', ')}`,
    description: `Die Mail enthält Anhänge, die sich per Doppelklick ausführen lassen oder ihre Endung tarnen (${bad.slice(0, 6).map((a) => a.name).join(', ')}). Seriöse Absender verschicken so etwas praktisch nie.`,
    impact: 'Ein Doppelklick startet den Anhang mit den Rechten des Benutzers.',
    remediation: 'Anhang nicht öffnen. Die Mail löschen bzw. an die IT melden.',
  });
  return { findings: out, urls: [...new Set(links.map((l) => l.href))].slice(0, 500), attachments: mail.attachments };
}

function readMail(buf, label) {
  const ext = path.extname(String(label)).toLowerCase();
  const mail = ext === '.msg' ? parseMsg(buf) : parseEml(buf);
  return mail ? analyzeMail(mail, label) : null;
}

module.exports = { parseEml, parseMsg, analyzeMail, readMail, parseAddress, baseDomain, decodeWords, extractLinks, MAIL_EXT: new Set(['.eml', '.msg']) };
