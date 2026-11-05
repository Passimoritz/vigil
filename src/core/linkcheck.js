'use strict';

// Links in Dokumenten (PDF, Office) und E-Mails gegen die taeglich geladenen Phishing-Listen
// (OpenPhish, URLhaus – siehe feeds.js) abgleichen, und die eigene Domain gegen dieselben Listen.
// Es wird kein Link aufgerufen; der Abgleich ist rein lokal.

const AdmZip = require('adm-zip');
const { normalizeFinding } = require('./schema');

// Geteilte Hosting-Dienste: dort zaehlt nur die genaue Adresse, nicht der ganze Host
const SHARED = /(^|\.)(google\.com|googleusercontent\.com|github\.io|githubusercontent\.com|firebaseapp\.com|web\.app|appspot\.com|blogspot\.com|weebly\.com|wixsite\.com|wix\.com|sharepoint\.com|onedrive\.live\.com|1drv\.ms|dropbox\.com|dropboxusercontent\.com|ipfs\.io|cloudflare-ipfs\.com|pages\.dev|workers\.dev|netlify\.app|vercel\.app|herokuapp\.com|azurewebsites\.net|amazonaws\.com|r2\.dev|glitch\.me|000webhostapp\.com|forms\.office\.com|docs\.google\.com|sites\.google\.com|microsoft\.com|live\.com|bit\.ly|t\.co|tinyurl\.com|discord\.com|discordapp\.com|telegram\.org|t\.me|linktr\.ee|notion\.site|canva\.site|webflow\.io|godaddysites\.com|square\.site|jimdosite\.com|mailchimpsites\.com)$/i;

const normUrl = (u) => { try { const x = new URL(String(u).trim()); return `${x.protocol}//${x.hostname.toLowerCase()}${x.port ? ':' + x.port : ''}${x.pathname}${x.search}`.replace(/\/$/, ''); } catch { return ''; } };
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase().replace(/\.$/, ''); } catch { return ''; } };

// Aus den Feed-Daten (Listen von URLs) einen schnellen Index bauen
function buildPhishIndex(lists) {
  const urls = new Set(), hosts = new Map();
  for (const { source, urls: list } of lists || []) {
    for (const u of list || []) {
      const n = normUrl(u); if (!n) continue;
      urls.add(n);
      const h = hostOf(n);
      if (h && !SHARED.test(h) && !hosts.has(h)) hosts.set(h, source);
    }
  }
  return { urls, hosts, size: urls.size };
}

function matchUrl(u, index) {
  if (!index || !index.size) return null;
  const n = normUrl(u); if (!n) return null;
  if (index.urls.has(n)) return { how: 'url' };
  const h = hostOf(n);
  if (h && index.hosts.has(h)) return { how: 'host', source: index.hosts.get(h) };
  return null;
}

// URLs aus Dokumenten ziehen: PDF (/URI-Aktionen), Office (externe Beziehungen, Feldfunktionen HYPERLINK)
function extractDocUrls(buf, ext) {
  const out = new Set();
  const add = (u) => { if (/^https?:\/\//i.test(u) && out.size < 500) out.add(u.trim().replace(/[)>\]"']+$/, '')); };
  if (!Buffer.isBuffer(buf)) return [];
  if (buf[0] === 0x50 && buf[1] === 0x4b) {
    let zip; try { zip = new AdmZip(buf); } catch { return []; }
    for (const e of zip.getEntries()) {
      if (!/\.rels$|document\.xml$|sheet\d*\.xml$|slide\d*\.xml$/i.test(e.entryName) || e.header.size > 8 * 1024 * 1024) continue;
      let t = ''; try { t = e.getData().toString('utf8'); } catch { continue; }
      for (const m of t.matchAll(/Target="(https?:\/\/[^"]+)"/gi)) add(m[1].replace(/&amp;/g, '&'));
      for (const m of t.matchAll(/HYPERLINK\s+(?:&quot;|")(https?:\/\/[^"&]+)/gi)) add(m[1]);
    }
    return [...out];
  }
  const t = buf.subarray(0, 64 * 1024 * 1024).toString('latin1');
  if (t.slice(0, 1024).includes('%PDF')) {
    for (const m of t.matchAll(/\/URI\s*\(((?:\\.|[^\\)])*)\)/g)) add(m[1].replace(/\\(.)/g, '$1'));
    for (const m of t.matchAll(/\/URI\s*<([0-9a-fA-F\s]+)>/g)) { try { add(Buffer.from(m[1].replace(/\s/g, ''), 'hex').toString('latin1')); } catch { /* egal */ } }
    return [...out];
  }
  for (const m of t.matchAll(/https?:\/\/[^\s"'<>)\]\\]{4,300}/gi)) add(m[0]);
  return [...out];
}

// links: [{ url, label }] -> Befunde fuer Treffer in den Phishing-Listen
function checkLinks(links, index) {
  const byLabel = new Map();
  for (const l of links || []) {
    const m = matchUrl(l.url, index);
    if (!m) continue;
    if (!byLabel.has(l.label)) byLabel.set(l.label, []);
    byLabel.get(l.label).push({ url: l.url, ...m });
  }
  const out = [];
  for (const [label, hits] of byLabel) {
    out.push(normalizeFinding({
      ruleId: 'phishing-link', severity: 'high', category: 'Other', confidence: hits.some((x) => x.how === 'url') ? 'high' : 'medium',
      title: `Link auf bekannte Phishing- bzw. Schadsoftware-Seite (${hits.length})`,
      description: `Die Datei enthält Links, die in aktuellen Phishing-/Schadsoftware-Listen (OpenPhish, URLhaus) stehen, z. B. ${hostOf(hits[0].url)}. Wer darauf klickt, landet auf einer gefälschten Anmeldeseite oder lädt Schadsoftware.`,
      remediation: 'Links nicht anklicken. Die Datei bzw. Mail löschen oder an die IT melden.',
      evidence: hits.slice(0, 5).map((x) => x.url.slice(0, 120)).join(' | '),
      location: String(label).replace(/\\/g, '/'), sourceModule: 'link-check',
    }, 'link-check'));
  }
  return out;
}

// Eigene Domains: steht die eigene Seite selbst auf einer Phishing-/Schadsoftware-Liste?
function checkOwnDomains(hosts, index, lists = []) {
  const out = [];
  if (!index || !index.size) return out;
  for (const host of [...new Set((hosts || []).map((h) => String(h).toLowerCase().replace(/^www\./, '')))]) {
    if (!host) continue;
    const listed = [];
    for (const l of lists) for (const u of l.urls || []) { const h = hostOf(u).replace(/^www\./, ''); if (h === host || h.endsWith('.' + host)) { listed.push({ url: u, source: l.source }); if (listed.length >= 5) break; } }
    if (!listed.length) continue;
    out.push(normalizeFinding({
      ruleId: 'own-domain-on-phishing-list', severity: 'critical', category: 'Other', confidence: 'high',
      title: `Eigene Domain steht auf einer Phishing-/Schadsoftware-Liste: ${host}`,
      description: `Adressen unter ${host} stehen in ${[...new Set(listed.map((x) => x.source))].join(', ')}, z. B. ${listed[0].url.slice(0, 140)}. Meist heißt das: Die Seite wurde übernommen und liefert Phishing-Seiten oder Schadsoftware aus.`,
      impact: 'Browser und Mailfilter sperren die Domain bald; Besucher werden angegriffen.',
      remediation: 'Webspace sofort auf fremde Dateien prüfen (z. B. neue Ordner, PHP-Dateien), Zugänge ändern, Software aktualisieren und danach beim Listenbetreiber die Entfernung beantragen.',
      location: `https://${host}/`, sourceModule: 'link-check',
    }, 'link-check'));
  }
  return out;
}

module.exports = { buildPhishIndex, matchUrl, extractDocUrls, checkLinks, checkOwnDomains, normUrl };
