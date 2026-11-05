'use strict';

// Container-Image Schicht fuer Schicht: Dateien, die in einer frueheren Schicht angelegt und spaeter
// geloescht oder ueberschrieben wurden, stecken weiterhin im Image (docker save packt sie aus).
// Liest nur: `docker save` in eine temporaere Datei (kein Pull, kein Start), danach wird sie geloescht.

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { normalizeFinding } = require('./schema');
const { check, DockerSaveManifestSchema, IMAGE_RE } = require('./validation');

const M = 'image-layers';
// Dateien, die nach Zugangsdaten klingen
const SENSITIVE = /(^|\/)(\.env(\.[\w-]+)?|id_rsa|id_dsa|id_ed25519|id_ecdsa|[\w.-]+\.(pem|key|p12|pfx|jks|keystore|ppk)|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.pgpass|\.htpasswd|\.docker\/config\.json|\.aws\/credentials|\.kube\/config|credentials\.json|service-account[\w.-]*\.json|secrets?\.(ya?ml|json|txt|env)|wp-config\.php)$/i;
// Kleine Textdateien ausserhalb typischer System-/Paketordner werden zusaetzlich auf Schluessel geprueft
const TEXTY = /\.(sh|bash|env|json|ya?ml|conf|cfg|ini|txt|properties|xml|toml|py|js|rb|php|tf)$/i;
const NOISE = /^(usr\/(share|lib|lib64|libexec|include|src)|var\/(cache|lib\/(apt|dpkg|rpm|yum|apk))|etc\/(ssl|ca-certificates|alternatives)|proc|sys|dev)\/|(^|\/)(node_modules|site-packages|dist-packages|__pycache__|\.cache)\//;
const MAX_KEEP = 64 * 1024, MAX_TOTAL = 50 * 1024 * 1024;

const strz = (b) => b.toString('utf8').replace(/\0[\s\S]*$/, '');
function tarSize(f) {
  if (f[0] & 0x80) { let n = 0; for (let i = 1; i < f.length; i++) n = n * 256 + f[i]; return n; }
  return parseInt(strz(f).trim() || '0', 8) || 0;
}
// Einfacher ustar/GNU/PAX-Leser ueber eine Lesefunktion (Datei oder Puffer)
function* walkTar(read, start, end) {
  let pos = start, longName = null, paxPath = null;
  while (pos + 512 <= end) {
    const h = read(pos, 512);
    if (h.length < 512 || !h.some((b) => b !== 0)) break;
    let name = strz(h.subarray(0, 100));
    const prefix = strz(h.subarray(345, 500));
    if (prefix && h.toString('latin1', 257, 262) === 'ustar') name = prefix + '/' + name;
    const size = tarSize(h.subarray(124, 136));
    const type = String.fromCharCode(h[156] || 48);
    const data = pos + 512;
    if (type === 'L') longName = strz(read(data, Math.min(size, 4096)));
    else if (type === 'x') { const pm = read(data, Math.min(size, 65536)).toString('utf8').match(/\d+ path=([^\n]*)\n/); if (pm) paxPath = pm[1]; }
    else if (type !== 'g') { yield { name: paxPath || longName || name, size, data, type }; longName = paxPath = null; }
    pos = data + Math.ceil(size / 512) * 512;
  }
}
const fileReader = (fd) => (pos, len) => { const b = Buffer.alloc(len); const n = fs.readSync(fd, b, 0, len, pos); return b.subarray(0, n); };
const bufReader = (buf) => (pos, len) => buf.subarray(pos, pos + len);

// Kern der Analyse: Pfad einer `docker save`-Datei -> [{ path, layer, laterLayer, by, content? }]
function hiddenFiles(tarPath, notes = []) {
  const fd = fs.openSync(tarPath, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const read = fileReader(fd);
    const entries = new Map();
    for (const e of walkTar(read, 0, size)) entries.set(e.name.replace(/^\.\//, ''), e);
    const man = entries.get('manifest.json');
    if (!man) throw new Error('manifest.json fehlt');
    let raw; try { raw = JSON.parse(read(man.data, man.size).toString('utf8')); } catch { throw new Error('manifest.json nicht lesbar'); }
    const v = check(DockerSaveManifestSchema, raw);
    if (!v.ok) throw new Error('manifest.json unerwartet');
    const layers = v.data[0].Layers;
    const state = new Map(); // Pfad -> { layer, content? }
    const hidden = [];
    let kept = 0;
    const hide = (p, rec, by, i) => hidden.push({ path: p, layer: rec.layer, laterLayer: i, by, content: rec.content });
    for (let i = 0; i < layers.length; i++) {
      const le = entries.get(layers[i].replace(/^\.\//, ''));
      if (!le) continue;
      let lread = read, s = le.data, e = le.data + le.size;
      const magic = read(le.data, 2);
      if (magic[0] === 0x1f && magic[1] === 0x8b) {
        if (le.size > 300 * 1024 * 1024) { notes.push(`Schicht ${i + 1} ist zu groß für die Analyse und wurde ausgelassen.`); continue; }
        const buf = zlib.gunzipSync(read(le.data, le.size));
        lread = bufReader(buf); s = 0; e = buf.length;
      }
      for (const x of walkTar(lread, s, e)) {
        const p = x.name.replace(/^\.?\//, '').replace(/\/$/, '');
        const slash = p.lastIndexOf('/');
        const dir = slash < 0 ? '' : p.slice(0, slash);
        const bn = p.slice(slash + 1);
        if (bn === '.wh..wh..opq') { for (const [k, rec] of state) if (k.startsWith(dir + '/')) { hide(k, rec, 'deleted', i); state.delete(k); } continue; }
        if (bn.startsWith('.wh.')) {
          const target = (dir ? dir + '/' : '') + bn.slice(4);
          for (const [k, rec] of state) if (k === target || k.startsWith(target + '/')) { hide(k, rec, 'deleted', i); state.delete(k); }
          continue;
        }
        if (x.type !== '0' && x.type !== '7' && x.type !== '\0') continue;
        if (state.has(p)) hide(p, state.get(p), 'overwritten', i);
        const rec = { layer: i };
        const wanted = SENSITIVE.test(p) || (TEXTY.test(p) && !NOISE.test(p));
        if (wanted && x.size <= MAX_KEEP && kept + x.size <= MAX_TOTAL) { rec.content = lread(x.data, x.size).toString('utf8'); kept += x.size; }
        if (SENSITIVE.test(p) || rec.content != null) state.set(p, rec);
        else state.delete(p);
      }
    }
    return hidden;
  } finally { fs.closeSync(fd); }
}

function defaultSave(image, outFile, signal) {
  const { runTool } = require('./tools');
  return runTool('docker', ['save', '-o', outFile, image], { signal, timeoutMs: 600000 }).then((r) => {
    if (!r.ok) return { ok: false, missing: true };
    if (r.code !== 0) return { ok: false, error: String(r.stderr || '').split('\n').filter(Boolean).slice(-1)[0] || `Code ${r.code}` };
    return { ok: true };
  });
}

// opts: { save(image, outFile, signal) -> {ok, missing?, error?}, signal, onProgress }
async function analyzeImageLayers(image, opts = {}) {
  if (!IMAGE_RE.test(String(image || ''))) return { findings: [], notes: [], ran: false };
  (opts.onProgress || (() => {}))({ phase: 'active', message: `Image-Schichten: ${image} …` });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-layers-'));
  const out = path.join(dir, 'image.tar');
  const notes = [];
  try {
    const r = await (opts.save || defaultSave)(image, out, opts.signal);
    if (!r.ok || !fs.existsSync(out)) {
      return { findings: [], notes: [r.missing ? 'Schichten-Analyse braucht docker – nicht installiert, Analyse ausgelassen.' : `Schichten-Analyse für ${image} nicht möglich (Image lokal nicht vorhanden?): ${r.error || ''}`.trim()], ran: false };
    }
    const hidden = hiddenFiles(out, notes);
    const { prescan } = require('./prescan');
    const findings = [];
    const seen = new Set();
    for (const h of hidden) {
      if (findings.length >= 30) break;
      if (seen.has(h.path)) continue;
      const hits = h.content ? prescan([{ label: h.path, content: h.content }], {}).findings.filter((f) => f.category === 'Secrets' && /^secret-/.test(f.ruleId)) : [];
      if (!hits.length && !SENSITIVE.test(h.path)) continue;
      seen.add(h.path);
      const names = [...new Set(hits.map((f) => String(f.title).replace(/^.*?:\s*/, '')))].slice(0, 4);
      findings.push(normalizeFinding({
        ruleId: 'image-layer-hidden-secret', severity: hits.length ? 'critical' : 'high', category: 'Secrets', confidence: hits.length ? 'high' : 'medium', sourceModule: M,
        title: `Gelöscht, aber noch im Image: /${h.path}`.slice(0, 200),
        location: `${image} [layer ${h.layer + 1}]`,
        ...(hits[0] && hits[0].evidence ? { evidence: hits[0].evidence } : {}),
        description: `Die Datei „/${h.path}“ wurde in Schicht ${h.layer + 1} angelegt und in Schicht ${h.laterLayer + 1} ${h.by === 'deleted' ? 'gelöscht' : 'überschrieben'}. Sie fehlt nur in der obersten Ansicht – wer das Image hat, packt die alte Schicht mit docker save aus und liest sie.${names.length ? ` Darin erkannt: ${names.join(', ')}.` : ''}`,
        impact: 'Zugangsdaten und Schlüssel aus dem Build sind für jeden lesbar, der das Image ziehen kann.',
        remediation: 'Geheimnisse nie in einer Schicht ablegen: beim Build RUN --mount=type=secret verwenden oder mehrstufig bauen (Multi-Stage) und nur das Ergebnis ins finale Image kopieren. Betroffene Schlüssel neu erzeugen und das Image neu bauen.',
      }, M));
    }
    notes.push(`Schichten-Analyse ${image}: ${hidden.length} verdeckte Datei(en) betrachtet, ${findings.length} Fund(e).`);
    return { findings, notes, ran: true };
  } catch (e) {
    return { findings: [], notes: [`Schichten-Analyse für ${image} fehlgeschlagen: ${e.message}`], ran: false };
  } finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* egal */ } }
}

module.exports = { analyzeImageLayers, hiddenFiles, walkTar };
