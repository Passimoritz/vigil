'use strict';

// Signierte Berichte und Audit-Pakete.
//  - Manifest: Liste der Dateien mit Groesse und SHA-256
//  - Signatur: Ed25519 ueber das Manifest (kanonisches JSON), Schluessel lokal erzeugt; der private
//    Schluessel wird vom Aufrufer verschluesselt gespeichert (Electron safeStorage)
//  - Einzelbericht: <datei>.sig.json neben der Datei
//  - Audit-Paket: ZIP mit Berichten, Rohdaten, SBOM, manifest.json, SHA256SUMS und manifest.sig.json
// Pruefen: Hashes neu berechnen und Signatur mit dem mitgelieferten oeffentlichen Schluessel testen;
// "vertraut" ist sie nur, wenn der Schluessel dem eigenen (lokalen) Schluessel entspricht.

const crypto = require('crypto');
const AdmZip = require('adm-zip');

const FORMAT = 'vigil-manifest/1';
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const toBuf = (d) => (Buffer.isBuffer(d) ? d : Buffer.from(String(d), 'utf8'));
const safeName = (n) => String(n || '').replace(/\\/g, '/').split('/').filter((p) => p && p !== '..' && p !== '.').join('/');

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }), privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}
function keyIdOf(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return sha256(der).slice(0, 16);
}
// Kanonisches JSON: Schluessel sortiert, keine Leerzeichen – unabhaengig von der Reihenfolge beim Einlesen
function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  return JSON.stringify(v);
}

// files: [{ name, data }]
function buildManifest(files, meta = {}) {
  return {
    format: FORMAT, tool: 'Vigil', createdAt: meta.createdAt || new Date().toISOString(), ...(meta.title ? { title: String(meta.title) } : {}),
    files: files.map((f) => { const b = toBuf(f.data); return { name: safeName(f.name), size: b.length, sha256: sha256(b) }; }),
  };
}
function signManifest(manifest, privateKeyPem, publicKeyPem) {
  const signature = crypto.sign(null, Buffer.from(canonical(manifest), 'utf8'), crypto.createPrivateKey(privateKeyPem)).toString('base64');
  return { format: FORMAT + '+sig', algorithm: 'Ed25519', keyId: keyIdOf(publicKeyPem), publicKey: publicKeyPem, signature, manifest };
}
function sha256sums(manifest) { return manifest.files.map((f) => `${f.sha256}  ${f.name}`).join('\n') + '\n'; }

// sigDoc: { manifest, signature, publicKey }, files: Map(name -> Buffer), trustedPem: eigener Schluessel (optional)
function verifySigned(sigDoc, files, trustedPem) {
  const out = { ok: false, signatureValid: false, trusted: false, keyId: null, files: [], errors: [] };
  if (!sigDoc || typeof sigDoc !== 'object' || !sigDoc.manifest || !sigDoc.signature || !sigDoc.publicKey) { out.errors.push('Keine gültige Signatur-Datei.'); return out; }
  try {
    out.keyId = keyIdOf(sigDoc.publicKey);
    out.signatureValid = crypto.verify(null, Buffer.from(canonical(sigDoc.manifest), 'utf8'), crypto.createPublicKey(sigDoc.publicKey), Buffer.from(String(sigDoc.signature), 'base64'));
  } catch (e) { out.errors.push('Signatur nicht lesbar: ' + e.message); }
  if (!out.signatureValid && !out.errors.length) out.errors.push('Signatur ungültig – das Manifest wurde verändert oder mit einem anderen Schlüssel signiert.');
  try { out.trusted = !!trustedPem && keyIdOf(trustedPem) === out.keyId; } catch { out.trusted = false; }
  for (const f of sigDoc.manifest.files || []) {
    const data = files.get(f.name);
    const actual = data ? sha256(data) : null;
    const ok = !!data && actual === f.sha256 && data.length === f.size;
    out.files.push({ name: f.name, ok, missing: !data });
    if (!data) out.errors.push(`Datei fehlt: ${f.name}`);
    else if (!ok) out.errors.push(`Datei verändert: ${f.name}`);
  }
  out.ok = out.signatureValid && out.files.length > 0 && out.files.every((f) => f.ok);
  out.createdAt = sigDoc.manifest.createdAt;
  return out;
}

// Einzelne Datei signieren -> Inhalt der <datei>.sig.json
function signFile(name, data, keys) {
  return JSON.stringify(signManifest(buildManifest([{ name, data }]), keys.privateKeyPem, keys.publicKeyPem), null, 2);
}

// Audit-Paket bauen. parts: [{ name, data }] ; keys optional (dann mit Signatur)
function buildAuditPackage(parts, keys, meta = {}) {
  const zip = new AdmZip();
  const files = parts.filter((p) => p && p.data != null).map((p) => ({ name: safeName(p.name), data: toBuf(p.data) }));
  for (const f of files) zip.addFile(f.name, f.data);
  const manifest = buildManifest(files, meta);
  zip.addFile('manifest.json', Buffer.from(JSON.stringify(manifest, null, 2), 'utf8'));
  zip.addFile('SHA256SUMS', Buffer.from(sha256sums(manifest), 'utf8'));
  if (keys) zip.addFile('manifest.sig.json', Buffer.from(JSON.stringify(signManifest(manifest, keys.privateKeyPem, keys.publicKeyPem), null, 2), 'utf8'));
  return zip.toBuffer();
}

// Audit-Paket pruefen (ZIP-Puffer). Ohne Signatur: nur Hashes aus manifest.json.
function verifyAuditPackage(buf, trustedPem) {
  let zip;
  try { zip = new AdmZip(buf); } catch (e) { return { ok: false, errors: ['Kein gültiges ZIP: ' + e.message], files: [] }; }
  const files = new Map();
  for (const e of zip.getEntries()) if (!e.isDirectory) files.set(safeName(e.entryName), e.getData());
  const sigRaw = files.get('manifest.sig.json');
  if (sigRaw) {
    let doc = null;
    try { doc = JSON.parse(sigRaw.toString('utf8')); } catch { /* unten */ }
    const r = verifySigned(doc, files, trustedPem);
    // manifest.json muss zum signierten Manifest passen
    try { const m = JSON.parse(files.get('manifest.json').toString('utf8')); if (canonical(m) !== canonical(doc.manifest)) { r.ok = false; r.errors.push('manifest.json passt nicht zur Signatur.'); } } catch { r.ok = false; r.errors.push('manifest.json fehlt oder ist ungültig.'); }
    return { ...r, signed: true };
  }
  let m = null;
  try { m = JSON.parse(files.get('manifest.json').toString('utf8')); } catch { return { ok: false, signed: false, errors: ['manifest.json fehlt oder ist ungültig.'], files: [] }; }
  const list = (m.files || []).map((f) => { const d = files.get(f.name); return { name: f.name, ok: !!d && sha256(d) === f.sha256, missing: !d }; });
  return { ok: list.length > 0 && list.every((f) => f.ok), signed: false, signatureValid: false, trusted: false, files: list, errors: list.filter((f) => !f.ok).map((f) => (f.missing ? 'Datei fehlt: ' : 'Datei verändert: ') + f.name), createdAt: m.createdAt };
}

module.exports = { generateKeyPair, keyIdOf, canonical, buildManifest, signManifest, verifySigned, signFile, buildAuditPackage, verifyAuditPackage, sha256sums, sha256 };
