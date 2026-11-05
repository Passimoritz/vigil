'use strict';

// Verifying downloaded data before it is used (detection feeds, tool archives).
//
//  sha256   pinning: the download must match one of the given hex digests
//  minisign signature check (Ed25519, legacy "Ed" and pre-hashed "ED" variants) – the format
//           used by many Go/Rust security tools for release signatures; pure Node, no binary
//  cosign   (sigstore) needs the transparency log and certificate chain; not implemented here –
//           releases signed only with cosign are pinned by SHA-256 instead (docs/THREAT_MODEL.md)
//
// Any mismatch throws: the caller keeps the last good copy and never uses the new data.

const crypto = require('crypto');

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function verifySha256(buf, pins) {
  const list = (Array.isArray(pins) ? pins : [pins]).filter(Boolean).map((p) => String(p).toLowerCase().trim());
  if (!list.length) return { ok: true, pinned: false, sha256: sha256(buf) };
  const got = sha256(buf);
  if (!list.includes(got)) throw new Error(`SHA-256 mismatch (got ${got.slice(0, 16)}…)`);
  return { ok: true, pinned: true, sha256: got };
}

// "untrusted comment: …\n<base64>" -> Buffer of the base64 line
function b64Line(text, idx) {
  const lines = String(text).replace(/\r/g, '').split('\n').filter((l) => l.trim());
  const line = lines[idx];
  if (!line) throw new Error('minisign: malformed input');
  return { lines, buf: Buffer.from(line.trim(), 'base64') };
}

function parseMinisignPublicKey(text) {
  // Accept the full .pub file or just the base64 line
  const raw = /untrusted comment/i.test(text) ? b64Line(text, 1).buf : Buffer.from(String(text).trim(), 'base64');
  if (raw.length !== 42 || raw.toString('latin1', 0, 2) !== 'Ed') throw new Error('minisign: unsupported public key');
  const keyId = raw.subarray(2, 10);
  const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.subarray(10).toString('base64url') }, format: 'jwk' });
  return { keyId, key };
}

function verifyMinisign(buf, sigText, pubKeyText) {
  const pub = parseMinisignPublicKey(pubKeyText);
  const { lines, buf: sig } = b64Line(sigText, 1);
  if (sig.length !== 74) throw new Error('minisign: malformed signature');
  const alg = sig.toString('latin1', 0, 2);
  if (alg !== 'Ed' && alg !== 'ED') throw new Error('minisign: unsupported signature algorithm');
  if (!sig.subarray(2, 10).equals(pub.keyId)) throw new Error('minisign: signed with a different key');
  const signature = sig.subarray(10);
  const message = alg === 'ED' ? crypto.createHash('blake2b512').update(buf).digest() : buf;
  if (!crypto.verify(null, message, pub.key, signature)) throw new Error('minisign: signature invalid');
  // trusted comment + global signature (covers signature || comment)
  const tc = lines.find((l) => l.startsWith('trusted comment: '));
  const gIdx = lines.indexOf(tc) + 1;
  if (tc && lines[gIdx]) {
    const comment = tc.slice('trusted comment: '.length);
    const global = Buffer.from(lines[gIdx].trim(), 'base64');
    if (!crypto.verify(null, Buffer.concat([signature, Buffer.from(comment, 'utf8')]), pub.key, global)) throw new Error('minisign: trusted comment signature invalid');
    return { ok: true, trustedComment: comment };
  }
  return { ok: true, trustedComment: null };
}

// spec: { sha256?: string|string[], minisign?: { signature, publicKey } }
function verifyDownload(buf, spec = {}) {
  const r = verifySha256(buf, spec.sha256);
  if (spec.minisign) verifyMinisign(buf, spec.minisign.signature, spec.minisign.publicKey);
  return { ...r, signed: !!spec.minisign };
}

module.exports = { sha256, verifySha256, verifyMinisign, parseMinisignPublicKey, verifyDownload };
