'use strict';

// Krypto-Inventar: welche Verfahren und Schluessellaengen nutzt das Projekt?
//  - ein Info-Befund mit der Uebersicht (Grundlage fuer Krypto-Agilitaet und PQC-Migration)
//  - ein Hinweis, wenn asymmetrische Verfahren ohne Post-Quanten-Alternative im Einsatz sind
//  - hoeher eingestuft: veraltete Verfahren und zu kurze Schluessel

const { base, mk, isText, lineOf } = require('./rulekit');

const M = 'crypto-inventory';
const CODE = /\.(m?[jt]sx?|cjs|py|rb|php|go|java|kt|kts|cs|swift|scala|dart|ex|exs|rs|c|cc|cpp|cxx|h|hpp|m|mm|lua|ps1|sh|tf|ya?ml|conf|properties|toml|json|xml)$/i;
const SKIP = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|go\.sum|poetry\.lock)$|\.min\.js$/i;

// [Name, Art, Regex] – Art: sym, hash, kdf, asym (klassisch), pq (Post-Quanten), weak (veraltet)
const ALGOS = [
  ['ML-KEM/Kyber', 'pq', /\b(ML[-_]?KEM|Kyber(512|768|1024)?|mlkem\d*)\b/gi],
  ['ML-DSA/Dilithium', 'pq', /\b(ML[-_]?DSA|Dilithium\d?|mldsa\d*)\b/gi],
  ['SLH-DSA/SPHINCS+', 'pq', /\b(SLH[-_]?DSA|SPHINCS\+?)\b/gi],
  ['RSA', 'asym', /\b(?:RSA(?:[-_]?(?:OAEP|PSS|PKCS1))?|RS(?:256|384|512)|PS(?:256|384|512)|RSACryptoServiceProvider)\b|\brsa\.(?:GenerateKey|generate_private_key|newkeys)\b|generateKeyPair(?:Sync)?\(\s*['"]rsa['"]/g],
  ['ECDSA/ECDH', 'asym', /\b(?:ECDSA|ECDH|ES(?:256|384|512)|secp(?:256|384|521)[rk]1|SECP(?:256|384|521)[RK]1|prime256v1|P-(?:256|384|521))\b|\becdsa\.GenerateKey\b|generateKeyPair(?:Sync)?\(\s*['"]ec['"]/g],
  ['Ed25519/X25519', 'asym', /\b(Ed25519|EdDSA|X25519|Curve25519|ed448|x448)\b/gi],
  ['DSA', 'asym', /(?<!(ML|SLH)[-_]?)\b(DSA(?!-)|DSS)\b/g],
  ['Diffie-Hellman', 'asym', /\b(Diffie[-_ ]?Hellman|createDiffieHellman|DHE?_|ffdhe\d+)/g],
  ['AES-GCM', 'sym', /\baes[-_]?(128|192|256)?[-_]?gcm\b|\bAESGCM\b|AES\/GCM/gi],
  ['AES-CBC', 'sym', /\baes[-_]?(128|192|256)?[-_]?cbc\b|AES\/CBC/gi],
  ['AES-CTR/CFB/OFB/CCM', 'sym', /\baes[-_]?(128|192|256)[-_]?(ctr|cfb|ofb|ccm|xts)\b|\bAES\.new\(/gi],
  ['ChaCha20-Poly1305', 'sym', /\b(x?chacha20[-_]?poly1305|ChaCha20)\b/gi],
  ['SHA-256/384/512', 'hash', /\bsha[-_]?(256|384|512)\b|\bSHA2\b/gi],
  ['SHA-3/BLAKE', 'hash', /\b(sha3[-_]?(256|384|512)?|blake2[bs]?|blake3)\b/gi],
  ['HMAC', 'hash', /\b(createHmac|hmac\.new|HmacSHA\d+|HMACSHA\d+|hmac\.New)\b/g],
  ['bcrypt/scrypt/Argon2/PBKDF2', 'kdf', /\b(bcrypt|scrypt|argon2(id|i|d)?|pbkdf2(Sync)?|PBKDF2WithHmacSHA\d+|Rfc2898DeriveBytes)\b/gi],
  ['MD5', 'weak', /\bmd5\b|\bMD5\.Create\(|createHash\(\s*['"]md5['"]/gi],
  ['SHA-1', 'weak', /\bsha[-_]?1\b|createHash\(\s*['"]sha1['"]|\bSHA1\.Create\(/gi],
  ['DES/3DES', 'weak', /\b(des[-_]ede3?(-cbc)?|3des|TripleDES|DESede|des-cbc)\b|createCipheriv?\(\s*['"]des\b/gi],
  ['RC4', 'weak', /\b(rc4|arcfour|ARC4)\b/gi],
  ['AES-ECB', 'weak', /\b(aes[-_]?\d*[-_]?ecb)\b|AES\/ECB|MODE_ECB|CipherMode\.ECB/gi],
];

// Schluessellaengen (RSA/DH) und kurze Kurven
const KEYSIZE = [
  /modulusLength\s*:\s*(\d{3,5})/g,
  /\bRSA\.generate\(\s*(\d{3,5})/g,
  /rsa\.GenerateKey\([^,]+,\s*(\d{3,5})\)/g,
  /\.initialize\(\s*(\d{3,5})\s*[,)]/g,
  /\bkey_size\s*=\s*(\d{3,5})/g,
  /\bRSA\s*\(\s*(\d{3,5})\s*\)|new\s+RSACryptoServiceProvider\(\s*(\d{3,5})\s*\)/g,
  /\bgenrsa\b[^\n]*?\s(\d{3,5})\b|-newkey\s+rsa:(\d{3,5})/g,
  /\brsa_bits\s*=\s*(\d{3,5})|\balgorithm\s*=\s*"RSA"[\s\S]{0,80}?rsa_bits\s*=\s*(\d{3,5})/g,
];
const SHORT_CURVE = /\b(secp(112|128|160|192)[rk][12]|prime192v1|P-192|sect163[kr]1)\b/gi;

function runCryptoInventory(units) {
  const inv = new Map(); // Name -> { kind, count, files:Set, first:{u,idx} }
  const weakKeys = [];
  for (const u of units) {
    if (!isText(u) || !CODE.test(base(u)) || SKIP.test(base(u))) continue;
    // In Server-Konfigurationen sind !RC4 / -MD5 Ausschluesse, keine Nutzung
    const c = /\.(conf|cfg|ini)$/i.test(base(u)) ? u.content.replace(/(^|[\s:,])([!-][\w-]+)/g, (m, a, b) => a + ' '.repeat(b.length)) : u.content;
    if (c.length > 600 * 1024) continue;
    for (const [name, kind, re] of ALGOS) {
      re.lastIndex = 0; let m, n = 0;
      while ((m = re.exec(c)) && n < 50) {
        n++;
        const e = inv.get(name) || { kind, count: 0, files: new Set(), first: null };
        e.count++; e.files.add(base(u)); if (!e.first) e.first = { u, idx: m.index };
        inv.set(name, e);
      }
    }
    for (const re of KEYSIZE) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(c))) {
        const bits = Number(m[1] || m[2]);
        if (bits >= 256 && bits < 2048 && (/modulus|genrsa|newkey|RSA\.generate|rsa\.GenerateKey|RSACrypto|rsa_bits|RSA\s*\(/i.test(m[0]) || /RSA|\brsa[._]|DiffieHellman|\bdh\.|"DH"|'DH'|DSA/.test(c.slice(Math.max(0, m.index - 200), m.index)))) weakKeys.push({ u, idx: m.index, what: `${bits} Bit`, ev: m[0] });
      }
    }
    SHORT_CURVE.lastIndex = 0; let sc;
    while ((sc = SHORT_CURVE.exec(c))) weakKeys.push({ u, idx: sc.index, what: sc[0], ev: sc[0] });
  }
  if (!inv.size && !weakKeys.length) return [];
  const out = [];
  const entries = [...inv.entries()].sort((a, b) => b[1].count - a[1].count);
  const fmt = (list) => list.map(([n, e]) => `${n} (${e.count}×)`).join(', ');
  if (entries.length) {
    const pq = entries.filter(([, e]) => e.kind === 'pq');
    // Hinweise nur mit Datei (ohne Zeile), damit sie nicht mit Einzelbefunden derselben Zeile verschmelzen
    const top = entries[0][1].first;
    out.push(mk(M, top.u, null, {
      ruleId: 'crypto-inventory', severity: 'info', category: 'Crypto', confidence: 'medium',
      title: `Krypto-Inventar: ${entries.length} Verfahren im Code`,
      description: `Gefundene Verfahren: ${fmt(entries)}. Die Übersicht hilft, schwache Verfahren gezielt zu ersetzen und die Umstellung auf Post-Quanten-Kryptografie zu planen${pq.length ? '' : ' (bisher keine Post-Quanten-Verfahren im Einsatz)'}.`,
      remediation: 'Inventar mit dem Team abgleichen, Verfahren zentral kapseln (Krypto-Agilität) und schwache Verfahren mit Priorität ersetzen.',
      evidence: entries.map(([n, e]) => `${n}: ${[...e.files].slice(0, 2).join(', ')}`).join(' · ').slice(0, 480),
    }));
    const asym = entries.filter(([, e]) => e.kind === 'asym');
    if (asym.length && !pq.length) {
      const f = asym[0][1].first;
      out.push(mk(M, f.u, null, {
        ruleId: 'crypto-not-pq-ready', severity: 'info', category: 'Crypto', confidence: 'medium',
        title: 'Asymmetrische Kryptografie ist nicht quantensicher',
        description: `Im Einsatz: ${asym.map(([n]) => n).join(', ')}. Diese Verfahren lassen sich mit einem ausreichend großen Quantencomputer brechen; heute aufgezeichnete, verschlüsselte Daten könnten später entschlüsselt werden („harvest now, decrypt later“).`,
        remediation: 'Für langlebige vertrauliche Daten hybride Verfahren (z. B. X25519 + ML-KEM) einplanen und die Krypto-Bibliotheken auf PQC-Unterstützung prüfen.',
      }));
    }
    const weak = entries.filter(([, e]) => e.kind === 'weak');
    if (weak.length) {
      const f = weak[0][1].first;
      out.push(mk(M, f.u, f.idx, {
        ruleId: 'crypto-weak-algorithm', severity: 'medium', category: 'Crypto', confidence: 'medium',
        title: `Veraltete Krypto-Verfahren im Einsatz: ${weak.map(([n]) => n).join(', ')}`,
        description: `Gefunden: ${fmt(weak)}. MD5, SHA-1, DES/3DES, RC4 und der ECB-Modus gelten als gebrochen bzw. unsicher und schützen weder Passwörter noch Daten zuverlässig.`,
        remediation: 'Durch aktuelle Verfahren ersetzen: SHA-256/SHA-3 für Prüfsummen, Argon2/bcrypt für Passwörter, AES-GCM oder ChaCha20-Poly1305 für Verschlüsselung.',
      }));
    }
  }
  for (const w of weakKeys.slice(0, 5)) out.push(mk(M, w.u, w.idx, {
    ruleId: 'crypto-weak-key-size', severity: 'high', category: 'Crypto', confidence: 'medium',
    title: `Zu kurzer Schlüssel: ${w.what}`,
    description: `RSA-/DH-Schlüssel unter 2048 Bit bzw. Kurven unter 224 Bit gelten als brechbar. Fundstelle: \`${String(w.ev).replace(/\s+/g, ' ').slice(0, 80)}\``,
    remediation: 'Mindestens RSA-3072 (bzw. 2048 nur übergangsweise) oder Kurven wie P-256/X25519 verwenden.',
  }));
  return out;
}

module.exports = { runCryptoInventory, lineOf };
