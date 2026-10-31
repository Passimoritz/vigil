'use strict';

// Methode: hohe Shannon-Entropie deutet auf geheime Schluessel/Token hin,
// die kein bekanntes Secret-Muster treffen (zufaellig aussehende Zeichenketten).
// Bewusst konservativ, um Fehlalarme (Hashes, Base64-Assets, Minify) zu begrenzen.

function shannon(s) {
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let H = 0;
  const n = s.length;
  for (const k in freq) { const p = freq[k] / n; H -= p * Math.log2(p); }
  return H;
}

const SECRETISH = /(key|secret|token|passw|pwd|auth|cred|api|private|signature|bearer|access)/i;
const TOKEN = /[A-Za-z0-9+/_=\-]{24,}/g;
// Zeilen, die eher Hashes/Assets/Integritaet enthalten -> ueberspringen.
const SKIP_LINE = /base64|data:image|integrity=|sha(?:256|384|512)|[a-f0-9]{40,}|\.(png|jpe?g|gif|svg|woff2?|ttf|ico)\b/i;

function findHighEntropy(content) {
  const hits = [];
  const lines = String(content || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 400 || SKIP_LINE.test(line)) continue;
    const contextSecret = SECRETISH.test(line);
    TOKEN.lastIndex = 0;
    let m;
    while ((m = TOKEN.exec(line))) {
      const tok = m[0];
      if (/^[0-9]+$/.test(tok) || /^[a-f0-9]+$/i.test(tok)) continue; // reine Zahlen/Hex (Hashes)
      const H = shannon(tok);
      const mixed = /[A-Z]/.test(tok) && /[a-z]/.test(tok) && /[0-9]/.test(tok);
      const strong = H >= 4.3 && tok.length >= 40 && mixed;
      if ((contextSecret && H >= 3.6 && tok.length >= 24) || strong) {
        hits.push({ value: tok, line: i + 1, entropy: Math.round(H * 100) / 100, context: contextSecret });
        if (hits.length >= 40) return hits;
      }
    }
  }
  return hits;
}

module.exports = { shannon, findHighEntropy };
