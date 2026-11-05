'use strict';

// Minimaler Leser fuer OLE2/Compound File Binary (MS-CFB): Outlook .msg, alte Office-Dateien.
// Liefert alle Streams als { 'Speicher/Stream': Buffer }. Mit Schleifen- und Groessenschutz.

const SIG = Buffer.from('d0cf11e0a1b11ae1', 'hex');
const END = 0xfffffffe, FREE = 0xffffffff;

function readCfb(buf, { maxStreamBytes = 64 * 1024 * 1024, maxEntries = 4000 } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length < 512 || !buf.subarray(0, 8).equals(SIG)) return null;
  const secSize = 1 << buf.readUInt16LE(0x1e);
  const miniSize = 1 << buf.readUInt16LE(0x20);
  if (secSize !== 512 && secSize !== 4096) return null;
  const nFat = buf.readUInt32LE(0x2c), dirStart = buf.readUInt32LE(0x30), cutoff = buf.readUInt32LE(0x38);
  const miniFatStart = buf.readUInt32LE(0x3c), difatStart = buf.readUInt32LE(0x44);
  const secOff = (n) => (n + 1) * secSize;
  const sector = (n) => (secOff(n) + secSize <= buf.length ? buf.subarray(secOff(n), secOff(n) + secSize) : null);
  // DIFAT -> FAT-Sektoren
  const fatSecs = [];
  for (let i = 0; i < 109 && fatSecs.length < nFat; i++) { const v = buf.readUInt32LE(0x4c + i * 4); if (v !== FREE) fatSecs.push(v); }
  let d = difatStart, guard = 0;
  while (d !== END && d !== FREE && fatSecs.length < nFat && guard++ < 10000) {
    const s = sector(d); if (!s) break;
    for (let i = 0; i < secSize / 4 - 1 && fatSecs.length < nFat; i++) { const v = s.readUInt32LE(i * 4); if (v !== FREE) fatSecs.push(v); }
    d = s.readUInt32LE(secSize - 4);
  }
  const fat = [];
  for (const fs of fatSecs) { const s = sector(fs); if (!s) continue; for (let i = 0; i < secSize / 4; i++) fat.push(s.readUInt32LE(i * 4)); }
  const chain = (start, table) => {
    const out = []; const seen = new Set();
    for (let n = start; n !== END && n !== FREE && n < table.length && !seen.has(n) && out.length < 1e6; n = table[n]) { seen.add(n); out.push(n); }
    return out;
  };
  const readChain = (start, limit) => {
    const parts = []; let len = 0;
    for (const n of chain(start, fat)) { const s = sector(n); if (!s) break; parts.push(s); len += s.length; if (len >= limit) break; }
    return Buffer.concat(parts).subarray(0, limit);
  };
  const dirBuf = readChain(dirStart, maxEntries * 128);
  const entries = [];
  for (let o = 0; o + 128 <= dirBuf.length; o += 128) {
    const e = dirBuf.subarray(o, o + 128);
    const nlen = e.readUInt16LE(0x40);
    entries.push({
      name: e.subarray(0, Math.max(0, Math.min(64, nlen) - 2)).toString('utf16le'),
      type: e[0x42], left: e.readUInt32LE(0x44), right: e.readUInt32LE(0x48), child: e.readUInt32LE(0x4c),
      start: e.readUInt32LE(0x74), size: e.readUInt32LE(0x78),
    });
  }
  const root = entries[0];
  if (!root || root.type !== 5) return null;
  const miniStream = readChain(root.start, Math.min(root.size, 256 * 1024 * 1024));
  const miniFat = [];
  for (const n of chain(miniFatStart, fat)) { const s = sector(n); if (!s) break; for (let i = 0; i < secSize / 4; i++) miniFat.push(s.readUInt32LE(i * 4)); }
  const readMini = (start, size) => {
    const parts = []; let len = 0;
    for (const n of chain(start, miniFat)) { const o = n * miniSize; if (o + miniSize > miniStream.length) break; parts.push(miniStream.subarray(o, o + miniSize)); len += miniSize; if (len >= size) break; }
    return Buffer.concat(parts).subarray(0, size);
  };
  const streams = {};
  const visited = new Set();
  const walk = (idx, prefix, depth) => {
    if (idx === FREE || idx >= entries.length || visited.has(idx) || depth > 64) return;
    visited.add(idx);
    const e = entries[idx];
    walk(e.left, prefix, depth + 1);
    walk(e.right, prefix, depth + 1);
    const full = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.type === 2) {
      const size = Math.min(e.size, maxStreamBytes);
      streams[full] = e.size < cutoff ? readMini(e.start, size) : readChain(e.start, size);
    } else if (e.type === 1) walk(e.child, full, depth + 1);
  };
  walk(root.child, '', 0);
  return streams;
}

module.exports = { readCfb };
