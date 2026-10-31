'use strict';

// Erzeugt assets/icon.png (256x256) und assets/icon.ico ohne externe Abhaengigkeiten.
// Motiv: blaues Schild mit Haken (passt zu Vigil).

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const W = 256, H = 256;
const buf = Buffer.alloc(W * H * 4); // RGBA

function set(x, y, r, g, b, a) {
  if (x < 0 || y < 0 || x >= W || y >= H) return;
  const i = (y * W + x) * 4;
  // einfaches "over"-Blending auf vorhandenen Inhalt
  const sa = a / 255;
  const da = buf[i + 3] / 255;
  const oa = sa + da * (1 - sa);
  if (oa === 0) return;
  buf[i] = Math.round((r * sa + buf[i] * da * (1 - sa)) / oa);
  buf[i + 1] = Math.round((g * sa + buf[i + 1] * da * (1 - sa)) / oa);
  buf[i + 2] = Math.round((b * sa + buf[i + 2] * da * (1 - sa)) / oa);
  buf[i + 3] = Math.round(oa * 255);
}

// --- Hintergrund: abgerundetes Quadrat mit vertikalem Blau-Verlauf -----
const R = 52;
function inRounded(x, y) {
  const minx = 0, miny = 0, maxx = W - 1, maxy = H - 1;
  const cx = Math.min(Math.max(x, minx + R), maxx - R);
  const cy = Math.min(Math.max(y, miny + R), maxy - R);
  return (x - cx) ** 2 + (y - cy) ** 2 <= R ** 2 || (x >= R && x <= W - 1 - R) || (y >= R && y <= H - 1 - R);
}
for (let y = 0; y < H; y++) {
  const t = y / H;
  const r = Math.round(76 + (47 - 76) * t);
  const g = Math.round(139 + (102 - 139) * t);
  const b = Math.round(245 + (216 - 245) * t);
  for (let x = 0; x < W; x++) if (inRounded(x, y)) set(x, y, r, g, b, 255);
}

// --- Schild (weiss gefuellt) -------------------------------------------
const shield = [[64, 66], [192, 66], [192, 150], [128, 212], [64, 150]];
function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
    if (((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}
for (let y = 50; y < 220; y++) for (let x = 50; x < 206; x++) if (inPoly(x, y, shield)) set(x, y, 255, 255, 255, 255);

// --- Haken (blau) ueber dem Schild -------------------------------------
function stamp(cx, cy, rad, r, g, b) {
  for (let y = -rad; y <= rad; y++) for (let x = -rad; x <= rad; x++) {
    if (x * x + y * y <= rad * rad) set(cx + x, cy + y, r, g, b, 255);
  }
}
function line(x0, y0, x1, y1, rad, r, g, b) {
  const steps = Math.ceil(Math.hypot(x1 - x0, y1 - y0));
  for (let s = 0; s <= steps; s++) {
    const t = s / steps;
    stamp(Math.round(x0 + (x1 - x0) * t), Math.round(y0 + (y1 - y0) * t), rad, r, g, b);
  }
}
line(96, 132, 120, 158, 11, 31, 95, 208);
line(120, 158, 170, 100, 11, 31, 95, 208);

// --- PNG kodieren -------------------------------------------------------
function crcTable() {
  const t = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
}
const CRC = crcTable();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const t = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}
function encodePng() {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const raw = Buffer.alloc((W * 4 + 1) * H);
  for (let y = 0; y < H; y++) {
    raw[y * (W * 4 + 1)] = 0; // Filter: none
    buf.copy(raw, y * (W * 4 + 1) + 1, y * W * 4, (y + 1) * W * 4);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

function encodeIco(png) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(1, 4);
  const entry = Buffer.alloc(16);
  entry[0] = 0; entry[1] = 0; // 256x256
  entry[2] = 0; entry[3] = 0;
  entry.writeUInt16LE(1, 4); entry.writeUInt16LE(32, 6);
  entry.writeUInt32LE(png.length, 8); entry.writeUInt32LE(22, 12);
  return Buffer.concat([header, entry, png]);
}

const outDir = path.join(__dirname, '..', 'assets');
fs.mkdirSync(outDir, { recursive: true });
const png = encodePng();
fs.writeFileSync(path.join(outDir, 'icon.png'), png);
fs.writeFileSync(path.join(outDir, 'icon.ico'), encodeIco(png));
console.log('Icon geschrieben:', png.length, 'Bytes PNG');
