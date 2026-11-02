'use strict';

// Erzeugt assets/icon.png (512 px) und assets/icon.ico (16–256 px) aus den SVG-Vorlagen:
//   npm run make-icon
// Gerendert wird mit einem lokal installierten Chrome/Edge (headless): jede Groesse wird direkt
// als Vektor auf ein Canvas gezeichnet – scharf auch bei 16 px. Kleine Groessen (<= 32 px)
// nutzen die vereinfachte Fassung assets/icon-small.svg.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ASSETS = path.join(__dirname, '..', 'assets');
const ICO_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256];
const PNG_SIZE = 512;

function findBrowser() {
  const pf = [process.env.ProgramFiles, process.env['ProgramFiles(x86)'], process.env.LOCALAPPDATA].filter(Boolean);
  const rel = ['Google/Chrome/Application/chrome.exe', 'Microsoft/Edge/Application/msedge.exe'];
  const list = [process.env.CHROME_PATH, ...pf.flatMap((p) => rel.map((r) => path.join(p, r))),
    '/usr/bin/google-chrome', '/usr/bin/chromium', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'];
  return list.find((p) => p && fs.existsSync(p));
}

// Seite zeichnet alle Groessen und schreibt die PNG-Daten als JSON in den Body.
function renderAll(jobs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-icon-'));
  for (const f of ['icon.svg', 'icon-small.svg']) fs.copyFileSync(path.join(ASSETS, f), path.join(dir, f));
  fs.writeFileSync(path.join(dir, 'render.html'), `<!doctype html><html><body><script>
    const jobs = ${JSON.stringify(jobs)};
    const load = (src) => new Promise((ok, err) => { const i = new Image(); i.onload = () => ok(i); i.onerror = err; i.src = src; });
    (async () => {
      const out = {};
      for (const j of jobs) {
        const img = await load(j.svg);
        const c = document.createElement('canvas'); c.width = c.height = j.size;
        const g = c.getContext('2d'); g.imageSmoothingQuality = 'high';
        g.drawImage(img, 0, 0, j.size, j.size);
        out[j.key] = c.toDataURL('image/png').split(',')[1];
      }
      document.body.textContent = 'ICONDATA' + JSON.stringify(out) + 'ICONEND';
    })();
  </script></body></html>`);
  const browser = findBrowser();
  if (!browser) throw new Error('Kein Chrome/Edge gefunden – Pfad per CHROME_PATH angeben.');
  const dom = execFileSync(browser, ['--headless=new', '--disable-gpu', '--allow-file-access-from-files',
    '--virtual-time-budget=10000', '--dump-dom', 'file:///' + path.join(dir, 'render.html').replace(/\\/g, '/')],
  { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  fs.rmSync(dir, { recursive: true, force: true });
  const m = dom.match(/ICONDATA(.*)ICONEND/s);
  if (!m) throw new Error('Rendern fehlgeschlagen (keine Bilddaten).');
  return Object.fromEntries(Object.entries(JSON.parse(m[1])).map(([k, v]) => [k, Buffer.from(v, 'base64')]));
}

// ICO mit PNG-Eintraegen (von Windows Vista an unterstuetzt).
function buildIco(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(entries.length, 4);
  const dir = Buffer.alloc(16 * entries.length);
  let offset = 6 + dir.length;
  entries.forEach(({ size, png }, i) => {
    const o = i * 16;
    dir.writeUInt8(size >= 256 ? 0 : size, o);
    dir.writeUInt8(size >= 256 ? 0 : size, o + 1);
    dir.writeUInt16LE(1, o + 4); dir.writeUInt16LE(32, o + 6);
    dir.writeUInt32LE(png.length, o + 8); dir.writeUInt32LE(offset, o + 12);
    offset += png.length;
  });
  return Buffer.concat([header, dir, ...entries.map((e) => e.png)]);
}

const jobs = [...ICO_SIZES.map((size) => ({ key: 'ico' + size, size, svg: size <= 32 ? 'icon-small.svg' : 'icon.svg' })),
  { key: 'png', size: PNG_SIZE, svg: 'icon.svg' }];
const imgs = renderAll(jobs);
fs.writeFileSync(path.join(ASSETS, 'icon.ico'), buildIco(ICO_SIZES.map((size) => ({ size, png: imgs['ico' + size] }))));
fs.writeFileSync(path.join(ASSETS, 'icon.png'), imgs.png);
console.log(`icon.ico (${ICO_SIZES.join(', ')} px) und icon.png (${PNG_SIZE} px) erzeugt.`);
