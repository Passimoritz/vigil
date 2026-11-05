'use strict';

// Rechner-Ausstattung erkennen (nur lesend) und das passende lokale Ollama-Modell empfehlen.
// Windows: PowerShell/CIM (Grafikkarte, Grafikspeicher aus der Registry, weil AdapterRAM bei
// 4 GB abgeschnitten ist), Fallback wmic; NVIDIA zusaetzlich ueber nvidia-smi (genau).
// Arbeitsspeicher kommt aus os.totalmem().

const os = require('os');
const { execFile } = require('child_process');

const GB = 1024 ** 3;
const run = (cmd, args, timeout = 8000) => new Promise((resolve) => {
  try {
    execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, out) => resolve(err ? '' : String(out || '')));
  } catch { resolve(''); }
});

const PS_SCRIPT = [
  "$ErrorActionPreference='SilentlyContinue'",
  "$v = @(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM)",
  "$r = @(Get-ItemProperty 'HKLM:\\SYSTEM\\ControlSet001\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0*' | Select-Object DriverDesc,'HardwareInformation.qwMemorySize')",
  "[pscustomobject]@{ video = $v; reg = $r } | ConvertTo-Json -Depth 4 -Compress",
].join('; ');

const vendorOf = (name) => (/nvidia|geforce|quadro|rtx|gtx|tesla/i.test(name) ? 'nvidia' : /amd|radeon/i.test(name) ? 'amd' : /intel|iris|uhd|arc/i.test(name) ? 'intel' : /apple/i.test(name) ? 'apple' : 'other');

function parseNvidiaSmi(out) {
  return String(out || '').split(/\r?\n/).map((l) => l.split(',').map((x) => x.trim())).filter((p) => p.length >= 2 && p[0] && /^\d+$/.test(p[1]))
    .map(([name, mib]) => ({ name, vendor: 'nvidia', vramGB: Math.round((Number(mib) / 1024) * 10) / 10, source: 'nvidia-smi' }));
}
function parsePsJson(out) {
  let j; try { j = JSON.parse(String(out || '').trim()); } catch { return []; }
  const arr = (x) => (Array.isArray(x) ? x : x ? [x] : []);
  const reg = arr(j.reg).map((r) => ({ name: String(r.DriverDesc || ''), bytes: Number(r['HardwareInformation.qwMemorySize']) || 0 }));
  return arr(j.video).filter((v) => v && v.Name && !/basic display|remote|virtual|mirror/i.test(v.Name)).map((v) => {
    const name = String(v.Name).trim();
    const r = reg.find((x) => x.name.trim() === name && x.bytes);
    const bytes = r ? r.bytes : Number(v.AdapterRAM) || 0;
    return { name, vendor: vendorOf(name), vramGB: Math.round((bytes / GB) * 10) / 10, source: r ? 'registry' : 'cim' };
  });
}
function parseWmicCsv(out) {
  const lines = String(out || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const head = (lines.shift() || '').split(',');
  const iRam = head.indexOf('AdapterRAM'), iName = head.indexOf('Name');
  if (iRam < 0 || iName < 0) return [];
  return lines.map((l) => l.split(',')).filter((p) => p[iName]).map((p) => ({ name: p[iName], vendor: vendorOf(p[iName]), vramGB: Math.round(((Number(p[iRam]) || 0) / GB) * 10) / 10, source: 'wmic' }));
}

// Liefert { platform, ramGB, cpuCores, gpus: [{name, vendor, vramGB, source}] }
async function detectHardware({ exec = run, platform = process.platform, totalmem = os.totalmem(), cpus = os.cpus().length } = {}) {
  const ramGB = Math.round((totalmem / GB) * 10) / 10;
  let gpus = parseNvidiaSmi(await exec('nvidia-smi', ['--query-gpu=name,memory.total', '--format=csv,noheader,nounits']));
  if (platform === 'win32') {
    let others = parsePsJson(await exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', PS_SCRIPT], 12000));
    if (!others.length) others = parseWmicCsv(await exec('wmic', ['path', 'win32_VideoController', 'get', 'Name,AdapterRAM', '/format:csv']));
    for (const g of others) if (!gpus.some((x) => x.name === g.name || (x.vendor === 'nvidia' && g.vendor === 'nvidia'))) gpus.push(g);
  } else if (platform === 'darwin' && /arm64/.test(process.arch)) {
    gpus.push({ name: 'Apple Silicon (gemeinsamer Speicher)', vendor: 'apple', vramGB: Math.round(ramGB * 0.65 * 10) / 10, source: 'unified' });
  }
  gpus.sort((a, b) => b.vramGB - a.vramGB);
  return { platform, ramGB, cpuCores: cpus, gpus };
}

// Modellstufen (Ollama-Bibliothek): benoetigter Speicher grob = Dateigroesse + ~20 %
const TIERS = [
  { name: 'qwen2.5-coder:32b', needGB: 22, label: 'Qwen 2.5 Coder 32B' },
  { name: 'qwen2.5-coder:14b', needGB: 11, label: 'Qwen 2.5 Coder 14B' },
  { name: 'qwen2.5-coder:7b', needGB: 6, label: 'Qwen 2.5 Coder 7B' },
  { name: 'qwen2.5-coder:3b', needGB: 3, label: 'Qwen 2.5 Coder 3B' },
  { name: 'qwen2.5-coder:1.5b', needGB: 0, label: 'Qwen 2.5 Coder 1.5B' },
];
const sizeOfName = (n) => { const m = String(n).match(/:(\d+(?:\.\d+)?)b\b/i); return m ? Number(m[1]) : null; };

// Empfehlung: Grafikspeicher einer tauglichen GPU (NVIDIA/AMD/Apple), sonst Arbeitsspeicher (CPU, langsamer).
// installed: Namen bereits installierter Modelle – passt eins, wird es bevorzugt (kein Download).
function recommendModel(hw, installed = []) {
  const gpu = (hw.gpus || []).find((g) => ['nvidia', 'amd', 'apple'].includes(g.vendor) && g.vramGB >= 4);
  const gpuMem = gpu ? gpu.vramGB : 0;
  // CPU: hoechstens ~60 % des Arbeitsspeichers fuer das Modell, und nicht groesser als 7B (sonst zu langsam)
  const cpuMem = Math.min((hw.ramGB || 0) * 0.6, 7);
  const mem = Math.max(gpuMem, cpuMem);
  const tier = TIERS.find((t) => mem >= t.needGB) || TIERS[TIERS.length - 1];
  const mode = gpuMem >= tier.needGB && gpuMem > 0 ? 'gpu' : 'cpu';
  const reason = mode === 'gpu'
    ? `${gpu.name} mit ${gpu.vramGB} GB Grafikspeicher`
    : `${hw.ramGB} GB Arbeitsspeicher, ohne passende Grafikkarte (läuft auf dem Prozessor, langsamer)`;
  // Bereits installiertes Coder-Modell, das in den Speicher passt? Dann das nehmen.
  const fit = installed.filter((n) => /coder|qwen|llama|deepseek|mistral|codestral|gemma|phi/i.test(n))
    .map((n) => ({ n, b: sizeOfName(n) }))
    .filter((x) => x.b != null && x.b <= (sizeOfName(tier.name) || 0))
    .sort((a, b) => (/coder/i.test(b.n) - /coder/i.test(a.n)) || b.b - a.b);
  return { name: tier.name, label: tier.label, mode, reason, needGB: tier.needGB, installedChoice: fit.length ? fit[0].n : null };
}

module.exports = { detectHardware, recommendModel, parseNvidiaSmi, parsePsJson, parseWmicCsv, TIERS };
