'use strict';

// Aktive Pruefung ueber etablierte, dafuer gebaute Werkzeuge: nmap (Ports/Dienste)
// und nuclei (aktive Schwachstellen-Templates). KEINE eigenen Exploit-Payloads,
// kein DoS/Last, kein Brute-Force. Nur gegen autorisierte Ziele (Aufrufer prueft das).
// Beide Laeufe sind ueber ein AbortSignal abbrechbar (Prozess wird beendet).

const { runSandboxed } = require('./sandbox');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { normalizeFinding, cvssToSeverity, clampScore, redactSecret } = require('./schema');
const { check, TrivyOutputSchema, SemgrepOutputSchema, GitleaksOutputSchema } = require('./validation');

function firstExisting(cands, fallback) {
  for (const c of cands) { try { if (c && fs.existsSync(c)) return c; } catch { /* ignore */ } }
  return fallback;
}
const NMAP = firstExisting([
  'C:\\Program Files (x86)\\Nmap\\nmap.exe',
  'C:\\Program Files\\Nmap\\nmap.exe',
], 'nmap');
const NUCLEI = firstExisting([
  path.join(os.homedir(), 'Tools', 'nuclei', 'nuclei.exe'),
  path.join(os.homedir(), 'Tools', 'nuclei', 'nuclei'),
], 'nuclei');
const GITLEAKS = firstExisting([
  path.join(os.homedir(), 'Tools', 'gitleaks', 'gitleaks.exe'),
], 'gitleaks');
const TRIVY = firstExisting([
  path.join(os.homedir(), 'Tools', 'trivy', 'trivy.exe'),
], 'trivy');
const SEMGREP = firstExisting([
  path.join(os.homedir(), '.local', 'bin', 'semgrep.exe'),
  path.join(os.homedir(), '.local', 'bin', 'semgrep'),
], 'semgrep');
// checkov bringt auf Windows keine .exe mit -> ueber die pipx-venv-Python starten.
const PIPX_VENVS = process.env.PIPX_LOCAL_VENVS || path.join(os.homedir(), 'AppData', 'Local', 'pipx', 'pipx', 'venvs');
const CHECKOV_PY = firstExisting([path.join(PIPX_VENVS, 'checkov', 'Scripts', 'python.exe')], null);
const CHECKOV = firstExisting([path.join(os.homedir(), '.local', 'bin', 'checkov.exe')], 'checkov');
// retire.js (OWASP) wird ueber node + sein CLI gestartet (npm legt keine .exe an).
const NPM_GLOBAL = path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'npm', 'node_modules');
const RETIRE_JS = firstExisting([path.join(NPM_GLOBAL, 'retire', 'lib', 'cli.js')], null);
const HADOLINT = firstExisting([path.join(os.homedir(), 'Tools', 'hadolint', 'hadolint.exe')], 'hadolint');
// osv-scanner (Google): einzelnes Go-Binary, liest Lockfiles vieler Oekosysteme
// (npm, pip, Go, Cargo, Maven, Composer, Bundler ...) und gleicht gegen OSV.dev ab.
const OSV = firstExisting([
  path.join(os.homedir(), 'Tools', 'osv-scanner', 'osv-scanner.exe'),
  path.join(os.homedir(), 'Tools', 'osv-scanner', 'osv-scanner'),
], 'osv-scanner');
// grype (Anchore): Schwachstellen in Paketen/SBOM/Dateisystem.
const GRYPE = firstExisting([
  path.join(os.homedir(), 'Tools', 'grype', 'grype.exe'),
  path.join(os.homedir(), 'Tools', 'grype', 'grype'),
], 'grype');
// trufflehog: Secret-Erkennung mit vielen Detektoren (ergaenzt gitleaks).
const TRUFFLEHOG = firstExisting([
  path.join(os.homedir(), 'Tools', 'trufflehog', 'trufflehog.exe'),
  path.join(os.homedir(), 'Tools', 'trufflehog', 'trufflehog'),
], 'trufflehog');
// bandit (Python-SAST) ueber die pipx-venv-Python starten, sonst ~/.local/bin, sonst PATH.
const BANDIT_PY = firstExisting([path.join(PIPX_VENVS, 'bandit', 'Scripts', 'python.exe')], null);
const BANDIT = firstExisting([path.join(os.homedir(), '.local', 'bin', 'bandit.exe')], 'bandit');

function mapSev(s) {
  const x = String(s || '').toLowerCase();
  if (x.includes('crit')) return 'critical';
  if (x.includes('high') || x === 'error') return 'high';
  if (x.includes('med') || x.includes('mod') || x === 'warning') return 'medium';
  if (x.includes('low')) return 'low';
  return 'info';
}

// Externe Werkzeuge laufen mit minimalen Rechten: ohne Shell, ohne Geheimnisse in der Umgebung,
// Arbeitsordner = Ziel, Zeitlimit und Groessengrenze fuer die Ausgabe (siehe sandbox.js).
// Zeitlimit oder Groessengrenze erreicht = unvollstaendig -> wie abgebrochen behandeln, damit
// fehlende Befunde nicht faelschlich als "behoben" gelten.
async function runTool(cmd, args, { signal, timeoutMs = 300000, maxBytes } = {}) {
  const r = await runSandboxed(cmd, args, { signal, timeoutMs, maxBytes });
  return { ...r, aborted: !!(r.aborted || r.timedOut || r.truncated) };
}

function hostOf(target) {
  try { return new URL(/^https?:\/\//i.test(target) ? target : 'https://' + target).hostname; }
  catch { return target.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0]; }
}

// --- nmap: offene Ports / Dienste (nicht-aggressiv) --------------------
const RISKY_PORTS = {
  21: 'FTP', 23: 'Telnet', 25: 'SMTP', 135: 'MS-RPC', 139: 'NetBIOS', 445: 'SMB',
  1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
  6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
};

async function runNmap(target, { signal, onProgress = () => {} } = {}) {
  const host = hostOf(target);
  onProgress({ phase: 'active', message: `nmap: Dienste auf ${host} …` });
  // -sV Versionsscan, -Pn ohne Ping, --top-ports 200 (nicht-aggressiv, kein -A/kein Skript).
  const res = await runTool(NMAP, ['-sV', '-Pn', '-T4', '--top-ports', '200', host], { signal, timeoutMs: 240000 });
  if (!res.ok) return { findings: [], notes: [`nmap nicht ausgefuehrt (${res.error || 'Fehler'}). Installiert?`] };
  if (res.aborted) return { findings: [], notes: ['nmap abgebrochen.'] };

  const findings = [];
  const re = /^(\d+)\/tcp\s+open\s+(\S+)\s*(.*)$/gm;
  let m, open = 0;
  while ((m = re.exec(res.stdout))) {
    open++;
    const port = parseInt(m[1], 10);
    const service = m[2];
    const version = (m[3] || '').trim();
    const risky = RISKY_PORTS[port];
    findings.push(normalizeFinding({
      title: risky ? `Exponierter Dienst: ${risky} (Port ${port})` : `Offener Port ${port}/${service}`,
      severity: risky ? 'medium' : 'info',
      category: 'Config',
      location: `${host}:${port}`,
      description: `nmap: Port ${port} offen – ${service}${version ? ' (' + version + ')' : ''}.`,
      reachability: 'Von aussen per Netzwerk erreichbar.',
      impact: risky ? 'Sensible/administrative Dienste sollten nicht offen ins Internet zeigen.' : 'Zusaetzliche Angriffsflaeche.',
      remediation: risky ? 'Dienst per Firewall/VPN einschraenken oder abschalten, falls nicht benoetigt; aktuelle Version + Auth erzwingen.' : 'Pruefen, ob der Port offen sein muss; sonst per Firewall schliessen.',
      confidence: 'high',
      source: 'nmap',
    }, 'nmap'));
  }
  return { findings, notes: [`nmap: ${open} offene Port(s) auf ${host}.`] };
}

// --- nuclei: aktive Schwachstellen-Templates ---------------------------
async function runNuclei(target, { signal, onProgress = () => {} } = {}) {
  const url = /^https?:\/\//i.test(target) ? target : 'https://' + target;
  onProgress({ phase: 'active', message: `nuclei: aktive Templates gegen ${url} … (erster Lauf laedt Templates)` });
  const res = await runTool(NUCLEI, [
    '-u', url, '-jsonl', '-silent', '-disable-update-check',
    '-severity', 'low,medium,high,critical', '-rate-limit', '50', '-timeout', '10',
  ], { signal, timeoutMs: 420000 });
  if (!res.ok) return { findings: [], notes: [`nuclei nicht ausgefuehrt (${res.error || 'Fehler'}). Installiert?`] };
  if (res.aborted) return { findings: [], notes: ['nuclei abgebrochen.'] };

  const findings = [];
  for (const line of res.stdout.split(/\r?\n/)) {
    const s = line.trim();
    if (!s.startsWith('{')) continue;
    let j; try { j = JSON.parse(s); } catch { continue; }
    const info = j.info || {};
    const sev = String(info.severity || 'info').toLowerCase();
    findings.push(normalizeFinding({
      title: `nuclei: ${info.name || j['template-id'] || 'Treffer'}`,
      severity: ['critical', 'high', 'medium', 'low', 'info'].includes(sev) ? sev : 'info',
      category: 'Other',
      location: j['matched-at'] || j.host || url,
      description: `${info.name || ''}${info.description ? ' – ' + info.description : ''} (Template: ${j['template-id'] || '?'}).`.trim(),
      reachability: 'Von nuclei aktiv gegen den laufenden Dienst verifiziert.',
      impact: Array.isArray(info.tags) ? ('Tags: ' + info.tags.join(', ')) : '',
      remediation: info.remediation || 'Siehe Template-Referenz des Advisories; betroffene Komponente aktualisieren/haerten.',
      confidence: 'high',
      source: 'nuclei',
    }, 'nuclei'));
  }
  return { findings, notes: [`nuclei: ${findings.length} Treffer gegen ${url}.`] };
}

// --- gitleaks: Secret-Scan ueber Dateien/Ordner ------------------------
async function runGitleaks(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `gitleaks: Secret-Scan in ${targetPath} …` });
  // JSON direkt auf stdout ("-"); den Klartext-Secret schwaerzen wir selbst, bevor er irgendwo landet.
  const res = await runTool(GITLEAKS, ['detect', '--source', targetPath, '--no-git', '--report-format', 'json', '--report-path', '-', '--no-banner'], { signal, timeoutMs: 180000 });
  if (!res.ok) return { findings: [], notes: ['gitleaks nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['gitleaks abgebrochen.'] };
  const findings = parseGitleaks(res.stdout);
  if (findings === null) return { findings: [], notes: ['gitleaks: Ausgabe nicht lesbar.'] };
  return { findings, notes: [`gitleaks: ${findings.length} Fund(e).`] };
}
// JSON-Ausgabe -> Befunde (null = ungueltige Ausgabe).
function parseGitleaks(stdout) {
  const s = String(stdout || '').trim();
  if (!s) return [];
  let raw; try { raw = JSON.parse(s.slice(s.indexOf('['))); } catch { return null; }
  const v = check(GitleaksOutputSchema, raw);
  if (!v.ok) return null;
  return v.data.slice(0, 200).map((g) => normalizeFinding({
    ruleId: g.RuleID || 'gitleaks-secret',
    title: `gitleaks: ${g.RuleID || g.Description || 'Secret'}`,
    severity: 'high', category: 'Secrets',
    location: `${g.File || '?'}:${g.StartLine || '?'}`,
    evidence: redactSecret(g.Secret || g.Match),
    description: `${g.Description || 'Moegliches Secret'} (Regel ${g.RuleID || '?'}).`,
    reachability: 'Direkt im Code/Repo lesbar.',
    impact: 'Falls echt: Uebernahme des zugehoerigen Dienstes/Kontos.',
    remediation: 'Secret rotieren und aus Code/History entfernen; ueber Secret-Store laden.',
    confidence: 'medium',
  }, 'gitleaks'));
}

// --- trivy: Schwachstellen/Secrets/Misconfig (Dateisystem oder Container-Image) ---
function parseTrivy(stdout, fallbackTarget) {
  let raw; try { raw = JSON.parse(stdout); } catch { return null; }
  const v = check(TrivyOutputSchema, raw);
  if (!v.ok) return null;
  const findings = [];
  for (const r of v.data.Results || []) {
    const where = r.Target || fallbackTarget;
    for (const x of r.Vulnerabilities || []) findings.push(normalizeFinding({
      ruleId: x.VulnerabilityID,
      title: `trivy: ${x.PkgName}@${x.InstalledVersion} (${x.VulnerabilityID})`,
      severity: mapSev(x.Severity), category: 'Dependencies', location: where,
      package: { ecosystem: r.Type || '', name: x.PkgName || '', version: x.InstalledVersion || '', fixed: String(x.FixedVersion || '').split(/[ ,]/)[0] },
      description: `${x.Title || x.VulnerabilityID}. ${(x.Description || '').slice(0, 300)}`.trim(),
      impact: `Bekannte Schwachstelle ${x.VulnerabilityID}.`,
      remediation: x.FixedVersion ? `Auf ${x.FixedVersion} aktualisieren.` : 'Auf eine gepatchte Version aktualisieren.',
      confidence: 'high',
    }, 'trivy'));
    for (const s of r.Secrets || []) findings.push(normalizeFinding({
      ruleId: s.RuleID || 'trivy-secret',
      title: `trivy: Secret – ${s.RuleID || s.Title || 'Fund'}`,
      severity: 'high', category: 'Secrets', location: `${where}:${s.StartLine || '?'}`,
      evidence: redactSecret(s.Match),
      description: `${s.Title || 'Secret gefunden'} (${s.RuleID || '?'}).`,
      remediation: 'Secret rotieren und aus dem Code entfernen.', confidence: 'medium',
    }, 'trivy'));
    for (const mc of r.Misconfigurations || []) findings.push(normalizeFinding({
      ruleId: mc.ID || 'trivy-misconfig',
      title: `trivy: ${mc.Title || mc.ID || 'Fehlkonfiguration'}`,
      severity: mapSev(mc.Severity), category: 'Config', location: where,
      description: `${mc.Description || mc.Message || ''} (${mc.ID || ''}).`.trim(),
      remediation: mc.Resolution || 'Konfiguration gemaess Empfehlung haerten.', confidence: 'high',
    }, 'trivy'));
  }
  return findings;
}
async function runTrivyFs(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `trivy: Dateisystem-Scan in ${targetPath} … (erster Lauf laedt DB)` });
  const res = await runTool(TRIVY, ['fs', '--quiet', '--format', 'json', '--scanners', 'vuln,secret,misconfig', targetPath], { signal, timeoutMs: 360000 });
  if (!res.ok) return { findings: [], notes: ['trivy nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['trivy abgebrochen.'] };
  const findings = parseTrivy(res.stdout, targetPath);
  if (findings === null) return { findings: [], notes: ['trivy: Ausgabe nicht lesbar.'] };
  return { findings, notes: [`trivy: ${findings.length} Fund(e).`] };
}
// Container-Image (SBOM + CVE-Abgleich). Die Referenz ist vorher per Zod geprueft.
async function runTrivyImage(image, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `trivy: Container-Image ${image} … (erster Lauf laedt DB und Image)` });
  const res = await runTool(TRIVY, ['image', '--quiet', '--format', 'json', '--scanners', 'vuln,secret,misconfig', image], { signal, timeoutMs: 600000 });
  if (!res.ok) return { findings: [], notes: ['Container-Image-Scan braucht trivy – nicht installiert (https://trivy.dev).'], missing: true };
  if (res.aborted) return { findings: [], notes: ['trivy abgebrochen.'] };
  const findings = parseTrivy(res.stdout, image);
  if (findings === null) return { findings: [], notes: [`trivy: Image ${image} konnte nicht geprueft werden. ${String(res.stderr || '').split('\n').filter(Boolean).slice(-1)[0] || ''}`.trim()] };
  return { findings, notes: [`trivy (Image ${image}): ${findings.length} Fund(e).`] };
}

// --- semgrep: statische Code-Analyse (SAST) ----------------------------
async function runSemgrep(targetPath, { signal, onProgress = () => {}, rulesFile } = {}) {
  onProgress({ phase: 'active', message: `semgrep: SAST in ${targetPath} …` });
  // Per Feed aktuell gehaltene Regeln (feeds.js) nutzen, sonst die Registry ("auto")
  const config = rulesFile && fs.existsSync(rulesFile) ? rulesFile : 'auto';
  const res = await runTool(SEMGREP, ['scan', '--config', config, '--json', '--quiet', ...(config !== 'auto' ? ['--metrics', 'off'] : []), targetPath], { signal, timeoutMs: 360000 });
  if (!res.ok) return { findings: [], notes: ['semgrep nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['semgrep abgebrochen.'] };
  let raw; try { raw = JSON.parse(res.stdout); } catch { return { findings: [], notes: ['semgrep: Ausgabe nicht lesbar.'] }; }
  const parsed = check(SemgrepOutputSchema, raw);
  if (!parsed.ok) return { findings: [], notes: ['semgrep: unerwartetes Ausgabeformat – ' + parsed.error] };
  const findings = parsed.data.results.slice(0, 300).map((r) => normalizeFinding({
    ruleId: r.check_id,
    title: `semgrep: ${r.check_id}`,
    severity: mapSev(r.extra && r.extra.severity), category: 'Other',
    location: `${r.path}:${r.start && r.start.line}`,
    description: (r.extra && r.extra.message) || r.check_id,
    remediation: (r.extra && r.extra.fix) || 'Gemaess Regel-Empfehlung beheben.',
    confidence: 'medium',
  }, 'semgrep'));
  return { findings, notes: [`semgrep: ${findings.length} Fund(e).`] };
}

// --- checkov: Infrastruktur-/IaC-Analyse -------------------------------
async function runCheckov(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `checkov: IaC-Analyse in ${targetPath} …` });
  let mode = '-d';
  try { if (!fs.statSync(targetPath).isDirectory()) mode = '-f'; } catch { /* default -d */ }
  const cmd = CHECKOV_PY || CHECKOV;
  const pre = CHECKOV_PY ? ['-m', 'checkov.main'] : [];
  const res = await runTool(cmd, [...pre, mode, targetPath, '-o', 'json', '--compact', '--quiet'], { signal, timeoutMs: 300000 });
  if (!res.ok) return { findings: [], notes: ['checkov nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['checkov abgebrochen.'] };
  let data; try { data = JSON.parse(res.stdout); } catch { return { findings: [], notes: ['checkov: keine IaC-Dateien oder Ausgabe nicht lesbar.'] }; }
  const blocks = Array.isArray(data) ? data : [data];
  const findings = [];
  for (const b of blocks) {
    const failed = (b && b.results && b.results.failed_checks) || [];
    for (const c of failed) {
      const line = Array.isArray(c.file_line_range) ? c.file_line_range[0] : '';
      findings.push(normalizeFinding({
        title: `checkov: ${c.check_id} – ${c.check_name}`,
        severity: c.severity ? mapSev(c.severity) : 'medium',
        category: 'Config',
        location: `${c.file_path || c.repo_file_path || '?'}${line ? ':' + line : ''}`,
        description: `${c.check_name} (${c.check_id}).`,
        reachability: 'Infrastruktur-/Konfigurations-Fehler laut Policy.',
        impact: 'Fehlkonfiguration kann Angriffsflaeche oder Datenabfluss ermoeglichen.',
        remediation: c.guideline || 'Gemaess Checkov-Richtlinie korrigieren.',
        confidence: 'high',
      }, 'checkov'));
    }
  }
  return { findings, notes: [`checkov: ${findings.length} Fund(e).`] };
}

// --- retire.js: verwundbare JS-Bibliotheken (auch gebuendelt) ----------
async function runRetire(targetPath, { signal, onProgress = () => {} } = {}) {
  if (!RETIRE_JS) return { findings: [], notes: ['retire.js nicht gefunden (global via npm installieren?).'] };
  onProgress({ phase: 'active', message: `retire.js: verwundbare JS-Libs in ${targetPath} …` });
  const tmp = path.join(os.tmpdir(), `vigil-retire-${Date.now()}.json`);
  const res = await runTool('node', [RETIRE_JS, '--path', targetPath, '--outputformat', 'json', '--outputpath', tmp], { signal, timeoutMs: 180000 });
  if (!res.ok) return { findings: [], notes: ['retire.js nicht ausgefuehrt (node fehlt?).'] };
  if (res.aborted) return { findings: [], notes: ['retire.js abgebrochen.'] };
  let data; try { data = JSON.parse(fs.readFileSync(tmp, 'utf8')); } catch { data = null; }
  try { fs.unlinkSync(tmp); } catch { /* ignore */ }
  if (!data) return { findings: [], notes: ['retire.js: Ausgabe nicht lesbar.'] };
  const findings = [];
  for (const d of data.data || []) {
    for (const r of d.results || []) {
      for (const v of r.vulnerabilities || []) {
        const ids = v.identifiers || {};
        const cve = Array.isArray(ids.CVE) && ids.CVE.length ? ' (' + ids.CVE.join(', ') + ')' : '';
        findings.push(normalizeFinding({
          title: `retire.js: ${r.component} ${r.version} verwundbar${cve}`,
          severity: mapSev(v.severity), category: 'Dependencies', location: d.file || targetPath,
          description: `${r.component}@${r.version}: ${ids.summary || (v.info || []).join(' ') || 'bekannte Schwachstelle'}`.slice(0, 400),
          impact: 'Bekannte Schwachstelle in eingebundener JS-Bibliothek.',
          remediation: 'Bibliothek auf eine gepatchte Version aktualisieren.',
          confidence: 'high',
        }, 'retire'));
      }
    }
  }
  return { findings, notes: [`retire.js: ${findings.length} Fund(e).`] };
}

// --- hadolint: Dockerfile-Linter (inkl. ShellCheck in RUN) -------------
function findDockerfiles(root, max = 50) {
  const out = [];
  const stack = [root];
  const skip = new Set(['node_modules', '.git', '.svn', 'dist', 'build', 'out', 'target', '.next', 'vendor']);
  while (stack.length && out.length < max) {
    const dir = stack.pop();
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!skip.has(e.name)) stack.push(full); }
      else if (/^dockerfile$|\.dockerfile$|^dockerfile\./i.test(e.name)) out.push(full);
    }
  }
  return out;
}

async function runHadolint(targetPath, { signal, onProgress = () => {} } = {}) {
  let files;
  try { files = fs.statSync(targetPath).isDirectory() ? findDockerfiles(targetPath) : [targetPath]; }
  catch { files = [targetPath]; }
  if (!files.length) return { findings: [], notes: ['hadolint: keine Dockerfiles gefunden.'] };
  onProgress({ phase: 'active', message: `hadolint: ${files.length} Dockerfile(s) in ${targetPath} …` });
  const findings = [];
  let notInstalled = false;
  for (const f of files) {
    if (signal && signal.aborted) return { findings, notes: ['hadolint abgebrochen.'] };
    const res = await runTool(HADOLINT, ['--format', 'json', '--no-fail', f], { signal, timeoutMs: 60000 });
    if (!res.ok) { notInstalled = true; break; }
    let arr; try { arr = JSON.parse(res.stdout); } catch { arr = []; }
    for (const h of arr || []) findings.push(normalizeFinding({
      title: `hadolint: ${h.code} – ${h.message}`,
      severity: mapSev(h.level), category: 'Config',
      location: `${h.file || f}:${h.line || '?'}`,
      description: `${h.message} (${h.code}).`,
      reachability: 'Dockerfile-Best-Practice-/Sicherheitsregel.',
      remediation: 'Gemaess hadolint-Regel korrigieren (siehe Regel-Code).',
      confidence: 'high',
    }, 'hadolint'));
  }
  if (notInstalled) return { findings: [], notes: ['hadolint nicht ausgefuehrt (nicht installiert?).'] };
  return { findings, notes: [`hadolint: ${findings.length} Fund(e) in ${files.length} Dockerfile(s).`] };
}

// --- osv-scanner: verwundbare Abhaengigkeiten ueber viele Oekosysteme ----
// Sammelt die behobenen Versionen einer Schwachstelle aus den OSV-Bereichen.
function osvFixedVersions(v) {
  const out = new Set();
  for (const a of v.affected || []) {
    for (const r of a.ranges || []) {
      for (const e of r.events || []) if (e && e.fixed) out.add(e.fixed);
    }
  }
  return [...out];
}

// Reine Funktion (ohne Prozess) fuer die osv-scanner-JSON-Ausgabe -> Befunde.
// Dadurch getrennt testbar, ohne dass das Binary installiert sein muss.
function parseOsv(data, sourcePath) {
  const findings = [];
  for (const r of (data && data.results) || []) {
    const where = (r.source && r.source.path) || sourcePath || '?';
    for (const p of r.packages || []) {
      const pkg = p.package || {};
      // Hoechste CVSS-Bewertung je Schwachstellen-ID aus den Gruppen merken.
      const scoreById = {};
      for (const g of p.groups || []) {
        if (g.max_severity == null || g.max_severity === '') continue;
        for (const id of g.ids || []) scoreById[id] = g.max_severity;
      }
      for (const v of p.vulnerabilities || []) {
        const aliases = Array.isArray(v.aliases) ? v.aliases : [];
        const cve = aliases.filter((a) => /^CVE-/i.test(a));
        const cvss = clampScore(scoreById[v.id]);
        const fromStr = v.database_specific && v.database_specific.severity
          ? mapSev(v.database_specific.severity) : null;
        const severity = cvssToSeverity(cvss) || fromStr || 'medium';
        const fixed = osvFixedVersions(v);
        const summary = v.summary || (v.details || '').slice(0, 300) || 'Bekannte Schwachstelle';
        findings.push(normalizeFinding({
          title: `osv-scanner: ${pkg.name || '?'}@${pkg.version || '?'} (${v.id}${cve.length ? ', ' + cve.join(', ') : ''})`,
          severity, cvss, category: 'Dependencies', location: where,
          package: { ecosystem: pkg.ecosystem || '', name: pkg.name || '', version: pkg.version || '', fixed: fixed[0] || '' },
          description: `${summary} – Paket ${pkg.name || '?'} ${pkg.version || '?'}${pkg.ecosystem ? ' (' + pkg.ecosystem + ')' : ''}.`.trim(),
          reachability: 'In einer eingebundenen Abhaengigkeit laut Lockfile.',
          impact: `Bekannte Schwachstelle ${v.id}${cve.length ? ' / ' + cve.join(', ') : ''}.`,
          remediation: fixed.length
            ? `Auf eine gepatchte Version aktualisieren (behoben in: ${fixed.join(', ')}).`
            : 'Auf eine gepatchte Version aktualisieren bzw. dem Advisory folgen.',
          confidence: 'high',
        }, 'osv-scanner'));
      }
    }
  }
  return findings.slice(0, 300);
}

async function runOsvScanner(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `osv-scanner: Abhaengigkeiten in ${targetPath} gegen OSV.dev …` });
  let isDir = false;
  try { isDir = fs.statSync(targetPath).isDirectory(); } catch { /* als Datei behandeln */ }
  // -r durchsucht einen Ordner rekursiv nach Lockfiles/SBOMs; bei einer Datei genuegt der Pfad.
  const args = ['--format', 'json', ...(isDir ? ['-r'] : []), targetPath];
  const res = await runTool(OSV, args, { signal, timeoutMs: 240000 });
  if (!res.ok) return { findings: [], notes: ['osv-scanner nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['osv-scanner abgebrochen.'] };
  // Exit-Code 1 = Schwachstellen gefunden (ist ok); JSON liegt auf stdout.
  let j; try { j = JSON.parse(res.stdout); }
  catch { return { findings: [], notes: ['osv-scanner: keine unterstuetzten Lockfiles gefunden oder Ausgabe nicht lesbar.'] }; }
  const findings = parseOsv(j, targetPath);
  return { findings, notes: [`osv-scanner: ${findings.length} Fund(e).`] };
}

// --- grype (Anchore): Schwachstellen in Paketen/SBOM/Dateisystem ---------
function parseGrype(data, sourcePath) {
  const findings = [];
  for (const m of (data && data.matches) || []) {
    const v = m.vulnerability || {};
    const a = m.artifact || {};
    const loc = (Array.isArray(a.locations) && a.locations[0] && a.locations[0].path) || sourcePath || '?';
    const fixed = (v.fix && Array.isArray(v.fix.versions) && v.fix.versions.length) ? v.fix.versions.join(', ') : '';
    const related = (m.relatedVulnerabilities || []).map((r) => r && r.id).filter((id) => id && id !== v.id);
    findings.push(normalizeFinding({
      title: `grype: ${a.name || '?'}@${a.version || '?'} (${v.id || '?'})`,
      severity: mapSev(v.severity), category: 'Dependencies', location: loc,
      package: { ecosystem: a.language || a.type || '', name: a.name || '', version: a.version || '', fixed: (v.fix && v.fix.versions && v.fix.versions[0]) || '' },
      description: `${v.description || v.id || 'Bekannte Schwachstelle'}`.slice(0, 400),
      reachability: 'In einem installierten Paket/einer Abhaengigkeit gefunden.',
      impact: `Bekannte Schwachstelle ${v.id || ''}${related.length ? ' / ' + related.join(', ') : ''}${a.type ? ' (' + a.type + ')' : ''}.`,
      remediation: fixed ? `Auf eine gepatchte Version aktualisieren (behoben in: ${fixed}).` : 'Auf eine gepatchte Version aktualisieren bzw. dem Advisory folgen.',
      confidence: 'high',
    }, 'grype'));
  }
  return findings.slice(0, 300);
}
async function runGrype(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `grype: Schwachstellen in ${targetPath} … (erster Lauf laedt DB)` });
  let isDir = false;
  try { isDir = fs.statSync(targetPath).isDirectory(); } catch { /* als Datei behandeln */ }
  const arg = isDir ? `dir:${targetPath}` : targetPath;
  const res = await runTool(GRYPE, [arg, '-o', 'json', '-q'], { signal, timeoutMs: 360000 });
  if (!res.ok) return { findings: [], notes: ['grype nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['grype abgebrochen.'] };
  let j; try { j = JSON.parse(res.stdout); } catch { return { findings: [], notes: ['grype: Ausgabe nicht lesbar.'] }; }
  const findings = parseGrype(j, targetPath);
  return { findings, notes: [`grype: ${findings.length} Fund(e).`] };
}

// --- trufflehog: Secret-Erkennung mit Detektoren (ergaenzt gitleaks) ------
function parseTrufflehog(stdout, sourcePath) {
  const findings = [];
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const s = line.trim();
    if (!s.startsWith('{')) continue;
    let j; try { j = JSON.parse(s); } catch { continue; }
    if (!j.DetectorName && !j.Raw && !j.Redacted) continue;
    const fsmeta = j.SourceMetadata && j.SourceMetadata.Data && j.SourceMetadata.Data.Filesystem;
    const where = (fsmeta && fsmeta.file) || sourcePath || '?';
    const lineNo = fsmeta && fsmeta.line != null ? ':' + fsmeta.line : '';
    findings.push(normalizeFinding({
      ruleId: `trufflehog-${String(j.DetectorName || 'secret').toLowerCase()}`,
      title: `trufflehog: ${j.DetectorName || 'Secret'}${j.Verified ? ' – verifiziert' : ''}`,
      severity: j.Verified ? 'critical' : 'high', category: 'Secrets', location: `${where}${lineNo}`,
      evidence: redactSecret(j.Raw || j.Redacted),
      description: `Moegliches Secret vom Typ ${j.DetectorName || '?'}.${j.Verified ? ' Als gueltig verifiziert.' : ''}`,
      reachability: 'Direkt im Code/in der Datei lesbar.',
      impact: j.Verified ? 'Verifiziert gueltig: direkter Zugriff auf den zugehoerigen Dienst moeglich.' : 'Falls echt: Uebernahme des zugehoerigen Dienstes/Kontos.',
      remediation: 'Secret rotieren und aus Code/History entfernen; ueber einen Secret-Store laden.',
      confidence: j.Verified ? 'high' : 'medium',
    }, 'trufflehog'));
  }
  return findings.slice(0, 200);
}
async function runTrufflehog(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `trufflehog: Secret-Scan in ${targetPath} …` });
  // --no-verification = rein passiv (keine Anfragen an Dienste, um Secrets zu pruefen).
  const res = await runTool(TRUFFLEHOG, ['filesystem', targetPath, '--json', '--no-verification'], { signal, timeoutMs: 240000 });
  if (!res.ok) return { findings: [], notes: ['trufflehog nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['trufflehog abgebrochen.'] };
  const findings = parseTrufflehog(res.stdout, targetPath);
  return { findings, notes: [`trufflehog: ${findings.length} Fund(e).`] };
}

// --- bandit: Python-SAST (ergaenzt semgrep bei Python-Code) ---------------
function parseBandit(data, sourcePath) {
  const findings = [];
  for (const r of (data && data.results) || []) {
    findings.push(normalizeFinding({
      title: `bandit: ${r.test_id || ''} ${r.test_name || ''}`.trim(),
      severity: mapSev(r.issue_severity), category: 'Other',
      location: `${r.filename || sourcePath || '?'}:${r.line_number || '?'}`,
      description: `${r.issue_text || r.test_name || 'Python-Sicherheitshinweis'} (Vertrauen: ${r.issue_confidence || '?'}).`,
      reachability: 'Von bandit im Python-Code erkannt.',
      remediation: r.more_info ? `Mehr Infos/Behebung: ${r.more_info}` : 'Gemaess bandit-Regel beheben.',
      confidence: 'medium',
    }, 'bandit'));
  }
  return findings.slice(0, 300);
}
async function runBandit(targetPath, { signal, onProgress = () => {} } = {}) {
  onProgress({ phase: 'active', message: `bandit: Python-SAST in ${targetPath} …` });
  const cmd = BANDIT_PY || BANDIT;
  const pre = BANDIT_PY ? ['-m', 'bandit'] : [];
  let isDir = false;
  try { isDir = fs.statSync(targetPath).isDirectory(); } catch { /* Datei */ }
  const args = [...pre, ...(isDir ? ['-r'] : []), targetPath, '-f', 'json', '-q'];
  const res = await runTool(cmd, args, { signal, timeoutMs: 300000 });
  if (!res.ok) return { findings: [], notes: ['bandit nicht ausgefuehrt (nicht installiert?).'] };
  if (res.aborted) return { findings: [], notes: ['bandit abgebrochen.'] };
  // bandit nutzt Exit-Code 1 bei Funden; JSON steht trotzdem auf stdout.
  let j; try { j = JSON.parse(res.stdout); } catch { return { findings: [], notes: ['bandit: keine Python-Dateien oder Ausgabe nicht lesbar.'] }; }
  const findings = parseBandit(j, targetPath);
  return { findings, notes: [`bandit: ${findings.length} Fund(e).`] };
}

// Fuer die Feed-Verwaltung: ist ein Werkzeug installiert? (nur "--version", sonst nichts)
async function toolAvailable(which) {
  const cmd = { nuclei: NUCLEI, semgrep: SEMGREP }[which];
  if (!cmd) return false;
  const r = await runTool(cmd, ['--version'], { timeoutMs: 20000 });
  return !!(r.ok && r.code === 0);
}
// nuclei-Vorlagen ueber nuclei selbst aktualisieren (laedt nur Vorlagen, prueft kein Ziel)
async function updateNucleiTemplates() {
  const r = await runTool(NUCLEI, ['-update-templates', '-silent', '-disable-update-check'], { timeoutMs: 600000 });
  if (!r.ok || r.code !== 0) return { ok: false, error: r.error || `nuclei meldete Code ${r.code}` };
  return { ok: true };
}

module.exports = { runTool, runNmap, runNuclei, runGitleaks, parseGitleaks, runTrivyFs, runTrivyImage, parseTrivy, runSemgrep, runCheckov, runRetire, runHadolint, runOsvScanner, parseOsv, runGrype, parseGrype, runTrufflehog, parseTrufflehog, runBandit, parseBandit, NMAP, NUCLEI, GITLEAKS, TRIVY, SEMGREP, CHECKOV, RETIRE_JS, HADOLINT, OSV, GRYPE, TRUFFLEHOG, BANDIT, toolAvailable, updateNucleiTemplates };
