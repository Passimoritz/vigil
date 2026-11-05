'use strict';

// Lieferkette, Container-Build und CI – rein statisch auf den eingelesenen Dateien:
//  lockfile-drift   Lockfile passt nicht zum Manifest (npm, Poetry, Pipenv, Bundler)
//  dockerfile-audit ADD mit URL, curl|bash, fehlender HEALTHCHECK, Geheimnisse in ARG/ENV
//  gha-audit        GitHub Actions: Script-Injection, fehlende Rechte, id-token, Self-hosted-Runner
//  ci-audit         GitLab CI, Azure Pipelines, Jenkinsfile
// Nichts wird ausgefuehrt; Geheimnisse erscheinen nur geschwaerzt.

const { normalizeFinding, redactSecret } = require('../schema');

const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const fileName = (u) => base(u).split('/').pop().toLowerCase();
const dirOf = (u) => { const b = base(u); const i = b.lastIndexOf('/'); return i < 0 ? '' : b.slice(0, i); };
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const list = (arr, n = 5) => arr.slice(0, n).join(', ') + (arr.length > n ? ' …' : '');

function mk(module, u, idx, o) {
  return normalizeFinding({
    confidence: 'high', ...o,
    location: idx == null || idx < 0 ? base(u) : `${base(u)}:${lineOf(u.content || '', idx)}`,
    sourceModule: module,
  }, module);
}

// Namen, die nach Zugangsdaten klingen (Variablen in Dockerfile/CI)
const SECRET_NAME = /(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH_?KEY)/i;
// Werte, die nur auf eine andere Variable/Secret-Quelle verweisen, sind kein Klartext
const IS_REFERENCE = /^\s*["']?\s*(\$\{\{|\$\{|\$\(|\$[A-Za-z_]|%[A-Za-z_]|<[A-Za-z_ -]+>|credentials\(|\{\{)/;
const PLACEHOLDER = /^(changeme|change_me|xxx+|\*+|todo|placeholder|example|your[-_]?\w*|dummy|test|none|null|true|false|\d{1,5})$/i;
const CURL_PIPE = /\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k)?sh\b|\b(?:ba)?sh\s+<\(\s*(?:curl|wget)\b|\bsh\s+-c\s+["']?\$\((?:curl|wget)\b/;

// --- Lockfile passt nicht zum Manifest ------------------------------------------------------
const pyName = (n) => String(n).toLowerCase().replace(/[-_.]+/g, '-');
// Abschnitte einer TOML-Datei grob lesen: { 'tool.poetry.dependencies': { name: wert } }
function tomlSections(c) {
  const out = {}; let cur = '';
  for (const raw of String(c).split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '');
    const h = line.match(/^\s*\[([^\]\[]+)\]\s*$/);
    if (h) { cur = h[1].trim(); out[cur] = out[cur] || {}; continue; }
    const kv = line.match(/^\s*["']?([A-Za-z0-9_.-]+)["']?\s*=\s*(.+)$/);
    if (kv && cur) out[cur][kv[1]] = kv[2].trim();
  }
  return out;
}
// PEP 621: dependencies = [ "requests>=2", ... ] (auch mehrzeilig)
function pep621Deps(c) {
  const m = String(c).match(/^\s*\[project\][\s\S]*?^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m);
  if (!m) return [];
  return [...m[1].matchAll(/["']\s*([A-Za-z0-9][A-Za-z0-9._-]*)/g)].map((x) => x[1]);
}

function npmDrift(pkgU, lockU) {
  let pj, pl; try { pj = JSON.parse(pkgU.content); pl = JSON.parse(lockU.content); } catch { return null; }
  const want = { ...(pj.dependencies || {}), ...(pj.devDependencies || {}), ...(pj.optionalDependencies || {}) };
  const root = pl.packages && pl.packages[''];
  const have = root ? { ...(root.dependencies || {}), ...(root.devDependencies || {}), ...(root.optionalDependencies || {}) } : null;
  const missing = [], changed = [], extra = [];
  for (const [n, spec] of Object.entries(want)) {
    if (have) { if (!(n in have)) missing.push(n); else if (String(have[n]) !== String(spec)) changed.push(`${n} (${spec} ≠ ${have[n]})`); }
    else if (!(pl.dependencies || {})[n]) missing.push(n);
  }
  if (have) for (const n of Object.keys(have)) if (!(n in want)) extra.push(n);
  return { missing, changed, extra, fix: 'npm install ausführen (aktualisiert package-lock.json) und das Lockfile mit einchecken; in CI npm ci verwenden – das bricht bei Abweichungen ab.' };
}
function poetryDrift(pyU, lockU) {
  const s = tomlSections(pyU.content || '');
  const names = new Set();
  for (const [sec, kv] of Object.entries(s)) if (/^tool\.poetry\.(dependencies|dev-dependencies|group\.[\w-]+\.dependencies)$/.test(sec)) for (const k of Object.keys(kv)) if (k.toLowerCase() !== 'python') names.add(k);
  for (const n of pep621Deps(pyU.content)) names.add(n);
  const locked = new Set([...String(lockU.content || '').matchAll(/^\s*name\s*=\s*"([^"]+)"/gm)].map((m) => pyName(m[1])));
  if (!locked.size) return null;
  return { missing: [...names].filter((n) => !locked.has(pyName(n))), changed: [], extra: [], fix: 'poetry lock ausführen und poetry.lock mit einchecken; in CI poetry install --sync bzw. poetry check --lock verwenden.' };
}
function pipenvDrift(pipU, lockU) {
  let pl; try { pl = JSON.parse(lockU.content); } catch { return null; }
  const s = tomlSections(pipU.content || '');
  const norm = (o) => new Set(Object.keys(o || {}).map(pyName));
  const def = norm(pl.default), dev = norm(pl.develop);
  const missing = [
    ...Object.keys(s.packages || {}).filter((n) => !def.has(pyName(n))),
    ...Object.keys(s['dev-packages'] || {}).filter((n) => !dev.has(pyName(n)) && !def.has(pyName(n))),
  ];
  return { missing, changed: [], extra: [], fix: 'pipenv lock ausführen und Pipfile.lock mit einchecken; in CI pipenv install --deploy verwenden – das bricht bei Abweichungen ab.' };
}
function bundlerDrift(gemU, lockU) {
  const gems = [...String(gemU.content || '').matchAll(/^\s*gem\s+["']([\w.-]+)["']/gm)].map((m) => m[1]);
  const lines = String(lockU.content || '').split(/\r?\n/);
  const at = lines.findIndex((l) => /^DEPENDENCIES\s*$/.test(l));
  if (at < 0) return null;
  const locked = [];
  for (let i = at + 1; i < lines.length && /^\s/.test(lines[i]); i++) { const m = lines[i].match(/^\s{2}([\w.-]+)/); if (m) locked.push(m[1]); }
  const lockedSet = new Set(locked), gemSet = new Set(gems);
  const extra = /^\s*gemspec\b/m.test(gemU.content || '') ? [] : locked.filter((n) => !gemSet.has(n));
  return { missing: gems.filter((n) => !lockedSet.has(n)), changed: [], extra, fix: 'bundle install ausführen und Gemfile.lock mit einchecken; in CI bundle config set frozen true verwenden – das bricht bei Abweichungen ab.' };
}

const PAIRS = [
  ['package.json', ['package-lock.json', 'npm-shrinkwrap.json'], npmDrift],
  ['pyproject.toml', ['poetry.lock'], poetryDrift],
  ['pipfile', ['pipfile.lock'], pipenvDrift],
  ['gemfile', ['gemfile.lock'], bundlerDrift],
];

function lockDrift(units) {
  const out = [];
  const M = 'lockfile-drift';
  const byDir = new Map();
  for (const u of units) { const d = dirOf(u); if (!byDir.has(d)) byDir.set(d, new Map()); byDir.get(d).set(fileName(u), u); }
  for (const files of byDir.values()) {
    for (const [manifest, locks, fn] of PAIRS) {
      const m = files.get(manifest);
      const lockName = locks.find((l) => files.has(l));
      if (!m || !lockName) continue;
      const l = files.get(lockName);
      const r = fn(m, l);
      if (!r || (!r.missing.length && !r.changed.length && !r.extra.length)) continue;
      // Jeder Satz mit eigenem festen Ende – so ordnet die Uebersetzung (findings-i18n.js) die Saetze eindeutig zu
      const parts = [`Manifest und Lockfile widersprechen sich (${base(m).split('/').pop()} ↔ ${base(l).split('/').pop()}) – folgende Pakete sind betroffen.`];
      if (r.missing.length) parts.push(`Fehlt im Lockfile: ${list(r.missing)} (im Manifest, aber nicht gesperrt).`);
      if (r.changed.length) parts.push(`Andere Versionsangabe im Lockfile: ${list(r.changed)} (Manifest ≠ Lockfile).`);
      if (r.extra.length) parts.push(`Nur noch im Lockfile: ${list(r.extra)} (aus dem Manifest entfernt).`);
      parts.push('Wer installiert, bekommt dann nicht das, was im Manifest steht – oder der Build löst Versionen frei neu auf, ohne geprüfte Prüfsummen.');
      out.push(mk(M, l, null, {
        ruleId: 'lockfile-drift', severity: 'medium', category: 'Dependencies',
        title: `Lockfile passt nicht zum Manifest: ${base(l).split('/').pop()}`,
        description: parts.join(' '),
        impact: 'Ungeprüfte Paketversionen gelangen in den Build; kompromittierte Updates fallen so nicht auf.',
        remediation: r.fix,
      }));
    }
  }
  return out;
}

// --- Dockerfile (erweitert) -----------------------------------------------------------------
// Anweisungen mit Fortsetzungszeilen (\ am Zeilenende) zusammenfassen
function instructions(c) {
  const out = [];
  const lines = String(c).split('\n');
  let off = 0;
  for (let i = 0; i < lines.length; i++) {
    const start = off;
    let text = lines[i];
    off += lines[i].length + 1;
    while (/\\\s*\r?$/.test(text) && i + 1 < lines.length) { text = text.replace(/\\\s*\r?$/, ' ') + lines[++i]; off += lines[i].length + 1; }
    const m = text.match(/^\s*([A-Za-z]+)\s+([\s\S]*)$/);
    if (m && !/^\s*#/.test(text)) out.push({ cmd: m[1].toUpperCase(), args: m[2].trim(), at: start });
  }
  return out;
}
// "ENV A=1 B=2" bzw. "ENV A 1" -> [[A,1],[B,2]]
function envPairs(args) {
  if (!/=/.test(args.split(/\s+/)[0] || '')) { const m = args.match(/^(\S+)\s+([\s\S]*)$/); return m ? [[m[1], m[2]]] : [[args, '']]; }
  return [...args.matchAll(/([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|'[^']*'|\S*)/g)].map((m) => [m[1], m[2].replace(/^["']|["']$/g, '')]);
}

function dockerfile(units) {
  const out = [];
  const M = 'dockerfile-audit';
  for (const u of units) {
    const n = fileName(u);
    if (!(n === 'dockerfile' || /\.dockerfile$/.test(n) || /^dockerfile\.[\w.-]+$/.test(n)) || n.endsWith('.dockerignore')) continue;
    const ins = instructions(u.content || '');
    if (!ins.some((x) => x.cmd === 'FROM')) continue;
    for (const x of ins) {
      if (x.cmd === 'ADD') {
        const srcs = x.args.split(/\s+/).filter((a) => !a.startsWith('--'));
        const url = srcs.find((a) => /^(https?|git):\/\//i.test(a) || /^git@/.test(a));
        if (url && !/--checksum=/.test(x.args)) out.push(mk(M, u, x.at, { ruleId: 'docker-add-url', severity: 'medium', category: 'Dependencies', title: `ADD lädt Datei aus dem Internet: ${url.slice(0, 120)}`, description: 'ADD holt die Datei bei jedem Build neu – ohne Prüfsumme. Ändert jemand die Datei auf dem Server oder schaltet sich dazwischen, landet unbemerkt fremder Inhalt im Image.', impact: 'Manipulierte Dateien oder Programme im fertigen Image.', remediation: 'Datei mit curl laden und per sha256sum -c prüfen oder ADD --checksum=sha256:<hash> verwenden; für lokale Dateien COPY statt ADD.' }));
      }
      if (x.cmd === 'RUN' && CURL_PIPE.test(x.args)) out.push(mk(M, u, x.at, { ruleId: 'docker-curl-pipe-sh', severity: 'high', category: 'Dependencies', title: 'Skript aus dem Internet wird beim Build direkt ausgeführt', description: `RUN führt aus, was der Server gerade liefert – ohne Prüfsumme und meist als root. Fundstelle: \`${x.args.replace(/\s+/g, ' ').slice(0, 120)}\``, impact: 'Wer den Server oder die Verbindung kontrolliert, bestimmt den Inhalt des Images.', remediation: 'Skript herunterladen, Prüfsumme kontrollieren (sha256sum -c) und erst dann ausführen – oder ein Paket aus der Paketverwaltung verwenden.' }));
      if (x.cmd === 'ENV' || x.cmd === 'ARG') {
        for (const [k, v] of envPairs(x.args)) {
          if (!SECRET_NAME.test(k) || /_(FILE|PATH|DIR|URL|NAME|USER|ID|HEADER|LENGTH)$/i.test(k)) continue;
          const literal = v && !IS_REFERENCE.test(v) && !PLACEHOLDER.test(v.trim());
          if (x.cmd === 'ENV' && !literal) continue;
          out.push(mk(M, u, x.at, {
            ruleId: x.cmd === 'ENV' ? 'docker-secret-env' : 'docker-secret-arg', severity: literal ? 'high' : 'medium', category: 'Secrets',
            ...(literal ? { evidence: redactSecret(v) } : {}),
            title: `Geheimnis in ${x.cmd} landet im Image: ${k}`,
            description: x.cmd === 'ENV' ? 'Werte aus ENV stehen in den Metadaten jedes Containers und Images – jeder mit Zugriff auf das Image liest sie mit docker inspect.' : 'Build-Argumente stehen in der Image-Historie (docker history) – auch wenn sie im fertigen Container nicht mehr gesetzt sind.',
            impact: 'Wer das Image bekommt (Registry, Export, Weitergabe), bekommt den Zugang mit.',
            remediation: 'Geheimnisse beim Build über RUN --mount=type=secret übergeben und zur Laufzeit als Umgebungsvariable oder Secret einspielen. Einen bereits verbauten Schlüssel beim Anbieter sperren und neu erzeugen.',
          }));
        }
      }
    }
    if (!ins.some((x) => x.cmd === 'HEALTHCHECK')) out.push(mk(M, u, null, { ruleId: 'docker-no-healthcheck', severity: 'info', category: 'Config', confidence: 'medium', title: 'Kein HEALTHCHECK im Dockerfile', description: 'Ohne HEALTHCHECK merkt Docker nicht, wenn die Anwendung hängt – der Container gilt weiter als gesund und wird nicht neu gestartet.', impact: 'Ausfälle bleiben länger unbemerkt.', remediation: 'HEALTHCHECK CMD mit einem schnellen Aufruf ergänzen, z. B. HEALTHCHECK CMD curl -fs http://localhost:8080/health || exit 1 (bzw. das Gegenstück im Orchestrator).' }));
  }
  return out;
}

// --- GitHub Actions (erweitert) -------------------------------------------------------------
// Vom Angreifer steuerbare Kontexte (Titel, Texte, Branch-Namen von Forks)
const UNTRUSTED = /\$\{\{\s*(github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[\w*]+\.page_name|commits\.[\w*]+\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))))\s*\}\}/g;
// run:/script:-Bloecke samt eingerueckter Folgezeilen
function scriptBlocks(c) {
  const lines = String(c).split('\n');
  const out = [];
  let off = 0;
  for (let i = 0; i < lines.length; i++) {
    const start = off; off += lines[i].length + 1;
    const m = lines[i].match(/^(\s*)(-\s+)?(run|script):\s*(.*)$/);
    if (!m) continue;
    const indent = m[1].length + (m[2] ? m[2].length : 0);
    let text = m[4];
    if (/^[|>][-+]?\d*\s*$/.test(m[4])) {
      while (i + 1 < lines.length && (/^\s*$/.test(lines[i + 1]) || lines[i + 1].match(/^\s*/)[0].length > indent)) { text += '\n' + lines[++i]; off += lines[i].length + 1; }
    }
    out.push({ text, at: start + m[0].length - m[4].length }); // at = Beginn des Werts (Text ist zusammenhaengend)
  }
  return out;
}
const OIDC_USER = /aws-actions\/configure-aws-credentials|google-github-actions\/auth|azure\/login|sigstore|cosign|actions\/attest|pypa\/gh-action-pypi-publish|--provenance|ACTIONS_ID_TOKEN_REQUEST|getIDToken|hashicorp\/vault-action|id-token-for|oidc/i;

function githubActions(units) {
  const out = [];
  const M = 'gha-audit';
  for (const u of units) {
    if (!/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(base(u))) continue;
    const c = u.content || '';
    const seen = new Set();
    for (const b of scriptBlocks(c)) {
      UNTRUSTED.lastIndex = 0; let m;
      while ((m = UNTRUSTED.exec(b.text)) && seen.size < 5) {
        if (seen.has(m[1])) continue;
        seen.add(m[1]);
        out.push(mk(M, u, b.at + m.index, { ruleId: 'gha-script-injection', severity: 'high', category: 'Injection', title: `Script-Injection in GitHub Actions: ${m[1]}`, description: `\${{ ${m[1]} }} wird vor dem Start wörtlich in das Skript eingesetzt. Diesen Wert bestimmt, wer ein Issue, einen Kommentar oder einen Pull Request anlegt – ein Titel wie \`"; curl … | sh #\` wird dann als Befehl ausgeführt, mit Zugriff auf Token und Secrets des Workflows.`, impact: 'Fremde können Befehle in deiner CI ausführen und Secrets oder Schreibrechte am Repository erlangen.', remediation: `Wert zuerst in eine Umgebungsvariable legen und nur diese verwenden: env: VALUE: \${{ ${m[1]} }} und im Skript "$VALUE" (in Anführungszeichen).` }));
      }
    }
    if (!/^\s*permissions\s*:/m.test(c)) out.push(mk(M, u, null, { ruleId: 'gha-missing-permissions', severity: 'low', category: 'AccessControl', title: 'Workflow legt keine Rechte für das GITHUB_TOKEN fest', description: 'Ohne permissions gelten die Standardrechte des Repositorys – bei älteren Repositorys und Organisationen sind das Schreibrechte auf Code, Pakete und Releases.', impact: 'Ein kompromittierter Schritt kann mit dem Token Code oder Releases verändern.', remediation: 'Oben im Workflow permissions: contents: read setzen und nur in einzelnen Jobs gezielt erweitern.' }));
    const idt = c.search(/id-token\s*:\s*write/);
    if (idt >= 0 && !OIDC_USER.test(c)) out.push(mk(M, u, idt, { ruleId: 'gha-unneeded-id-token', severity: 'medium', category: 'AccessControl', title: 'id-token: write ohne erkennbaren Bedarf', description: 'Mit id-token: write kann jeder Schritt ein OIDC-Token anfordern, mit dem sich der Workflow bei Cloud-Konten (AWS, Azure, GCP) oder Paket-Registries anmeldet. Im Workflow ist keine Anmeldung zu sehen, die das braucht.', impact: 'Ein kompromittierter Schritt kann sich als dein Workflow bei verbundenen Cloud-Konten ausgeben.', remediation: 'id-token: write entfernen oder nur im Job setzen, der sich tatsächlich per OIDC anmeldet.' }));
    const sh = c.search(/^\s*runs-on\s*:.*self-hosted/m);
    const onPr = /^\s*(?:on\s*:.*\bpull_request(?:_target)?\b|pull_request(?:_target)?\s*:|-\s*pull_request(?:_target)?\s*$)/m.test(c);
    if (sh >= 0 && onPr) out.push(mk(M, u, sh, { ruleId: 'gha-self-hosted-pr', severity: 'high', category: 'Config', title: 'Self-hosted-Runner für Pull Requests', description: 'Der Workflow läuft bei Pull Requests auf einem eigenen Rechner. Bei öffentlichen Repositorys kann jeder per Fork-PR Code auf diesem Rechner ausführen – und der Runner bleibt danach oft verseucht.', impact: 'Fremde erhalten Zugriff auf den Runner-Rechner, sein Netz und spätere Jobs.', remediation: 'Für Pull Requests GitHub-gehostete Runner verwenden oder Fork-PRs nur nach Freigabe starten (Require approval for all outside collaborators) und kurzlebige, isolierte Runner nutzen.' }));
  }
  return out;
}

// --- GitLab CI, Azure Pipelines, Jenkinsfile ----------------------------------------------
const CI_KIND = [
  ['GitLab CI', (p) => /(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)\.gitlab\/ci\/[^/]+\.ya?ml$|\.gitlab-ci\.ya?ml$/i.test(p)],
  ['Azure Pipelines', (p) => /(^|\/)(\.)?azure-pipelines[\w.-]*\.ya?ml$|(^|\/)\.azure(devops|-pipelines)\/.*\.ya?ml$/i.test(p)],
  ['Jenkinsfile', (p) => /(^|\/)jenkinsfile([.-][\w.-]+)?$|\.jenkinsfile$/i.test(p)],
];
function ciKind(u) { const p = base(u); const k = CI_KIND.find(([, t]) => t(p)); return k ? k[0] : null; }

function ciOther(units) {
  const out = [];
  const M = 'ci-audit';
  for (const u of units) {
    const c = u.content || '';
    // GitLab-Runner-Konfiguration
    if (fileName(u) === 'config.toml' && /\[runners\.docker\]/.test(c)) {
      const i = c.search(/^\s*privileged\s*=\s*true/m);
      if (i >= 0) out.push(mk(M, u, i, { ruleId: 'ci-privileged-runner', severity: 'high', category: 'Config', title: 'GitLab-Runner startet Container privilegiert', description: 'privileged = true gibt jedem Job fast vollen Zugriff auf den Runner-Rechner. Ein Job aus einem fremden Branch oder Merge Request kann so aus dem Container ausbrechen.', impact: 'Übernahme des Runner-Rechners und aller Secrets späterer Jobs.', remediation: 'privileged = false setzen; für Image-Builds kaniko, buildah oder rootless BuildKit verwenden.' }));
      continue;
    }
    const kind = ciKind(u);
    if (!kind) continue;
    const add = (idx, o) => out.push(mk(M, u, idx, { ...o, title: `${o.title} (${kind})` }));
    // Klartext-Geheimnisse
    let n = 0;
    const secretRes = kind === 'Jenkinsfile'
      ? [/^\s*([A-Za-z_][\w]*)\s*=\s*(["'])([^"'\n]{4,})\2/gm]
      : [/^\s*-?\s*["']?([A-Za-z_][\w.-]*)["']?\s*:\s*(["']?)([^"'\n#]{4,}?)\2\s*$/gm, /^\s*-\s*name\s*:\s*["']?([A-Za-z_][\w.-]*)["']?\s*\n\s*value\s*:\s*(["']?)([^"'\n#]{4,}?)\2\s*$/gm];
    for (const re of secretRes) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(c)) && n < 5) {
        const [, key, , val] = m;
        if (!SECRET_NAME.test(key) || /(file|path|dir|url|name|user|id|variable|header|ref|type|length)$/i.test(key) || IS_REFERENCE.test(val) || PLACEHOLDER.test(val.trim()) || /^(name|value|secret|variables|key)$/i.test(key)) continue;
        n++;
        add(m.index, { ruleId: 'ci-plaintext-secret', severity: 'high', category: 'Secrets', evidence: redactSecret(val), title: `Geheimnis im Klartext in der Pipeline: ${key}`, description: 'Der Wert steht direkt in der Pipeline-Datei und damit für jeden lesbar, der das Repository sieht – auch in Forks und alten Versionen.', impact: 'Wer das Repository lesen kann, kann den Zugang benutzen.', remediation: 'Wert als geschützte/maskierte Variable bzw. Secret im CI-System anlegen (GitLab: CI/CD Variables, Azure: Variable Groups/Key Vault, Jenkins: credentials()), aus der Datei entfernen und den Schlüssel beim Anbieter neu erzeugen.' });
      }
    }
    // curl | sh
    const cp = c.search(new RegExp(CURL_PIPE.source));
    if (cp >= 0) add(cp, { ruleId: 'ci-curl-pipe-sh', severity: 'high', category: 'Dependencies', title: 'Skript aus dem Internet wird direkt ausgeführt', description: 'curl … | sh führt in der Pipeline ungeprüft aus, was der Server gerade liefert – mit Zugriff auf alle Secrets des Jobs.', impact: 'Wer den Server oder die Verbindung kontrolliert, steuert deine Pipeline.', remediation: 'Skript herunterladen, Prüfsumme kontrollieren (sha256sum -c) und dann ausführen – oder ein fest versioniertes Paket/Image verwenden.' });
    // Container-Images ohne feste Version
    const imgRes = kind === 'Jenkinsfile' ? [/(?:\bimage\s+|docker\.image\(\s*)["']([^"'$]+)["']/g]
      : [/^\s*(?:-\s*)?image\s*:\s*["']?([a-z0-9][\w.\-/:@]*)["']?\s*$/gm, /^\s*(?:-\s*)?image\s*:\s*\n\s*name\s*:\s*["']?([a-z0-9][\w.\-/:@]*)["']?\s*$/gm];
    const seenImg = new Set();
    for (const imgRe of imgRes) for (let im = imgRe.exec(c); im && seenImg.size < 5; im = imgRe.exec(c)) {
      const img = im[1];
      if (seenImg.has(img) || img.includes('@sha256:')) continue;
      seenImg.add(img);
      const latest = /:latest$/.test(img) || !/:[\w.-]+$/.test(img.split('/').pop());
      add(im.index, { ruleId: latest ? 'ci-image-latest' : 'ci-image-unpinned', severity: latest ? 'medium' : 'low', category: 'Dependencies', title: `CI-Image ohne feste Version: ${img}`, description: latest ? 'Ohne Tag bzw. mit :latest läuft bei jedem Job eventuell ein anderes Image – auch ein manipuliertes.' : 'Ein Tag kann neu vergeben werden; nur der sha256-Digest ist unveränderlich.', impact: 'Ein ausgetauschtes Image läuft mit allen Secrets der Pipeline.', remediation: `${img.split('@')[0].replace(/:latest$/, '')}@sha256:<digest> verwenden (Digest z. B. mit docker buildx imagetools inspect ermitteln).` });
    }
    // Fremde Vorlagen/Bibliotheken ohne feste Version
    if (kind === 'GitLab CI') {
      let m; const re = /^\s*-?\s*remote\s*:\s*["']?(https?:\/\/\S+?)["']?\s*$/gm;
      while ((m = re.exec(c))) if (!/integrity\s*:/.test(c.slice(m.index, m.index + 300))) add(m.index, { ruleId: 'ci-include-remote', severity: 'medium', category: 'Dependencies', title: `Pipeline lädt Vorlage von fremder Adresse: ${m[1].slice(0, 100)}`, description: 'include: remote holt die Datei bei jedem Lauf neu und führt sie als Teil der Pipeline aus – ohne Prüfsumme.', impact: 'Wer die Datei ändert, steuert deine Pipeline samt Secrets.', remediation: 'Vorlage ins eigene Repository übernehmen oder integrity: sha256-… angeben.' });
      const pr = /^\s*-?\s*project\s*:\s*["']?([\w./-]+)["']?/gm;
      while ((m = pr.exec(c))) {
        const block = c.slice(m.index, m.index + 300).split(/\n\s*-\s/)[0];
        const ref = (block.match(/^\s*ref\s*:\s*["']?([\w./-]+)/m) || [])[1];
        if (!ref || !/^[0-9a-f]{40}$/.test(ref)) add(m.index, { ruleId: 'ci-include-unpinned', severity: ref ? 'low' : 'medium', category: 'Dependencies', title: `Vorlage aus anderem Projekt ohne feste Version: ${m[1]}`, description: ref ? `Die Vorlage folgt „${ref}“ – ein Branch oder Tag, der sich ändern kann.` : 'Ohne ref folgt die Vorlage immer dem Standard-Branch des anderen Projekts.', impact: 'Änderungen im anderen Projekt laufen ungeprüft in deiner Pipeline.', remediation: 'ref: auf einen festen Commit-SHA setzen.' });
      }
      const dind = c.search(/docker:[\w.-]*dind/);
      if (dind >= 0) add(dind, { ruleId: 'ci-docker-dind', severity: 'medium', category: 'Config', title: 'Docker-in-Docker braucht einen privilegierten Runner', description: 'Der Dienst docker:dind läuft nur auf Runnern mit privileged = true. Jeder Job auf diesem Runner kann damit aus dem Container auf den Runner-Rechner durchgreifen.', impact: 'Ein manipulierter Job übernimmt den Runner und die Secrets anderer Jobs.', remediation: 'Images mit kaniko, buildah oder rootless BuildKit bauen; falls dind nötig ist, einen eigenen, isolierten Runner nur für vertrauenswürdige Branches verwenden.' });
    }
    if (kind === 'Azure Pipelines') {
      let m; const re = /^\s*-\s*repository\s*:\s*[\w.-]+/gm;
      while ((m = re.exec(c))) {
        const block = c.slice(m.index, m.index + 400).split(/\n\s*-\s/)[0];
        if (!/type\s*:\s*(github|git|bitbucket)/i.test(block)) continue;
        const ref = (block.match(/^\s*ref\s*:\s*["']?([\w./-]+)/m) || [])[1];
        if (!ref || !/^[0-9a-f]{40}$/.test(ref.replace(/^refs\/tags\//, ''))) add(m.index, { ruleId: 'ci-include-unpinned', severity: ref ? 'low' : 'medium', category: 'Dependencies', title: 'Vorlagen-Repository ohne feste Version', description: ref ? `Die Vorlagen folgen „${ref}“ – ein Branch oder Tag, der sich ändern kann.` : 'Ohne ref folgen die Vorlagen immer dem Standard-Branch des anderen Repositorys.', impact: 'Änderungen im anderen Repository laufen ungeprüft in deiner Pipeline.', remediation: 'ref: auf einen festen Commit-SHA setzen.' });
      }
    }
    if (kind === 'Jenkinsfile') {
      let m; const re = /@Library\(\s*\[?\s*["']([^"']+)["']/g;
      while ((m = re.exec(c))) {
        const ver = m[1].split('@')[1];
        if (!ver || !/^[0-9a-f]{40}$/.test(ver)) add(m.index, { ruleId: 'ci-include-unpinned', severity: ver ? 'low' : 'medium', category: 'Dependencies', title: `Jenkins-Bibliothek ohne feste Version: ${m[1].split('@')[0]}`, description: ver ? `Die Bibliothek folgt „${ver}“ – ein Branch oder Tag, der sich ändern kann.` : 'Ohne @Version lädt Jenkins den Standard-Branch der Bibliothek – deren Code läuft mit allen Rechten der Pipeline.', impact: 'Änderungen an der Bibliothek laufen ungeprüft in deiner Pipeline.', remediation: '@Library(\'name@<commit-sha>\') verwenden.' });
      }
    }
    const priv = c.search(/--privileged\b/);
    if (priv >= 0) add(priv, { ruleId: 'ci-privileged-container', severity: 'high', category: 'Config', title: 'Pipeline startet einen privilegierten Container', description: '--privileged hebt die Trennung zwischen Container und Build-Rechner fast vollständig auf.', impact: 'Ein manipulierter Build übernimmt den Build-Rechner und die Secrets anderer Jobs.', remediation: '--privileged entfernen; für Image-Builds kaniko, buildah oder rootless BuildKit verwenden.' });
  }
  return out;
}

module.exports = { lockDrift, dockerfile, githubActions, ciOther, instructions, envPairs, scriptBlocks, CURL_PIPE };
