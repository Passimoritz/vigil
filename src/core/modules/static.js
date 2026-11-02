'use strict';

// Statische Audit-Module ohne externe Werkzeuge. Sie lesen die bereits eingelesenen
// Dateien (Units) und melden Befunde mit fester Regel-ID; Erklaerungen, Schnipsel und
// Links ergaenzt die Wissensbasis (remedies.js).
//
//  supply-chain-audit   Lockfiles, Registries, Install-Skripte, Tippfehler-Pakete, Dockerfile, CI
//  container-host-audit docker-compose / Dockerfile-Haertung
//  semgrep-custom-sast  Race Conditions, Krypto, Timing, JWT, Prototype Pollution, ReDoS, SSRF, Mass Assignment
//  llm-prompt-security  Prompt-Injection-Muster, KI-Ausgabe in gefaehrlichen Senken, offene KI-Server
//  linux-host-audit     sshd_config, Dateirechte sensibler Dateien (statisch, nur Linux/macOS)

const fs = require('fs');
const path = require('path');
const { normalizeFinding } = require('../schema');

const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const fileName = (u) => base(u).split('/').pop().toLowerCase();
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const isTestFile = (u) => /(^|\/)(test|tests|__tests__|spec|e2e|fixtures?|mocks?|examples?)(\/|$)|\.(test|spec)\.[jt]sx?$/i.test(base(u));
const isCode = (u) => /\.(m?[jt]sx?|cjs|py|rb|php|go|java|kt|cs)$/i.test(base(u));

function mk(module, u, idx, o) {
  return normalizeFinding({
    ...o,
    location: idx == null || idx < 0 ? base(u) : `${base(u)}:${lineOf(u.content, idx)}`,
    sourceModule: module,
    devOnly: isTestFile(u) || o.devOnly,
  }, module);
}

// --- Lieferkette ---------------------------------------------------------
const TOP_PACKAGES = ['react', 'lodash', 'express', 'axios', 'chalk', 'commander', 'debug', 'request', 'moment', 'webpack', 'typescript', 'vue', 'next', 'jquery', 'dotenv', 'uuid', 'yargs', 'eslint', 'prettier', 'jest', 'mocha', 'cross-env', 'colors', 'electron', 'mongoose', 'redux', 'socket.io', 'body-parser', 'jsonwebtoken', 'bcrypt', 'nodemailer', 'requests', 'numpy', 'pandas', 'django', 'flask', 'urllib3', 'boto3', 'pillow'];
// Bekannte echte Pakete, die nur zufaellig nah an einem Top-Paket liegen.
const NOT_TYPO = new Set(['preact', 'redis', 'got', 'ws', 'nodemon', 'uid', 'axe', 'next-auth', 'yarn', 'pump', 'react-is', 'jsdom', 'mobx', 'moment-timezone', 'chai', 'vuex', 'debug-js']);
// Abstand 1 (ein Zeichen eingefuegt/entfernt/ersetzt) oder zwei vertauschte Nachbarzeichen.
function lev1(a, b) {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diff = [...a].map((ch, i) => (ch !== b[i] ? i : -1)).filter((i) => i >= 0);
    if (diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]]) return true;
  }
  let i = 0, j = 0, edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (a.length > b.length) i++; else if (b.length > a.length) j++; else { i++; j++; }
  }
  return edits + (a.length - i) + (b.length - j) === 1;
}

function supplyChain(units) {
  const out = [];
  const M = 'supply-chain-audit';
  const names = new Set(units.map(fileName));
  for (const u of units) {
    const n = fileName(u);
    const c = u.content || '';
    if (n === 'package.json') {
      let pj; try { pj = JSON.parse(c); } catch { continue; }
      const deps = { ...(pj.dependencies || {}), ...(pj.devDependencies || {}) };
      for (const name of Object.keys(deps)) {
        const twin = !NOT_TYPO.has(name) && name.length >= 4 && TOP_PACKAGES.find((t) => t !== name && lev1(name, t));
        if (twin) out.push(mk(M, u, c.indexOf(`"${name}"`), { ruleId: 'typosquat-suspect', severity: 'high', category: 'Dependencies', title: `Möglicher Tippfehler-Paketname: ${name} (gemeint: ${twin}?)`, description: `Das Paket „${name}“ unterscheidet sich nur in einem Zeichen vom beliebten Paket „${twin}“. Solche Namen werden gezielt für Schadpakete registriert (Typosquatting).`, remediation: `Prüfen, ob wirklich „${name}“ gemeint ist; sonst durch „${twin}“ ersetzen.`, confidence: 'medium' }));
        if (/^(git(\+\w+)?|https?|file):|^github:/.test(String(deps[name]))) out.push(mk(M, u, c.indexOf(`"${name}"`), { ruleId: 'lockfile-custom-registry', severity: 'medium', category: 'Dependencies', title: `Abhängigkeit aus Git/URL statt Registry: ${name}`, description: `„${name}“ wird direkt von ${deps[name]} geladen – ohne Versions-Pinning und Integritätsprüfung der Registry.`, remediation: 'Veröffentlichte Version aus der Registry verwenden oder auf einen festen Commit pinnen.', confidence: 'high' }));
      }
      for (const hook of ['preinstall', 'install', 'postinstall']) {
        if (pj.scripts && pj.scripts[hook]) out.push(mk(M, u, c.indexOf(`"${hook}"`), { ruleId: 'install-script', severity: 'low', category: 'Dependencies', title: `Install-Skript im Projekt: ${hook}`, description: `„${hook}: ${String(pj.scripts[hook]).slice(0, 80)}“ läuft bei jedem npm install automatisch. Bei Abhängigkeiten ist das ein beliebter Weg für Schadcode.`, remediation: 'Nur behalten, wenn nötig; in CI mit --ignore-scripts installieren.', confidence: 'medium' }));
      }
      if (pj.dependencies && Object.keys(pj.dependencies).length && !['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'npm-shrinkwrap.json', 'bun.lockb', 'bun.lock'].some((l) => names.has(l))) {
        out.push(mk(M, u, null, { ruleId: 'lockfile-missing', severity: 'medium', category: 'Dependencies', title: 'Kein Lockfile vorhanden', description: 'Ohne Lockfile installiert jeder Build eventuell andere Versionen – ein kompromittiertes Update kommt unbemerkt hinein.', remediation: 'package-lock.json erzeugen und einchecken; in CI npm ci verwenden.', confidence: 'high' }));
      }
    }
    if (n === 'package-lock.json') {
      let pl; try { pl = JSON.parse(c); } catch { continue; }
      const pkgs = Object.entries(pl.packages || {}).filter(([k]) => k);
      const short = (k) => k.replace(/^.*node_modules\//, '');
      const noInt = pkgs.filter(([, v]) => v && v.resolved && !v.integrity && !v.link);
      if (noInt.length) out.push(mk(M, u, null, { ruleId: 'lockfile-missing-integrity', severity: 'medium', category: 'Dependencies', title: `${noInt.length} Paket(e) ohne Integritäts-Hash im Lockfile`, description: `Für ${noInt.slice(0, 3).map(([k]) => short(k)).join(', ')}${noInt.length > 3 ? ' …' : ''} fehlt der sha512-Hash – manipulierte Pakete fallen so nicht auf.`, remediation: 'Lockfile mit aktuellem npm neu erzeugen (npm install --package-lock-only).', confidence: 'high' }));
      const foreign = pkgs.filter(([, v]) => v && /^https?:/.test(v.resolved || '') && !/registry\.npmjs\.org|registry\.yarnpkg\.com/.test(v.resolved));
      if (foreign.length) { let host = '?'; try { host = new URL(foreign[0][1].resolved).host; } catch { /* egal */ }
        out.push(mk(M, u, null, { ruleId: 'lockfile-custom-registry', severity: 'low', category: 'Dependencies', title: `${foreign.length} Paket(e) aus fremder Registry`, description: `Beispiel: ${short(foreign[0][0])} von ${host}. Gemischte Registries begünstigen Dependency-Confusion.`, remediation: 'Registry pro Scope fest in .npmrc hinterlegen.', confidence: 'medium' })); }
      const internal = pkgs.filter(([k, v]) => /node_modules\/@(firma|company|intern|internal|corp|private)[^/]*\//i.test(k) && v && /registry\.npmjs\.org/.test(v.resolved || ''));
      if (internal.length) out.push(mk(M, u, null, { ruleId: 'dependency-confusion-scope', severity: 'high', category: 'Dependencies', title: `Internes Paket aus öffentlicher npm-Registry: ${short(internal[0][0])}`, description: 'Ein offenbar internes Scope-Paket wurde von registry.npmjs.org aufgelöst. Genau so funktionieren Dependency-Confusion-Angriffe.', remediation: 'Scope in .npmrc auf die interne Registry mappen und den Namen bei npm reservieren.', confidence: 'medium' }));
    }
    if (n === 'dockerfile' || /\.dockerfile$/.test(n)) {
      const re = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)/gim; let m;
      const stages = new Set();
      while ((m = re.exec(c))) {
        const img = m[1];
        const as = c.slice(m.index, m.index + 200).match(/\bAS\s+(\w+)/i);
        if (as) stages.add(as[1].toLowerCase());
        if (/^scratch$|^\$\{?\w+/i.test(img) || stages.has(img.toLowerCase())) continue;
        const latest = /:latest$/.test(img) || !/[:@]/.test(img.split('/').pop());
        if (!img.includes('@sha256:')) out.push(mk(M, u, m.index, { ruleId: latest ? 'docker-latest-tag' : 'docker-unpinned-base', severity: latest ? 'medium' : 'low', category: 'Config', title: `Basis-Image nicht per Digest fixiert: ${img}`, description: latest ? 'Ohne Tag bzw. mit :latest ändert sich das Basis-Image bei jedem Build.' : 'Ein Tag kann neu vergeben werden; nur der sha256-Digest ist unveränderlich.', remediation: `FROM ${img.split('@')[0]}@sha256:<digest> verwenden.`, confidence: 'high' }));
      }
      if (/^\s*FROM\s/im.test(c) && !/^\s*USER\s+(?!root\b|0\b)\S+/im.test(c)) out.push(mk('container-host-audit', u, null, { ruleId: 'dockerfile-root-user', severity: 'medium', category: 'Config', title: 'Container läuft als root (kein USER im Dockerfile)', description: 'Ohne USER-Anweisung läuft der Prozess im Container als root. Eine Lücke in der App bedeutet dann root im Container – ein großer Schritt Richtung Host.', remediation: 'Eigenen Nutzer anlegen und mit USER wechseln.', confidence: 'high' }));
    }
    if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(base(u))) {
      const re = /^\s*-?\s*uses:\s*([\w.-]+\/[\w./-]+)@([\w.-]+)/gim; let m;
      while ((m = re.exec(c))) {
        if (/^[0-9a-f]{40}$/.test(m[2])) continue;
        out.push(mk(M, u, m.index, { ruleId: 'gha-unpinned-action', severity: /^actions\//.test(m[1]) ? 'low' : 'medium', category: 'Config', title: `GitHub Action nicht auf Commit gepinnt: ${m[1]}@${m[2]}`, description: 'Tags und Branches einer Action kann der Autor jederzeit auf anderen Code umbiegen – der läuft dann mit deinen Secrets.', remediation: `${m[1]}@<40-stelliger Commit-SHA> # ${m[2]}`, confidence: 'high' }));
      }
      const wa = c.search(/^\s*permissions:\s*write-all/im);
      if (wa >= 0) out.push(mk(M, u, wa, { ruleId: 'gha-write-all', severity: 'high', category: 'Config', title: 'Workflow mit permissions: write-all', description: 'Das GITHUB_TOKEN darf alles schreiben – ein kompromittierter Schritt kann Code, Releases und Pakete verändern.', remediation: 'permissions: contents: read setzen und nur einzeln erweitern.', confidence: 'high' }));
      const prt = c.search(/pull_request_target/);
      if (prt >= 0 && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)/.test(c)) out.push(mk(M, u, prt, { ruleId: 'gha-pull-request-target', severity: 'critical', category: 'Config', title: 'pull_request_target checkt fremden PR-Code aus', description: 'Der Workflow läuft mit Secrets und Schreibrechten, führt aber Code aus einem fremden Pull Request aus („Pwn Request“).', remediation: 'pull_request statt pull_request_target verwenden oder den PR-Code nicht auschecken/ausführen.', confidence: 'high' }));
    }
  }
  return out;
}

// --- Container (docker-compose) -----------------------------------------
const DB_PORTS = { 5432: 'PostgreSQL', 3306: 'MySQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 11211: 'Memcached', 5984: 'CouchDB', 1433: 'MSSQL' };
function composeServices(c) {
  const servicesAt = c.search(/^services:\s*$/m);
  if (servicesAt < 0) return [];
  const svcRe = /^( {2}|\t)([\w.-]+):\s*$/gm; const starts = []; let m;
  while ((m = svcRe.exec(c))) if (m.index > servicesAt) starts.push({ name: m[2], at: m.index });
  return starts.map((s, i) => ({ ...s, block: c.slice(s.at, i + 1 < starts.length ? starts[i + 1].at : c.length) }));
}
function containers(units) {
  const out = [];
  const M = 'container-host-audit';
  for (const u of units) {
    if (!/(^|[-.])(docker-)?compose[\w.-]*\.ya?ml$/i.test(fileName(u))) continue;
    for (const s of composeServices(u.content || '')) {
      const { block } = s;
      const at = (re) => { const k = re ? block.search(re) : -1; return k < 0 ? s.at : s.at + k; };
      const add = (ruleId, severity, title, description, remediation, re) => out.push(mk(M, u, at(re), { ruleId, severity, category: 'Config', title: `${title} (Dienst „${s.name}“)`, description, remediation, confidence: 'high' }));
      if (/privileged:\s*true/.test(block)) add('container-privileged', 'critical', 'Container läuft privileged', 'privileged hebt fast die gesamte Isolation auf – der Container hat praktisch Root-Zugriff auf den Host.', 'privileged entfernen und nur benötigte Capabilities freigeben.', /privileged:/);
      if (/docker\.sock/.test(block)) add('container-docker-sock', 'critical', 'Docker-Socket in den Container gemountet', 'Wer im Container ist, steuert damit den Docker-Daemon und kann beliebige privilegierte Container auf dem Host starten.', 'Socket-Mount entfernen; falls nötig einen eingeschränkten Socket-Proxy verwenden.', /docker\.sock/);
      if (/user:\s*["']?(root|0)(:0)?["']?\s*$/m.test(block)) add('container-root-user', 'high', 'Container explizit als root', 'Der Dienst läuft als root.', 'user: "10001:10001" setzen.', /user:/);
      if (/network_mode:\s*["']?host/.test(block)) add('container-host-network', 'high', 'Host-Netzwerk statt eigenem Netz', 'Der Container teilt sich das Netzwerk des Hosts und erreicht alle lokalen Dienste.', 'network_mode: host entfernen und Ports gezielt freigeben.', /network_mode:/);
      if (/SYS_ADMIN|cap_add:\s*\[?\s*["']?ALL/.test(block)) add('container-cap-sys-admin', 'high', 'Gefährliche Capability (SYS_ADMIN/ALL)', 'SYS_ADMIN erlaubt Mounts und vieles mehr – ein bekannter Weg aus dem Container.', 'cap_add auf das Nötigste beschränken.', /cap_add:/);
      if (!/cap_drop:/.test(block)) add('container-missing-cap-drop', 'low', 'Keine Capabilities entfernt', 'Ohne cap_drop behält der Container die Standard-Capabilities.', 'cap_drop: [ALL] setzen.');
      if (!/no-new-privileges/.test(block)) add('container-no-new-privileges', 'low', 'no-new-privileges nicht gesetzt', 'Prozesse im Container können per setuid-Binaries Rechte erhöhen.', 'security_opt: ["no-new-privileges:true"]');
      const portsAt = block.search(/^\s*ports:/m);
      if (portsAt >= 0) {
        const portsBlock = block.slice(portsAt).split(/\n\s{4}(?!-)[\w-]+:/)[0];
        const pm = /["']?(?:(\d+\.\d+\.\d+\.\d+):)?(\d+):(\d+)["']?/g; let p;
        while ((p = pm.exec(portsBlock))) {
          const inner = Number(p[3]);
          if (DB_PORTS[inner] && (!p[1] || p[1] === '0.0.0.0')) add('container-db-port-public', 'critical', `${DB_PORTS[inner]}-Port ${p[2]} auf allen Schnittstellen`, 'Die Datenbank ist ohne Bindung an 127.0.0.1 von außen erreichbar – zusammen mit schwachen Passwörtern ein häufiger Einbruchsweg.', `ports: ["127.0.0.1:${p[2]}:${inner}"] oder nur über ein internes Docker-Netz erreichbar machen.`, /ports:/);
        }
      }
    }
  }
  return out;
}

// --- Eigene SAST-Regeln -------------------------------------------------
const SAST_RULES = [
  { id: 'sast-insecure-random', sev: 'high', cat: 'Crypto', re: /\b(token|secret|otp|password|passwd|nonce|salt|session|apikey|api_key|reset\w*|verification\w*)\w*\s*[:=][^;\n]{0,60}Math\.random\(\)/gi, title: 'Math.random() für Token/Code/Geheimnis', desc: 'Math.random() ist nicht kryptografisch sicher – damit erzeugte Werte sind vorhersagbar.' },
  { id: 'sast-weak-hash', sev: 'medium', cat: 'Crypto', re: /createHash\(\s*['"](md5|sha1)['"]|hashlib\.(md5|sha1)\(/gi, title: 'Schwacher Hash (MD5/SHA-1)', desc: 'MD5 und SHA-1 sind für Sicherheitszwecke gebrochen.' },
  { id: 'sast-weak-cipher', sev: 'high', cat: 'Crypto', re: /createCipheriv?\(\s*['"](des|des-ede3?|rc4|aes-\d+-ecb|bf)[\w-]*['"]/gi, title: 'Schwache Verschlüsselung (DES/RC4/ECB)', desc: 'Diese Verfahren bzw. der ECB-Modus schützen Daten nicht zuverlässig.' },
  { id: 'sast-timing-compare', sev: 'medium', cat: 'Crypto', re: /\b\w*(signature|hmac|digest|apiKey|api_key|webhookSecret)\w*\s*(===|!==|==|!=)\s*[\w.[\]'"]+/gi, title: 'Geheimnis mit === verglichen (Timing-Angriff)', desc: 'Ein normaler Vergleich ist nicht zeitkonstant und kann den richtigen Wert über Antwortzeiten verraten.', test: (m, c) => !/timingSafeEqual|compare_digest/.test(c.slice(Math.max(0, m.index - 300), m.index + 300)) },
  { id: 'sast-jwt-decode-no-verify', sev: 'high', cat: 'Auth', re: /jwt\.decode\(/g, title: 'jwt.decode() ohne Signaturprüfung', desc: 'jwt.decode() liest das Token nur – die Signatur wird nicht geprüft.', unless: /jwt\.verify\(/ },
  { id: 'sast-jwt-no-expiry', sev: 'medium', cat: 'Auth', re: /jwt\.sign\([^;]*?\)\s*[;\n]/g, title: 'JWT ohne Ablaufzeit', desc: 'Ohne expiresIn bleibt ein geleaktes Token unbegrenzt gültig.', test: (m) => !/expiresIn|\bexp\s*:/.test(m[0]) },
  { id: 'sast-prototype-pollution', sev: 'medium', cat: 'Injection', re: /for\s*\(\s*(?:const|let|var)\s+(\w+)\s+in\s+(\w+)\s*\)\s*\{?[^}]{0,120}\[\s*\1\s*\]\s*=/g, title: 'Ungefiltertes Objekt-Merge (Prototype Pollution)', desc: 'Schlüssel wie __proto__ werden nicht ausgefiltert.', test: (m, c) => !/__proto__|hasOwnProperty|hasOwn\(|Object\.create\(null\)/.test(c.slice(Math.max(0, m.index - 200), m.index + 400)) },
  { id: 'sast-redos', sev: 'medium', cat: 'DoS', re: /\/\^?[^/\n]*\((?:[^()\n]*[+*])\)[+*][^/\n]*\/[gimsuy]*/g, title: 'Regulärer Ausdruck mit verschachtelter Wiederholung (ReDoS)', desc: 'Muster wie (a+)+ können bei böswilliger Eingabe exponentiell lange laufen.' },
  { id: 'sast-ssrf', sev: 'high', cat: 'SSRF', re: /\b(fetch|axios(?:\.get|\.post)?|got|request|http\.get|https\.get|urlopen|requests\.get)\(\s*(req\.(query|body|params)\.\w+|request\.(args|GET|json)\b|`[^`]*\$\{\s*req\.(query|body|params))/g, title: 'Server ruft vom Nutzer übergebene URL ab (SSRF)', desc: 'Ohne Allowlist erreicht der Angreifer interne Dienste oder Cloud-Metadaten.' },
  { id: 'sast-mass-assignment', sev: 'high', cat: 'AccessControl', re: /\.(create|update|updateMany|upsert|insert|insertOne|findOneAndUpdate|findByIdAndUpdate)\(\s*(\{\s*(where\s*:[^}]*\}\s*,\s*)?data\s*:\s*)?req\.body\s*[,)}]/g, title: 'req.body ungefiltert in die Datenbank (Mass Assignment)', desc: 'Nutzer können zusätzliche Felder wie role oder balance mitschicken.' },
  { id: 'sast-toctou-race', sev: 'high', cat: 'Other', re: /(findUnique|findFirst|findOne|findById)\([^;]{0,160}\)[\s\S]{0,300}?\b(balance|stock|quantity|credits?|coupon|used|redeemed|inventory)\b[\s\S]{0,300}?\.(update|create|save|decrement|increment)\(/g, title: 'Lesen-dann-Schreiben ohne Transaktion (Race Condition)', desc: 'Prüfung und Änderung passieren getrennt – parallele Anfragen können sie doppelt auslösen.', test: (m, c) => !/\$transaction|transaction\(|FOR UPDATE|withLock|mutex|\block\(/i.test(c.slice(Math.max(0, m.index - 400), m.index + m[0].length + 100)) },
];
function sast(units) {
  const out = [];
  for (const u of units) {
    if (!isCode(u)) continue;
    const c = u.content || '';
    for (const r of SAST_RULES) {
      if (r.unless && r.unless.test(c)) continue;
      r.re.lastIndex = 0; let m, hits = 0;
      while ((m = r.re.exec(c)) && hits < 5) {
        if (r.test && !r.test(m, c)) continue;
        hits++;
        out.push(mk('semgrep-custom-sast', u, m.index, { ruleId: r.id, severity: r.sev, category: r.cat, title: r.title, description: `${r.desc} Fundstelle: \`${m[0].replace(/\s+/g, ' ').slice(0, 120)}\``, remediation: 'Siehe Lösungsschritte.', confidence: 'medium' }));
      }
    }
  }
  return out;
}

// --- KI / LLM -------------------------------------------------------------
function llm(units) {
  const out = [];
  const M = 'llm-prompt-security';
  for (const u of units) {
    const c = u.content || '';
    if (isCode(u)) {
      const re = /(system\w*|sys(?:Msg|Prompt)?|role\s*:\s*['"]system['"]\s*,\s*content)\s*[:=]\s*`[^`]*\$\{\s*(req\.|request\.|input|userInput|query|message|body|params)/gi; let m;
      while ((m = re.exec(c))) out.push(mk(M, u, m.index, { ruleId: 'llm-prompt-injection-concat', severity: 'high', category: 'Injection', title: 'Nutzereingabe direkt im System-Prompt', description: 'Unvertraute Eingaben werden in den System-Prompt eingesetzt. Damit kann ein Nutzer die Anweisungen der KI überschreiben (Prompt Injection).', remediation: 'Eingabe als eigene user-Nachricht übergeben.', confidence: 'medium' }));
      const sinks = [
        /(eval|execSync|exec|new Function)\(\s*(completion|response|answer|llmOutput|aiResponse|aiOutput|reply|generated)\w*[.\w[\]]*\)/gi,
        /\.innerHTML\s*=\s*(completion|response|answer|llmOutput|aiResponse|aiOutput|reply|generated)\w*[.\w[\]]*/gi,
        /dangerouslySetInnerHTML=\{\{\s*__html:\s*(completion|response|answer|llmOutput|aiResponse|reply|generated)/gi,
      ];
      for (const r of sinks) { r.lastIndex = 0; while ((m = r.exec(c))) out.push(mk(M, u, m.index, { ruleId: 'llm-output-to-sink', severity: 'high', category: 'Injection', title: 'KI-Ausgabe landet in gefährlicher Senke', description: 'Eine KI-Antwort wird ausgeführt oder als HTML verwendet. Über indirekte Prompt-Injection (präparierte Webseiten oder Dokumente) steuert so ein Dritter deinen Code.', remediation: 'KI-Ausgabe validieren und nur als Text verwenden.', confidence: 'medium' })); }
    }
    const bind = c.search(/OLLAMA_HOST\s*[=:]\s*["']?0\.0\.0\.0|["']?0\.0\.0\.0:11434|-p\s+11434:11434\b|["']11434:11434["']|vllm[^\n]{0,80}--host[= ]0\.0\.0\.0/i);
    if (bind >= 0) out.push(mk(M, u, bind, { ruleId: 'llm-server-exposed', severity: 'high', category: 'Config', title: 'KI-Server lauscht auf allen Schnittstellen', description: 'Ollama/vLLM wird ohne Bindung an 127.0.0.1 und ohne Anmeldung gestartet. Jeder im Netz kann die Modelle nutzen oder verändern.', remediation: 'An 127.0.0.1 binden oder Proxy mit Authentifizierung davorschalten.', confidence: 'high' }));
  }
  return out;
}

// --- Linux-Host (statisch) ------------------------------------------------
const SENSITIVE_FILE = /(^|\/)(\.env(\.[\w-]+)?|id_rsa|id_ed25519|id_ecdsa|[\w.-]+\.(pem|key|p12|pfx|sql|dump|bak))$/i;
function linuxStatic(units) {
  const out = [];
  const M = 'linux-host-audit';
  for (const u of units) {
    const c = u.content || '';
    if (/(^|\/)sshd_config$|\/sshd_config\.d\/[^/]+\.conf$/.test(base(u))) {
      const rules = [
        ['ssh-root-login', 'high', /^\s*PermitRootLogin\s+yes\b/im, 'SSH erlaubt Root-Login'],
        ['ssh-password-auth', 'medium', /^\s*PasswordAuthentication\s+yes\b/im, 'SSH erlaubt Passwort-Anmeldung'],
        ['ssh-empty-passwords', 'critical', /^\s*PermitEmptyPasswords\s+yes\b/im, 'SSH erlaubt leere Passwörter'],
      ];
      for (const [ruleId, severity, re, title] of rules) { const i = c.search(re); if (i >= 0) out.push(mk(M, u, i, { ruleId, severity, category: 'Auth', title, description: `${title} – beliebtes Ziel automatisierter Angriffe aus dem Internet.`, remediation: 'Siehe sshd_config-Schnipsel.', confidence: 'high' })); }
    }
    // Dateirechte nur dort pruefbar, wo POSIX-Rechte existieren
    if (process.platform !== 'win32' && u.path && SENSITIVE_FILE.test(base(u))) {
      try {
        const mode = fs.statSync(u.path).mode & 0o777;
        if (mode & 0o077) out.push(mk(M, u, null, { ruleId: 'file-perms-sensitive', severity: (mode & 0o007) ? 'high' : 'medium', category: 'Config', title: `Sensible Datei für andere lesbar (${mode.toString(8).padStart(4, '0')}): ${path.basename(u.path)}`, description: 'Gruppe oder alle Nutzer dürfen diese Datei lesen.', remediation: `chmod 600 ${path.basename(u.path)}`, confidence: 'high' }));
      } catch { /* Datei weg */ }
    }
  }
  return out;
}

const { runIac } = require('./iac');
const { runLicense } = require('./license');
const { runLangs } = require('./langs');
const { runMobile } = require('./mobile');

const MODULES = [
  { id: 'supply-chain-audit', label: 'Lieferkette & CI', run: supplyChain },
  { id: 'container-host-audit', label: 'Container-Konfiguration', run: containers },
  { id: 'semgrep-custom-sast', label: 'Code-Regeln (Race, Krypto, JWT …)', run: sast },
  { id: 'llm-prompt-security', label: 'KI-/LLM-Sicherheit', run: llm },
  { id: 'linux-host-audit', label: 'Server-Konfiguration', run: linuxStatic },
  { id: 'iac-audit', label: 'Server-Einrichtung als Code (Terraform, Kubernetes …)', run: runIac },
  { id: 'license-audit', label: 'Lizenzen der Pakete', run: runLicense },
  { id: 'mobile-audit', label: 'Handy-Apps (Android, iOS)', run: runMobile },
  { id: 'lang-rules', label: 'Regeln für Go, Rust, C#, PHP, Kotlin, Swift', run: runLangs },
];

function runStaticModules(units, onProgress = () => {}) {
  const findings = [];
  const ran = [];
  const errors = [];
  for (const m of MODULES) {
    onProgress({ phase: 'prescan', message: `Modul: ${m.label} …` });
    try { findings.push(...m.run(units)); ran.push(m.id); }
    catch (e) { errors.push(`${m.label}: ${e.message}`); }
  }
  return { findings, ran, errors };
}

module.exports = { runStaticModules, MODULES, lev1, composeServices };
