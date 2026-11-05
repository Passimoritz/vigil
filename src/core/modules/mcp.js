'use strict';

// MCP-Konfigurationen (Model Context Protocol) fuer KI-Assistenten: .mcp.json, mcp.json,
// claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json u. a.
// Geprueft: Tokens im Klartext, ungepinnte Pakete (npx -y / uvx), zu weit freigegebene Ordner
// fuer den Dateisystem-Server und unverschluesselte Remote-Server. Werte werden maskiert.

const { base, fileName, mk, isText } = require('./rulekit');
const { redactSecret } = require('../schema');

const M = 'mcp-config-audit';
const MCP_FILE = /(^|\/)(\.mcp\.json|mcp\.json|mcp_config\.json|claude_desktop_config\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.roo\/mcp\.json|cline_mcp_settings\.json)$/i;
const SECRET_KEY = /(token|secret|password|passwd|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key|bearer)/i;
const SECRET_VALUE = /^(gh[pousr]_[0-9A-Za-z]{30,}|github_pat_\w{20,}|sk-[\w-]{20,}|sk-ant-[\w-]{20,}|xox[baprs]-[\w-]{10,}|AKIA[0-9A-Z]{16}|AIza[\w-]{35}|glpat-[\w-]{20}|npm_[0-9A-Za-z]{36}|(Bearer|Basic)\s+[\w.~+/=-]{12,})/;
const PLACEHOLDER = /^\s*$|\$\{[^}]*\}|^\$\w+|^%\w+%$|^<[^>]*>$|^(your|my|insert|replace|changeme|xxx|todo|example|dummy|test)[\w-]*$|^\*+$|^(true|false|\d+)$/i;
// Ordner, die zu viel freigeben (Laufwerk, Systemwurzel, ganzes Benutzerprofil)
const BROAD_ROOT = /^(\/|~\/?|\$HOME\/?|%USERPROFILE%\\?|[A-Za-z]:[\\/]?|\/(home|Users|root|etc|var)\/?|\/(home|Users)\/[^/\\]+\/?|[A-Za-z]:[\\/]+Users([\\/]+[^\\/]+)?[\\/]?|\\\\[^\\]+\\?)$/i;

function stripJsonComments(s) {
  return s.replace(/("(?:[^"\\]|\\.)*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str) => str || '');
}

function servers(doc) {
  const out = [];
  for (const key of ['mcpServers', 'servers', 'mcp_servers']) {
    const s = doc && doc[key];
    if (s && typeof s === 'object') for (const [name, v] of Object.entries(s)) if (v && typeof v === 'object') out.push([name, v]);
  }
  if (doc && doc.mcp && typeof doc.mcp === 'object') out.push(...servers(doc.mcp));
  return out;
}

// Paket-Argument hinter npx/uvx/pipx/bunx – ist eine feste Version angegeben?
function unpinned(cmd, args) {
  const prog = String(cmd || '').split(/[\\/]/).pop().replace(/\.(cmd|exe)$/i, '').toLowerCase();
  let list = (args || []).map(String);
  let runner = prog;
  if (['cmd', 'sh', 'bash'].includes(prog)) { const flat = list.join(' ').split(/\s+/).filter(Boolean); const i = flat.findIndex((a) => /^(npx|uvx|bunx|pnpx)(\.cmd)?$/i.test(a)); if (i < 0) return null; runner = flat[i].replace(/\.cmd$/i, '').toLowerCase(); list = flat.slice(i + 1); }
  if (!['npx', 'bunx', 'pnpx', 'uvx', 'pipx'].includes(runner)) return null;
  if (runner === 'pipx') { if (list[0] !== 'run') return null; list = list.slice(1); }
  const pkg = list.find((a) => !a.startsWith('-'));
  if (!pkg || /^[./\\]|^[A-Za-z]:[\\/]/.test(pkg)) return null;
  if (runner === 'uvx' || runner === 'pipx') {
    if (/==\d|@\d/.test(pkg) || list.some((a, i) => a === '--from' && /==\d|@\d/.test(list[i + 1] || ''))) return null;
    return pkg;
  }
  const at = pkg.lastIndexOf('@');
  const version = at > 0 ? pkg.slice(at + 1) : '';
  if (version && /^\d+\.\d+\.\d+/.test(version)) return null;
  return pkg;
}

function runMcp(units) {
  const out = [];
  for (const u of units) {
    if (!isText(u) || !MCP_FILE.test(base(u))) continue;
    const c = u.content;
    let doc;
    try { doc = JSON.parse(stripJsonComments(c)); } catch { continue; }
    const at = (needle, from = 0) => { const i = c.indexOf(needle, from); return i < 0 ? null : i; };
    for (const [name, s] of servers(doc)) {
      const nameAt = at(`"${name}"`) ?? 0;
      // Klartext-Tokens in env, headers und Argumenten
      const secrets = [];
      for (const field of ['env', 'headers']) {
        if (!s[field] || typeof s[field] !== 'object') continue;
        for (const [k, v] of Object.entries(s[field])) {
          const val = String(v == null ? '' : v);
          if (PLACEHOLDER.test(val.replace(/^(Bearer|Basic)\s+/i, ''))) continue;
          if ((SECRET_KEY.test(k) && val.length >= 8) || SECRET_VALUE.test(val)) secrets.push({ k, val });
        }
      }
      for (const a of Array.isArray(s.args) ? s.args.map(String) : []) {
        const kv = a.match(/^--?([\w-]*(token|key|secret|password)[\w-]*)[=:](.+)$/i);
        if ((kv && !PLACEHOLDER.test(kv[3])) || SECRET_VALUE.test(a)) secrets.push({ k: kv ? kv[1] : 'args', val: kv ? kv[3] : a });
      }
      const url = typeof s.url === 'string' ? s.url : typeof s.serverUrl === 'string' ? s.serverUrl : '';
      if (/[?&](token|key|api_?key|access_token|secret)=([^&\s"]{8,})/i.test(url)) secrets.push({ k: 'url', val: url.match(/[?&](?:token|key|api_?key|access_token|secret)=([^&\s"]+)/i)[1] });
      for (const sec of secrets.slice(0, 3)) out.push(mk(M, u, at(sec.val.slice(0, 12), nameAt) ?? nameAt, {
        ruleId: 'mcp-plaintext-token', severity: 'high', category: 'Secrets',
        title: `Zugangsdaten im Klartext in der MCP-Konfiguration (${name})`,
        description: `Für den MCP-Server „${name}“ steht ein Geheimnis (${sec.k}) direkt in der Datei. Solche Dateien landen leicht im Repository oder in Backups, und jedes Programm mit Lesezugriff kann den Schlüssel nutzen.`,
        remediation: 'Den Schlüssel beim Anbieter sperren und neu erzeugen. In der Konfiguration nur einen Verweis eintragen (z. B. "${env:GITHUB_TOKEN}" bzw. eine Umgebungsvariable) und die Datei in .gitignore aufnehmen.',
        evidence: `${sec.k}=${redactSecret(sec.val)}`,
        confidence: 'high',
      }));
      // Ungepinnte Pakete
      const pkg = unpinned(s.command, s.args);
      if (pkg) out.push(mk(M, u, at(pkg, nameAt) ?? nameAt, {
        ruleId: 'mcp-unpinned-package', severity: 'medium', category: 'Dependencies',
        title: `MCP-Server lädt ungepinntes Paket: ${pkg}`,
        description: `„${name}“ wird bei jedem Start über ${String(s.command).split(/[\\/]/).pop()} in der jeweils neuesten Version geladen und ausgeführt. Ein kompromittiertes Update läuft dann sofort mit den Rechten des KI-Assistenten – inklusive Zugriff auf Dateien und Tokens.`,
        remediation: 'Eine feste Version angeben (z. B. paket@1.2.3 bzw. paket==1.2.3) und Updates bewusst prüfen.',
        evidence: [s.command, ...(s.args || [])].join(' ').slice(0, 160),
        confidence: 'high',
      }));
      // Dateisystem-Server mit zu weitem Wurzelordner
      const argv = Array.isArray(s.args) ? s.args.map(String) : [];
      if (/filesystem|server-fs|mcp-fs|file-?system/i.test(`${name} ${argv.join(' ')}`)) {
        const broad = argv.filter((a) => BROAD_ROOT.test(a.trim()));
        if (broad.length) out.push(mk(M, u, at(JSON.stringify(broad[0]).slice(1, -1), nameAt) ?? nameAt, {
          ruleId: 'mcp-broad-fs-root', severity: 'high', category: 'AccessControl',
          title: `MCP-Dateisystem-Server mit zu weitem Ordner: ${broad.join(', ')}`,
          description: `„${name}“ gibt dem KI-Assistenten Zugriff auf ${broad.join(', ')} – also auf SSH-Schlüssel, Browser-Profile, Passwort-Dateien und alle Projekte. Eine Prompt-Injection in einem gelesenen Dokument kann diese Dateien abgreifen oder verändern.`,
          remediation: 'Nur die konkreten Projektordner freigeben (z. B. C:\\Users\\name\\Projekte\\app) und schreibenden Zugriff vermeiden.',
          evidence: broad.join(', '),
          confidence: 'high',
        }));
      }
      if (/^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.|\[::1\])/i.test(url)) out.push(mk(M, u, at(url) ?? nameAt, {
        ruleId: 'mcp-remote-http', severity: 'medium', category: 'Transport',
        title: `MCP-Server über unverschlüsseltes HTTP (${name})`,
        description: 'Anfragen, Antworten und mitgeschickte Tokens zum entfernten MCP-Server gehen unverschlüsselt durchs Netz und können mitgelesen oder verändert werden.',
        remediation: 'Den Server nur über https:// ansprechen.',
        evidence: url.replace(/([?&][^=]+=)[^&]+/g, '$1…').slice(0, 160),
      }));
    }
  }
  return out;
}

module.exports = { runMcp, unpinned, MCP_FILE, fileName };
