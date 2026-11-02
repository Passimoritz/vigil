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
function check(name, cond) {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name); }
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
    check('static: alle 5 Module gelaufen', r.ran.length === 5 && !r.errors.length);
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

  console.log('Threat-Intel, Risiko, Angriffspfade:');
  {
    const { applyIntel, contextualRisk, correlate } = require('../src/core/intel');
    const { normalizeFinding: nf } = require('../src/core/schema');
    const intel = { kev: new Set(['CVE-2021-44228']), epss: new Map([['CVE-2021-44228', [0.97, 0.999]], ['CVE-2020-8203', [0.02, 0.8]]]) };
    const [log4j, lodash] = applyIntel([nf({ title: 'log4j (CVE-2021-44228)', severity: 'critical', cvss: 10, category: 'Dependencies' }, 'osv'), nf({ title: 'lodash (CVE-2020-8203)', severity: 'high', cvss: 7.4, category: 'Dependencies' }, 'osv')], intel);
    check('intel: KEV + EPSS übernommen', log4j.inCisaKev && log4j.epssScore === 0.97 && !lodash.inCisaKev);
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
    const freePort = await new Promise((r) => { const s = require('net').createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
    check('api: startet auf 127.0.0.1', (await api.start(freePort)).ok);
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

  console.log(`\n${pass} ok, ${fail} fehlgeschlagen`);
  process.exit(fail ? 1 : 0);
})();
