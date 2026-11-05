'use strict';

// Datenschutz und Datenlecks im Code:
//  - personenbezogene Daten in Code und Testdaten (IBAN mit Pruefsumme, E-Mail-Listen,
//    deutsche Telefonnummern, Steuer-ID und Ausweisnummer mit Pruefziffer)
//  - Log-Aufrufe, die Passwoerter, Tokens oder ganze Anfragen ausgeben
//  - Jupyter-Notebooks mit Geheimnissen oder personenbezogenen Daten in gespeicherten Ausgaben
// Alle gefundenen Werte werden maskiert (redactSecret).

const { redactSecret } = require('../schema');
const { base, fileName, mk, isText, isTestFile, oneLine } = require('./rulekit');

const M = 'privacy-audit';
const CODE = /\.(m?[jt]sx?|cjs|py|rb|php|go|java|kt|kts|cs|swift|scala|dart|ex|exs|rs|c|cc|cpp|h|hpp|lua|ps1|sh|sql|json|ya?ml|csv|xml|txt|properties|env)$/i;
const SKIP = /(^|\/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|poetry\.lock|Cargo\.lock|go\.sum|CHANGELOG[^/]*|AUTHORS[^/]*|CONTRIBUTORS[^/]*|LICENSE[^/]*|CODEOWNERS|\.mailmap)$|\.min\.(js|css)$|\.map$/i;

// --- IBAN ---------------------------------------------------------------
const IBAN_LEN = { DE: 22, AT: 20, CH: 21, LI: 21, FR: 27, NL: 18, BE: 16, LU: 20, IT: 27, ES: 24, PT: 25, GB: 22, IE: 22, PL: 28, CZ: 24, DK: 18, SE: 24, NO: 15, FI: 18, HU: 28, GR: 27, SK: 24, SI: 19, HR: 21, RO: 24, BG: 22, EE: 20, LV: 21, LT: 20, MT: 31, CY: 28, IS: 26 };
// Oeffentlich bekannte Beispiel-IBANs aus Dokumentationen (keine echten Konten)
const EXAMPLE_IBANS = new Set(['DE89370400440532013000', 'DE02120300000000202051', 'DE75512108001245126199', 'GB82WEST12345698765432', 'GB29NWBK60161331926819', 'FR1420041010050500013M02606', 'NL91ABNA0417164300', 'AT611904300234573201', 'CH9300762011623852957', 'BE68539007547034', 'ES9121000418450200051332', 'IT60X0542811101000000123456']);
function ibanValid(raw) {
  const s = raw.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s) || IBAN_LEN[s.slice(0, 2)] !== s.length) return false;
  const r = s.slice(4) + s.slice(0, 4);
  let mod = 0;
  for (const ch of r) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const d of v) mod = (mod * 10 + Number(d)) % 97;
  }
  return mod === 1;
}

// --- Steuer-ID (11 Ziffern, ISO 7064 MOD 11,10) ---------------------------
function steuerIdValid(s) {
  if (!/^[1-9]\d{10}$/.test(s)) return false;
  const counts = {}; for (const d of s.slice(0, 10)) counts[d] = (counts[d] || 0) + 1;
  const reps = Object.values(counts);
  if (!(reps.filter((n) => n > 1).length === 1 && reps.some((n) => n === 2 || n === 3))) return false;
  let p = 10;
  for (let i = 0; i < 10; i++) { let sum = (Number(s[i]) + p) % 10; if (sum === 0) sum = 10; p = (sum * 2) % 11; }
  let check = 11 - p; if (check === 10) check = 0;
  return check === Number(s[10]);
}
// --- Personalausweis-Nummer (9 Zeichen + Pruefziffer, Gewichte 7-3-1) -------
function ausweisValid(s) {
  const v = s.toUpperCase();
  if (!/^[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\d$/.test(v)) return false;
  const val = (ch) => (/\d/.test(ch) ? Number(ch) : ch.charCodeAt(0) - 55);
  let sum = 0; const w = [7, 3, 1];
  for (let i = 0; i < 9; i++) sum += val(v[i]) * w[i % 3];
  return sum % 10 === Number(v[9]);
}

const EMAIL = /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b/g;
const EMAIL_SKIP = /@(example|test|localhost|domain|email|mail|foo|bar|acme|company|yourcompany|yourdomain|sample|invalid)\.|^(noreply|no-reply|donotreply|info|support|admin|contact|hello|security|privacy|webmaster|postmaster|abuse|git|user|name|you|me|someone|john\.doe|jane\.doe)@|@users\.noreply\.github\.com$|\.(png|jpe?g|gif|svg|webp)$/i;
const PHONE = /(?:\+49|0049)[\s/-]?\(?0?\)?[1-9]\d{1,4}[\s/-]?\d{3,8}(?:[\s-]?\d{1,5})?|\b01[5-7]\d[\s/-]?\d{3,4}[\s-]?\d{3,5}\b/g;

function pii(u, out) {
  const c = u.content;
  const found = [];
  let m;
  // IBAN
  const ibanRe = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;
  const ibans = [];
  while ((m = ibanRe.exec(c)) && ibans.length < 20) {
    const s = m[0].replace(/\s+/g, '');
    if (EXAMPLE_IBANS.has(s) || !ibanValid(m[0])) continue;
    ibans.push({ v: s, i: m.index });
  }
  if (ibans.length) found.push({ id: 'pii-iban', sev: 'medium', i: ibans[0].i, n: new Set(ibans.map((x) => x.v)).size, ev: ibans.slice(0, 3).map((x) => redactSecret(x.v)).join(', '), what: 'IBAN' });
  // E-Mail-Listen (ab 5 verschiedenen echten Adressen)
  const mails = new Map();
  EMAIL.lastIndex = 0;
  while ((m = EMAIL.exec(c)) && mails.size < 200) if (!EMAIL_SKIP.test(m[0]) && !mails.has(m[0].toLowerCase())) mails.set(m[0].toLowerCase(), m.index);
  if (mails.size >= 5) { const first = [...mails.entries()]; found.push({ id: 'pii-email-list', sev: 'medium', i: first[0][1], n: mails.size, ev: first.slice(0, 3).map(([e]) => redactSecret(e)).join(', '), what: 'E-Mail-Adressen' }); }
  // Telefonnummern (ab 2 verschiedenen)
  const phones = new Map();
  PHONE.lastIndex = 0;
  while ((m = PHONE.exec(c)) && phones.size < 100) {
    const digits = m[0].replace(/\D/g, '');
    if (digits.length < 9 || /(\d)\1{6,}/.test(digits) || /^(49)?0?(123456|1234567|0000)/.test(digits.replace(/^0049/, '49'))) continue;
    if (!phones.has(digits)) phones.set(digits, { i: m.index, raw: m[0] });
  }
  if (phones.size >= 2) { const first = [...phones.values()]; found.push({ id: 'pii-phone-list', sev: 'low', i: first[0].i, n: phones.size, ev: first.slice(0, 3).map((p) => redactSecret(p.raw)).join(', '), what: 'Telefonnummern' }); }
  // Steuer-ID und Ausweisnummer (nur mit passendem Begriff in der Naehe und gueltiger Pruefziffer)
  const ids = [];
  const idRe = /(steuer[-_ ]?id|steuer[-_ ]?identifikation|tax[-_ ]?id|idnr|tin)\W{0,20}(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})|(personalausweis|ausweis(?:nummer|nr)?|id[-_ ]?card|document[-_ ]?number|dokumentennummer)\W{0,20}([A-Z0-9]{10})\b/gi;
  while ((m = idRe.exec(c)) && ids.length < 10) {
    const tax = m[2] && m[2].replace(/\s/g, '');
    if (tax && steuerIdValid(tax)) ids.push({ v: tax, i: m.index, what: 'Steuer-ID' });
    if (m[4] && ausweisValid(m[4])) ids.push({ v: m[4], i: m.index, what: 'Ausweisnummer' });
  }
  if (ids.length) found.push({ id: 'pii-german-id', sev: 'high', i: ids[0].i, n: ids.length, ev: ids.slice(0, 3).map((x) => `${x.what}: ${redactSecret(x.v)}`).join(', '), what: [...new Set(ids.map((x) => x.what))].join('/') });

  for (const f of found) {
    out.push(mk(M, u, f.i, {
      ruleId: f.id, severity: f.sev, category: 'Other', confidence: f.id === 'pii-phone-list' ? 'low' : 'medium',
      title: `Personenbezogene Daten im Code: ${f.n}× ${f.what}`,
      description: `In der Datei stehen ${f.what} (${f.n} verschiedene${f.id === 'pii-iban' || f.id === 'pii-german-id' ? ', Prüfziffer gültig' : ''}). Echte personenbezogene Daten in Code, Testdaten oder Fixtures landen in Repositories, Backups und Build-Artefakten – nach DSGVO ein meldepflichtiges Risiko, falls sie abfließen.`,
      remediation: 'Durch erfundene Testdaten ersetzen (z. B. Faker, Beispiel-IBAN DE89370400440532013000, @example.com) und echte Daten auch aus der Git-Historie entfernen.',
      evidence: f.ev,
    }));
  }
}

// --- Log-Ausgaben mit Geheimnissen ----------------------------------------
const LOG_CALL = /\b(console\.(?:log|info|debug|warn|error|trace)|(?:logger|log|logging|_logger|this\.logger|self\.logger|Log|LOG|Rails\.logger|winston|pino|bunyan)\.(?:info|debug|warn|warning|error|trace|fatal|critical|log|Info|Debug|Warn|Error|Printf|Println|LogInformation|LogDebug|LogWarning|LogError|[dievw])|System\.out\.print(?:ln)?|System\.err\.print(?:ln)?|fmt\.Print(?:ln|f)?|log\.Print(?:ln|f)?|print|println!?|eprintln!?|error_log|NSLog|Debug\.Log)\s*\(|\bputs\s+(?=\S)/g;
const SENSITIVE_ID = /\b(password|passwd|passwort|pwd|secret|client_?secret|api_?key|apikey|access_?token|refresh_?token|id_?token|auth_?token|token|bearer|authorization|credentials?|private_?key|session_?id|cookie|otp|pin|cvv|card_?number|iban)\b/i;
const WHOLE_REQUEST = /\b(req|request)\.(headers|body|cookies)\b|JSON\.stringify\(\s*(req|request)\b|\b(req|request)\s*[,)]|request\.(META|POST|data|json)\b|\$_(POST|SERVER|COOKIE)\b|\bHttpContext\.Request\.Headers\b/;

// Argument der Log-Zeile ohne reine Text-Literale (Platzhalter in Template-/f-Strings bleiben)
function argCode(s) {
  return s
    .replace(/`([^`]*)`/g, (m, x) => ' ' + (x.match(/\$\{[^}]*\}/g) || []).join(' ') + ' ')
    .replace(/\bf(["'])((?:(?!\1).)*)\1/g, (m, q, x) => ' ' + (x.match(/\{[^}]*\}/g) || []).join(' ') + ' ')
    .replace(/(["'])((?:\\.|(?!\1).)*)\1/g, (m, q, x) => (/#\{[^}]*\}/.test(x) ? ' ' + x.match(/#\{[^}]*\}/g).join(' ') + ' ' : ' ""'));
}

function logSecrets(u, out) {
  const c = u.content;
  if (!/\.(m?[jt]sx?|cjs|py|rb|php|go|java|kt|cs|swift|scala|rs|dart|ex|exs)$/i.test(base(u))) return;
  LOG_CALL.lastIndex = 0;
  let m, n = 0;
  while ((m = LOG_CALL.exec(c)) && n < 5) {
    const line = c.slice(m.index + m[0].length, c.indexOf('\n', m.index) < 0 ? c.length : c.indexOf('\n', m.index)).slice(0, 240);
    if (/^\s*$/.test(line)) continue;
    const code = argCode(line);
    const sens = code.match(SENSITIVE_ID);
    const whole = WHOLE_REQUEST.test(code);
    if (!sens && !whole) continue;
    // "token.length", "password_reset_url" u. ae. sind harmlos
    if (sens && !whole && /\.(length|size|count)\b|_(url|path|form|field|hint|policy|reset|expires?|type|label|valid)\b|is_?valid|\bhas_?\w+/i.test(code.slice(code.search(SENSITIVE_ID)))) continue;
    n++;
    out.push(mk(M, u, m.index, whole ? {
      ruleId: 'log-full-request', severity: 'medium', category: 'Logging',
      title: 'Ganze Anfrage wird protokolliert (Header/Body)',
      description: 'Die Log-Ausgabe enthält die komplette Anfrage bzw. ihre Header oder den Body. Darin stecken Passwörter aus Formularen, Cookies und Authorization-Header – sie landen dann im Klartext in Log-Dateien und Log-Diensten.',
      remediation: 'Nur ausgewählte, unkritische Felder loggen (Methode, Pfad, Status, Request-ID) und sensible Felder vorher maskieren.',
      evidence: oneLine(m[0] + line),
    } : {
      ruleId: 'log-sensitive-data', severity: 'medium', category: 'Logging',
      title: `Geheimer Wert wird protokolliert (${sens[1]})`,
      description: 'Eine Log-Ausgabe enthält eine Variable, die nach Passwort, Token oder Schlüssel aussieht. Logs werden oft lange aufbewahrt, an externe Dienste geschickt und von vielen Personen gelesen.',
      remediation: 'Den Wert nicht loggen oder nur maskiert (z. B. die letzten 4 Zeichen); im Logger zentrale Redaktionsregeln für Felder wie password, token und authorization einrichten.',
      evidence: oneLine(m[0] + line),
    }));
  }
}

// --- Jupyter-Notebooks ------------------------------------------------------
let SECRET_RULES = null;
function notebook(u, out) {
  let nb; try { nb = JSON.parse(u.content); } catch { return; }
  if (!nb || !Array.isArray(nb.cells)) return;
  if (!SECRET_RULES) SECRET_RULES = require('../prescan').SECRET_RULES.filter((r) => !/Generisches|Klartext-HTTP|JWT/.test(r.name));
  const texts = [];
  for (const cell of nb.cells) for (const o of (cell && Array.isArray(cell.outputs) ? cell.outputs : [])) {
    const parts = [o.text, o.data && o.data['text/plain'], o.data && o.data['text/html'], o.traceback];
    for (const p of parts) if (p) texts.push(Array.isArray(p) ? p.join('') : String(p));
  }
  if (!texts.length) return;
  const all = texts.join('\n').slice(0, 2 * 1024 * 1024);
  const hits = [];
  for (const r of SECRET_RULES) { r.re.lastIndex = 0; const m = r.re.exec(all); if (m) hits.push({ name: r.name, v: m[0] }); }
  const generic = all.match(/\b(password|passwd|secret|api[_-]?key|token|access[_-]?key)\b['"]?\s*[:=]\s*['"]?([^\s'"]{8,})/i);
  if (generic && !/^(\*+|x+|<[^>]+>|None|null|true|false)$/i.test(generic[2])) hits.push({ name: generic[1], v: generic[2] });
  const at = (v) => { const i = u.content.indexOf(JSON.stringify(v).slice(1, 21)); return i < 0 ? null : i; };
  if (hits.length) out.push(mk(M, u, at(hits[0].v), {
    ruleId: 'notebook-output-secret', severity: 'high', category: 'Secrets',
    title: `Geheimnis in gespeicherter Notebook-Ausgabe: ${hits[0].name}`,
    description: 'In den gespeicherten Ausgaben einer Zelle steht ein Schlüssel oder Passwort – etwa weil eine Variable oder Umgebung ausgegeben wurde. Ausgaben werden mit dem Notebook geteilt und eingecheckt, auch wenn der Code den Wert später nicht mehr enthält.',
    remediation: 'Den Schlüssel sperren und neu erzeugen, die Ausgaben löschen (jupyter nbconvert --clear-output --inplace) und nbstripout als Git-Filter einrichten.',
    evidence: hits.slice(0, 3).map((h) => `${h.name}: ${redactSecret(h.v)}`).join(', '),
  }));
  // personenbezogene Daten in Ausgaben (z. B. df.head() mit Kundendaten)
  const mails = new Set((all.match(EMAIL) || []).filter((e) => !EMAIL_SKIP.test(e)).map((e) => e.toLowerCase()));
  const ibans = (all.match(/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g) || []).filter((x) => ibanValid(x) && !EXAMPLE_IBANS.has(x.replace(/\s/g, '')));
  const phones = new Set((all.match(PHONE) || []).map((p) => p.replace(/\D/g, '')).filter((d) => d.length >= 9));
  const kinds = [mails.size >= 3 ? `${mails.size} E-Mail-Adressen` : '', ibans.length ? `${ibans.length} IBAN` : '', phones.size >= 3 ? `${phones.size} Telefonnummern` : ''].filter(Boolean);
  if (kinds.length) {
    const first = [...mails][0] || ibans[0] || [...phones][0];
    out.push(mk(M, u, at(first), {
      ruleId: 'notebook-output-pii', severity: 'medium', category: 'Other',
      title: 'Personenbezogene Daten in gespeicherter Notebook-Ausgabe',
      description: `Die gespeicherten Ausgaben enthalten ${kinds.join(', ')} – typischerweise aus df.head() oder print() auf echten Daten. Mit dem Notebook werden diese Daten geteilt und versioniert.`,
      remediation: 'Ausgaben vor dem Einchecken löschen (nbstripout) und für Beispiele anonymisierte oder erfundene Daten verwenden.',
      evidence: [...mails].slice(0, 2).map(redactSecret).concat(ibans.slice(0, 1).map(redactSecret)).join(', '),
    }));
  }
}

function runPrivacy(units) {
  const out = [];
  for (const u of units) {
    if (!isText(u)) continue;
    const p = base(u);
    if (/\.ipynb$/i.test(p)) { notebook(u, out); continue; }
    if (SKIP.test(p) || fileName(u) === '.vigilignore') continue;
    if (CODE.test(p) || isTestFile(u)) pii(u, out);
    logSecrets(u, out);
  }
  return out;
}

module.exports = { runPrivacy, ibanValid, steuerIdValid, ausweisValid };
