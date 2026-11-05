'use strict';

// Rechte und Zugaenge in SQL-Dateien und Migrationen: GRANT ALL, Rechte fuer PUBLIC bzw. jeden Host,
// Standard-Passwoerter beim Anlegen von Nutzern, Superuser-Rollen. Passwoerter werden maskiert.

const { base, applyRules, isText } = require('./rulekit');

const M = 'sql-audit';
// .sql-Dateien und alles in Migrations-/Seed-Ordnern (dort steht SQL oft in Strings von .rb/.py/.js)
const SQL_FILE = /\.sql$|(^|\/)(migrations?|db\/migrate|seeds?|schema|initdb|docker-entrypoint-initdb\.d|flyway|liquibase)\//i;
const WEAK_PW = "(password|passwort|admin|root|123456|12345678|changeme|change_me|secret|postgres|mysql|test|sa|qwerty|letmein|default|welcome|geheim|pass)";

const RULES = [
  { id: 'sql-default-password', sev: 'high', cat: 'Secrets', redact: true, re: new RegExp(`\\b(CREATE|ALTER)\\s+(USER|ROLE|LOGIN)\\b[^;]{0,160}?\\b(IDENTIFIED\\s+(WITH\\s+\\w+\\s+)?BY|PASSWORD)\\s*=?\\s*['"]${WEAK_PW}['"]`, 'gi'), title: 'Datenbank-Nutzer mit Standard-Passwort', desc: 'Ein Datenbank-Zugang wird mit einem bekannten Standard-Passwort angelegt. Solche Passwörter stehen in jeder Angriffsliste und werden als Erstes ausprobiert.', fix: 'Ein langes, zufälliges Passwort verwenden, es aus einem Secret-Manager bzw. einer Umgebungsvariable einsetzen und den bestehenden Zugang sofort ändern.' },
  { id: 'sql-plaintext-password', sev: 'medium', cat: 'Secrets', redact: true, re: /\b(CREATE|ALTER)\s+(USER|ROLE|LOGIN)\b[^;]{0,160}?\b(IDENTIFIED\s+(WITH\s+\w+\s+)?BY|PASSWORD)\s*=?\s*'[^'$:{]{4,}'/gi, test: (m) => !new RegExp(`['"]${WEAK_PW}['"]`, 'i').test(m[0]), title: 'Passwort eines Datenbank-Nutzers im Klartext', desc: 'Das Passwort steht direkt in der SQL-Datei bzw. Migration und damit im Repository. Jeder mit Lesezugriff kennt den Zugang.', fix: 'Passwort beim Deployment aus einer Umgebungsvariable oder einem Secret-Manager setzen und das bisherige Passwort ändern.' },
  { id: 'sql-grant-all', sev: 'high', cat: 'AccessControl', re: /\bGRANT\s+ALL(\s+PRIVILEGES)?\s+ON\b[^;]*/gi, title: 'GRANT ALL: Datenbank-Nutzer bekommt sämtliche Rechte', desc: 'Der Nutzer darf alles – auch Tabellen löschen, Rechte vergeben oder Dateien lesen (je nach Datenbank). Wird die Anwendung übernommen, ist damit die ganze Datenbank verloren.', fix: 'Nur die benötigten Rechte vergeben, z. B. GRANT SELECT, INSERT, UPDATE ON app.* TO app_user; Schema-Änderungen über einen eigenen Migrations-Nutzer.' },
  { id: 'sql-grant-public', sev: 'medium', cat: 'AccessControl', re: /\bGRANT\s+[\w\s,]+?\s+ON\b[^;]{0,200}?\bTO\s+PUBLIC\b/gi, title: 'Rechte für PUBLIC vergeben (jeder Datenbank-Nutzer)', desc: 'Rechte für PUBLIC gelten für jeden, der sich an der Datenbank anmelden kann – auch für Zugänge anderer Anwendungen.', fix: 'Rechte nur an konkrete Rollen vergeben und PUBLIC-Rechte entziehen (REVOKE … FROM PUBLIC).' },
  { id: 'sql-grant-any-host', sev: 'medium', cat: 'AccessControl', re: /\bGRANT\b[^;]{0,200}?\bTO\s+['"`]?[\w-]+['"`]?@['"`]%['"`]|\bCREATE\s+USER\s+['"`]?[\w-]+['"`]?@['"`]%['"`]/gi, title: 'Datenbank-Zugang von jedem Rechner erlaubt (@\'%\')', desc: 'Der Nutzer darf sich von jeder Adresse aus anmelden. Ist der Datenbank-Port erreichbar, können Angreifer das Passwort direkt ausprobieren.', fix: 'Den Host einschränken (z. B. \'app\'@\'10.0.0.%\' oder \'app\'@\'localhost\').' },
  { id: 'sql-superuser-role', sev: 'high', cat: 'AccessControl', re: /\b(CREATE|ALTER)\s+(USER|ROLE)\b[^;]*\bSUPERUSER\b|\bsp_addsrvrolemember\b[^;]*sysadmin|\bALTER\s+SERVER\s+ROLE\s+sysadmin\s+ADD\s+MEMBER|\bGRANT\s+(SUPER|FILE)\b[^;]*\bON\s+\*\.\*/gi, test: (m) => !/\bNO\s*SUPERUSER\b/i.test(m[0]), title: 'Datenbank-Nutzer mit Administrator-Rechten', desc: 'Die Rolle bekommt Superuser- bzw. sysadmin-Rechte. Damit lassen sich oft auch Dateien auf dem Server lesen oder Befehle ausführen.', fix: 'Anwendungen mit einer Rolle ohne Superuser-Rechte verbinden; Administrator-Zugänge nur für Wartung und getrennt halten.' },
];

function runSqlAudit(units) {
  const out = [];
  for (const u of units) {
    if (!isText(u) || !SQL_FILE.test(base(u))) continue;
    if (!/\b(GRANT|CREATE\s+USER|CREATE\s+ROLE|CREATE\s+LOGIN|ALTER\s+USER|ALTER\s+ROLE|sp_addsrvrolemember|ALTER\s+SERVER\s+ROLE)\b/i.test(u.content)) continue;
    applyRules(M, u, RULES, out);
  }
  return out;
}

module.exports = { runSqlAudit, SQL_RULES: RULES };
