'use strict';

// Eigene Regeln fuer Go, Rust, C#, PHP, Kotlin und Swift. Je Regel: Sprache(n), Muster,
// optional ein Gegentest im Umfeld (z. B. "wird bereits parametrisiert"). Alle Texte in
// Alltagssprache; Loesungsschritte je Regel stehen direkt dabei.

const { normalizeFinding } = require('../schema');

const M = 'lang-rules';
const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;
const LANG = { '.go': 'go', '.rs': 'rust', '.cs': 'csharp', '.php': 'php', '.kt': 'kotlin', '.kts': 'kotlin', '.swift': 'swift', '.plist': 'plist' };
const langOf = (u) => LANG[(base(u).match(/\.\w+$/) || [''])[0].toLowerCase()] || null;

const SQL = '(SELECT|INSERT|UPDATE|DELETE)\\b';
const RULES = [
  // --- Go ---
  { lang: 'go', id: 'go-sql-concat', sev: 'high', cat: 'Injection', re: new RegExp(`\\.(Query|QueryRow|Exec)(Context)?\\([^)]*(fmt\\.Sprintf\\(\\s*"[^"]*${SQL}|"[^"]*${SQL}[^"]*"\\s*\\+)`, 'gi'), title: 'SQL-Befehl wird aus Text zusammengebaut (Go)', desc: 'Werte werden direkt in den SQL-Text eingesetzt. Wer den Wert steuert, kann den Befehl verändern und fremde Daten lesen oder löschen.', fix: 'Platzhalter verwenden: db.Query("SELECT … WHERE id = $1", id).' },
  { lang: 'go', id: 'go-shell-exec', sev: 'high', cat: 'Injection', re: /exec\.Command(Context)?\(\s*(ctx\s*,\s*)?"(sh|bash|cmd(\.exe)?|powershell)"\s*,\s*"(-c|\/c)"/g, title: 'Befehl wird über die Shell ausgeführt (Go)', desc: 'Über sh -c wird ein ganzer Text als Befehl gestartet. Steckt darin eine Eingabe, kann man eigene Befehle anhängen.', fix: 'Programm direkt mit getrennten Argumenten starten: exec.Command("git", "log", arg).' },
  { lang: 'go', id: 'go-insecure-tls', sev: 'high', cat: 'Transport', re: /InsecureSkipVerify\s*:\s*true/g, title: 'Zertifikatsprüfung abgeschaltet (Go)', desc: 'Die Verbindung akzeptiert jedes Zertifikat. Jemand im selben Netz kann sich unbemerkt dazwischenschalten.', fix: 'InsecureSkipVerify entfernen; für eigene Zertifikate RootCAs setzen.' },
  { lang: 'go', id: 'go-weak-rand', sev: 'medium', cat: 'Crypto', re: /"math\/rand"/g, test: (c) => /(token|secret|password|nonce|otp|session|key)/i.test(c), title: 'Unsicherer Zufall für Geheimnisse (Go)', desc: 'math/rand ist vorhersagbar. Damit erzeugte Tokens oder Codes lassen sich erraten.', fix: 'crypto/rand verwenden.' },
  { lang: 'go', id: 'go-weak-hash', sev: 'medium', cat: 'Crypto', re: /\b(md5|sha1)\.(New|Sum)\(/g, title: 'Schwaches Hash-Verfahren (Go)', desc: 'MD5 und SHA-1 gelten als gebrochen und schützen Passwörter oder Signaturen nicht mehr.', fix: 'Für Passwörter bcrypt/argon2, sonst sha256 verwenden.' },
  { lang: 'go', id: 'go-template-unescaped', sev: 'medium', cat: 'XSS', re: /template\.HTML\(\s*[a-zA-Z_]\w*(\.\w+)*\s*\)/g, title: 'Text wird ungeprüft als HTML ausgegeben (Go)', desc: 'template.HTML schaltet den Schutz gegen eingeschleusten Code ab. Kommt der Wert vom Nutzer, kann er Skripte in die Seite schmuggeln.', fix: 'Den Wert normal als string ausgeben lassen; html/template maskiert dann automatisch.' },
  // --- Rust ---
  { lang: 'rust', id: 'rust-insecure-tls', sev: 'high', cat: 'Transport', re: /danger_accept_invalid_(certs|hostnames)\(\s*true\s*\)/g, title: 'Zertifikatsprüfung abgeschaltet (Rust)', desc: 'Die Verbindung akzeptiert jedes Zertifikat und ist damit nicht vor Mitlesen geschützt.', fix: 'Aufruf entfernen; eigene Zertifikate über add_root_certificate hinzufügen.' },
  { lang: 'rust', id: 'rust-shell-exec', sev: 'high', cat: 'Injection', re: /Command::new\(\s*"(sh|bash|cmd)"\s*\)[\s\S]{0,60}?\.arg\(\s*"(-c|\/C)"\s*\)[\s\S]{0,40}?\.arg\(\s*(&?format!|[a-z_]\w*)/g, title: 'Befehl wird über die Shell ausgeführt (Rust)', desc: 'Ein zusammengesetzter Text wird als Shell-Befehl gestartet. Eingaben darin können eigene Befehle anhängen.', fix: 'Programm direkt mit .arg() je Argument starten, ohne sh -c.' },
  { lang: 'rust', id: 'rust-sql-format', sev: 'high', cat: 'Injection', re: new RegExp(`(query|execute|query_as)\\w*\\(\\s*&?format!\\(\\s*"[^"]*${SQL}`, 'gi'), title: 'SQL-Befehl wird mit format! gebaut (Rust)', desc: 'Werte landen direkt im SQL-Text. Wer sie steuert, verändert den Befehl.', fix: 'Platzhalter mit .bind(wert) verwenden (sqlx, diesel).' },
  { lang: 'rust', id: 'rust-unsafe-block', sev: 'info', cat: 'Other', re: /\bunsafe\s*\{/g, max: 1, title: 'unsafe-Block im Code (Rust)', desc: 'In unsafe-Blöcken prüft der Compiler Speicherfehler nicht. Diese Stellen sollten besonders sorgfältig geprüft werden.', fix: 'Wenn möglich durch sichere Alternativen ersetzen und jeden Block mit einem SAFETY-Kommentar begründen.' },
  // --- C# ---
  { lang: 'csharp', id: 'cs-sql-concat', sev: 'high', cat: 'Injection', re: new RegExp(`new\\s+(Sql|Npgsql|MySql|Sqlite|OleDb)Command\\(\\s*(\\$"[^"]*${SQL}[^"]*\\{|"[^"]*${SQL}[^"]*"\\s*\\+)|\\.(FromSqlRaw|ExecuteSqlRaw)\\(\\s*(\\$"|"[^"]*"\\s*\\+)`, 'gi'), title: 'SQL-Befehl wird aus Text zusammengebaut (C#)', desc: 'Werte werden direkt in den SQL-Text eingesetzt. Damit lässt sich der Befehl verändern.', fix: 'SqlParameter verwenden: cmd.Parameters.AddWithValue("@id", id) bzw. FromSqlInterpolated.' },
  { lang: 'csharp', id: 'cs-binaryformatter', sev: 'high', cat: 'Deserialization', re: /\bnew\s+(BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter)\s*\(/g, title: 'Unsicheres Einlesen von Objekten (C#)', desc: 'BinaryFormatter und Verwandte können beim Einlesen fremder Daten beliebigen Code ausführen. Microsoft rät dringend davon ab.', fix: 'System.Text.Json oder einen anderen sicheren Serialisierer verwenden.' },
  { lang: 'csharp', id: 'cs-cert-validation-off', sev: 'high', cat: 'Transport', re: /(ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback)\s*=\s*(\([^)]*\)|\w+)\s*=>\s*true/g, title: 'Zertifikatsprüfung abgeschaltet (C#)', desc: 'Jedes Zertifikat wird akzeptiert – die Verbindung ist nicht mehr vor Mitlesen geschützt.', fix: 'Callback entfernen oder nur ein bestimmtes, bekanntes Zertifikat zulassen.' },
  { lang: 'csharp', id: 'cs-process-concat', sev: 'high', cat: 'Injection', re: /Process\.Start\(\s*"(cmd(\.exe)?|powershell(\.exe)?|\/bin\/(ba)?sh)"\s*,\s*(\$"|"[^"]*"\s*\+)/gi, title: 'Befehl wird mit zusammengesetztem Text gestartet (C#)', desc: 'Eingaben im Befehlstext können zusätzliche Befehle einschleusen.', fix: 'ProcessStartInfo mit ArgumentList und ohne Shell verwenden.' },
  { lang: 'csharp', id: 'cs-weak-hash', sev: 'medium', cat: 'Crypto', re: /\b(MD5|SHA1)\.Create\(\)|new\s+(MD5|SHA1)CryptoServiceProvider/g, title: 'Schwaches Hash-Verfahren (C#)', desc: 'MD5 und SHA-1 gelten als gebrochen.', fix: 'Für Passwörter Rfc2898DeriveBytes/PBKDF2 oder BCrypt, sonst SHA256 verwenden.' },
  { lang: 'csharp', id: 'cs-weak-rand', sev: 'medium', cat: 'Crypto', re: /new\s+Random\(\)/g, test: (c) => /(token|secret|password|otp|code|key)/i.test(c), title: 'Unsicherer Zufall für Geheimnisse (C#)', desc: 'System.Random ist vorhersagbar.', fix: 'RandomNumberGenerator.GetBytes() verwenden.' },
  // --- PHP ---
  { lang: 'php', id: 'php-sql-concat', sev: 'critical', cat: 'Injection', re: /(mysqli_query|->query|mysql_query|pg_query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)/g, title: 'Eingabe landet direkt im SQL-Befehl (PHP)', desc: 'Ein Wert aus der Anfrage wird ungeprüft in einen SQL-Befehl eingesetzt. Damit lässt sich die ganze Datenbank auslesen.', fix: 'Prepared Statements verwenden: $stmt = $pdo->prepare("… WHERE id = ?"); $stmt->execute([$id]);' },
  { lang: 'php', id: 'php-xss-echo', sev: 'high', cat: 'XSS', re: /\b(echo|print)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)\[/g, title: 'Eingabe wird ungeprüft ausgegeben (PHP)', desc: 'Ein Wert aus der Anfrage landet ohne Maskierung in der Seite. So lassen sich Skripte einschleusen.', fix: 'htmlspecialchars($wert, ENT_QUOTES, \'UTF-8\') verwenden.' },
  { lang: 'php', id: 'php-cmd-exec', sev: 'critical', cat: 'Injection', re: /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)/g, title: 'Eingabe landet in einem Systembefehl (PHP)', desc: 'Ein Wert aus der Anfrage wird als Teil eines Befehls auf dem Server ausgeführt. Damit kann man den Server übernehmen.', fix: 'Auf Systembefehle verzichten; wenn nötig nur feste Werte zulassen und escapeshellarg() verwenden.' },
  { lang: 'php', id: 'php-file-include', sev: 'critical', cat: 'PathTraversal', re: /\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)/g, title: 'Datei-Einbindung aus der Anfrage (PHP)', desc: 'Welche Datei eingebunden wird, bestimmt der Besucher. Damit lassen sich Serverdateien lesen oder fremder Code ausführen.', fix: 'Nur Dateien aus einer festen Liste erlauben.' },
  { lang: 'php', id: 'php-unserialize', sev: 'high', cat: 'Deserialization', re: /unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/g, title: 'Fremde Daten werden als Objekt eingelesen (PHP)', desc: 'unserialize() mit Daten vom Besucher kann Code auf dem Server ausführen.', fix: 'json_decode() verwenden.' },
  { lang: 'php', id: 'php-extract', sev: 'medium', cat: 'Injection', re: /extract\s*\(\s*\$_(GET|POST|REQUEST)/g, title: 'Anfrage-Werte werden zu Variablen (PHP)', desc: 'extract() legt aus der Anfrage beliebige Variablen an und kann so z. B. $isAdmin überschreiben.', fix: 'Werte einzeln und geprüft auslesen.' },
  { lang: 'php', id: 'php-weak-password-hash', sev: 'high', cat: 'Crypto', re: /\b(md5|sha1)\s*\(\s*\$\w*(pass|pw|pwd)/gi, title: 'Passwort mit schwachem Verfahren gespeichert (PHP)', desc: 'md5/sha1-Passwörter lassen sich in Sekunden zurückrechnen.', fix: 'password_hash() und password_verify() verwenden.' },
  // --- Kotlin ---
  { lang: 'kotlin', id: 'kt-sql-concat', sev: 'high', cat: 'Injection', re: new RegExp(`(rawQuery|execSQL)\\(\\s*"[^"]*${SQL}[^"]*("\\s*\\+|\\$\\{?\\w)`, 'gi'), title: 'SQL-Befehl wird aus Text zusammengebaut (Kotlin)', desc: 'Werte landen direkt im SQL-Text der App-Datenbank.', fix: 'Platzhalter mit selectionArgs verwenden: rawQuery("… WHERE id = ?", arrayOf(id)).' },
  { lang: 'kotlin', id: 'kt-webview-js-bridge', sev: 'high', cat: 'Injection', re: /addJavascriptInterface\(/g, test: (c) => /javaScriptEnabled\s*=\s*true/.test(c), title: 'Webseite darf App-Funktionen aufrufen (Kotlin)', desc: 'Mit JavaScript und addJavascriptInterface kann jede in der WebView geladene Seite Funktionen der App aufrufen – auch fremde Seiten.', fix: 'Nur eigene, per HTTPS geladene Seiten zulassen und die Schnittstelle auf das Nötigste beschränken.' },
  { lang: 'kotlin', id: 'kt-trust-all', sev: 'high', cat: 'Transport', re: /hostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}|override\s+fun\s+checkServerTrusted\([^)]*\)\s*(\{\s*\}|=\s*Unit)/g, title: 'Zertifikatsprüfung abgeschaltet (Kotlin)', desc: 'Die App akzeptiert jedes Zertifikat. In öffentlichen WLANs lässt sich der Verkehr mitlesen.', fix: 'Eigene TrustManager entfernen; für eigene Zertifikate network_security_config verwenden.' },
  { lang: 'kotlin', id: 'kt-shell-exec', sev: 'high', cat: 'Injection', re: /Runtime\.getRuntime\(\)\.exec\(\s*("[^"]*"\s*\+|"[^"]*\$)/g, title: 'Befehl mit zusammengesetztem Text (Kotlin)', desc: 'Eingaben im Befehlstext können zusätzliche Befehle einschleusen.', fix: 'ProcessBuilder mit einzelnen Argumenten verwenden.' },
  { lang: 'kotlin', id: 'kt-world-readable', sev: 'medium', cat: 'Config', re: /MODE_WORLD_(READABLE|WRITEABLE)/g, title: 'Datei für alle Apps lesbar (Kotlin)', desc: 'Andere Apps auf dem Gerät können diese Datei lesen oder ändern.', fix: 'MODE_PRIVATE verwenden.' },
  // --- Swift ---
  { lang: 'swift', id: 'swift-sql-interp', sev: 'high', cat: 'Injection', re: new RegExp(`sqlite3_(exec|prepare(_v2)?)\\([^,]+,\\s*"[^"]*${SQL}[^"]*\\\\\\(`, 'gi'), title: 'SQL-Befehl mit eingesetzten Werten (Swift)', desc: 'Werte werden per \\( ) direkt in den SQL-Text eingesetzt.', fix: 'sqlite3_bind_* mit Platzhaltern verwenden.' },
  { lang: 'swift', id: 'swift-secret-userdefaults', sev: 'medium', cat: 'Secrets', re: /UserDefaults\.standard\.set\([^)]*forKey:\s*"[^"]*(password|token|secret|pin)/gi, title: 'Geheimnis in UserDefaults gespeichert (Swift)', desc: 'UserDefaults ist unverschlüsselt und landet in Backups.', fix: 'Passwörter und Tokens im Schlüsselbund (Keychain) speichern.' },
  { lang: 'swift', id: 'swift-trust-all', sev: 'high', cat: 'Transport', re: /completionHandler\(\s*\.useCredential\s*,\s*URLCredential\(trust:/g, test: (c) => !/SecTrustEvaluate|evaluateWithError|pinned/i.test(c), title: 'Jedes Server-Zertifikat wird akzeptiert (Swift)', desc: 'Die App vertraut jedem Zertifikat, ohne es zu prüfen.', fix: 'Zertifikat mit SecTrustEvaluateWithError prüfen oder den Standard-Ablauf verwenden.' },
  { lang: 'swift', id: 'swift-weak-hash', sev: 'medium', cat: 'Crypto', re: /\bCC_(MD5|SHA1)\(|Insecure\.(MD5|SHA1)/g, title: 'Schwaches Hash-Verfahren (Swift)', desc: 'MD5 und SHA-1 gelten als gebrochen.', fix: 'SHA256 aus CryptoKit verwenden.' },
  { lang: ['swift', 'plist'], id: 'ios-ats-disabled', sev: 'medium', cat: 'Transport', re: /NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>|NSAllowsArbitraryLoads"?\s*[:=]\s*true/g, title: 'App erlaubt unverschlüsselte Verbindungen (iOS)', desc: 'App Transport Security ist abgeschaltet – die App darf jede Seite auch ohne HTTPS laden.', fix: 'NSAllowsArbitraryLoads entfernen und nur einzelne Domains per NSExceptionDomains freigeben.' },
];

function runLangs(units) {
  const out = [];
  for (const u of units) {
    const lang = langOf(u);
    if (!lang && !/Info\.plist$/i.test(base(u))) continue;
    const l = lang || 'plist';
    const c = u.content || '';
    for (const r of RULES) {
      if (!(Array.isArray(r.lang) ? r.lang.includes(l) : r.lang === l)) continue;
      if (r.test && !r.test(c)) continue;
      r.re.lastIndex = 0; let m, n = 0;
      while ((m = r.re.exec(c)) && n < (r.max || 5)) {
        n++;
        out.push(normalizeFinding({
          ruleId: r.id, severity: r.sev, category: r.cat, confidence: 'medium',
          title: r.title, description: r.desc, remediation: r.fix,
          location: `${base(u)}:${lineOf(c, m.index)}`, evidence: m[0].replace(/\s+/g, ' ').slice(0, 160),
          sourceModule: M,
        }, M));
      }
    }
  }
  return out;
}

module.exports = { runLangs, LANG_RULES: RULES };
