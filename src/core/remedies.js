'use strict';

// Loesungs-Wissensbasis: Zu jeder Regel eine verstaendliche Erklaerung, konkrete Schritte,
// kopierfertige Konfig-Schnipsel und weiterfuehrende Links. Bei verwundbaren Paketen
// zusaetzlich ein Versions-Patch auf die erste behobene Version.
//
// Links: feste Doku-Seiten (OWASP, MDN, NVD, OSV …) plus Suchlinks zu heise und YouTube –
// Suchen statt erfundener Einzelartikel, damit kein Link ins Leere fuehrt.

const enc = encodeURIComponent;
const heise = (q) => ({ label: `heise: „${q}“`, url: `https://www.heise.de/suche/?q=${enc(q)}`, kind: 'news' });
const video = (q) => ({ label: `Video: ${q}`, url: `https://www.youtube.com/results?search_query=${enc(q)}`, kind: 'video' });
const doc = (label, url) => ({ label, url, kind: 'doc' });

const OWASP_HEADERS = doc('OWASP HTTP Headers Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html');
const MDN = (h) => doc(`MDN: ${h}`, `https://developer.mozilla.org/de/docs/Web/HTTP/Headers/${h}`);

// Header-Schnipsel fuer die drei verbreitetsten Webserver.
const headerSnips = (name, value) => ({
  nginx: `# in server { … } bzw. location { … }\nadd_header ${name} "${value}" always;`,
  apache: `# in VirtualHost oder .htaccess (mod_headers aktiv)\nHeader always set ${name} "${value}"`,
  caddy: `# im Site-Block\nheader ${name} "${value}"`,
  express: `// Node/Express – am einfachsten mit helmet: npm i helmet\napp.use((req, res, next) => { res.setHeader('${name}', '${value}'); next(); });`,
});

const KB = [
  // --- Web-Header ----------------------------------------------------------
  { match: /^missing-hsts-header$/, explanation: 'Ohne HSTS kann ein Angreifer im selben WLAN den allerersten Aufruf auf unverschlüsseltes HTTP umbiegen (SSL-Stripping) und Logins mitlesen. HSTS sagt dem Browser: „Diese Seite nur noch per HTTPS öffnen.“',
    steps: ['Sicherstellen, dass die ganze Seite inkl. Subdomains per HTTPS erreichbar ist.', 'Header zunächst mit kurzer max-age (z. B. 1 Tag) setzen und testen.', 'Danach auf ein Jahr erhöhen und optional in die HSTS-Preload-Liste eintragen.'],
    snippets: headerSnips('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'),
    links: [MDN('Strict-Transport-Security'), doc('HSTS Preload', 'https://hstspreload.org/'), heise('HSTS'), video('HSTS erklärt')] },
  { match: /^missing-csp-header$|^unsafe-csp-directive$|^csp-wildcard-script-src$/, explanation: 'Die Content-Security-Policy legt fest, woher Skripte geladen werden dürfen. Fehlt sie – oder erlaubt sie Inline-Skripte, eval oder „*“ – kann eingeschleuster Code (XSS) ungehindert Sitzungen und Daten stehlen.',
    steps: ['Mit einer Report-Only-Policy starten und Verstöße beobachten.', 'Inline-Skripte in Dateien auslagern oder per Nonce/Hash erlauben.', "Auf 'unsafe-inline', 'unsafe-eval' und Wildcards in script-src verzichten, dann scharf schalten."],
    snippets: headerSnips('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
    links: [MDN('Content-Security-Policy'), doc('OWASP CSP Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'), doc('Google CSP Evaluator', 'https://csp-evaluator.withgoogle.com/'), heise('Content Security Policy'), video('Content Security Policy tutorial')] },
  { match: /^missing-x-content-type-options$/, explanation: 'Ohne „nosniff“ errät der Browser Dateitypen selbst – eine hochgeladene Textdatei kann so als Skript ausgeführt werden.',
    steps: ['Header für alle Antworten setzen.', 'Korrekte Content-Type-Header für alle Dateitypen sicherstellen.'],
    snippets: headerSnips('X-Content-Type-Options', 'nosniff'), links: [MDN('X-Content-Type-Options'), OWASP_HEADERS] },
  { match: /^missing-clickjacking-protection$/, explanation: 'Fremde Seiten können deine Seite unsichtbar einbetten und Nutzer zu Klicks verleiten (Clickjacking) – etwa auf „Konto löschen“ oder „Zahlung bestätigen“.',
    steps: ['Einbetten verbieten (DENY) oder auf die eigene Domain beschränken (SAMEORIGIN).', 'Moderner: CSP-Direktive frame-ancestors verwenden.'],
    snippets: headerSnips('X-Frame-Options', 'DENY'), links: [MDN('X-Frame-Options'), doc('OWASP Clickjacking', 'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'), video('Clickjacking explained')] },
  { match: /^missing-referrer-policy$/, explanation: 'Ohne Referrer-Policy schickt der Browser beim Klick auf externe Links die volle Adresse mit – inklusive Pfaden, IDs oder Tokens in der URL.',
    steps: ['strict-origin-when-cross-origin setzen – überträgt extern nur noch die Domain.'], snippets: headerSnips('Referrer-Policy', 'strict-origin-when-cross-origin'), links: [MDN('Referrer-Policy')] },
  { match: /^missing-permissions-policy$/, explanation: 'Ohne Permissions-Policy dürfen eingebettete Skripte und iFrames Kamera, Mikrofon oder Standort anfragen. Eine Policy schaltet ungenutzte Funktionen ab.',
    steps: ['Nur die wirklich genutzten Browser-Funktionen erlauben.'], snippets: headerSnips('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'), links: [MDN('Permissions-Policy')] },
  { match: /^missing-coop$/, explanation: 'Cross-Origin-Opener-Policy trennt dein Fenster von fremden Pop-ups und schützt vor Angriffen über window.opener und Seitenkanälen (Spectre-artig).',
    steps: ['same-origin setzen; bei OAuth-Pop-ups ggf. same-origin-allow-popups.'], snippets: headerSnips('Cross-Origin-Opener-Policy', 'same-origin'), links: [MDN('Cross-Origin-Opener-Policy')] },
  { match: /^version-disclosure-|^tech-disclosure-/, explanation: 'Exakte Versionsnummern im Server-Header verraten Angreifern, welche bekannten Lücken sie gezielt ausprobieren können. Das Verbergen behebt keine Lücke, macht automatisierte Angriffe aber unwahrscheinlicher.',
    steps: ['Versionsangaben im Webserver abschalten.', 'X-Powered-By im Framework deaktivieren.', 'Wichtiger als das Verstecken: die Software aktuell halten.'],
    snippets: { nginx: '# http { … }\nserver_tokens off;', apache: 'ServerTokens Prod\nServerSignature Off', php: '; php.ini\nexpose_php = Off', express: "app.disable('x-powered-by');" },
    links: [OWASP_HEADERS, heise('Server-Banner verbergen')] },
  { match: /^cookie-missing-/, explanation: 'Session-Cookies ohne Secure gehen auch über HTTP, ohne HttpOnly kann ein XSS-Skript sie auslesen, ohne SameSite werden sie bei fremden Formularen mitgeschickt (CSRF).',
    steps: ['Beim Setzen des Cookies alle drei Attribute angeben.', 'SameSite=Lax als Standard, Strict für reine Session-Cookies.'],
    snippets: { http: 'Set-Cookie: session=…; Path=/; Secure; HttpOnly; SameSite=Lax', express: "res.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'lax' });", php: "session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);" },
    links: [MDN('Set-Cookie'), doc('OWASP Session Management', 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html')] },
  { match: /^cors-/, explanation: 'Eine zu offene CORS-Regel erlaubt fremden Webseiten, im Namen eingeloggter Nutzer Daten von deiner API zu lesen. Besonders gefährlich: Die Herkunft wird blind zurückgespiegelt und Credentials sind erlaubt.',
    steps: ['Erlaubte Origins als feste Liste pflegen – nie den Origin-Header ungeprüft zurückgeben.', 'Access-Control-Allow-Credentials nur zusammen mit konkreten Origins.', 'Vary: Origin setzen, damit Caches nicht falsch ausliefern.'],
    snippets: { nginx: 'map $http_origin $cors_ok { default ""; "https://app.example.com" $http_origin; }\nadd_header Access-Control-Allow-Origin $cors_ok always;\nadd_header Vary Origin always;', express: "app.use(require('cors')({ origin: ['https://app.example.com'], credentials: true }));" },
    links: [doc('MDN: CORS', 'https://developer.mozilla.org/de/docs/Web/HTTP/CORS'), doc('PortSwigger: CORS', 'https://portswigger.net/web-security/cors'), video('CORS misconfiguration explained')] },
  { match: /^tls-cert-/, explanation: 'Ein abgelaufenes oder ungültiges Zertifikat führt zu Browser-Warnungen; Nutzer gewöhnen sich daran, Warnungen wegzuklicken – genau das nutzen Angreifer aus.',
    steps: ['Zertifikat erneuern bzw. vollständige Kette ausliefern.', 'Automatische Erneuerung per ACME (Let’s Encrypt, certbot, Caddy) einrichten.', 'Ablauf-Monitoring mit Vorwarnung einrichten.'],
    snippets: { certbot: 'sudo certbot renew --dry-run\n# Timer prüfen:\nsystemctl list-timers | grep certbot', caddy: '# Caddy holt und erneuert Zertifikate automatisch:\nexample.com {\n  reverse_proxy 127.0.0.1:3000\n}' },
    links: [doc('Let’s Encrypt', 'https://letsencrypt.org/de/getting-started/'), doc('SSL Labs Test', 'https://www.ssllabs.com/ssltest/'), heise('Zertifikat abgelaufen')] },
  { match: /^tls-legacy-protocol$|^tls-weak-cipher$/, explanation: 'TLS 1.0/1.1 und alte Chiffren (RC4, 3DES, NULL/EXPORT) gelten als gebrochen bzw. veraltet. Moderne Browser brauchen sie nicht mehr.',
    steps: ['Nur TLS 1.2 und 1.3 erlauben.', 'Moderne Chiffren-Liste verwenden (Mozilla-Generator).'],
    snippets: { nginx: 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;', apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3' },
    links: [doc('Mozilla SSL Config Generator', 'https://ssl-config.mozilla.org/'), heise('TLS 1.0 abschalten')] },
  { match: /^no-https$|^mixed-content$|^dom-mixed-content$/, explanation: 'Unverschlüsselte Verbindungen (http://, ws://) können unterwegs mitgelesen und verändert werden – auch wenn die Hauptseite selbst HTTPS nutzt.',
    steps: ['Alle Ressourcen und WebSockets über https:// bzw. wss:// laden.', 'HTTP dauerhaft auf HTTPS umleiten.', "Zur Absicherung CSP upgrade-insecure-requests setzen."],
    snippets: { nginx: 'server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}', csp: "Content-Security-Policy: upgrade-insecure-requests" },
    links: [doc('MDN: Mixed Content', 'https://developer.mozilla.org/de/docs/Web/Security/Mixed_content')] },
  { match: /^exposed-|^web-sourcemap-exposed$/, explanation: 'Dateien wie .env, .git, Backups oder SourceMaps gehören nicht ins Web. Sie verraten Zugangsdaten oder den kompletten Quellcode – oft der erste Schritt eines Angriffs.',
    steps: ['Datei sofort aus dem Web-Root entfernen bzw. Zugriff sperren.', 'Enthaltene Zugangsdaten als kompromittiert betrachten und rotieren.', 'Build so konfigurieren, dass SourceMaps nicht mit ausgeliefert werden.'],
    snippets: { nginx: '# versteckte Dateien und SourceMaps sperren\nlocation ~ /\\.(?!well-known) { deny all; }\nlocation ~* \\.map$ { deny all; }', apache: '<FilesMatch "^\\.|\\.map$">\n  Require all denied\n</FilesMatch>', vite: '// vite.config.js\nexport default { build: { sourcemap: false } };', webpack: "// webpack.config.js (Produktion)\nmodule.exports = { devtool: false };" },
    links: [doc('OWASP: Information Exposure', 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'), heise('.git Verzeichnis öffentlich'), video('exposed .git directory')] },
  { match: /^graphql-introspection$/, explanation: 'Mit aktivierter Introspection liefert die GraphQL-API ihre komplette Struktur aus – inklusive interner Felder und Mutationen, die Angreifer dann gezielt ansprechen.',
    steps: ['Introspection in Produktion abschalten.', 'Zusätzlich Abfragetiefe und -komplexität begrenzen.'],
    snippets: { apollo: 'new ApolloServer({ schema, introspection: process.env.NODE_ENV !== "production" });', yoga: "import { useDisableIntrospection } from '@graphql-yoga/plugin-disable-introspection';" },
    links: [doc('OWASP GraphQL Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'), video('GraphQL security introspection')] },
  { match: /^http-trace$|^http-write-methods$|^directory-listing$/, explanation: 'Unnötig erlaubte HTTP-Methoden oder Verzeichnis-Listings vergrößern die Angriffsfläche ohne Nutzen.',
    steps: ['Nur benötigte Methoden (GET, POST, HEAD) zulassen.', 'Directory-Listing abschalten.'],
    snippets: { nginx: 'autoindex off;\nif ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }', apache: 'Options -Indexes\nTraceEnable off' }, links: [OWASP_HEADERS] },

  // --- DNS & Mail ---------------------------------------------------------
  { match: /^dns-spf-/, explanation: 'SPF legt fest, welche Server E-Mails für deine Domain verschicken dürfen. Fehlt es oder endet es mit +all/?all, können Betrüger täuschend echte Mails in deinem Namen senden.',
    steps: ['Alle legitimen Versender (Mailserver, Newsletter-Dienst) erfassen.', 'SPF-Eintrag mit -all (oder zunächst ~all) setzen.', 'Maximal 10 DNS-Lookups – sonst ist SPF ungültig.'],
    snippets: { dns: 'example.com.  TXT  "v=spf1 mx include:_spf.google.com -all"' }, links: [doc('SPF-Generator & Check (MXToolbox)', 'https://mxtoolbox.com/spf.aspx'), heise('SPF DKIM DMARC'), video('SPF DKIM DMARC erklärt')] },
  { match: /^dns-dmarc-/, explanation: 'DMARC sagt Empfängern, was mit Mails passieren soll, die SPF/DKIM nicht bestehen. Ohne DMARC (oder mit p=none) landen gefälschte Mails trotzdem im Postfach.',
    steps: ['Mit p=none und Berichten (rua) starten, Auswertungen prüfen.', 'Schrittweise auf p=quarantine und dann p=reject verschärfen.'],
    snippets: { dns: '_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=s; aspf=s"' }, links: [doc('DMARC.org Overview', 'https://dmarc.org/overview/'), heise('DMARC'), video('DMARC setup')] },
  { match: /^dns-dkim-/, explanation: 'DKIM signiert ausgehende Mails kryptografisch. Ohne gültige Signatur kann DMARC nicht zuverlässig greifen.',
    steps: ['DKIM im Mail-Dienst aktivieren und den öffentlichen Schlüssel als TXT-Eintrag veröffentlichen.'], snippets: { dns: 'selector1._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBg…"' }, links: [heise('DKIM einrichten')] },
  { match: /^dns-caa-missing$/, explanation: 'Ein CAA-Eintrag bestimmt, welche Zertifizierungsstellen Zertifikate für deine Domain ausstellen dürfen – das erschwert Fehlausstellungen.',
    steps: ['CAA für die genutzte CA (z. B. Let’s Encrypt) setzen.'], snippets: { dns: 'example.com.  CAA  0 issue "letsencrypt.org"\nexample.com.  CAA  0 iodef "mailto:security@example.com"' }, links: [doc('CAA-Eintrag (Let’s Encrypt)', 'https://letsencrypt.org/de/docs/caa/')] },
  { match: /^dns-dangling-cname$/, explanation: 'Ein CNAME zeigt auf eine gelöschte Cloud-Ressource (GitHub Pages, S3, Azure …). Wer sie neu anlegt, übernimmt deine Subdomain – inklusive Cookies und Vertrauen deiner Nutzer (Subdomain-Takeover).',
    steps: ['Den verwaisten DNS-Eintrag sofort löschen.', 'Oder die Ziel-Ressource wieder selbst belegen.', 'DNS-Einträge bei jedem Abbau von Cloud-Diensten mit aufräumen.'],
    snippets: { dns: '; verwaisten Eintrag entfernen\n; shop.example.com.  CNAME  alt-shop.herokuapp.com.   <- löschen' }, links: [doc('can-i-take-over-xyz', 'https://github.com/EdOverflow/can-i-take-over-xyz'), heise('Subdomain Takeover'), video('subdomain takeover explained')] },

  // --- Browser-Laufzeit ---------------------------------------------------
  { match: /^dom-token-in-storage$/, explanation: 'Tokens in localStorage/sessionStorage sind für jedes Skript auf der Seite lesbar. Eine einzige XSS-Lücke oder ein kompromittiertes Drittanbieter-Skript reicht, um Sitzungen zu stehlen.',
    steps: ['Session-Token in ein HttpOnly-Secure-SameSite-Cookie verschieben.', 'Kurze Laufzeiten und Refresh-Rotation verwenden.'],
    snippets: { express: "res.cookie('access_token', token, { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 15 * 60 * 1000 });" }, links: [doc('OWASP HTML5 Security', 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage'), video('localStorage JWT security')] },
  { match: /^dom-missing-sri$/, explanation: 'Externe Skripte ohne Subresource-Integrity: Wird der CDN-Anbieter kompromittiert, läuft fremder Code mit vollen Rechten auf deiner Seite (Beispiel: polyfill.io 2024).',
    steps: ['integrity- und crossorigin-Attribut für alle externen Skripte setzen.', 'Besser noch: Skripte selbst hosten.'],
    snippets: { html: '<script src="https://cdn.example.com/lib.min.js"\n        integrity="sha384-…"\n        crossorigin="anonymous"></script>', shell: '# Hash erzeugen\ncurl -s URL | openssl dgst -sha384 -binary | openssl base64 -A' },
    links: [doc('MDN: Subresource Integrity', 'https://developer.mozilla.org/de/docs/Web/Security/Subresource_Integrity'), doc('SRI-Hash-Generator', 'https://www.srihash.org/'), heise('polyfill.io Supply-Chain')] },
  { match: /^dom-console-leak$/, explanation: 'Konsolenausgaben in Produktion verraten Tokens, interne Zustände oder Stacktraces – sichtbar für jeden, der die Entwicklerwerkzeuge öffnet.',
    steps: ['console.* im Produktions-Build entfernen.', 'Fehler an ein Logging-Backend schicken statt in die Konsole.'],
    snippets: { vite: "// vite.config.js\nexport default { esbuild: { drop: ['console', 'debugger'] } };", terser: '// terser: compress: { drop_console: true }' }, links: [] },

  // --- API-Rechte ---------------------------------------------------------
  { match: /^api-bola-cross-tenant$|^api-unauthenticated-access$/, explanation: 'Broken Object Level Authorization (BOLA/IDOR) ist die häufigste API-Lücke: Die API prüft nur, ob jemand eingeloggt ist – nicht, ob ihm das angefragte Objekt gehört. Andere Nutzer lesen so fremde Rechnungen, Profile oder Bestellungen.',
    steps: ['Bei jedem Objektzugriff serverseitig prüfen, ob das Objekt dem anfragenden Nutzer bzw. Mandanten gehört.', 'Zugriff zentral über eine Policy-Schicht absichern statt in jedem Endpunkt einzeln.', 'Nicht ratbare IDs (UUID) verwenden – als zusätzliche Hürde, nicht als Ersatz.'],
    snippets: { express: "const invoice = await db.invoice.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });\nif (!invoice) return res.sendStatus(404); // nicht 403 – verrät nichts über Existenz", prisma: '// Mandantentrennung erzwingen\nprisma.$extends({ query: { $allModels: { async findMany({ args, query }) { args.where = { ...args.where, tenantId: ctx.tenantId }; return query(args); } } } });' },
    links: [doc('OWASP API1:2023 BOLA', 'https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/'), heise('IDOR Sicherheitslücke'), video('BOLA IDOR API security')] },

  // --- Lieferkette & CI ---------------------------------------------------
  { match: /^lockfile-|^dependency-confusion-scope$|^typosquat-suspect$|^install-script$/, explanation: 'Angriffe über die Lieferkette nutzen fehlende Integritäts-Hashes, fremde Registries, Tippfehler-Pakete oder Install-Skripte, die beim npm install beliebigen Code ausführen.',
    steps: ['Lockfile einchecken und in CI mit npm ci (bzw. --frozen-lockfile) installieren.', 'Interne Scopes fest auf die eigene Registry mappen (.npmrc).', 'Install-Skripte standardmäßig sperren und nur bekannte Pakete freigeben.', 'Paketnamen auf Tippfehler prüfen, bevor sie hinzugefügt werden.'],
    snippets: { npmrc: '# .npmrc\n@firma:registry=https://npm.firma.intern/\nignore-scripts=true\naudit=true', ci: 'npm ci --ignore-scripts\nnpm audit signatures' },
    links: [doc('OWASP: Software Supply Chain', 'https://owasp.org/www-project-top-10-ci-cd-security-risks/'), doc('npm: audit signatures', 'https://docs.npmjs.com/cli/commands/npm-audit'), heise('Supply-Chain-Angriff npm'), video('npm supply chain attack')] },
  { match: /^docker-unpinned-base$|^docker-latest-tag$/, explanation: 'Mit :latest oder ohne Digest baut jeder Build auf einem anderen Basis-Image – ein kompromittiertes oder fehlerhaftes Update landet unbemerkt in Produktion.',
    steps: ['Basis-Image auf eine konkrete Version und den sha256-Digest festlegen.', 'Updates bewusst über Dependabot/Renovate einspielen.'],
    snippets: { dockerfile: 'FROM node:22.11.0-alpine@sha256:<digest>\n# Digest ermitteln:\n# docker buildx imagetools inspect node:22.11.0-alpine' }, links: [doc('Docker: Image-Digests', 'https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier'), doc('Renovate', 'https://docs.renovatebot.com/')] },
  { match: /^gha-/, explanation: 'GitHub Actions, die nur auf einen Branch oder Tag zeigen, können vom Autor jederzeit verändert werden (Beispiel: tj-actions/changed-files 2025). Mit write-all-Rechten oder pull_request_target kann fremder Code deine Secrets stehlen.',
    steps: ['Actions auf den vollen 40-stelligen Commit-SHA pinnen.', 'Rechte minimal setzen (permissions: contents: read).', 'pull_request_target nie zusammen mit dem Auschecken von Fremdcode verwenden.'],
    snippets: { yaml: 'permissions:\n  contents: read\n\nsteps:\n  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2' },
    links: [doc('GitHub: Security hardening for Actions', 'https://docs.github.com/de/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions'), heise('GitHub Actions Supply-Chain'), video('GitHub Actions security pinning')] },

  // --- Container ----------------------------------------------------------
  { match: /^container-|^dockerfile-root-user$/, explanation: 'Container sind nur so gut isoliert wie ihre Konfiguration. Root-Rechte, privileged, gemountetes Docker-Socket oder zusätzliche Capabilities öffnen den Weg aus dem Container auf den Host.',
    steps: ['Als unprivilegierter Nutzer laufen lassen (USER bzw. user:).', 'Alle Capabilities entfernen, nur Benötigtes wieder hinzufügen.', 'Docker-Socket nie in Anwendungs-Container mounten.', 'Datenbank-Ports nur an 127.0.0.1 oder ein internes Netz binden.'],
    snippets: { compose: 'services:\n  app:\n    image: app@sha256:<digest>\n    user: "10001:10001"\n    read_only: true\n    cap_drop: [ALL]\n    security_opt: ["no-new-privileges:true"]\n    pids_limit: 200\n    mem_limit: 512m\n  db:\n    image: postgres:17\n    ports: ["127.0.0.1:5432:5432"]', dockerfile: 'RUN addgroup -S app && adduser -S app -G app\nUSER app' },
    links: [doc('OWASP Docker Security', 'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'), doc('Docker: Rootless', 'https://docs.docker.com/engine/security/rootless/'), heise('Docker Container Ausbruch'), video('docker security best practices')] },

  // --- Linux-Host ---------------------------------------------------------
  { match: /^ssh-/, explanation: 'SSH mit Root-Login oder Passwörtern ist Ziel ständiger, automatisierter Rate-Angriffe aus dem ganzen Internet.',
    steps: ['Schlüssel-Login einrichten und testen (in zweiter Sitzung!).', 'Root-Login und Passwort-Login abschalten.', 'fail2ban oder CrowdSec gegen Brute-Force aktivieren.'],
    snippets: { sshd_config: '# /etc/ssh/sshd_config\nPermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nKbdInteractiveAuthentication no\nMaxAuthTries 3', shell: 'sudo sshd -t && sudo systemctl reload ssh' },
    links: [doc('Mozilla OpenSSH Guidelines', 'https://infosec.mozilla.org/guidelines/openssh'), heise('SSH absichern'), video('SSH härten Linux')] },
  { match: /^file-perms-sensitive$/, explanation: 'Schlüssel, .env-Dateien und Backups, die für andere Nutzer lesbar sind, gibt jeder kompromittierte Dienst auf dem System preis.',
    steps: ['Rechte auf 600 (nur Eigentümer) setzen.', 'Eigentümer auf den Dienst-Nutzer setzen.'], snippets: { shell: 'chmod 600 .env ~/.ssh/id_ed25519 backup.sql\nchown app:app .env' }, links: [heise('Linux Dateirechte chmod')] },
  { match: /^host-firewall-inactive$|^host-public-listeners$|^host-no-ips$/, explanation: 'Ohne aktive Firewall ist jeder Dienst, der auf 0.0.0.0 lauscht, direkt aus dem Internet erreichbar – auch solche, die nur intern gedacht waren.',
    steps: ['Firewall aktivieren: nur SSH, HTTP und HTTPS freigeben.', 'Interne Dienste an 127.0.0.1 binden.', 'fail2ban/CrowdSec gegen Brute-Force einsetzen.'],
    snippets: { ufw: 'sudo ufw default deny incoming\nsudo ufw allow OpenSSH\nsudo ufw allow 80,443/tcp\nsudo ufw enable', fail2ban: 'sudo apt install fail2ban\nsudo systemctl enable --now fail2ban' },
    links: [doc('Ubuntu: UFW', 'https://help.ubuntu.com/community/UFW'), video('ufw firewall tutorial')] },
  { match: /^cron-writable-script$/, explanation: 'Ein Root-Cronjob ruft ein Skript auf, das andere Nutzer verändern können – ein klassischer Weg zur Rechteausweitung auf root.',
    steps: ['Skript root:root zuordnen und Schreibrechte für andere entziehen.', 'Skript in ein geschütztes Verzeichnis (/usr/local/sbin) verschieben.'], snippets: { shell: 'sudo chown root:root /pfad/skript.sh\nsudo chmod 755 /pfad/skript.sh' }, links: [] },
  { match: /^unattended-upgrades-off$/, explanation: 'Ohne automatische Sicherheitsupdates bleiben bekannte Lücken oft wochenlang offen.',
    steps: ['unattended-upgrades installieren und aktivieren.'], snippets: { shell: 'sudo apt install unattended-upgrades\nsudo dpkg-reconfigure -plow unattended-upgrades' }, links: [doc('Debian Wiki: UnattendedUpgrades', 'https://wiki.debian.org/UnattendedUpgrades')] },

  // --- Code (SAST) --------------------------------------------------------
  { match: /^sast-toctou-race$/, explanation: 'Erst lesen, dann schreiben – ohne Transaktion: Zwei gleichzeitige Anfragen sehen beide das alte Guthaben/den gültigen Gutschein und lösen die Aktion doppelt aus (Race Condition).',
    steps: ['Prüfung und Änderung in einer atomaren Transaktion bzw. mit Zeilensperre ausführen.', 'Oder bedingtes Update verwenden (UPDATE … WHERE balance >= x).'],
    snippets: { prisma: "await prisma.$transaction(async (tx) => {\n  const acc = await tx.account.findUniqueOrThrow({ where: { id } });\n  if (acc.balance < amount) throw new Error('Guthaben zu gering');\n  await tx.account.update({ where: { id }, data: { balance: { decrement: amount } } });\n}, { isolationLevel: 'Serializable' });", sql: 'UPDATE accounts SET balance = balance - $1 WHERE id = $2 AND balance >= $1;' },
    links: [doc('PortSwigger: Race Conditions', 'https://portswigger.net/web-security/race-conditions'), video('race condition web security')] },
  { match: /^sast-insecure-random$/, explanation: 'Math.random() ist vorhersagbar. Damit erzeugte Tokens, Codes oder IDs können Angreifer erraten.',
    steps: ['Für alles Sicherheitsrelevante den Krypto-Zufall verwenden.'], snippets: { node: "const { randomBytes, randomInt } = require('node:crypto');\nconst token = randomBytes(32).toString('base64url');\nconst otp = randomInt(0, 1_000_000).toString().padStart(6, '0');" }, links: [doc('OWASP: Cryptographic Storage', 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html')] },
  { match: /^sast-weak-hash$|^sast-weak-cipher$/, explanation: 'MD5, SHA-1, DES, RC4 und AES im ECB-Modus gelten als gebrochen bzw. ungeeignet – für Passwörter sind schnelle Hashes ohnehin falsch.',
    steps: ['Für Integrität SHA-256, für Passwörter argon2id/bcrypt, für Verschlüsselung AES-256-GCM verwenden.'],
    snippets: { node: "// Passwörter\nconst argon2 = require('argon2');\nconst hash = await argon2.hash(password, { type: argon2.argon2id });\n// Verschlüsselung\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));" },
    links: [doc('OWASP Password Storage', 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html')] },
  { match: /^sast-timing-compare$/, explanation: 'Ein normaler Vergleich bricht beim ersten falschen Zeichen ab. Über die Antwortzeit lässt sich so ein Signatur- oder API-Key Zeichen für Zeichen erraten.',
    steps: ['Geheimnisse immer zeitkonstant vergleichen.'], snippets: { node: "const { timingSafeEqual } = require('node:crypto');\nconst a = Buffer.from(sig), b = Buffer.from(expected);\nconst ok = a.length === b.length && timingSafeEqual(a, b);" }, links: [video('timing attack explained')] },
  { match: /^sast-jwt-/, explanation: 'jwt.decode() prüft keine Signatur – jeder kann sich ein Token mit beliebigem Inhalt bauen. Tokens ohne Ablaufzeit bleiben nach einem Leak für immer gültig.',
    steps: ['Immer jwt.verify() mit fest vorgegebenem Algorithmus verwenden.', 'Kurze Ablaufzeit (expiresIn) setzen.'], snippets: { node: "const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ['RS256'], issuer: 'auth.example.com' });\nconst t = jwt.sign(claims, PRIVATE_KEY, { algorithm: 'RS256', expiresIn: '15m' });" },
    links: [doc('OWASP JWT Cheat Sheet', 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'), video('JWT security pitfalls')] },
  { match: /^sast-prototype-pollution$/, explanation: 'Ungefiltertes Zusammenführen von Objekten erlaubt Schlüssel wie __proto__ – damit verändert ein Angreifer das Verhalten aller Objekte der Anwendung.',
    steps: ['Gefährliche Schlüssel herausfiltern oder Objekte ohne Prototyp verwenden.', 'Eingaben per Schema (Zod) auf erlaubte Felder beschränken.'], snippets: { node: "const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);\nfor (const k of Object.keys(src)) if (!BLOCKED.has(k)) target[k] = src[k];\n// oder: const safe = Object.assign(Object.create(null), src);" }, links: [doc('PortSwigger: Prototype Pollution', 'https://portswigger.net/web-security/prototype-pollution')] },
  { match: /^sast-redos$/, explanation: 'Verschachtelte Wiederholungen in regulären Ausdrücken ((a+)+) brauchen bei böswilliger Eingabe exponentiell lange – ein einzelner Request legt den Server lahm.',
    steps: ['Ausdruck ohne verschachtelte Quantoren umschreiben.', 'Eingabelänge begrenzen oder eine lineare Regex-Engine (re2) verwenden.'], snippets: { node: "const RE2 = require('re2');\nconst re = new RE2('^[a-z]+$');" }, links: [doc('OWASP ReDoS', 'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS')] },
  { match: /^sast-ssrf$/, explanation: 'Wenn der Server eine vom Nutzer übergebene URL abruft, kann der Angreifer interne Dienste oder die Cloud-Metadaten (169.254.169.254) erreichen und dort Zugangsdaten abgreifen (SSRF).',
    steps: ['Nur erlaubte Ziel-Hosts zulassen (Allowlist).', 'Aufgelöste IP prüfen und private/Link-Local-Bereiche blockieren.', 'Weiterleitungen nicht automatisch folgen.'],
    snippets: { node: "const { lookup } = require('node:dns/promises');\nconst ALLOWED = new Set(['api.partner.com']);\nconst u = new URL(input);\nif (!ALLOWED.has(u.hostname)) throw new Error('Ziel nicht erlaubt');\nconst { address } = await lookup(u.hostname);\nif (/^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.)/.test(address)) throw new Error('internes Ziel');\nawait fetch(u, { redirect: 'manual' });" },
    links: [doc('OWASP SSRF Prevention', 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'), video('SSRF explained')] },
  { match: /^sast-mass-assignment$/, explanation: 'Wird req.body ungefiltert in die Datenbank geschrieben, kann ein Nutzer zusätzliche Felder wie role: "admin" oder balance mitschicken (Mass Assignment).',
    steps: ['Erlaubte Felder per Schema festlegen und nur diese übernehmen.'], snippets: { node: "const Input = z.object({ name: z.string().max(100), email: z.string().email() });\nconst data = Input.parse(req.body);\nawait prisma.user.update({ where: { id: req.user.id }, data });" },
    links: [doc('OWASP Mass Assignment', 'https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html')] },

  // --- KI / LLM -----------------------------------------------------------
  { match: /^llm-prompt-injection-concat$|^llm-output-to-sink$/, explanation: 'Nutzereingaben direkt im System-Prompt oder KI-Antworten, die ungeprüft ausgeführt oder als HTML angezeigt werden, erlauben Prompt-Injection: Ein Angreifer bringt die KI dazu, Befehle auszuführen oder Daten preiszugeben.',
    steps: ['Nutzereingaben strukturell getrennt übergeben (eigene Rolle/Nachricht, klar markiert).', 'KI-Ausgaben wie unvertraute Eingaben behandeln: validieren, escapen, nie in eval/Shell/SQL geben.', 'Werkzeuge der KI auf das Nötigste beschränken und kritische Aktionen bestätigen lassen.'],
    snippets: { node: "// Eingabe getrennt, nicht im System-Prompt\nmessages: [\n  { role: 'system', content: SYSTEM_PROMPT },\n  { role: 'user', content: userInput }\n]\n// Ausgabe nur als Text anzeigen\nel.textContent = answer; // statt innerHTML" },
    links: [doc('OWASP Top 10 für LLM-Anwendungen', 'https://genai.owasp.org/llm-top-10/'), heise('Prompt Injection'), video('prompt injection explained')] },
  { match: /^llm-server-exposed$/, explanation: 'Ein KI-Server (Ollama, vLLM) ohne Anmeldung, der auf allen Netzwerkschnittstellen lauscht, lässt jeden im Netz deine Modelle nutzen, löschen oder neue laden.',
    steps: ['Nur an 127.0.0.1 binden.', 'Für Fernzugriff einen Reverse-Proxy mit Authentifizierung davorschalten.'], snippets: { shell: '# Ollama nur lokal\nOLLAMA_HOST=127.0.0.1:11434 ollama serve', compose: 'ports: ["127.0.0.1:11434:11434"]' }, links: [heise('Ollama offen im Internet')] },

  // --- Angriffspfade -------------------------------------------------------
  // Texte und Schritte erzeugt der Korrelator konkret aus den beteiligten Befunden (intel.js).
  { match: /^toxic-/, explanation: 'Einzeln wirken diese Schwächen oft harmlos. Zusammen ergeben sie einen vollständigen Weg für einen Angriff. Schon eine einzige Behebung unterbricht ihn – fang mit der einfachsten an.',
    steps: [], snippets: {}, links: [doc('MITRE ATT&CK: bekannte Angriffstechniken', 'https://attack.mitre.org/')] },

  // --- Secrets (generisch) ------------------------------------------------
  { match: /^secret-|^gitleaks|^trufflehog|^trivy-secret|^custom-/, explanation: 'Ein Zugangsschlüssel im Code ist für jeden lesbar, der an Repo, Build oder Backup kommt – auch nach dem Löschen bleibt er in der Git-Historie.',
    steps: ['Schlüssel sofort beim Anbieter widerrufen und neu erzeugen.', 'Aus dem Code entfernen und über Umgebungsvariablen/Secret-Store laden.', 'Git-Historie bereinigen (git filter-repo) und Push-Schutz aktivieren.'],
    snippets: { shell: '# aus der Historie entfernen\npip install git-filter-repo\ngit filter-repo --invert-paths --path .env', node: "// statt im Code:\nconst key = process.env.STRIPE_SECRET_KEY;" },
    links: [doc('OWASP Secrets Management', 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'), doc('GitHub: Secret entfernen', 'https://docs.github.com/de/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository'), heise('API-Schlüssel GitHub geleakt'), video('remove secret from git history')] },
];

// Fallback je Kategorie, wenn keine Regel passt.
const BY_CATEGORY = {
  Injection: { links: [doc('OWASP Injection Prevention', 'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'), video('SQL injection prevention')] },
  XSS: { links: [doc('OWASP XSS Prevention', 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'), video('XSS prevention')] },
  AccessControl: { links: [doc('OWASP Authorization', 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html')] },
  Auth: { links: [doc('OWASP Authentication', 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html')] },
  Crypto: { links: [doc('OWASP Cryptographic Storage', 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html')] },
  Deserialization: { links: [doc('OWASP Deserialization', 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html')] },
  PathTraversal: { links: [doc('OWASP Path Traversal', 'https://owasp.org/www-community/attacks/Path_Traversal')] },
  SSRF: { links: [doc('OWASP SSRF Prevention', 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html')] },
};

const VULN_ID = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)\b/i;

// Versions-Patch: Befehl + Manifest-Aenderung je Oekosystem.
function versionPatch(pkg) {
  if (!pkg || !pkg.name || !pkg.fixed) return null;
  const { name, version, fixed } = pkg;
  const ECO = { pip: 'pypi', 'python-pkg': 'pypi', poetry: 'pypi', pipenv: 'pypi', gomod: 'go', 'go-module': 'go', gobinary: 'go', cargo: 'crates.io', bundler: 'rubygems', gemspec: 'rubygems', 'gem': 'rubygems', composer: 'packagist', jar: 'maven', pom: 'maven', gradle: 'maven', 'node-pkg': 'npm', yarn: 'npm', pnpm: 'npm' };
  const raw = String(pkg.ecosystem || '').toLowerCase();
  const eco = ECO[raw] || raw;
  const from = version ? `${version} → ${fixed}` : `→ ${fixed}`;
  if (eco === 'npm') return { title: `${name} ${from}`, command: `npm install ${name}@^${fixed}`, manifest: `// package.json\n-  "${name}": "${version || '…'}"\n+  "${name}": "^${fixed}"`, note: 'Danach npm audit und die Tests laufen lassen.' };
  if (eco === 'pypi') return { title: `${name} ${from}`, command: `pip install --upgrade "${name}>=${fixed}"`, manifest: `# requirements.txt\n-${name}==${version || '…'}\n+${name}>=${fixed}` };
  if (eco === 'go') return { title: `${name} ${from}`, command: `go get ${name}@v${String(fixed).replace(/^v/, '')} && go mod tidy` };
  if (eco === 'crates.io' || eco === 'cargo') return { title: `${name} ${from}`, command: `cargo update -p ${name} --precise ${fixed}`, manifest: `# Cargo.toml\n${name} = "${fixed}"` };
  if (eco === 'rubygems') return { title: `${name} ${from}`, command: `bundle update ${name} --conservative`, manifest: `# Gemfile\ngem "${name}", ">= ${fixed}"` };
  if (eco === 'maven') return { title: `${name} ${from}`, manifest: `<!-- pom.xml -->\n<dependency>\n  <groupId>${name.split(':')[0]}</groupId>\n  <artifactId>${name.split(':')[1] || name}</artifactId>\n  <version>${fixed}</version>\n</dependency>` };
  if (eco === 'packagist' || eco === 'composer') return { title: `${name} ${from}`, command: `composer require ${name}:^${fixed}` };
  if (eco === 'nuget') return { title: `${name} ${from}`, command: `dotnet add package ${name} --version ${fixed}` };
  return { title: `${name} ${from}`, command: `# Paket ${name} auf mindestens ${fixed} aktualisieren` };
}

function vulnLinks(id, pkg) {
  const links = [];
  if (/^CVE-/i.test(id)) links.push(doc(`NVD: ${id}`, `https://nvd.nist.gov/vuln/detail/${id}`));
  links.push(doc(`OSV: ${id}`, `https://osv.dev/vulnerability/${id}`));
  if (/^GHSA-/i.test(id)) links.push(doc(`GitHub Advisory ${id}`, `https://github.com/advisories/${id}`));
  links.push(heise(id));
  links.push(video(`${id}${pkg && pkg.name ? ' ' + pkg.name : ''}`));
  return links;
}

function lookup(f) {
  const id = String(f.ruleId || '');
  return KB.find((k) => k.match.test(id)) || null;
}

// Reichert einen Befund an (nur Felder, die noch fehlen – Scanner-eigene Texte haben Vorrang).
function enrichRemedy(f) {
  const entry = lookup(f);
  const out = { ...f };
  const vid = (String(f.ruleId || '').match(VULN_ID) || String(f.title || '').match(VULN_ID) || [])[0];
  if (entry) {
    out.explanation = out.explanation || entry.explanation;
    out.steps = out.steps && out.steps.length ? out.steps : entry.steps;
    if (!out.snippets && Object.keys(entry.snippets || {}).length) out.snippets = entry.snippets;
    out.links = [...(f.links || []), ...entry.links];
  } else if (BY_CATEGORY[f.category]) {
    out.links = [...(f.links || []), ...BY_CATEGORY[f.category].links];
  }
  if (vid) {
    out.links = [...(out.links || []), ...vulnLinks(vid.toUpperCase(), f.package)];
    out.explanation = out.explanation || `${f.package && f.package.name ? `Das Paket ${f.package.name} ${f.package.version || ''}` : 'Eine eingesetzte Komponente'} enthält eine öffentlich bekannte Schwachstelle (${vid.toUpperCase()}). Exploits für bekannte CVEs werden oft innerhalb weniger Tage automatisiert eingesetzt – Aktualisieren ist meist der schnellste und sicherste Weg.`;
    if (!out.steps || !out.steps.length) out.steps = ['Auf die behobene Version aktualisieren (Patch unten).', 'Tests laufen lassen und Changelog auf Breaking Changes prüfen.', 'Falls kein Fix existiert: betroffene Funktion meiden oder Komponente ersetzen.'];
  }
  const vp = versionPatch(f.package);
  if (vp) out.versionPatch = vp;
  // Doppelte Links (gleiche URL) entfernen
  if (out.links) out.links = [...new Map(out.links.map((l) => [l.url, l])).values()];
  return out;
}

// Erlaubte Ziele fuer "Link oeffnen" (Main-Prozess prueft dagegen).
const LINK_HOSTS = ['heise.de', 'youtube.com', 'owasp.org', 'developer.mozilla.org', 'nvd.nist.gov', 'osv.dev', 'github.com', 'docs.github.com', 'cisa.gov', 'first.org', 'docs.docker.com', 'letsencrypt.org', 'ssllabs.com', 'ssl-config.mozilla.org', 'hstspreload.org', 'csp-evaluator.withgoogle.com', 'portswigger.net', 'mxtoolbox.com', 'dmarc.org', 'srihash.org', 'docs.npmjs.com', 'docs.renovatebot.com', 'help.ubuntu.com', 'wiki.debian.org', 'infosec.mozilla.org', 'attack.mitre.org', 'genai.owasp.org', 'cheatsheetseries.owasp.org', 'trivy.dev', 'ollama.com'];
function isAllowedLink(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:') return false;
    const h = u.hostname.toLowerCase().replace(/^www\./, '');
    return LINK_HOSTS.some((d) => h === d || h.endsWith('.' + d));
  } catch { return false; }
}

module.exports = { enrichRemedy, versionPatch, isAllowedLink, KB };
