// Englische Oberflaeche. Die App ist auf Deutsch geschrieben; bei "English" werden Textknoten
// und Attribute (placeholder, title, aria-label) ueber dieses Woerterbuch ersetzt – auch fuer
// spaeter eingefuegte Inhalte (MutationObserver). Das Original bleibt gemerkt, damit das
// Zurueckschalten ohne Neustart geht. Befundtexte aus der Pruefung bleiben vorerst Deutsch.
(() => {
  const EN = {
    'Neue Prüfung': 'New scan', 'Ergebnis': 'Results', 'Übersicht': 'Overview', 'Verlauf': 'History', 'Aktive KI': 'Active AI', 'Einstellungen': 'Settings',
    'Was soll Vigil prüfen?': 'What should Vigil check?',
    'Ordner hineinziehen, Adresse eintippen oder unten eine Art wählen. Vigil prüft nur, was dir gehört – zerstörungsfrei.': 'Drop a folder, type an address or pick a type below. Vigil only checks what you own – non-destructively.',
    'Loslassen zum Hinzufügen': 'Release to add', 'Hinzufügen': 'Add', 'Projektordner': 'Project folder', 'Code, Abhängigkeiten, Zugangsdaten': 'Code, dependencies, credentials',
    'Einzelne Dateien': 'Single files', 'Skripte, ZIP, JAR oder EXE': 'Scripts, ZIP, JAR or EXE', 'Webseite': 'Website', 'Zertifikat, Header, Cookies': 'Certificate, headers, cookies',
    'Container-Image': 'Container image', 'Pakete und bekannte Lücken': 'Packages and known vulnerabilities', 'Oder ein System prüfen – nur lesend:': 'Or check a system – read-only:',
    'Dieser Windows-PC': 'This Windows PC', 'Laufende Docker-Container': 'Running Docker containers', 'AWS-Konto': 'AWS account', 'Azure-Abonnement': 'Azure subscription', 'Google-Cloud-Projekt': 'Google Cloud project',
    'Bekannte & vertraute Ziele': 'Known & trusted targets', 'Alle': 'All', 'Vertraut': 'Trusted', '✓ vertraut': '✓ trusted', 'Vertrauen entziehen': 'Revoke trust', 'Ausblenden': 'Hide', 'in der Prüfliste': 'in the list', 'noch nicht geprüft': 'not checked yet', 'Domain nachgewiesen': 'domain verified',
    '„Vertraut“ heißt: Vigil prüft diese Webadresse bzw. diesen Server ohne erneute Rückfrage. Mit „Vertrauen entziehen“ fragt Vigil beim nächsten Mal wieder nach. „Ausblenden“ entfernt ein Ziel nur aus dieser Liste – Befunde und Verlauf bleiben erhalten.': '“Trusted” means Vigil checks this address or server without asking again. “Revoke trust” makes Vigil ask next time. “Hide” only removes a target from this list – findings and history are kept.',
    'Ich bin berechtigt, diesen Server zu prüfen.': 'I am authorised to check this server.', 'Diese Webseite gehört mir bzw. ich darf sie prüfen.': 'This website is mine or I am allowed to check it.',
    'Webadressen und Server prüft Vigil nur zerstörungsfrei: Zertifikat, Sicherheits-Header, Cookies, CORS und offen liegende Pfade. Keine Angriffe, keine Last-Tests.': 'Vigil checks websites and servers non-destructively only: certificate, security headers, cookies, CORS and exposed paths. No attacks, no load tests.',
    'Prüfliste': 'Scan list', 'Alle entfernen': 'Remove all', 'KI': 'AI', 'Wer analysiert den Code? Webadressen, Server und Images laufen ohne KI.': 'Who analyses the code? Websites, servers and images run without AI.',
    'Lokal': 'Local', 'privat & kostenlos': 'private & free', 'Cloud': 'Cloud', 'Gefundene lokale KI': 'Local AI found', 'Erneut suchen': 'Search again', 'Modell': 'Model', 'Prüfe Ollama …': 'Checking Ollama …',
    'Weitere Modelle': 'More models', 'einmal laden, danach offline nutzbar': 'download once, then use offline', 'Laden': 'Download', 'Abbrechen': 'Cancel', 'Anbieter': 'Provider', 'API-Schlüssel': 'API key', 'aus .env': 'from .env', 'anzeigen': 'show',
    'Code geht an den Anbieter. Erkannte Secrets schwärzt Vigil vorher. Für sensible Projekte ist': 'Code is sent to the provider. Vigil redacts detected secrets first. For sensitive projects',
    'die bessere Wahl.': 'is the better choice.', 'Startklar?': 'Ready to go?', 'Kosten und Dauer siehst du vor dem ersten Token': 'You see cost and duration before the first token',
    'Ziel hinzufügen': 'Add a target', 'KI wählen': 'Choose AI', 'Kosten und Dauer prüfen': 'Check cost and duration', 'Ziele': 'Targets', 'Gründlichkeit': 'Depth', 'Gründlich': 'Thorough', 'Schnell': 'Fast',
    'Prüfung starten': 'Start scan', 'Strg': 'Ctrl', 'startet': 'starts', 'So arbeitet Vigil': 'How Vigil works', 'Regeln & Datenbanken': 'Rules & databases',
    'finden Secrets, verwundbare Pakete und Fehlkonfigurationen.': 'find secrets, vulnerable packages and misconfigurations.', 'Die KI': 'The AI',
    'sucht Logik- und Zugriffsfehler und prüft ihre Funde gegen.': 'looks for logic and access flaws and double-checks its findings.', 'Vigil fasst zusammen': 'Vigil merges everything',
    ': keine Doppelungen, mit konkreter Lösung, Verlauf über alle Läufe.': ': no duplicates, a concrete fix, history across all runs.',
    'Exportieren': 'Export', 'Kurzbericht (PDF)': 'Executive summary (PDF)', 'eine Seite für die Geschäftsführung': 'one page for management', 'zum Teilen und Archivieren': 'to share and archive',
    'interaktiver Bericht': 'interactive report', 'für Tickets und Wikis': 'for tickets and wikis', 'maschinenlesbar, inkl. Risiko und Lösungen': 'machine-readable, incl. risk and fixes',
    'Noch kein Ergebnis': 'No results yet', 'Starte eine Prüfung. Die Befunde erscheinen hier, sortiert nach Risiko, ohne Doppelungen und mit konkreter Lösung.': 'Start a scan. Findings appear here, sorted by risk, without duplicates and with a concrete fix.',
    'Sammeln': 'Collect', 'Vorprüfung': 'Pre-scan', 'Schwachstellen-DB': 'Vulnerability DB', 'Server-Checks': 'Server checks', 'Aktiv-Scan': 'Active scan', 'KI-Analyse': 'AI analysis', 'Gegenprüfung': 'Cross-check', 'Fertig': 'Done',
    'Starte …': 'Starting …', 'vergangen': 'elapsed', 'noch etwa': 'about', 'dieser Schritt': 'this step', 'Prüfung läuft …': 'Scan running …', 'Technische Details': 'Technical details', 'Strg K': 'Ctrl K',
    'Prüfung abgeschlossen': 'Scan complete', 'Abgebrochen – Teilergebnis': 'Cancelled – partial result', 'Prüfung fehlgeschlagen': 'Scan failed', 'gleich': 'any moment', 'dauert länger als geplant': 'taking longer than planned',
    'Sicherheitswert': 'Security score', 'Entwicklung': 'Trend', 'Letzte Läufe': 'Recent runs', 'Alle Befunde': 'All findings', 'Aktiv': 'Active', 'Behoben': 'Resolved', 'Fehlalarm / akzeptiert': 'False positive / accepted',
    'Alle Schweregrade': 'All severities', 'Kritisch': 'Critical', 'Hoch': 'High', 'Mittel': 'Medium', 'Niedrig': 'Low', 'Hinweis': 'Info',
    'Neu seit Baseline': 'New since baseline', 'Nur Angriffswege': 'Attack paths only', 'Nur Ziel:': 'Target only:', 'Filter entfernen': 'Clear filter', '✕ Schließen': '✕ Close', 'Schließen': 'Close',
    'Paketsuche (SBOM)': 'Package search (SBOM)', 'Neue Lücke in einem Paket gemeldet? Hier siehst du sofort, in welchen geprüften Projekten es steckt und in welcher Version.': 'New vulnerability reported in a package? See instantly which checked projects use it and in which version.',
    'Die letzten Läufe, lokal auf deinem Rechner gespeichert. Zum Öffnen anklicken.': 'Recent runs, stored locally on your computer. Click to open.', 'Verlauf leeren': 'Clear history',
    'Alles wird lokal gespeichert. Schlüssel und Tokens liegen verschlüsselt auf diesem Rechner.': 'Everything is stored locally. Keys and tokens are encrypted on this computer.', 'Speichern': 'Save',
    'Analyse': 'Analysis', 'Datenschutz': 'Privacy', 'Freigaben': 'Allowed targets', 'Tiefe Prüfungen': 'Deep checks', 'API-Rechtematrix': 'API access matrix', 'Externe Tools': 'External tools', 'Eigene Regeln': 'Custom rules',
    'Netzwerk': 'Network', 'KI-Server': 'AI servers', 'Darstellung': 'Appearance', 'Daten': 'Data', 'Profil': 'Profile', 'Ein Klick stellt alles Wichtige passend ein. Feinheiten darunter.': 'One click sets everything important. Details below.',
    'Schnell & günstig': 'Fast & cheap', 'Ein KI-Durchgang, ohne Zusatz-Tools. Für den schnellen Überblick.': 'One AI pass, no extra tools. For a quick overview.', 'Ausgewogen': 'Balanced',
    'Fünf KI-Durchgänge mit Gegenprüfung. Empfohlen für die meisten Projekte.': 'Five AI passes with cross-check. Recommended for most projects.', 'Maximal gründlich': 'Maximum depth',
    'Alles an: externe Tools, Browser-Prüfung, Schwachstellen-Datenbank.': 'Everything on: external tools, browser check, vulnerability database.',
    'Gründlich = fünf fokussierte Durchgänge (Zugriff, Injection, Krypto, Logik, Konfig). Findet mehr, kostet mehr.': 'Thorough = five focused passes (access, injection, crypto, logic, config). Finds more, costs more.',
    'Gründlich – 5 Durchgänge': 'Thorough – 5 passes', 'Schnell – 1 Durchgang': 'Fast – 1 pass', 'Kostenbremse': 'Cost limit', 'Vor dem Start nachfragen, wenn ein Cloud-Lauf voraussichtlich mehr kostet.': 'Ask before starting if a cloud run is expected to cost more.',
    'Genauigkeit der KI': 'AI precision', 'Schwachstellen-Datenbank': 'Vulnerability database', 'Abhängigkeiten (npm, PyPI, Maven, Go, Cargo, RubyGems) gegen OSV.dev prüfen. Kostenlos, braucht Internet.': 'Check dependencies (npm, PyPI, Maven, Go, Cargo, RubyGems) against OSV.dev. Free, needs internet.',
    'Nur Geändertes neu prüfen': 'Only re-check changes', 'Vigil merkt sich die KI-Ergebnisse je Datei. Unveränderte Dateien kommen beim nächsten Lauf aus dem Zwischenspeicher – das spart meist den Großteil an Zeit und Kosten.': 'Vigil remembers AI results per file. Unchanged files come from the cache on the next run – usually saving most of the time and cost.',
    'Leeren': 'Clear', 'Gelöschte Schlüssel in der Git-Historie suchen': 'Search deleted keys in Git history', 'Auch Zugangsdaten, die längst aus dem Code entfernt wurden, stehen oft noch in alten Versionen. Nur für Ordner, die ein Git-Repository sind.': 'Credentials removed from the code long ago often remain in old versions. Only for folders that are Git repositories.',
    'Kleines Modell sortiert vor': 'Small model pre-sorts', 'Optional: Ein günstiges Modell markiert verdächtige Dateien, nur diese gehen an das große Modell. Leer lassen zum Abschalten. Gilt für den gerade gewählten Anbieter.': 'Optional: a cheap model flags suspicious files; only those go to the large model. Leave empty to turn off. Applies to the selected provider.',
    'Zweites Modell prüft gegen': 'Second model cross-checks', 'Optional: Ein zweites Modell prüft dieselben Dateien. Was beide finden, gilt als sicher, Einzelfunde werden heruntergestuft. Verdoppelt Zeit und Kosten der KI-Analyse.': 'Optional: a second model checks the same files. What both find counts as confirmed; single findings are downgraded. Doubles AI time and cost.',
    'Belastbarkeit & Datenschutz': 'Reliability & privacy', 'KI-Befunde gegenprüfen': 'Cross-check AI findings', 'Ein zweiter KI-Schritt versucht jeden reinen KI-Fund am Code-Ausschnitt zu widerlegen. Widerlegtes fliegt raus.': 'A second AI step tries to refute every AI-only finding against the code. Refuted findings are dropped.',
    'Secrets schwärzen': 'Redact secrets', 'Bevor Code an externe KI-Anbieter geht. Lokale Modelle sehen den Code unverändert, dort verlässt nichts den Rechner.': 'Before code goes to external AI providers. Local models see the code unchanged – nothing leaves the computer.',
    'Freigegebene Ziele': 'Allowed targets', 'Webadressen und Server prüft Vigil nur, wenn sie hier stehen oder du sie beim Hinzufügen bestätigst.': 'Vigil only checks websites and servers listed here or confirmed when adding them.',
    'gilt auch für Subdomains,': 'also covers subdomains,', 'nur für Subdomains. Die REST-API darf nur Ziele von dieser Liste prüfen.': 'subdomains only. The REST API may only check targets on this list.',
    'Tiefe Prüfungen & Threat-Intel': 'Deep checks & threat intel', 'Browser-Laufzeitprüfung': 'Browser runtime check', 'Für verifizierte Webseiten: Tokens im Speicher, Drittskripte ohne SRI, unverschlüsselte Aufrufe.': 'For verified websites: tokens in storage, third-party scripts without SRI, unencrypted requests.',
    'Jetzt aktualisieren': 'Update now', 'Externe Sicherheits-Tools': 'External security tools', 'Installierte Tools einbeziehen': 'Use installed tools', 'Eigene Regeln & Muster': 'Custom rules & patterns',
    'Eigene Muster als regulären Ausdruck, z. B. ein firmeninternes Schlüsselformat.': 'Custom patterns as regular expressions, e.g. an internal key format.', '+ Eigene Regel': '+ Custom rule', 'Eingebaute Regeln deaktivieren': 'Disable built-in rules',
    'Netzwerk: Proxy / VPN': 'Network: proxy / VPN', 'Leer = Direktverbindung. Unterstützt': 'Empty = direct connection. Supports', '(z. B. Tor unter': '(e.g. Tor at', ') und': ') and', 'Testen': 'Test',
    'Server-Adressen der KI-Anbieter': 'AI provider server addresses', 'Nur für eigene Server (z. B. Ollama auf einem anderen Rechner) oder OpenAI-kompatible Dienste. Leer = Standard.': 'Only for own servers (e.g. Ollama on another machine) or OpenAI-compatible services. Empty = default.',
    'Darstellung & App': 'Appearance & app', 'Farbschema': 'Colour scheme', 'Unabhängig von der Windows-Einstellung.': 'Independent of the Windows setting.', 'Wie Windows': 'Like Windows', 'Hell': 'Light', 'Dunkel': 'Dark',
    'Schriftgröße': 'Text size', 'Vergrößert die ganze Oberfläche. Auch mit Strg + Plus / Minus.': 'Enlarges the whole interface. Also with Ctrl + plus / minus.', 'Klein': 'Small', 'Normal': 'Normal', 'Groß': 'Large', 'Sehr groß': 'Very large',
    'Sprache': 'Language', 'Oberfläche auf Deutsch oder Englisch. Befundtexte bleiben vorerst Deutsch.': 'Interface in German or English. Finding texts stay German for now.',
    'Absturzberichte': 'Crash reports', 'Stürzt Vigil ab, landet ein Bericht nur auf diesem PC – nichts wird übertragen. Bei Bedarf kannst du ihn selbst weitergeben.': 'If Vigil crashes, a report is stored on this PC only – nothing is sent. Share it yourself if needed.',
    'Ordner öffnen': 'Open folder', 'Einführung': 'Introduction', 'Die kurze Einführung vom ersten Start noch einmal zeigen.': 'Show the short first-start introduction again.', 'Einführung zeigen': 'Show introduction',
    'Lokale REST-API': 'Local REST API', 'REST-API anbieten': 'Offer REST API', 'Für Skripte und CI auf diesem Rechner. Lauscht nur auf 127.0.0.1, verlangt das Token und prüft nur freigegebene Ziele.': 'For scripts and CI on this computer. Listens on 127.0.0.1 only, requires the token and only checks allowed targets.',
    'Kopieren': 'Copy', 'Neu': 'New', 'Kurzbericht für die Geschäftsführung': 'Executive summary', 'Eine Seite in Klartext: Lage, wichtigste Risiken, nächste Schritte und Normen auf einen Blick. Firmenname und Logo erscheinen im Kopf.': 'One page in plain language: situation, top risks, next steps and standards at a glance. Company name and logo appear in the header.',
    'Firmenname': 'Company name', 'Erscheint oben im Bericht.': 'Shown at the top of the report.', 'PNG, JPG, SVG oder WebP, höchstens 300 KB.': 'PNG, JPG, SVG or WebP, max. 300 KB.', 'Entfernen': 'Remove', 'Logo wählen': 'Choose logo',
    'Gespeicherte Befunde': 'Stored findings', 'Vigil merkt sich Befunde über alle Läufe (Status, zuerst und zuletzt gesehen), um Neues, Behobenes und Wiederkehrendes zu erkennen.': 'Vigil keeps findings across runs (status, first and last seen) to detect new, fixed and recurring issues.', 'Befund-Speicher leeren': 'Clear finding store',
    'Willkommen bei Vigil': 'Welcome to Vigil', 'Vigil sucht Sicherheitslücken in deinen eigenen Projekten, Webseiten, Servern und Cloud-Konten – und erklärt in Klartext, was zu tun ist.': 'Vigil finds security issues in your own projects, websites, servers and cloud accounts – and explains in plain language what to do.',
    'Feste Regeln und Datenbanken': 'Fixed rules and databases', 'finden Bekanntes sicher: Zugangsdaten im Code, verwundbare Pakete, Fehlkonfigurationen.': 'reliably find known issues: credentials in code, vulnerable packages, misconfigurations.', 'Eine KI': 'An AI',
    'sucht zusätzlich nach Logikfehlern und prüft ihre Funde selbst gegen.': 'also looks for logic flaws and double-checks its own findings.', 'Nur Eigenes, zerstörungsfrei:': 'Your own systems only, non-destructive:',
    'keine Angriffe, keine Last-Tests, Zugangsdaten werden vor dem Versand an eine Cloud-KI geschwärzt.': 'no attacks, no load tests, credentials are redacted before anything goes to a cloud AI.', 'Welche KI soll mithelfen?': 'Which AI should help?',
    'Lässt sich später jederzeit ändern. Für Webseiten, Server und Container braucht Vigil gar keine KI.': 'You can change this any time. Websites, servers and containers need no AI at all.', 'Lokal auf diesem PC': 'Locally on this PC',
    'Kostenlos und privat – der Code verlässt den Rechner nicht. Braucht Ollama und etwas Geduld.': 'Free and private – the code never leaves the computer. Needs Ollama and some patience.', 'Cloud-KI': 'Cloud AI',
    'Claude, OpenAI oder Gemini: schneller und genauer, kostet meist wenige Cent je Prüfung. Braucht einen API-Schlüssel.': 'Claude, OpenAI or Gemini: faster and more accurate, usually a few cents per scan. Needs an API key.', 'Los geht’s': 'Let’s go',
    'Am schnellsten siehst du, was Vigil kann, am mitgelieferten Übungsprojekt – es steckt voller absichtlicher Lücken.': 'The quickest way to see what Vigil can do is the bundled practice project – full of intentional flaws.',
    'Beispiel-Lauf ansehen': 'View a sample run', 'Prüft das Übungsprojekt in wenigen Sekunden mit den festen Regeln, ganz ohne KI.': 'Checks the practice project in seconds with the fixed rules, no AI needed.', 'Eigenen Projektordner wählen': 'Choose your own project folder',
    'Danach nur noch auf „Prüfung starten“ klicken.': 'Then just click “Start scan”.', 'Überspringen': 'Skip', 'Zurück': 'Back', 'Weiter': 'Next',
    'Was ist los?': 'What is wrong?', 'Was kann passieren?': 'What can happen?', 'Lösung': 'Fix', 'Beteiligte Befunde': 'Related findings', 'Betroffener Code': 'Affected code', 'Rückfrage an die KI': 'Ask the AI', 'Fundstelle': 'Evidence',
    'Wirklich ausnutzbar?': 'Really exploitable?', 'Wie genau beheben?': 'How exactly to fix?', 'Fehlalarm?': 'False positive?', 'Fragen': 'Ask', 'Du': 'You',
    'Offen': 'Open', 'In Arbeit': 'In progress', 'Fehlalarm': 'False positive', 'Risiko akzeptiert': 'Risk accepted', 'Schwere': 'Severity', 'Befund': 'Finding', 'Ziel': 'Target', 'Zuletzt gesehen': 'Last seen',
    'Datei/Ordner': 'File/folder', 'Webadresse': 'Website', 'Angriffsweg': 'Attack path', 'Zugangsdaten': 'Credentials', 'Lizenz': 'License',
    'Tage bis zur Behebung (Ø)': 'Days to fix (avg.)', 'behoben (30 Tage)': 'fixed (30 days)', 'neu gefunden (30 Tage)': 'newly found (30 days)', 'Sicherheitswert seit erstem Lauf': 'Score since first run', 'Die Grafik erscheint ab dem zweiten Lauf.': 'The chart appears after the second run.',
    'Bereiche': 'Sections', 'Neue Prüfung (Strg+1)': 'New scan (Ctrl+1)', 'Ergebnis (Strg+2)': 'Results (Ctrl+2)', 'Übersicht (Strg+3)': 'Overview (Ctrl+3)', 'Verlauf (Strg+4)': 'History (Ctrl+4)', 'Einstellungen (Strg+,)': 'Settings (Ctrl+,)',
    'Ziele – Dateien oder Ordner hierher ziehen': 'Targets – drop files or folders here', 'Ziel eingeben: Webadresse, Server, Container-Image oder Pfad': 'Enter target: website, server, container image or path', 'Art des Ziels': 'Target type', 'System prüfen': 'Check a system',
    'Ziele durchsuchen …': 'Search targets …', 'Bekannte Ziele durchsuchen': 'Search known targets', 'Art der KI': 'AI type', 'Lokale KI auswählen': 'Choose local AI', 'Eigenes Modell': 'Custom model', 'Modelle neu laden': 'Reload models',
    'Modellname eingeben': 'Enter model name', 'API-Schlüssel einfügen': 'Paste API key', 'Checkliste vor dem Start': 'Pre-start checklist', 'Umschalten': 'Toggle', 'Befunde durchsuchen': 'Search findings', 'Befunde': 'Findings', 'Titel, Ort oder Regel': 'Title, location or rule',
    'Schweregrad': 'Severity', 'Befund-Details': 'Finding details', 'Vorheriger Befund': 'Previous finding', 'Nächster Befund': 'Next finding', 'Paket suchen, z. B. lodash oder lodash@4.17': 'Search package, e.g. lodash or lodash@4.17', 'Paket suchen': 'Search package', 'Einstellungsbereiche': 'Settings sections',
    'Eigene Frage zu diesem Befund …': 'Your own question about this finding …', 'Frage zu diesem Befund': 'Question about this finding',
    // Uebersicht (neu)
    'Alle Prüfungen zusammen': 'All scans combined', 'Aktualisieren': 'Refresh', 'Aufräumen ▾': 'Clean up ▾', 'Behobene Befunde löschen': 'Delete resolved findings', 'entfernt alles, was als behoben gilt': 'removes everything marked as resolved',
    'Alle gefilterten Befunde löschen': 'Delete all filtered findings', 'nur die gerade angezeigte Liste': 'only the list currently shown', 'Offene Befunde nach Schwere': 'Open findings by severity', 'Pakete': 'Packages',
    'Alle Ziele': 'All targets', 'Status setzen …': 'Set status …', 'Löschen': 'Delete', 'Auswahl aufheben': 'Clear selection', 'Alle auswählen': 'Select all', 'Auswählen': 'Select', 'Befund löschen': 'Delete finding',
    'Erneut prüfen': 'Scan again', 'Baseline': 'Baseline', 'Nachweisen': 'Verify', 'nachgewiesen': 'verified', '✓ nichts offen': '✓ nothing open', 'offene Angriffswege': 'open attack paths', 'Lauf löschen': 'Delete run',
    'Alle bisher geprüften Ziele. „Löschen“ entfernt das Ziel mit allen seinen Befunden aus der Übersicht – die Prüfung selbst lässt sich jederzeit wiederholen.': 'All targets checked so far. “Delete” removes the target and all its findings from the overview – you can scan it again any time.',
    'Sehr gut aufgestellt': 'In very good shape', 'Gut – kleinere Baustellen': 'Good – minor issues', 'Ordentlich, aber mit Lücken': 'Decent, but with gaps', 'Deutlicher Handlungsbedarf': 'Clear need for action', 'Dringend handeln': 'Act urgently', 'Noch nichts geprüft': 'Nothing checked yet',
    'Befund löschen?': 'Delete finding?', 'Ziel löschen?': 'Delete target?', 'Lauf löschen?': 'Delete run?', 'Behobene Befunde löschen?': 'Delete resolved findings?', 'Noch keine Ziele': 'No targets yet', 'Noch keine Läufe.': 'No runs yet.',
    // Einstellungen (neu)
    'Login-Prüfung': 'Login check', 'Schadsoftware': 'Malware', 'Schadsoftware & Webseiten-Durchgang': 'Malware & website crawl', 'Programme und Dateien auf Schadsoftware prüfen': 'Check programs and files for malware',
    'Abgleich mit bekannten Schadprogrammen': 'Match against known malware', 'Unterseiten und Formulare durchgehen': 'Crawl subpages and forms', 'Darstellung & App': 'Appearance & app',
    'Anmelde-Adresse, z. B. https://meine-seite.de/login': 'Login address, e.g. https://my-site.com/login', 'Benutzername oder E-Mail des Testkontos': 'Username or e-mail of the test account', 'Passwort des Testkontos (leer = unverändert)': 'Test account password (empty = unchanged)',
    'Feldname Benutzer (optional, sonst automatisch)': 'User field name (optional, otherwise automatic)', 'Feldname Passwort (optional)': 'Password field name (optional)', 'Auth-Key (leer = unverändert)': 'Auth key (empty = unchanged)', 'Noch kein Testkonto hinterlegt.': 'No test account stored yet.',
  };
  // Teil-Uebersetzungen fuer zusammengesetzte Texte (Regex -> Ersatz)
  const PARTS = [
    [/^Erkannt: /, 'Detected: '], [/^Schritt (\d+) von (\d+)$/, 'Step $1 of $2'], [/^Befund (\d+) von (\d+)$/, 'Finding $1 of $2'], [/^zuletzt /, 'last '], [/ offen$/, ' open'],
    [/^Bereit – (\d+) Ziele? mit /, 'Ready – $1 target(s) with '], [/^(\d+) Ziele? in der Prüfliste$/, '$1 target(s) in the list'], [/^KI bereit: /, 'AI ready: '], [/^Kostenlos · /, 'Free · '],
    [/ Sek\.$/, ' sec'], [/ Min\.$/, ' min'], [/ Std\.$/, ' h'], [/^Füge oben zuerst etwas zur Prüfliste hinzu\.$/, 'Add something to the scan list first.'], [/^letzte (\d+) Läufe$/, 'last $1 runs'],
  ];
  const ATTRS = ['placeholder', 'title', 'aria-label'];
  const orig = new Map();      // Textknoten -> deutscher Originaltext
  const origAttr = new Map();  // Element -> { attr: original }
  let lang = 'de', observer = null;

  const tr = (s) => {
    const key = String(s).replace(/\s+/g, ' ').trim();
    if (!key) return null;
    if (EN[key]) return String(s).replace(/\S[\s\S]*\S|\S/, EN[key]);
    let out = key, hit = false;
    for (const [re, rep] of PARTS) if (re.test(out)) { out = out.replace(re, rep); hit = true; }
    return hit ? out : null;
  };
  function translateNode(root) {
    if (!root) return;
    if (root.nodeType === 3) { const t = tr(root.nodeValue); if (t != null && t !== root.nodeValue) { if (!orig.has(root)) orig.set(root, root.nodeValue); root.nodeValue = t; } return; }
    if (root.nodeType !== 1 || /^(SCRIPT|STYLE|CODE|PRE)$/.test(root.tagName)) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, { acceptNode: (n) => (n.parentElement && n.parentElement.closest('script,style,code,pre') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT) });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const n of nodes) translateNode(n);
    for (const el of [root, ...root.querySelectorAll('*')]) for (const a of ATTRS) {
      const v = el.getAttribute(a);
      if (!v) continue;
      const t = tr(v);
      if (t != null && t !== v) { const o = origAttr.get(el) || {}; if (!(a in o)) o[a] = v; origAttr.set(el, o); el.setAttribute(a, t); }
    }
  }
  function restore() {
    for (const [n, v] of orig) if (n.isConnected) n.nodeValue = v;
    for (const [el, o] of origAttr) if (el.isConnected) for (const [a, v] of Object.entries(o)) el.setAttribute(a, v);
    orig.clear(); origAttr.clear();
  }
  window.applyLanguage = (l) => {
    lang = l === 'en' ? 'en' : 'de';
    document.documentElement.lang = lang;
    if (observer) { observer.disconnect(); observer = null; }
    if (lang === 'de') { restore(); return; }
    translateNode(document.body);
    observer = new MutationObserver((muts) => {
      observer.disconnect();
      try {
        for (const m of muts) {
          if (m.type === 'characterData') { orig.delete(m.target); translateNode(m.target); }
          else for (const n of m.addedNodes) translateNode(n);
        }
      } finally { observer.observe(document.body, { childList: true, subtree: true, characterData: true }); }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  };
  window.translateText = (s) => (lang === 'en' ? tr(String(s)) || s : s);
})();
