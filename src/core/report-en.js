'use strict';

// Englische Berichte: Die Berichtsvorlagen (reportdoc.js, report.js) schreiben Deutsch. Fuer die
// englische Oberflaeche wird der fertige Bericht nachtraeglich uebersetzt – Textstuecke zwischen
// HTML-Tags bzw. Markdown-Zeilen, ueber die Berichtsbegriffe unten und das Befund-Woerterbuch.
// Code-Bloecke (<pre>, <code>, ```), Skripte und Styles bleiben unangetastet.

const { translate } = require('./findings-i18n');

const PAIRS = [
  ['Sicherheitsbericht', 'Security report'], ['Sicherheits-Prüfung', 'Security check'], ['Kurzbericht', 'Executive summary'],
  ['Kritisch', 'Critical'], ['Hoch', 'High'], ['Mittel', 'Medium'], ['Niedrig', 'Low'], ['Hinweis', 'Info'],
  ['kritisch', 'critical'], ['hoch', 'high'], ['mittel', 'medium'], ['gering', 'low'], ['niedrig', 'low'],
  ['Sofort handeln – direkt ausnutzbar, große Wirkung.', 'Act now – directly exploitable, major impact.'], ['Zeitnah beheben (Tage) – ernsthaftes Risiko.', 'Fix soon (days) – serious risk.'],
  ['Im normalen Ablauf beheben (Wochen).', 'Fix in the normal workflow (weeks).'], ['Bei Gelegenheit beheben.', 'Fix when convenient.'], ['Zur Kenntnis, kein direktes Risiko.', 'For information, no direct risk.'],
  ['Eingabe-Lücke', 'Injection'], ['Skript-Einschleusung', 'Cross-site scripting'], ['Unsicheres Einlesen', 'Unsafe deserialization'], ['Zugangsdaten', 'Credentials'], ['Verschlüsselung', 'Cryptography'],
  ['Anmeldung', 'Authentication'], ['Zugriffsrechte', 'Access control'], ['Server-Anfragen', 'Server-side requests'], ['Dateipfade', 'File paths'], ['Konfiguration', 'Configuration'], ['Pakete', 'Packages'],
  ['Verfügbarkeit', 'Availability'], ['Protokollierung', 'Logging'], ['Transport', 'Transport'], ['Sonstiges', 'Other'], ['Lieferkette', 'Supply chain'], ['Angriffsweg', 'Attack path'], ['Lizenz', 'License'],
  ['KI-Analyse', 'AI analysis'], ['Regeln', 'rules'], ['Server-Check', 'server check'], ['Angriffsweg-Analyse', 'attack path analysis'],
  ['offene Befunde', 'open findings'], ['kritisch oder hoch', 'critical or high'], ['aktiv ausgenutzt (CISA)', 'actively exploited (CISA)'], ['Angriffswege', 'Attack paths'], ['Zuerst beheben', 'Fix first'],
  ['Vertraulich – enthält Informationen über Schwachstellen.', 'Confidential – contains information about vulnerabilities.'], ['Zugangsdaten sind gekürzt.', 'Credentials are truncated.'],
  ['Befunde durchsuchen …', 'Search findings …'], ['Befunde durchsuchen', 'Search findings'], ['Alle', 'All'],
  ['Zusammenfassung', 'Summary'], ['Bedrohungsmodell (STRIDE)', 'Threat model (STRIDE)'], ['STRIDE', 'STRIDE'], ['Bedrohung', 'Threat'], ['Wahrscheinlichkeit', 'Likelihood'], ['Auswirkung', 'Impact'],
  ['Gegenmaßnahmen', 'Mitigations'], ['Schützenswert:', 'Assets:'], ['Eingänge:', 'Entry points:'], ['Annahmen: {0}', 'Assumptions: {0}'],
  ['Erstellt von der KI ({0}) – bitte fachlich prüfen.', 'Created by the AI ({0}) – please review.'], ['Erstellt von der KI – bitte fachlich prüfen.', 'Created by the AI – please review.'], ['Ohne KI aus den Befunden abgeleitet.', 'Derived from the findings without AI.'],
  ['Auf einen Blick', 'At a glance'], ['Als Nächstes tun', 'Do next'], ['Regelmäßig weiter prüfen.', 'Keep checking regularly.'], ['Die wichtigsten Risiken', 'Top risks'],
  ['{0} Befund(e) sind als Fehlalarm oder akzeptiertes Risiko markiert bzw. bereits behoben und hier nicht aufgeführt.', '{0} finding(s) are marked as false positive or accepted risk, or already fixed, and are not listed here.'],
  ['Alle Befunde', 'All findings'], ['Nr.', 'No.'], ['Schwere', 'Severity'], ['Befund', 'Finding'], ['Bereich', 'Area'], ['Ort', 'Location'], ['Befunde', 'Findings'], ['Befunde im Detail', 'Findings in detail'],
  ['Bei dieser Prüfung wurden keine offenen Befunde gefunden.', 'No open findings were found in this check.'], ['Übersicht', 'Overview'],
  ['Was ist los?', 'What is wrong?'], ['Was kann passieren?', 'What can happen?'], ['Lösung', 'Fix'], ['Änderung', 'Change'], ['Aktualisieren', 'Update'], ['Mehr dazu', 'Learn more'], ['Fundstelle:', 'Location:'],
  ['Beleg', 'Evidence'], ['Kontext', 'Context'],
  ['Erkannt durch {0}', 'Detected by {0}'], ['Verlässlichkeit {0}', 'confidence {0}'], ['Regel {0}', 'rule {0}'],
  ['Nachweise für Normen', 'Evidence for standards'], ['Anforderung', 'Requirement'], ['Stand', 'Status'], ['Offene Befunde', 'Open findings'],
  ['erfüllt (keine offenen Befunde)', 'met (no open findings)'], ['dringende Befunde', 'urgent findings'], ['kein offener Befund', 'no open finding'], ['keine offenen Befunde', 'no open findings'],
  ['Technische Einordnung der offenen Befunde in gängige Kataloge – ein prüfbarer Baustein für Audits, ersetzt aber keine Zertifizierung oder Rechtsberatung.', 'Technical mapping of the open findings to common catalogues – a verifiable building block for audits, but no substitute for certification or legal advice.'],
  ['Technische Einordnung der offenen Befunde in gängige Kataloge. Ersetzt keine Zertifizierung oder Rechtsberatung, liefert aber prüfbare Belege für die jeweiligen Anforderungen.', 'Technical mapping of the open findings to common catalogues. No substitute for certification or legal advice, but it provides verifiable evidence for each requirement.'],
  ['Anhang', 'Appendix'], ['ISO/IEC 27001:2022 – Anhang A', 'ISO/IEC 27001:2022 – Annex A'], ['So wurde geprüft', 'How it was checked'], ['Was die Stufen bedeuten', 'What the levels mean'], ['Hinweise zum Lauf', 'Notes on this run'],
  ['Feste Regeln und öffentliche Schwachstellen-Datenbanken (OSV.dev, CISA KEV, EPSS, gitleaks, retire.js), dazu KI-Analyse mit {0} / {1} und Gegenprüfung jedes KI-Funds. Alle Prüfungen sind zerstörungsfrei.', 'Fixed rules and public vulnerability databases (OSV.dev, CISA KEV, EPSS, gitleaks, retire.js), plus AI analysis with {0} / {1} and a cross-check of every AI finding. All checks are non-destructive.'],
  ['Feste Regeln und öffentliche Schwachstellen-Datenbanken (OSV.dev, CISA KEV, EPSS, gitleaks, retire.js). Alle Prüfungen sind zerstörungsfrei.', 'Fixed rules and public vulnerability databases (OSV.dev, CISA KEV, EPSS, gitleaks, retire.js). All checks are non-destructive.'],
  ['Gelaufene Prüfungen: {0}', 'Checks run: {0}'], ['{0} Dateien eingelesen.', '{0} files read.'],
  ['Erstellt mit Vigil · {0} · Gefundene Zugangsdaten sind in diesem Bericht gekürzt.', 'Created with Vigil · {0} · Credentials found are truncated in this report.'],
  ['Erstellt mit Vigil – zerstörungsfreie Prüfung eigener bzw. freigegebener Systeme.', 'Created with Vigil – non-destructive checks of your own or authorised systems.'],
  ['Erstellt mit Vigil – zerstörungsfreie Prüfung eigener bzw. freigegebener Systeme. Technische Details im vollständigen Bericht.', 'Created with Vigil – non-destructive checks of your own or authorised systems. Technical details in the full report.'],
  ['Erstellt am {0}', 'Created on {0}'], ['Stand {0}', 'As of {0}'], ['Ziele: {0}', 'Targets: {0}'], ['Note {0}', 'Grade {0}'], ['Sicherheitswert {0}/100', 'Security score {0}/100'], ['Sicherheitswert {0} von 100', 'Security score {0} of 100'], ['Sicherheitswert', 'Security score'], ['Note', 'Grade'],
  ['Keine Befunde – sehr gut aufgestellt.', 'No findings – in very good shape.'], ['Keine offenen Befunde.', 'No open findings.'],
  ['{0} kritische Schwachstelle muss sofort behoben werden.', '{0} critical vulnerability must be fixed immediately.'], ['{0} kritische Schwachstellen müssen sofort behoben werden.', '{0} critical vulnerabilities must be fixed immediately.'],
  ['Keine kritischen Befunde, aber {0} mit hohem Risiko – zeitnah beheben.', 'No critical findings, but {0} with high risk – fix soon.'],
  ['Keine kritischen oder hohen Risiken – die übrigen Punkte im normalen Ablauf abarbeiten.', 'No critical or high risks – work through the remaining points in the normal workflow.'],
  ['Es gibt {0} kritische Schwachstelle, die kurzfristig behoben werden muss.', 'There is {0} critical vulnerability that must be fixed at short notice.'], ['Es gibt {0} kritische Schwachstellen, die kurzfristig behoben werden müssen.', 'There are {0} critical vulnerabilities that must be fixed at short notice.'],
  ['Keine kritischen Schwachstellen, aber {0} mit hohem Risiko.', 'No critical vulnerabilities, but {0} with high risk.'], ['Keine dringenden Risiken.', 'No urgent risks.'], ['Keine kritischen oder hohen Risiken.', 'No critical or high risks.'],
  ['offene Befunde, letzte {0} Prüfungen', 'open findings, last {0} checks'], ['Offene Befunde im Verlauf', 'Open findings over time'], ['Nächste Schritte', 'Next steps'], ['Beheben lassen', 'Have it fixed'],
  ['Regelmäßig weiter prüfen (z. B. monatlich) und neue Befunde zeitnah beheben.', 'Keep checking regularly (e.g. monthly) and fix new findings promptly.'],
  ['{0} mittlere Befunde im normalen Entwicklungsablauf abarbeiten.', 'Work through {0} medium findings in the normal development workflow.'], ['Normen auf einen Blick', 'Standards at a glance'],
  ['{0} Anforderung(en) mit dringenden Befunden', '{0} requirement(s) with urgent findings'], ['{0} Anforderung(en) mit offenen Befunden', '{0} requirement(s) with open findings'],
];

// Eigenes kleines Woerterbuch (vor dem Befund-Woerterbuch)
const exact = new Map();
const templates = [];
for (const [de, en] of PAIRS) {
  if (!/\{\d+\}/.test(de)) { exact.set(de, en); continue; }
  const src = de.split(/(\{\d+\})/).map((p) => (/^\{\d+\}$/.test(p) ? '([\\s\\S]*?)' : p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('');
  templates.push({ re: new RegExp('^' + src + '$'), en, ids: (de.match(/\{(\d+)\}/g) || []).map((x) => x.slice(1, -1)) });
}
const MONTHS = { Januar: 'January', Februar: 'February', März: 'March', April: 'April', Mai: 'May', Juni: 'June', Juli: 'July', August: 'August', September: 'September', Oktober: 'October', November: 'November', Dezember: 'December' };
const dates = (s) => s.replace(/(\d{1,2})\. (Januar|Februar|März|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember) (\d{4})(?: um (\d{1,2}:\d{2}))?/g, (m, d, mo, y, t) => `${d} ${MONTHS[mo]} ${y}${t ? ', ' + t : ''}`);

function tr(text, depth = 0) {
  const core = String(text).replace(/\s+/g, ' ').trim();
  if (!core || !/[A-Za-zÄÖÜäöüß]/.test(core)) return text;
  let out = exact.get(core);
  if (out == null) {
    for (const t of templates) {
      const m = t.re.exec(core);
      if (!m) continue;
      out = t.en.replace(/\{(\d+)\}/g, (x, n) => { const v = m[t.ids.indexOf(n) + 1]; return v == null ? x : depth < 3 ? tr(v, depth + 1) : v; });
      break;
    }
  }
  if (out == null && core.includes(' · ') && depth < 3) {
    const parts = core.split(' · ').map((p) => tr(p, depth + 1));
    out = parts.join(' · ');
  }
  if (out == null) out = translate(core);
  out = dates(out);
  return out === core ? text : String(text).replace(/\S[\s\S]*\S|\S/, () => out);
}

function localizeReportHtml(html) {
  // geschuetzte Bereiche herausnehmen
  const keep = [];
  let s = String(html).replace(/<(script|style|pre|code)\b[\s\S]*?<\/\1>/gi, (m) => { keep.push(m); return `\u0000${keep.length - 1}\u0000`; });
  s = s.replace(/<html lang="de"/i, '<html lang="en"');
  s = s.replace(/>([^<>\u0000]+)</g, (m, t) => '>' + tr(t) + '<');
  s = s.replace(/\b(placeholder|aria-label|title)="([^"]*)"/g, (m, a, v) => `${a}="${tr(v)}"`);
  s = s.replace(/<title>([^<]*)<\/title>/, (m, t) => `<title>${tr(t)}</title>`);
  return s.replace(/\u0000(\d+)\u0000/g, (m, i) => keep[Number(i)]);
}

function localizeReportMd(md) {
  let inCode = false;
  const one = (line) => {
    if (/^```/.test(line)) { inCode = !inCode; return line; }
    if (inCode || !line.trim()) return line;
    if (/^> /.test(line)) return '> ' + one(line.slice(2));
    let l = line.replace(/\*\*([^*]+)\*\*/g, (m, t) => `**${tr(t.replace(/:$/, '')) + (t.endsWith(':') ? ':' : '')}**`);
    l = l.replace(/^Mehr dazu: /, 'Learn more: ').replace(/<summary>([^<]+)<\/summary>/, (m, t) => `<summary>${tr(t)}</summary>`);
    const head = /^(#{1,6} |> |- |\d+\. |_)(.*?)(_?)$/.exec(l);
    if (head && !/\*\*/.test(head[2])) return head[1] + tr(head[2]) + head[3];
    if (/^\|/.test(l)) return l.split('|').map((c) => (c.trim() && !/^[:-]+$/.test(c.trim()) && !/`/.test(c) ? c.replace(c.trim(), tr(c.trim())) : c)).join('|');
    // Fliesstext nach einem Label ("**Was ist los?** …") und Meta-Zeilen ("**Kritisch** · …")
    return l.replace(/^(\*\*[^*]+\*\*)( · )?(.*)$/, (m, a, sep, rest) => a + (sep || ' ') + (sep ? rest.split(' · ').map((p) => (/`/.test(p) ? p : tr(p))).join(' · ') : tr(rest))).replace(/^(\*\*[^*]+\*\*) $/, '$1').replace(/^([^*#>|].*)$/, (m) => dates(tr(m)));
  };
  return String(md).split('\n').map(one).join('\n');
}

module.exports = { localizeReportHtml, localizeReportMd, translateReportText: tr };
