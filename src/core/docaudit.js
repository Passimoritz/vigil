'use strict';

// Dokumente mit aktivem Inhalt: Office-Makros (docm/xlsm/pptm und alte .doc/.xls/.ppt),
// fremde Vorlagen und eingebettete Objekte in Office-Dateien, JavaScript/Startaktionen in PDFs,
// eingebettete Objekte in RTF. Nur Erkennung – nichts wird ausgefuehrt.

const AdmZip = require('adm-zip');
const { normalizeFinding } = require('./schema');

const DOC_EXT = new Set(['.docx', '.docm', '.dotm', '.dotx', '.xlsx', '.xlsm', '.xltm', '.xlam', '.pptx', '.pptm', '.potm', '.ppsm', '.doc', '.dot', '.xls', '.xla', '.ppt', '.pdf', '.rtf', '.one']);
// Typische Befehle in boesartigen Makros
const SUSPECT = [
  ['AutoOpen|Document_Open|Workbook_Open|Auto_Open|AutoExec', 'startet automatisch beim Öffnen'],
  ['Shell|WScript\\.Shell|ShellExecute|CreateProcess', 'startet Programme'],
  ['powershell|cmd\\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin', 'ruft System-Werkzeuge auf'],
  ['URLDownloadToFile|XMLHTTP|WinHttp|InternetOpen|MSXML2', 'lädt Dateien aus dem Internet'],
  ['CreateObject|GetObject', 'steuert andere Programme'],
  ['Environ\\(|Kill |FileCopy|Open .* For (Output|Binary)', 'schreibt oder löscht Dateien'],
  ['VirtualAlloc|RtlMoveMemory|CallWindowProc|Declare (PtrSafe )?Function', 'greift direkt auf den Speicher zu'],
  ['Chr\\(\\d+\\)\\s*&\\s*Chr|StrReverse|Base64', 'versteckt Text (Verschleierung)'],
];

const F = (o) => normalizeFinding({ category: 'Other', confidence: 'high', sourceModule: 'document-audit', ...o }, 'document-audit');

function macroFindings(text, label, kind) {
  const hits = SUSPECT.filter(([re]) => new RegExp(re, 'i').test(text)).map(([, what]) => what);
  const auto = /AutoOpen|Document_Open|Workbook_Open|Auto_Open|AutoExec/i.test(text);
  const danger = hits.filter((h) => h !== 'startet automatisch beim Öffnen' && h !== 'steuert andere Programme').length;
  return F({
    ruleId: danger ? 'doc-macro-suspicious' : 'doc-macro', severity: danger >= 2 || (auto && danger) ? 'high' : danger ? 'medium' : 'low',
    title: `${kind} enthält Makros${danger ? ' mit verdächtigen Befehlen' : ''}`,
    description: `In „${label}“ steckt VBA-Code.${hits.length ? ` Er ${hits.join(', ')}.` : ''} Makros sind der häufigste Weg, über den Schadsoftware per E-Mail-Anhang kommt.`,
    impact: danger ? 'Erlaubt man die Makros, kann das Dokument Programme starten oder weitere Schadsoftware nachladen.' : 'Makros an sich sind nicht gefährlich, sollten aber nur aus bekannter Quelle aktiviert werden.',
    remediation: 'Makros nicht aktivieren, wenn die Herkunft nicht sicher ist. Eigene Dokumente ohne Makros als .docx/.xlsx speichern oder die Makros signieren.',
    location: label,
  });
}

function analyzeDocument(buf, label) {
  const ext = (String(label).match(/\.[a-z0-9]+$/i) || [''])[0].toLowerCase();
  const out = [];
  if (!Buffer.isBuffer(buf) || !DOC_EXT.has(ext)) return out;
  const head = buf.subarray(0, 8);
  // Office Open XML (ZIP)
  if (head[0] === 0x50 && head[1] === 0x4b) {
    let zip; try { zip = new AdmZip(buf); } catch { return out; }
    const names = zip.getEntries().map((e) => e.entryName);
    const kind = /^\.(doc|dot)/.test(ext) ? 'Word-Dokument' : /^\.xl/.test(ext) ? 'Excel-Datei' : 'PowerPoint-Datei';
    const vba = zip.getEntries().find((e) => /vbaProject\.bin$/i.test(e.entryName));
    if (vba) { let t = ''; try { t = vba.getData().toString('latin1'); } catch { /* egal */ } out.push(macroFindings(t, label, kind)); }
    if (/\.(docx|xlsx|pptx)$/.test(ext) && vba) out.push(F({ ruleId: 'doc-macro-wrong-extension', severity: 'high', title: `${kind} mit Makros trotz Endung ${ext}`, description: `Die Endung ${ext} steht für „ohne Makros“, die Datei enthält aber trotzdem welche. Das ist ein bekannter Täuschungstrick.`, remediation: 'Datei nicht öffnen bzw. Makros nicht aktivieren.', location: label }));
    for (const n of names.filter((x) => /_rels\/.*\.rels$/i.test(x))) {
      let rels = ''; try { rels = zip.readAsText(n); } catch { continue; }
      const ext2 = rels.match(/Target="(https?:\/\/[^"]+)"[^>]*TargetMode="External"|TargetMode="External"[^>]*Target="(https?:\/\/[^"]+)"/i);
      if (ext2 && /attachedTemplate|oleObject|frame|subDocument/i.test(rels)) out.push(F({ ruleId: 'doc-remote-template', severity: 'high', title: `${kind} lädt Inhalte aus dem Internet nach`, description: `Beim Öffnen holt das Dokument eine Vorlage bzw. ein Objekt von ${(ext2[1] || ext2[2]).slice(0, 120)}. So wird Schadcode nachgeladen, ohne dass er in der Datei selbst steht („Remote Template Injection“).`, remediation: 'Datei nicht öffnen; Herkunft prüfen.', location: `${label}!/${n}` }));
    }
    const ole = names.filter((x) => /embeddings\/.*(\.bin|oleObject)/i.test(x));
    if (ole.length) out.push(F({ ruleId: 'doc-embedded-object', severity: 'medium', confidence: 'medium', title: `${kind} enthält eingebettete Objekte (${ole.length})`, description: 'Eingebettete OLE-Objekte können Programme oder Skripte enthalten, die per Doppelklick starten.', remediation: 'Eingebettete Objekte nur aus bekannter Quelle öffnen.', location: label }));
    return out;
  }
  // Alte Office-Formate (OLE2)
  if (head.readUInt32LE(0) === 0xe011cfd0) {
    const t = buf.toString('latin1');
    if (/_VBA_PROJECT|Attribute VB_|VBA\x00|Macros/.test(t)) out.push(macroFindings(t, label, /^\.(doc|dot)/.test(ext) ? 'Word-Dokument' : /^\.xl/.test(ext) ? 'Excel-Datei' : 'Office-Datei'));
    if (/\.xls$/.test(ext) && /Auto_Open|EXEC\(|CALL\(|REGISTER\(/i.test(t) && /Excel 4\.0|XLM|\bMacro1\b/i.test(t)) out.push(F({ ruleId: 'doc-xlm-macro', severity: 'high', title: 'Excel-Datei mit alten Excel-4.0-Makros', description: 'Excel-4.0-Makros (XLM) werden von vielen Virenscannern schlecht erkannt und sind deshalb bei Angreifern beliebt.', remediation: 'Nicht öffnen bzw. Makros nicht aktivieren.', location: label }));
    return out;
  }
  // PDF
  if (buf.subarray(0, 1024).toString('latin1').includes('%PDF')) {
    const t = buf.toString('latin1');
    const has = (re) => re.test(t);
    const acts = [];
    if (has(/\/JavaScript|\/JS\s*[(<]/)) acts.push('JavaScript');
    if (has(/\/OpenAction|\/AA\s*<</)) acts.push('Aktion beim Öffnen');
    if (has(/\/Launch/)) acts.push('startet Programme (/Launch)');
    if (has(/\/EmbeddedFile/)) acts.push('eingebettete Dateien');
    if (has(/\/SubmitForm|\/ImportData/)) acts.push('sendet bzw. lädt Formulardaten');
    if (has(/\/RichMedia|\/XFA/)) acts.push('Flash/XFA-Inhalte');
    if (acts.length) {
      const danger = acts.includes('startet Programme (/Launch)') || (acts.includes('JavaScript') && acts.includes('Aktion beim Öffnen'));
      out.push(F({ ruleId: danger ? 'pdf-active-suspicious' : 'pdf-active-content', severity: danger ? 'high' : 'low', confidence: 'medium', title: `PDF mit aktivem Inhalt: ${acts.join(', ')}`, description: `„${label}“ enthält ${acts.join(', ')}. Normale PDFs (Rechnungen, Berichte) brauchen das nicht; Schad-PDFs nutzen genau diese Funktionen.`, remediation: danger ? 'Nicht öffnen; in einem sicheren Betrachter ohne JavaScript ansehen.' : 'Nur öffnen, wenn die Herkunft bekannt ist; JavaScript im PDF-Programm abschalten.', location: label }));
    }
    return out;
  }
  // RTF
  if (buf.subarray(0, 6).toString('latin1') === '{\\rtf1' || buf.subarray(0, 5).toString('latin1') === '{\\rtf') {
    const t = buf.toString('latin1');
    if (/\\objdata|\\object\\objemb|\\objupdate/.test(t)) out.push(F({ ruleId: 'rtf-embedded-object', severity: /\\objupdate|Equation\.3|Package/.test(t) ? 'high' : 'medium', title: 'RTF-Dokument mit eingebettetem Objekt', description: 'Eingebettete Objekte in RTF-Dateien wurden mehrfach für Angriffe genutzt (z. B. über den alten Formel-Editor), teils ohne weiteren Klick.', remediation: 'Nicht in Word öffnen, wenn die Herkunft unklar ist.', location: label }));
  }
  return out;
}

module.exports = { analyzeDocument, DOC_EXT };
