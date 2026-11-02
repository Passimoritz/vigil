'use strict';

// Trefferquote messen: Befunde eines Laufs gegen die erwarteten Luecken des Uebungsprojekts
// (bench/expected.json) abgleichen. Ein erwarteter Fund gilt als gefunden, wenn ein Befund in
// derselben Datei liegt und Kategorie ODER Regel-ID passen.
//   Trefferquote (Recall)   = gefundene / erwartete Luecken
//   Genauigkeit (Precision) = Befunde, die zu einer erwarteten Luecke gehoeren / alle Befunde
//                             (ohne Hinweise der Stufe "info")

const fileOf = (loc) => String(loc || '').replace(/\\/g, '/').replace(/(:\d+)+$/, '').replace(/@[0-9a-f]{7,}$/, '').toLowerCase();

function matches(f, exp) {
  const file = fileOf(f.location);
  const want = exp.file.toLowerCase();
  if (!(file === want || file.endsWith('/' + want))) return false;
  return (exp.cats || []).includes(f.category) || new RegExp(exp.rule, 'i').test(`${f.ruleId || ''} ${f.title || ''}`);
}

function scoreBench(findings, expected) {
  const relevant = findings.filter((f) => f.severity !== 'info' && f.category !== 'AttackPath');
  const hits = expected.issues.map((exp) => {
    const by = relevant.filter((f) => matches(f, exp));
    return { id: exp.id, label: exp.label, found: by.length > 0, by: [...new Set(by.map((f) => f.source))] };
  });
  const matched = relevant.filter((f) => expected.issues.some((exp) => matches(f, exp)));
  const recall = hits.filter((h) => h.found).length / expected.issues.length;
  const precision = relevant.length ? matched.length / relevant.length : 1;
  const extra = relevant.filter((f) => !matched.includes(f)).map((f) => ({ title: f.title, location: f.location, source: f.source }));
  return { recall, precision, found: hits.filter((h) => h.found).length, total: expected.issues.length, hits, extra };
}

module.exports = { scoreBench, matches };
