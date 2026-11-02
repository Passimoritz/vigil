'use strict';

// Zugangsdaten in der gesamten Git-Historie: liest alle Commits (git log -p, nur
// hinzugefuegte Zeilen) und sucht mit denselben Regeln wie die Vorpruefung. Gemeldet
// wird nur, was im aktuellen Stand NICHT mehr steht – das findet die Vorpruefung sonst
// ohnehin. Rein lesend; der Wert wird geschwaerzt.

const { execFile } = require('child_process');
const { SECRET_RULES } = require('./prescan');
const { normalizeFinding, redactSecret } = require('./schema');

const MAX_COMMITS = 3000;
const MAX_BYTES = 64 * 1024 * 1024;

function git(cwd, args, { signal, timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const child = execFile('git', args, { cwd, maxBuffer: MAX_BYTES, timeout: timeoutMs, windowsHide: true, signal }, (err, stdout) => {
      if (err) resolve({ ok: false, error: err.code === 'ENOENT' ? 'git nicht installiert' : err.message.split('\n')[0], stdout: stdout || '' });
      else resolve({ ok: true, stdout });
    });
    child.on('error', () => { /* im Callback behandelt */ });
  });
}

// Ausgabe von git log -p --format=@@C %H|%an|%ad in Treffer zerlegen.
function scanLog(text, rules = SECRET_RULES) {
  const hits = [];
  let commit = null, file = null;
  for (const line of text.split('\n')) {
    if (line.startsWith('@@C ')) { const [h, a, d] = line.slice(4).split('|'); commit = { hash: h, author: a, date: d }; continue; }
    if (line.startsWith('+++ ')) { file = line.slice(4).replace(/^b\//, ''); continue; }
    if (!line.startsWith('+') || line.startsWith('+++') || !commit || !file || file === '/dev/null') continue;
    const added = line.slice(1);
    if (added.length > 2000) continue;
    for (const r of rules) {
      r.re.lastIndex = 0;
      const m = r.re.exec(added);
      if (m) hits.push({ rule: r, value: m[0], file, commit });
    }
  }
  return hits;
}

// currentText: gesamter aktueller Inhalt der eingelesenen Dateien (zum Abgleich)
async function scanGitHistory(dir, { currentText = '', signal, onProgress = () => {} } = {}) {
  const inside = await git(dir, ['rev-parse', '--is-inside-work-tree'], { signal, timeoutMs: 10000 });
  if (!inside.ok || !/true/.test(inside.stdout)) return { findings: [], notes: [], ran: false };
  onProgress({ phase: 'prescan', message: 'Git-Historie: suche Zugangsdaten in alten Versionen …' });
  const log = await git(dir, ['log', '--all', '-p', '--no-color', '--no-ext-diff', '-U0', `-n${MAX_COMMITS}`, '--date=short', '--format=@@C %H|%an|%ad'], { signal });
  if (!log.ok) return { findings: [], notes: [`Git-Historie konnte nicht gelesen werden: ${log.error}`], ran: false };
  const seen = new Set();
  const findings = [];
  for (const h of scanLog(log.stdout)) {
    if (currentText.includes(h.value)) continue;        // steht noch im Code -> meldet die Vorpruefung
    const key = h.rule.name + h.value;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(normalizeFinding({
      ruleId: 'git-history-secret', severity: h.rule.sev === 'low' ? 'low' : h.rule.sev === 'medium' ? 'medium' : 'high', category: 'Secrets', confidence: 'high',
      title: `Gelöschter Zugangsschlüssel steht noch in der Git-Historie (${h.rule.name})`,
      description: `Der Wert ${redactSecret(h.value)} wurde am ${h.commit.date} von ${h.commit.author} in „${h.file}“ eingetragen und später entfernt. In der Historie ist er weiterhin für jeden lesbar, der das Repository hat.`,
      impact: 'Wer das Repository klont oder einsehen kann – auch über einen alten Fork oder eine Kopie – kann den Schlüssel benutzen, solange er gültig ist.',
      remediation: 'Den Schlüssel sofort beim Anbieter sperren und neu erzeugen. Das Entfernen aus der Historie (git filter-repo) ist danach nur noch Aufräumen – die Sperre ist der wichtige Schritt.',
      location: `${h.file}@${h.commit.hash.slice(0, 7)}`, sourceModule: 'git-history',
    }, 'git-history'));
    if (findings.length >= 30) break;
  }
  return { findings, notes: [`Git-Historie geprüft (${(log.stdout.match(/^@@C /gm) || []).length} Commits).`], ran: true };
}

module.exports = { scanGitHistory, scanLog };
