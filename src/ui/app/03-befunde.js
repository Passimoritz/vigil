'use strict';

// Vigil-Oberfläche, Teil 3/9: Bedrohungsmodell, Befund-Detail, KI-Hilfe, Lösungsteil, Befund-Status.
// Klassisches Skript – teilt den globalen Gueltigkeitsbereich mit den anderen Teilen in src/ui/app/.

// --- STRIDE-Bedrohungsmodell ---------------------------------------------------
const STRIDE_ORDER = ['S', 'T', 'R', 'I', 'D', 'E'];
const LEVEL_DE = { high: 'hoch', medium: 'mittel', low: 'niedrig' };
function renderThreatModel() {
  const el = $('threatPanel'); if (!el) return;
  const tm = state.threatBusy ? { pending: true } : state.lastResult && state.lastResult.meta && state.lastResult.meta.threatModel;
  el.hidden = !tm;
  if (!tm) return;
  if (tm.pending) { el.innerHTML = `<h3>Bedrohungsmodell (STRIDE)</h3><p class="muted small">Wird erstellt …</p>${dots}`; return; }
  const groups = STRIDE_ORDER.map((s) => ({ s, list: (tm.threats || []).filter((t) => t.stride === s) })).filter((g) => g.list.length);
  el.innerHTML = `<div class="tm-head"><h3>Bedrohungsmodell (STRIDE)</h3><span class="muted small">${tm.source === 'ai' ? `KI${tm.model ? ' · ' + esc(tm.model) : ''}` : 'aus den Befunden abgeleitet'} · ${esc(fmtDate(tm.at))} · auch im Bericht enthalten</span><button type="button" class="btn tiny ghost tm-close">Ausblenden</button></div>
    ${tm.summary ? `<p>${esc(tm.summary)}</p>` : ''}
    ${tm.error ? `<p class="muted small">${esc(tm.error)}</p>` : ''}
    ${(tm.assets || []).length || (tm.entryPoints || []).length ? `<div class="tm-facts">${tm.assets.length ? `<div><h4>Schützenswert</h4><ul>${tm.assets.map((a) => `<li>${esc(a)}</li>`).join('')}</ul></div>` : ''}${tm.entryPoints.length ? `<div><h4>Eingänge</h4><ul>${tm.entryPoints.map((a) => `<li>${esc(a)}</li>`).join('')}</ul></div>` : ''}</div>` : ''}
    <div class="tm-grid">${groups.map((g) => g.list.map((t) => `<article class="tm-card stride-${g.s}">
      <div class="tm-cat"><b>${g.s}</b> ${esc(t.category)}</div>
      <h4 class="tm-title">${esc(t.title)}</h4>
      ${t.asset ? `<p class="muted small">Betrifft: ${esc(t.asset)}</p>` : ''}
      ${t.description ? `<p>${esc(t.description)}</p>` : ''}
      <p class="small">Wahrscheinlichkeit <b>${esc(LEVEL_DE[t.likelihood] || t.likelihood)}</b> · Auswirkung <b>${esc(LEVEL_DE[t.impact] || t.impact)}</b></p>
      ${t.mitigations.length ? `<ul class="tm-mit">${t.mitigations.map((m) => `<li>${esc(m)}</li>`).join('')}</ul>` : ''}
      ${t.findings.length ? `<div class="tm-links">${t.findings.map((x) => `<button type="button" class="chip-btn tm-f" data-id="${esc(x.id || '')}" data-title="${esc(x.title)}">#${x.n} ${esc(x.title.slice(0, 60))}</button>`).join('')}</div>` : ''}
    </article>`).join('')).join('')}</div>
    ${(tm.assumptions || []).length ? `<p class="muted small">Annahmen: ${esc(tm.assumptions.join(' · '))}</p>` : ''}`;
  el.querySelector('.tm-close').onclick = () => { el.hidden = true; };
  el.querySelectorAll('.tm-f').forEach((b) => b.onclick = () => {
    const i = state.lastFindings.findIndex((x) => (b.dataset.id && x.id === b.dataset.id) || x.title === b.dataset.title);
    if (i >= 0) selectFinding(findingKey(state.lastFindings[i], i));
  });
}
async function buildThreatModel() {
  if (state.threatBusy || !state.lastResult) return;
  state.threatBusy = true; renderThreatModel();
  $('threatPanel').scrollIntoView({ block: 'nearest' });
  const r = await window.vigil.threatModel();
  state.threatBusy = false;
  if (r && r.ok) {
    for (const res of [state.lastResult, state.rawResult]) if (res) res.meta = { ...(res.meta || {}), threatModel: r.threatModel };
    toast('Bedrohungsmodell erstellt', 'ok');
  } else flash('Bedrohungsmodell nicht erstellt: ' + ((r && r.error) || 'unbekannter Fehler'));
  renderThreatModel();
}

// Werkzeug-Praefix ("gitleaks: …") aus dem Titel nehmen – die Quelle steht daneben.
const TOOL_PREFIX = /^(gitleaks|trufflehog|trivy|grype|semgrep|bandit|checkov|retire\.js|hadolint|osv-scanner|nuclei|binary)\s*:\s*/i;
function cleanTitle(t) {
  const s = String(t || '').replace(TOOL_PREFIX, '').trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function findingSources(f) { return f.sources && f.sources.length ? f.sources : [f.source]; }
function matchesQuery(f, q) {
  if (!q) return true;
  const hay = [f.title, f.location, f.category, f.description, ...findingSources(f).map(sourceLabel)].join(' ').toLowerCase();
  return q.split(/\s+/).every((w) => hay.includes(w));
}
const CONF_LABEL = { high: 'hoch', medium: 'mittel', low: 'niedrig' };
// Beleg-Stufen: KI-Funde zaehlen erst, wenn sie deterministisch oder per Gegenpruefung bestaetigt sind.
const EVIDENCE = {
  'confirmed-multi': { label: 'Mehrfach bestätigt', cls: 'ev-strong', help: 'Von mehreren unabhängigen Prüfungen gefunden.' },
  deterministic: { label: 'Regelbasiert belegt', cls: 'ev-strong', help: 'Von einer deterministischen Prüfung (Muster, Datenbank, Tool) gefunden – nicht nur von der KI.' },
  'ai-verified': { label: 'KI-gegengeprüft', cls: 'ev-ok', help: 'Nur die KI hat es gemeldet, aber die Gegenprüfung am Code-Ausschnitt hat es bestätigt.' },
  unverified: { label: 'Unbestätigt', cls: 'ev-weak', help: 'Nur von der KI gemeldet und nicht bestätigt – bitte selbst prüfen, kann ein Fehlalarm sein.' },
};
const CONTEXT = {
  'internet-exposed': 'aus dem Internet erreichbar',
  'request-handler': 'in einem Request-Handler',
  'sensitive-data': 'berührt sensible Daten',
  'supply-chain': 'Lieferkette (Abhängigkeit)',
};

const riskOf = (f) => (f.contextualRiskScore != null ? f.contextualRiskScore : (f.cvss != null ? f.cvss * 10 : null));
const riskCls = (r) => (r >= 85 ? 'crit' : r >= 65 ? 'high' : r >= 40 ? 'med' : 'low');
const findingKey = (f, i) => f.id || 'i' + i;

// Kategorien in Alltagssprache
const CATEGORY_LABEL = {
  Other: 'Sonstiges', Config: 'Konfiguration', Transport: 'Verschlüsselung', Dependencies: 'Abhängigkeiten', Secrets: 'Zugangsdaten',
  AccessControl: 'Zugriffsrechte', Auth: 'Anmeldung', Injection: 'Einschleusen von Befehlen', XSS: 'Einschleusen von Skripten',
  Crypto: 'Verschlüsselung', SSRF: 'Server-Anfragen von außen', PathTraversal: 'Dateizugriff', Deserialization: 'Datenverarbeitung',
  Logic: 'Programmlogik', DoS: 'Überlastung', Supply: 'Lieferkette', SupplyChain: 'Lieferkette', Container: 'Container', Host: 'Server',
  DNS: 'DNS & E-Mail', LLM: 'KI-Sicherheit', Logging: 'Protokollierung', License: 'Lizenz', AttackPath: 'Angriffsweg',
};
// Beteiligte Befunde eines Angriffswegs (verknuepft ueber ruleId@location)
function linkedOf(f) {
  if (!Array.isArray(f.linkedKeys) || !f.linkedKeys.length) return [];
  const want = new Set(f.linkedKeys);
  return state.lastFindings.map((x, i) => ({ x, k: findingKey(x, i) })).filter(({ x }) => want.has(`${x.ruleId}@${x.location}`));
}

// Kompakte Zeile in der Befundliste (links).
function findingRow(f, key) {
  const risk = riskOf(f);
  const flags = `${f.inCisaKev ? '<span class="fr-flag kev" title="Aktiv ausgenutzt (CISA KEV)"></span>' : ''}${f.isNew && state.lastResult && state.lastResult.hasBaseline ? '<span class="fr-flag new" title="Neu seit dem letzten Lauf"></span>' : ''}`;
  return `<button type="button" class="frow sev-${f.severity}${state.selected === key ? ' active' : ''}${f.suppressed ? ' is-suppressed' : ''}" role="option" aria-selected="${state.selected === key}" data-key="${esc(key)}">
      <span class="fr-main">
        <span class="fr-title" title="${esc(cleanTitle(f.title))}">${esc(cleanTitle(f.title))}</span>
        <span class="fr-sub"><span class="fr-loc">${esc(f.location || f.category || '')}</span></span>
      </span>
      <span class="fr-side">${flags}${risk != null ? `<span class="risk risk-${riskCls(risk)}" title="Kontext-Risiko 0–100">${Math.round(risk)}</span>` : ''}</span>
    </button>`;
}

// Volle Detailansicht eines Befunds (rechts).
const OWASP_LABEL = { A01: 'Fehlerhafte Zugriffskontrolle', A02: 'Kryptografische Fehler', A03: 'Injection', A04: 'Unsicheres Design', A05: 'Fehlkonfiguration', A06: 'Veraltete und verwundbare Komponenten', A07: 'Fehler bei Anmeldung', A08: 'Fehlende Integrität von Software und Daten', A09: 'Unzureichendes Protokollieren', A10: 'Server-Side Request Forgery' };
const REACH_LABEL = { used: 'Paket wird genutzt', 'function-used': 'betroffene Funktion wird aufgerufen', 'function-unused': 'betroffene Funktion ungenutzt', unused: 'Paket ungenutzt', transitive: 'nur indirekt enthalten' };
const REACH_HELP = { 'function-used': 'Die Lücke ist sehr wahrscheinlich erreichbar.', 'function-unused': 'Risiko deutlich geringer – trotzdem aktualisieren.', unused: 'Am einfachsten: Paket entfernen.', transitive: 'Kommt über ein anderes Paket mit.' };
function findingDetail(f) {
  const srcs = findingSources(f);
  const srcNames = srcs.map(sourceLabel).join(', ');
  const ev = EVIDENCE[f.assurance];
  const risk = riskOf(f);
  const chips = [
    `<span class="sev-tag sev-${f.severity}" title="${esc(SEV_HELP[f.severity])}">${SEV_LABEL[f.severity]}</span>`,
    risk != null ? `<span class="risk risk-${riskCls(risk)}" title="Kontext-Risiko 0–100${f.cvss != null ? ' · CVSS ' + Number(f.cvss).toFixed(1) : ''}">Risiko ${Math.round(risk)}</span>` : '',
    ev ? `<span class="chip ${ev.cls}" title="${esc(ev.help)}">${ev.label}</span>` : '',
    f.inCisaKev ? '<span class="chip badge-kev" title="Steht im CISA-Katalog aktiv ausgenutzter Lücken">aktiv ausgenutzt</span>' : '',
    f.epssScore >= 0.1 ? `<span class="chip badge-epss" title="Wahrscheinlichkeit einer Ausnutzung in 30 Tagen">EPSS ${Math.round(f.epssScore * 100)} %</span>` : '',
    f.isNew && state.lastResult && state.lastResult.hasBaseline ? '<span class="chip badge-new">neu</span>' : '',
    f.regression ? '<span class="chip badge-reg" title="War als behoben markiert und ist wieder da">wieder da</span>' : '',
    `<span class="chip">${esc(CATEGORY_LABEL[f.category] || f.category)}</span>`,
    f.owasp ? `<span class="chip" title="${esc(OWASP_LABEL[f.owasp] || f.owasp)} – Einordnung nach OWASP Top 10">OWASP ${esc(f.owasp)}</span>` : '',
    f.cwe ? `<span class="chip" title="Schwachstellen-Typ nach der CWE-Liste">${esc(f.cwe)}</span>` : '',
    f.reach ? `<span class="chip reach-${esc(f.reach)}" title="${esc(REACH_HELP[f.reach] || '')}">${esc(REACH_LABEL[f.reach] || f.reach)}</span>` : '',
    f.consensus === 'both' ? '<span class="chip ev-multi" title="Beide KI-Modelle haben diesen Befund unabhängig gefunden">von 2 Modellen bestätigt</span>' : '',
  ].filter(Boolean).join('');
  const ctx = (f.context || []).filter((c) => CONTEXT[c]);
  const danger = [f.impact, f.reachability].filter(Boolean).join(' ');
  const secs = [
    f.description && `<div class="f-sec${danger ? '' : ' full'}"><h4>Was ist los?</h4><p>${glossify(esc(f.description))}</p></div>`,
    danger && `<div class="f-sec${f.description ? '' : ' full'}"><h4>Was kann passieren?</h4><p>${glossify(esc(danger))}</p></div>`,
  ].filter(Boolean).join('');
  const check = f.validation && f.validation.reason
    ? `<div class="f-sec check-sec"><h4>Gegenprüfung: ${f.validation.verdict === 'confirmed' ? 'bestätigt' : 'nicht eindeutig'}</h4><p>${esc(f.validation.reason)}</p></div>` : '';
  // Angriffsweg: die beteiligten Einzelbefunde zum Anklicken
  const linked = linkedOf(f);
  const linkedHtml = linked.length ? `<div class="f-sec linked-sec"><h4>Beteiligte Befunde</h4><div class="linked-list">${linked.map(({ x, k }) => `<button type="button" class="linked-row sev-${x.severity}" data-key="${esc(k)}"><span class="sev-tag">${SEV_LABEL[x.severity]}</span><span class="linked-title">${esc(cleanTitle(x.title))}</span><span class="linked-go" aria-hidden="true">›</span></button>`).join('')}</div></div>` : '';
  return `
    <header class="fd-head">
      <div class="fd-top">${chips}</div>
      <h2 class="fd-title">${esc(cleanTitle(f.title))}</h2>
      ${f.location ? `<div class="fd-loc">${esc(f.location)}</div>` : ''}
      <div class="fd-meta">
        <span class="meta-text"${f.ruleId ? ` title="Regel: ${esc(f.ruleId)}"` : ''}>${srcs.length > 1 ? 'Gefunden von' : 'Erkannt durch'}: ${esc(srcNames)}${f.confidence ? ' · Verlässlichkeit ' + esc(CONF_LABEL[f.confidence] || f.confidence) : ''}</span>
        ${f.id ? statusSelect(f.id, f.status || 'OPEN') : ''}
      </div>
    </header>
    <div class="fd-body">
      ${f.locationDetail ? `<p class="loc-detail"><span>Fundort</span>${esc(f.locationDetail)}</p>` : ''}
      ${ctx.length ? `<div class="ctx-row">${ctx.map((c) => `<span class="ctx-chip ctx-${c}">${CONTEXT[c]}</span>`).join('')}</div>` : ''}
      ${secs ? `<div class="f-cols">${secs}</div>` : ''}
      ${linkedHtml}
      ${check}
      ${f.evidence ? `<div class="f-sec evidence"><h4>Fundstelle</h4><code>${esc(f.evidence)}</code></div>` : ''}
      ${/:\d+(:\d+)?$/.test(f.location || '') && !/^https?:/i.test(f.location || '') ? '<div class="f-sec code-sec" hidden><h4>Betroffener Code</h4><div class="code-view"></div></div>' : ''}
      ${solutionBlock(f)}
      ${aiHelpBlock(f)}
      ${noteBlock(f)}
      <div class="f-sec ask-sec">
        <h4>Rückfrage an die KI</h4>
        <div class="ask-log" aria-live="polite"></div>
        <div class="ask-quick">
          <button type="button" class="chip-btn" data-q="Ist das bei mir wirklich ausnutzbar? Was müsste dafür gegeben sein?">Wirklich ausnutzbar?</button>
          <button type="button" class="chip-btn" data-q="Wie behebe ich das genau in meinem Code? Bitte mit konkretem Beispiel.">Wie genau beheben?</button>
          <button type="button" class="chip-btn" data-q="Kann das ein Fehlalarm sein? Woran erkenne ich das?">Fehlalarm?</button>
        </div>
        <form class="ask-form"><input type="text" class="ask-input" placeholder="Eigene Frage zu diesem Befund …" aria-label="Frage zu diesem Befund" maxlength="2000" /><button type="submit" class="btn primary tiny">Fragen</button></form>
      </div>
    </div>`;
}

// Kleines, sicheres Markdown fuer KI-Antworten: Absaetze, Ueberschriften, Listen, **fett**, *kursiv*,
// `Code`, Codebloecke und https-Links. Alles wird zuerst maskiert – die KI kann kein HTML einschleusen.
function mdInline(t) {
  return esc(t)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s.,;:!?)]|$)/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https:\/\/[^)\s]+)\)/g, '<a href="#" class="md-link" data-url="$2">$1</a>');
}
function miniMarkdown(src) {
  const parts = String(src || '').replace(/\r/g, '').split('```');
  let html = '';
  parts.forEach((part, i) => {
    if (i % 2) { html += `<pre class="md-code"><code>${esc(part.replace(/^[\w+.-]*\n/, '').replace(/\n$/, ''))}</code></pre>`; return; }
    let list = null;
    const close = () => { if (list) { html += `</${list}>`; list = null; } };
    for (const raw of part.split('\n')) {
      const l = raw.trimEnd();
      let m;
      if (!l.trim()) { close(); continue; }
      if ((m = l.match(/^\s*#{1,4}\s+(.*)$/))) { close(); html += `<p class="md-h">${mdInline(m[1])}</p>`; continue; }
      if ((m = l.match(/^\s*[-*•]\s+(.*)$/))) { if (list !== 'ul') { close(); html += '<ul>'; list = 'ul'; } html += `<li>${mdInline(m[1])}</li>`; continue; }
      if ((m = l.match(/^\s*\d+[.)]\s+(.*)$/))) { if (list !== 'ol') { close(); html += '<ol>'; list = 'ol'; } html += `<li>${mdInline(m[1])}</li>`; continue; }
      close();
      html += `<p>${mdInline(l)}</p>`;
    }
    close();
  });
  return html;
}

// Nach dem Einfuegen der Detailansicht: Code-Ausschnitt laden und Rueckfragen verdrahten.
// Gespraeche bleiben je Befund erhalten, solange die App laeuft.
state.chats = state.chats || {};
function hydrateDetail(root, f) {
  const codeSec = root.querySelector('.code-sec');
  if (codeSec && window.vigil.findingSnippet) {
    window.vigil.findingSnippet(f.location).then((s) => {
      if (!s || !s.ok || !root.contains(codeSec)) return;
      codeSec.hidden = false;
      codeSec.querySelector('.code-view').innerHTML = `<div class="code-file">${esc(s.file)}</div><pre>${s.lines.map((l, i) => { const n = s.from + i; return `<span class="cl${n === s.line ? ' hit' : ''}"><i>${n}</i>${esc(l) || ' '}</span>`; }).join('')}</pre>`;
    }).catch(() => {});
  }
  const sec = root.querySelector('.ask-sec');
  if (!sec) return;
  const key = f.id || `${f.ruleId}@${f.location}`;
  const chat = state.chats[key] || (state.chats[key] = []);
  const log = sec.querySelector('.ask-log');
  const paint = () => {
    log.innerHTML = chat.map((m) => `<div class="ask-msg ${m.role}"><span class="ask-who">${m.role === 'user' ? 'Du' : esc(m.model || 'KI')}</span><div class="${m.role === 'ai' ? 'ask-md' : ''}">${m.pending ? '<span class="ask-dots"><i></i><i></i><i></i></span>' : m.role === 'ai' ? miniMarkdown(m.text) : esc(m.text)}</div></div>`).join('');
    log.querySelectorAll('.md-link').forEach((a) => a.onclick = (e) => { e.preventDefault(); window.vigil.openLink(a.dataset.url); });
    log.hidden = !chat.length;
  };
  paint();
  const ask = async (q) => {
    q = String(q || '').trim();
    if (!q || chat.some((m) => m.pending)) return;
    const history = chat.filter((m) => !m.pending).map((m) => ({ role: m.role, text: m.text }));
    chat.push({ role: 'user', text: q }, { role: 'ai', pending: true });
    paint();
    const r = await window.vigil.askFinding({ question: q, history, finding: { title: f.title, severity: f.severity, location: f.location, category: f.category, description: f.description, impact: f.impact, reachability: f.reachability, remediation: f.remediation } });
    chat.pop();
    chat.push({ role: 'ai', text: r && r.ok ? r.answer : `Keine Antwort: ${(r && r.error) || 'unbekannter Fehler'}`, model: r && r.model });
    if (root.contains(sec)) paint();
  };
  sec.querySelectorAll('[data-q]').forEach((b) => b.onclick = () => ask(b.dataset.q));
  sec.querySelector('.ask-form').onsubmit = (e) => { e.preventDefault(); const inp = sec.querySelector('.ask-input'); ask(inp.value); inp.value = ''; };
  hydrateAiHelp(root, f);
}

// --- KI-Hilfe im Detail: Erklaerstufen, Fix als Diff, Upgrade-Hinweise ------------------
// Alles sind Vorschlaege: Vigil aendert keine Datei – Kopieren und Uebernehmen macht der Nutzer.
const LEVEL_LABEL = { lay: 'Laie', dev: 'Entwickler', expert: 'Experte' };
state.aiHelp = state.aiHelp || {};
const findingPayload = (f) => ({ id: f.id, title: f.title, severity: f.severity, location: f.location, category: f.category, cwe: f.cwe, description: f.description, impact: f.impact, reachability: f.reachability, remediation: f.remediation });
function aiHelpBlock(f) {
  const pkg = f.package && f.package.name ? f.package : null;
  const codeFix = /:\d+(:\d+)?$/.test(f.location || '') && !/^https?:/i.test(f.location || '');
  return `<div class="f-sec ai-help">
    <h4>KI-Hilfe</h4>
    <div class="lvl-row"><span class="muted small">Erklärung für</span>
      <span class="seg lvl-seg" role="radiogroup" aria-label="Erklärstufe">${Object.entries(LEVEL_LABEL).map(([k, v]) => `<button type="button" role="radio" aria-checked="false" data-level="${k}">${v}</button>`).join('')}</span>
    </div>
    <div class="explain-out ask-md" aria-live="polite" hidden></div>
    <div class="patch-row">
      ${codeFix ? '<button type="button" class="btn small gen-patch">Fix generieren</button>' : ''}
      ${pkg ? '<button type="button" class="btn small upg-btn">Upgrade-Hinweise</button>' : ''}
      ${codeFix || pkg ? '<span class="muted small">Nur Vorschläge – Vigil ändert keine Datei.</span>' : ''}
    </div>
    <div class="patch-out" aria-live="polite" hidden></div>
    <div class="upg-out" aria-live="polite" hidden></div>
  </div>`;
}
const dots = '<span class="ask-dots"><i></i><i></i><i></i></span>';
function diffHtml(d) {
  return `<pre class="diff-view">${String(d).split('\n').map((l) => `<span class="${/^(\+\+\+|---)/.test(l) ? 'd-file' : /^@@/.test(l) ? 'd-hunk' : /^\+/.test(l) ? 'd-add' : /^-/.test(l) ? 'd-del' : 'd-ctx'}">${esc(l) || ' '}</span>`).join('')}</pre>`;
}
function hydrateAiHelp(root, f) {
  const box = root.querySelector('.ai-help');
  if (!box) return;
  const key = f.id || `${f.ruleId}@${f.location}`;
  const mem = state.aiHelp[key] || (state.aiHelp[key] = { explain: {} });
  const out = box.querySelector('.explain-out');
  const paintExplain = () => {
    box.querySelectorAll('.lvl-seg button').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.level === mem.level)));
    const e = mem.level && mem.explain[mem.level];
    out.hidden = !e;
    if (!e) return;
    out.innerHTML = e.pending ? dots : e.error ? `<p class="err small">${esc(e.error)}</p>`
      : `${miniMarkdown(e.text)}<p class="muted small">${esc(e.model || 'KI')}${e.cached ? ' · aus dem Zwischenspeicher' : ''} · <a href="#" class="re-explain">neu erklären</a></p>`;
    const re = out.querySelector('.re-explain');
    if (re) re.onclick = (ev) => { ev.preventDefault(); explain(mem.level, true); };
  };
  const explain = async (level, refresh) => {
    mem.level = level;
    if (mem.explain[level] && !refresh && !mem.explain[level].error) { paintExplain(); return; }
    mem.explain[level] = { pending: true };
    paintExplain();
    const r = await window.vigil.explainFinding(findingPayload(f), level, refresh);
    mem.explain[level] = r && r.ok ? { text: r.text, model: r.model, cached: r.cached } : { error: `Keine Antwort: ${(r && r.error) || 'unbekannter Fehler'}` };
    if (root.contains(box)) paintExplain();
  };
  box.querySelectorAll('.lvl-seg button').forEach((b) => b.onclick = () => explain(b.dataset.level));
  paintExplain();

  const pout = box.querySelector('.patch-out');
  const paintPatch = () => {
    const p = mem.patch;
    pout.hidden = !p;
    if (!p) return;
    if (p.pending) { pout.innerHTML = `<p class="muted small">Die KI schreibt einen Fix-Vorschlag …</p>${dots}`; return; }
    if (p.error) { pout.innerHTML = `<p class="err small">${esc(p.error)}</p>`; return; }
    const chk = p.check && p.check.checked ? (p.check.applies ? '<span class="chip ev-ok">passt zum aktuellen Code</span>' : '<span class="chip ev-weak">passt nicht exakt – vor dem Übernehmen prüfen</span>') : '';
    pout.innerHTML = `${p.summary ? `<p>${esc(p.summary)}</p>` : ''}
      ${p.diff ? `<div class="sol-head"><span class="muted small">+${p.stats.added} / −${p.stats.removed} Zeilen · ${esc(p.model || '')}${p.confidence ? ' · Verlässlichkeit ' + esc(CONF_LABEL[p.confidence] || p.confidence) : ''}</span>${chk}${copyBtn(p.diff)}</div>${diffHtml(p.diff)}<p class="muted small">Nichts wurde angewendet. Kopieren und z. B. mit <code>git apply</code> übernehmen – vorher lesen und testen.</p>` : '<p class="muted small">Kein Diff möglich.</p>'}
      ${p.notes ? `<div class="ask-md">${miniMarkdown(p.notes)}</div>` : ''}`;
    bindSolutionControls(pout);
  };
  const pb = box.querySelector('.gen-patch');
  if (pb) pb.onclick = async () => {
    if (mem.patch && mem.patch.pending) return;
    mem.patch = { pending: true }; paintPatch(); pb.disabled = true;
    const r = await window.vigil.patchFinding(findingPayload(f));
    mem.patch = r && r.ok ? r : { error: `Kein Vorschlag: ${(r && r.error) || 'unbekannter Fehler'}` };
    pb.disabled = false;
    if (root.contains(box)) paintPatch();
  };
  paintPatch();

  const uout = box.querySelector('.upg-out');
  const paintUpg = () => {
    const u = mem.upgrade;
    uout.hidden = !u;
    if (!u) return;
    if (u.pending) { uout.innerHTML = `<p class="muted small">Suche Changelog und Release Notes …</p>${dots}`; return; }
    if (u.error && !u.links) { uout.innerHTML = `<p class="err small">${esc(u.error)}</p>`; return; }
    const j = u.jump || {};
    const warn = j.breaking ? `<p class="upg-warn">⚠ ${j.kind === 'major' ? `Sprung über ${j.majors || 1} Hauptversion(en)` : 'Versionssprung in 0.x'} (${esc(j.from)} → ${esc(j.to)}) – brechende Änderungen sind wahrscheinlich.</p>`
      : j.kind === 'unknown' ? '<p class="muted small">Versionssprung nicht bestimmbar.</p>' : `<p class="muted small">${j.kind === 'minor' ? 'Kleiner Versionssprung' : 'Fehlerbehebungs-Version'} (${esc(j.from)} → ${esc(j.to)}) – nach semver ohne brechende Änderungen.</p>`;
    uout.innerHTML = warn
      + (u.aiSummary ? `<div class="ask-md">${miniMarkdown(u.aiSummary)}</div>` : '')
      + (u.hints && u.hints.length ? `<h4>Hinweise aus den Release Notes</h4><ul class="upg-hints">${u.hints.map((h) => `<li><b>${esc(h.tag)}</b> ${esc(h.text)}</li>`).join('')}</ul>` : '')
      + (u.links && u.links.length ? `<div class="link-row">${u.links.map((l) => `<button type="button" class="link-chip kind-${esc(l.kind || 'doc')}" data-url="${esc(l.url)}" title="${esc(l.url)}">${LINK_ICON[l.kind] || '🔗'} ${esc(l.label)}</button>`).join('')}</div>` : '<p class="muted small">Keine Changelog-Links in den Paket-Metadaten gefunden.</p>')
      + (u.error ? `<p class="muted small">Hinweis: ${esc(u.error)}</p>` : '');
    bindSolutionControls(uout);
  };
  const ub = box.querySelector('.upg-btn');
  if (ub) ub.onclick = async () => {
    if (mem.upgrade && mem.upgrade.pending) return;
    mem.upgrade = { pending: true }; paintUpg(); ub.disabled = true;
    const r = await window.vigil.upgradeGuide(f.package);
    mem.upgrade = r && r.ok ? r : { error: `Keine Hinweise: ${(r && r.error) || 'unbekannter Fehler'}` };
    ub.disabled = false;
    if (root.contains(box)) paintUpg();
  };
  paintUpg();
}

// --- Loesungsteil: Warum, Schritte, Versions-Patch, Schnipsel, Links -------
const LINK_ICON = { doc: '📘', news: '📰', video: '▶' };
const SNIP_LABEL = { nginx: 'nginx', apache: 'Apache', caddy: 'Caddy', express: 'Node/Express', node: 'Node.js', php: 'PHP', compose: 'docker-compose', dockerfile: 'Dockerfile', yaml: 'GitHub Actions', sshd_config: 'sshd_config', shell: 'Shell', ufw: 'ufw', fail2ban: 'fail2ban', dns: 'DNS-Eintrag', prisma: 'Prisma', sql: 'SQL', html: 'HTML', vite: 'Vite', webpack: 'webpack', npmrc: '.npmrc', ci: 'CI', certbot: 'certbot', csp: 'CSP', http: 'HTTP', apollo: 'Apollo', yoga: 'GraphQL Yoga', terser: 'terser' };
function copyBtn(text) { return `<button type="button" class="btn tiny copy-btn" data-copy="${esc(text)}">Kopieren</button>`; }
function solutionBlock(f) {
  const parts = [];
  if (f.explanation) parts.push(`<div class="sol-why"><h4>Warum das wichtig ist</h4><p>${glossify(esc(f.explanation))}</p></div>`);
  const steps = f.steps && f.steps.length ? f.steps : (f.remediation ? [f.remediation] : []);
  if (steps.length) parts.push(`<div class="sol-steps"><h4>So behebst du es</h4><ol>${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>${f.remediation && f.steps && f.steps.length && !f.steps.includes(f.remediation) && !/^Siehe /.test(f.remediation) ? `<p class="muted small">Für diesen Fund: ${esc(f.remediation)}</p>` : ''}</div>`);
  if (f.versionPatch) {
    const vp = f.versionPatch;
    const code = [vp.command, vp.manifest].filter(Boolean).join('\n\n');
    parts.push(`<div class="sol-patch"><div class="sol-head"><h4>⬆ Versions-Patch · ${esc(vp.title)}</h4>${copyBtn(vp.command || code)}</div><pre>${esc(code)}</pre>${vp.note ? `<p class="muted small">${esc(vp.note)}</p>` : ''}</div>`);
  }
  const snips = Object.entries(f.snippets || {});
  if (f.patch) snips.unshift(['patch', f.patch]);
  if (snips.length) {
    parts.push(`<div class="sol-snips"><div class="snip-tabs" role="tablist">${snips.map(([k], i) => `<button type="button" class="snip-tab${i ? '' : ' active'}" data-i="${i}">${esc(k === 'patch' ? 'Vorschlag' : SNIP_LABEL[k] || k)}</button>`).join('')}</div>${snips.map(([, v], i) => `<div class="snip-pane"${i ? ' hidden' : ''}>${copyBtn(v)}<pre>${esc(v)}</pre></div>`).join('')}</div>`);
  }
  if (f.links && f.links.length) {
    parts.push(`<div class="sol-links"><h4>Mehr dazu</h4><div class="link-row">${f.links.slice(0, 10).map((l) => `<button type="button" class="link-chip kind-${esc(l.kind || 'doc')}" data-url="${esc(l.url)}" title="${esc(l.url)}">${LINK_ICON[l.kind] || '🔗'} ${esc(l.label)}</button>`).join('')}</div></div>`);
  }
  return parts.length ? `<div class="solution"><div class="sol-title">Lösung</div>${parts.join('')}</div>` : '';
}
function bindSolutionControls(root) {
  root.querySelectorAll('.copy-btn').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Kopiert ✓'; setTimeout(() => { b.textContent = 'Kopieren'; }, 1400); } catch { b.textContent = 'Nicht möglich'; }
  });
  root.querySelectorAll('.snip-tabs').forEach((tabs) => tabs.querySelectorAll('.snip-tab').forEach((t) => t.onclick = (e) => {
    e.stopPropagation();
    tabs.querySelectorAll('.snip-tab').forEach((x) => x.classList.toggle('active', x === t));
    tabs.parentElement.querySelectorAll('.snip-pane').forEach((p, i) => { p.hidden = String(i) !== t.dataset.i; });
  }));
  root.querySelectorAll('.link-chip').forEach((b) => b.onclick = async (e) => {
    e.stopPropagation();
    const r = await window.vigil.openLink(b.dataset.url);
    if (r && r.ok === false) flash(r.error || 'Link nicht erlaubt.');
  });
}

// Banner fuer Angriffspfade (Toxic Combinations) – ganz oben, weil am dringendsten.
function toxicBanner(list) {
  const toxic = list.filter((f) => /^toxic-/.test(f.ruleId || '') && !f.suppressed);
  if (!toxic.length) return '';
  return `<div class="toxic-banner" role="alert"><div class="toxic-ico">⚠</div><div><b>${toxic.length} ${toxic.length === 1 ? 'Angriffsweg' : 'Angriffswege'} erkannt</b><ul>${toxic.map((t) => `<li>${esc(t.title.replace(/^(Möglicher )?Angriffsweg:\s*/, ''))}</li>`).join('')}</ul><span class="muted small">Mehrere Schwächen ergeben zusammen einen kompletten Weg für einen Angriff. Schon eine einzige Behebung unterbricht ihn.</span></div></div>`;
}

function visibleList() {
  const q = state.query.trim().toLowerCase();
  let list = state.filter === 'all' ? state.lastFindings : state.lastFindings.filter((f) => f.severity === state.filter);
  if (!state.showSuppressed) list = list.filter((f) => !f.suppressed);
  if (state.onlyNew) list = list.filter((f) => f.isNew);
  if (state.onlyProven) list = list.filter((f) => f.assurance !== 'unverified');
  return list.filter((f) => matchesQuery(f, q));
}
function renderFindings() {
  const box = $('findings');
  const list = visibleList();
  const keyed = list.map((f) => ({ f, key: findingKey(f, state.lastFindings.indexOf(f)) }));
  if (!keyed.length) {
    box.innerHTML = state.lastFindings.length
      ? '<div class="empty"><b>Keine Treffer</b>Filter oder Suche anpassen.</div>'
      : '<div class="empty"><b>Alles sauber</b>Vigil hat in diesem Lauf nichts gefunden.</div>';
    state.selected = null;
    renderDetail();
    return;
  }
  // Auswahl behalten, sonst den dringendsten Befund zeigen
  if (!keyed.some((x) => x.key === state.selected)) state.selected = keyed[0].key;
  box.innerHTML = toxicBanner(state.lastFindings) + groupFindings(keyed).map((g) => `<div class="group-head${g.sev ? ' sev-' + g.sev : ' gb'}" title="${esc(g.label)}">${esc(g.label)} <span class="gcount">${g.items.length}</span></div>` + g.items.map((x) => findingRow(x.f, x.key)).join('')).join('');
  box.querySelectorAll('.frow').forEach((r) => r.onclick = () => selectFinding(r.dataset.key));
  renderDetail();
}
function selectFinding(key, focus) {
  state.selected = key;
  $('findings').querySelectorAll('.frow').forEach((r) => {
    const on = r.dataset.key === key;
    r.classList.toggle('active', on); r.setAttribute('aria-selected', on ? 'true' : 'false');
    if (on) { r.scrollIntoView({ block: 'nearest' }); if (focus) r.focus(); }
  });
  renderDetail();
}
function renderDetail() {
  const pane = $('findingDetail');
  const f = state.lastFindings.find((x, i) => findingKey(x, i) === state.selected);
  if (!f) { pane.innerHTML = '<div class="fd-empty">Wähle links einen Befund, um Details und Lösung zu sehen.</div>'; return; }
  pane.innerHTML = findingDetail(f);
  pane.scrollTop = 0;
  bindSolutionControls(pane);
  hydrateDetail(pane, f);
  pane.querySelectorAll('.linked-row').forEach((b) => b.onclick = () => {
    // Ausgeblendeter Teilbefund? Filter zuruecksetzen, damit er in der Liste auftaucht.
    if (!visibleList().some((x) => findingKey(x, state.lastFindings.indexOf(x)) === b.dataset.key)) { state.filter = 'all'; state.query = ''; $('findingSearch').value = ''; state.onlyNew = false; state.onlyProven = false; refreshResultView(); }
    selectFinding(b.dataset.key);
  });
  bindNote(pane, f, (note) => { state.lastFindings.forEach((x) => { if (x.id === f.id) x.note = note; }); if (state.rawResult) (state.rawResult.findings || []).forEach((x) => { if (x.id === f.id) x.note = note; }); });
  bindStatusSelects(pane, (id, status) => {
    state.lastFindings.forEach((x) => { if (x.id === id) { x.status = status; x.suppressed = HIDDEN_STATUS.has(status); } });
    toast(`Status: ${STATUS_LABEL[status]}`, 'ok');
    refreshResultView();
  });
}
// Pfeiltasten in der Befundliste
function moveSelection(delta) {
  const rows = [...$('findings').querySelectorAll('.frow')];
  if (!rows.length) return;
  const i = rows.findIndex((r) => r.dataset.key === state.selected);
  const next = rows[Math.min(rows.length - 1, Math.max(0, (i < 0 ? 0 : i + delta)))];
  selectFinding(next.dataset.key, true);
}

// --- Befund-Status (Lebenszyklus) ---------------------------------------
const STATUS_LABEL = { OPEN: 'Offen', IN_PROGRESS: 'In Arbeit', ACCEPTED_RISK: 'Risiko akzeptiert', FALSE_POSITIVE: 'Fehlalarm', RESOLVED: 'Behoben' };
const HIDDEN_STATUS = new Set(['FALSE_POSITIVE', 'ACCEPTED_RISK']);
function statusSelect(id, status) {
  return `<select class="status-select st-${status}" data-id="${esc(id)}" aria-label="Status des Befunds">${Object.entries(STATUS_LABEL).map(([k, v]) => `<option value="${k}"${k === status ? ' selected' : ''}>${v}</option>`).join('')}</select>`;
}
// "Risiko akzeptiert" ist befristet: Frist (Standard 90 Tage) und Begruendung abfragen.
// Liefert { days, note } oder null (abgebrochen).
function askAcceptance() {
  return new Promise((resolve) => {
    const dlg = document.createElement('dialog');
    dlg.className = 'accept-dlg';
    dlg.innerHTML = `<form method="dialog">
      <h3>Risiko akzeptieren</h3>
      <p class="muted small">Die Akzeptanz läuft ab – danach ist der Befund wieder offen und wird neu bewertet.</p>
      <label class="field"><span>Gültig für</span><select class="acc-days">${[[30, '30 Tage'], [90, '90 Tage (Standard)'], [180, '180 Tage'], [365, '1 Jahr']].map(([d, l]) => `<option value="${d}"${d === 90 ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
      <label class="field"><span>Begründung (optional)</span><input type="text" class="acc-note" maxlength="500" placeholder="z. B. nur intern erreichbar, Behebung im nächsten Release" /></label>
      <div class="dlg-actions"><button type="button" class="btn ghost acc-cancel">Abbrechen</button><button type="submit" class="btn primary acc-ok">Akzeptieren</button></div>
    </form>`;
    document.body.appendChild(dlg);
    const done = (v) => { try { dlg.close(); } catch { /* egal */ } dlg.remove(); resolve(v); };
    dlg.querySelector('.acc-cancel').onclick = () => done(null);
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); done(null); });
    dlg.querySelector('form').onsubmit = (e) => { e.preventDefault(); done({ days: Number(dlg.querySelector('.acc-days').value) || 90, note: dlg.querySelector('.acc-note').value.trim() }); };
    try { dlg.showModal(); } catch { dlg.setAttribute('open', ''); }
    dlg.querySelector('.acc-days').focus();
  });
}
function bindStatusSelects(root, onChanged) {
  root.querySelectorAll('.status-select').forEach((sel) => {
    sel.onclick = (e) => e.stopPropagation();
    let prev = sel.value;
    sel.onfocus = () => { prev = sel.value; };
    sel.onchange = async () => {
      let r;
      if (sel.value === 'ACCEPTED_RISK') {
        const a = await askAcceptance();
        if (!a) { sel.value = prev; return; }
        r = await window.vigil.setFindingStatus(sel.dataset.id, sel.value, a.note, a.days);
        if (r.ok && r.acceptedUntil) toast(`Akzeptiert bis ${new Date(r.acceptedUntil).toLocaleDateString(state.config && state.config.lang === 'de' ? 'de-DE' : 'en-GB')}`, 'ok');
      } else r = await window.vigil.setFindingStatus(sel.dataset.id, sel.value);
      if (r.ok) { prev = sel.value; onChanged(sel.dataset.id, r.status); }
      else flash('Status nicht gespeichert: ' + r.error);
    };
  });
}

// Vergleich mit frueheren Laeufen (aus dem Befund-Speicher).
function updateBaselineStatus() {
  const el = $('baselineStatus'); if (!el) return;
  const lc = state.lastResult && state.lastResult.lifecycle;
  if (!lc) { el.textContent = ''; return; }
  if (!state.lastResult.hasBaseline) { el.textContent = 'Erster Lauf für dieses Ziel – ab dem nächsten Lauf siehst du hier, was neu ist und was behoben wurde.'; return; }
  const parts = [`${lc.created} neu`, `${lc.updated} bekannt`];
  if (lc.reopened) parts.push(`${lc.reopened} wieder aufgetaucht`);
  if (lc.resolved) parts.push(`${lc.resolved} automatisch als behoben markiert`);
  el.textContent = 'Im Vergleich zum letzten Lauf: ' + parts.join(' · ') + '.';
}
function renderViewToggles() {
  const box = $('viewToggles'); if (!box) return;
  const r = state.lastResult;
  const newCount = state.lastFindings.filter((f) => f.isNew).length;
  const suppCount = state.lastFindings.filter((f) => f.suppressed).length;
  let html = '';
  if (r && r.hasBaseline && (newCount || state.onlyNew)) html += `<button class="fbtn toggle${state.onlyNew ? ' active' : ''}" data-t="onlyNew">Nur neue (${newCount})</button>`;
  const provenCount = state.lastFindings.filter((f) => !f.suppressed && f.assurance && f.assurance !== 'unverified').length;
  if (state.lastFindings.some((f) => f.assurance === 'unverified') || state.onlyProven) html += `<button class="fbtn toggle${state.onlyProven ? ' active' : ''}" data-t="onlyProven" title="Nur Befunde, die regelbasiert oder per Gegenprüfung bestätigt sind">Nur belegte (${provenCount})</button>`;
  if (suppCount || state.showSuppressed) html += `<button class="fbtn toggle${state.showSuppressed ? ' active' : ''}" data-t="showSupp">Fehlalarme &amp; akzeptierte zeigen (${suppCount})</button>`;
  box.innerHTML = html;
  box.querySelectorAll('.fbtn').forEach((b) => b.onclick = () => {
    if (b.dataset.t === 'onlyNew') state.onlyNew = !state.onlyNew;
    else if (b.dataset.t === 'onlyProven') state.onlyProven = !state.onlyProven;
    else state.showSuppressed = !state.showSuppressed;
    renderViewToggles(); renderFindings();
  });
}
// Namen der neueren Pruefmodule (Wunschliste); sonst fallen sie unten auf die rohe Kennung zurueck
const SOURCE_EXTRA = {
  'api-live': 'API-Abruf ohne Anmeldung', 'api-spec-audit': 'API-Beschreibungen', 'archive-audit': 'Archive', 'bundled-libs': 'Eingebaute Bibliotheken',
  'ci-audit': 'CI-Systeme', 'cms-audit': 'CMS-Konfiguration', 'cms-nvd': 'CMS-Versionen (NVD)', 'cms-web': 'CMS-Erkennung', 'code-quality': 'Code-Qualität',
  'crypto-inventory': 'Krypto-Inventar', 'dns-dnssec': 'DNSSEC', 'dockerfile-audit': 'Dockerfile', 'document-audit': 'Dokumente', 'domain-expiry': 'Domain-Ablauf',
  'framework-rules': 'Framework-Regeln', 'gha-audit': 'GitHub Actions', 'gitleaks-feed': 'Zugangsdaten-Regeln (Feed)', 'iac-audit': 'Infrastruktur als Code',
  'image-layers': 'Image-Schichten', internetdb: 'Shodan InternetDB', 'js-secrets': 'Skripte der Webseite', 'lang-rules': 'Sprach-Regeln', 'license-audit': 'Lizenzen',
  'link-check': 'Phishing-Links', 'lnk-audit': 'Verknüpfungen', 'lockfile-drift': 'Lockfile-Abgleich', 'mail-audit': 'E-Mails', 'mail-extended': 'E-Mail-Sicherheit',
  malwarebazaar: 'MalwareBazaar', 'mcp-config-audit': 'MCP-Konfiguration', 'mobile-audit': 'Handy-Apps', 'model-file-audit': 'KI-Modelldateien', 'ocr-image-audit': 'Texterkennung in Bildern',
  'package-health': 'Paket-Pflege', 'pe-hardening': 'Programm-Schutzfunktionen', 'privacy-audit': 'Personenbezogene Daten', 'retire-feed': 'JS-Bibliotheken (Feed)',
  'script-audit': 'Verschleierte Skripte', signature: 'Digitale Signatur', 'sql-audit': 'SQL-Rechte', 'taint-flow': 'Datenfluss-Analyse', 'tls-deep': 'TLS im Detail',
  'typo-domains': 'Tippfehler-Domains', 'web-a11y': 'Barrierefreiheit', 'web-change-watch': 'Änderungs-Wächter', 'web-crawl': 'Unterseiten-Durchgang', 'web-csp-suggest': 'CSP-Vorschlag',
  'web-legal': 'Impressum & Datenschutz', 'web-links': 'Defekte Links', 'web-login': 'Login-Prüfung', 'web-observatory': 'Observatory-Note', 'web-privacy': 'Datenschutz der Webseite',
  'web-probe': 'Testwerte in Parametern', 'web-sectxt': 'security.txt', 'web-seo': 'SEO', 'web-speed': 'Ladezeit', 'web-sri': 'SRI-Prüfsummen', 'web-subdomains': 'Subdomains',
  'webserver-config-audit': 'Webserver-Konfiguration', yara: 'YARA', defender: 'Microsoft Defender',
  'system-aws': 'AWS-Konto', 'system-azure': 'Azure', 'system-gcp': 'Google Cloud', 'system-docker': 'Docker', 'system-windows': 'Windows-PC', 'system-backup': 'Datensicherung',
  'system-browserext': 'Browser-Erweiterungen', 'system-cicd': 'CI/CD-Konten', 'system-dbdirect': 'Datenbank', 'system-hibp': 'Have I Been Pwned', 'system-hosting': 'Hosting-Anbieter',
  'system-iam': 'Cloud-Rechte', 'system-k8s': 'Kubernetes', 'system-lan': 'Heimnetz', 'system-linuxssh': 'Linux-Server', 'system-m365': 'Microsoft 365 / Google Workspace',
  'system-macos': 'macOS', 'system-router': 'Router', 'system-winapps': 'Installierte Programme',
};
function sourceLabel(s) { if (SOURCE_EXTRA[s]) return SOURCE_EXTRA[s]; return ({ osv: 'Schwachstellen-DB (OSV)', prescan: 'statische Prüfung', webscan: 'Server-Check', nmap: 'nmap', nuclei: 'nuclei', gitleaks: 'gitleaks', trufflehog: 'trufflehog', trivy: 'trivy', grype: 'grype', semgrep: 'semgrep', bandit: 'bandit', checkov: 'checkov', retire: 'retire.js', hadolint: 'hadolint', 'osv-scanner': 'osv-scanner', binary: 'Binary-Analyse', ai: 'KI', 'supply-chain-audit': 'Lieferkette', 'container-host-audit': 'Container-Prüfung', 'semgrep-custom-sast': 'Code-Regeln', 'llm-prompt-security': 'KI-Sicherheit', 'linux-host-audit': 'Server-Konfig', 'web-exposure-audit': 'Web-Exposure', 'web-tls-posture': 'Web/TLS', 'dns-mail-drift': 'DNS & Mail', 'headless-dom-audit': 'Browser-Prüfung', 'api-auth-matrix': 'API-Rechtematrix', correlator: 'Angriffsweg-Analyse' })[s] || s || 'KI'; }

// Details eines Laufs: Modell, Kosten, Zusammenfassung und (falls aufgezeichnet) das
// Reproduzierbarkeits-Protokoll mit Prompt- und Antwort-Pruefsummen.
const REPRO_KIND = { analyze: 'Analyse', triage: 'Vorsortierung', validate: 'Gegenprüfung', summary: 'Zusammenfassung' };
function historyDetailsHtml(d) {
  const u = d.usage || {};
  const facts = [
    d.provider && `${esc(d.provider)} / ${esc(d.model || '–')}`,
    u.inputTokens || u.outputTokens ? `${fmtK((u.inputTokens || 0) + (u.outputTokens || 0))} Tokens` : '',
    u.priced ? fmtUsd(u.usd || 0) : u.local ? 'Lokal' : '',
    d.lookups != null ? `${d.lookups} Nachschlage-Abfragen` : '',
    d.privacyMode ? 'strenger Datenschutz' : '',
    d.skippedByBudget ? `${d.skippedByBudget} Dateien wegen Budget übersprungen` : '',
  ].filter(Boolean).map((x) => '<span>' + x + '</span>').join(' · ');
  const r = d.repro;
  const repro = r ? `<h4>Protokoll für Reproduzierbarkeit</h4>
    <p class="muted small"><span>${r.calls} KI-Aufruf(e)</span> · <span>Prompt-Version ${esc(r.promptVersion || '–')}</span> · <span>${r.integrity && r.integrity.ok ? 'Prüfsummen stimmen' : 'Prüfsummen weichen ab: ' + esc((r.integrity && r.integrity.bad || []).join(', '))}</span>${r.truncated ? ' · <span>Prompts teilweise nur als Prüfsumme (Größenlimit)</span>' : ''}</p>
    <div class="repro-list">${(r.entries || []).slice(0, 200).map((e) => `<details class="repro-item"><summary><b>#${e.n}</b> <span>${esc(REPRO_KIND[e.kind] || e.kind)}</span> · ${esc(e.model || '')} · T=${esc(String(e.params && e.params.temperature != null ? e.params.temperature : '–'))} · max ${esc(String((e.params && e.params.maxTokens) || '–'))} <code title="SHA-256 des Prompts">${esc(String(e.promptSha256).slice(0, 12))}</code> → <code title="SHA-256 der Antwort">${esc(String(e.responseSha256).slice(0, 12))}</code></summary>
      <p class="muted small">Prompt-SHA-256: <code>${esc(e.promptSha256)}</code><br>Antwort-SHA-256: <code>${esc(e.responseSha256)}</code></p>
      ${e.prompt ? `<pre class="repro-pre">${esc([e.prompt.system, e.prompt.prefix, e.prompt.user].filter(Boolean).join('\n\n').slice(0, 20000))}</pre><h4>Antwort</h4><pre class="repro-pre">${esc(String(e.response || '').slice(0, 8000))}</pre>` : '<p class="muted small">Nur Prüfsummen gespeichert.</p>'}
    </details>`).join('')}</div>` : '<p class="muted small">Kein Reproduzierbarkeits-Protokoll (in den Einstellungen unter „Belastbarkeit &amp; Datenschutz“ einschaltbar).</p>';
  return `${facts ? `<p class="small">${facts}</p>` : ''}${d.runSummary && d.runSummary.text ? `<p>${esc(d.runSummary.text)}</p>` : ''}${repro}`;
}
