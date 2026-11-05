'use strict';

// Grosse Projekte: Dateien nach Sicherheits-Relevanz ordnen, damit die KI innerhalb des
// Budgets zuerst die riskantesten Dateien sieht. Heuristik aus Pfad (Routen, Controller,
// Auth, Upload …), Einstiegspunkten und Code-Signalen (Request-Eingaben, Shell, SQL, eval,
// Krypto); Tests, Doku, Minifiziertes und Generiertes rutschen nach hinten.
// Optional: lokale Embeddings ueber Ollama (nichts verlaesst den Rechner).

const PATH_HOT = [
  [/(^|\/)(routes?|controllers?|handlers?|endpoints?|api|views?|resolvers?|webhooks?|middlewares?)(\/|\.|$)/i, 14],
  [/(auth|login|logout|session|token|oauth|sso|password|passwort|signup|register|permission|acl|rbac|admin)/i, 12],
  [/(upload|download|file|export|import|payment|checkout|billing|invoice|order|cart)/i, 9],
  [/(db|database|query|sql|repository|model|dao|orm)/i, 6],
  [/(crypto|cipher|encrypt|hash|sign|jwt|secret|key)/i, 8],
  [/(config|settings|\.env|docker|compose|k8s|helm|terraform|nginx|apache|web\.config)/i, 5],
  [/(ipc|preload|electron|main)/i, 5],
];
const ENTRY = /(^|\/)(index|main|app|server|wsgi|asgi|manage|program|startup|bootstrap|urls|router)\.[a-z]+$/i;
const PATH_COLD = [
  [/(^|\/)(tests?|__tests__|spec|specs|e2e|fixtures?|mocks?|__mocks__|examples?|samples?|demo|docs?|documentation)(\/|$)/i, -16],
  [/\.(test|spec)\.[a-z]+$/i, -16],
  [/\.min\.(js|css)$|(^|\/)(dist|build|out|vendor|third_party|node_modules|coverage)\//i, -20],
  [/\.(d\.ts|css|scss|less|svg|md|txt|lock|map)$/i, -10],
  [/(generated|\.g\.|\.pb\.|_pb2)/i, -12],
];
const CODE_SIGNALS = [
  [/\b(req|request)\.(body|query|params|headers|cookies|files)\b|\$_(GET|POST|REQUEST|COOKIE|FILES)\b|request\.(args|form|json|GET|POST)\b|@RequestParam|\[FromBody\]/g, 3, 12],
  [/\b(?:app|router)\.(?:get|post|put|patch|delete|all|use)\s*\(|@(?:app|bp|router)\.(?:route|get|post)|@(?:Get|Post|Put|Delete|Request)Mapping|ipcMain\.handle|createServer\s*\(/g, 3, 12],
  [/\b(exec|execSync|spawn|execFile|system|popen|subprocess\.\w+|Runtime\.getRuntime|shell_exec|passthru)\s*\(/g, 4, 12],
  [/\b(eval|Function|setTimeout\s*\(\s*['"`]|vm\.run\w*|pickle\.loads|yaml\.load|unserialize|ObjectInputStream|Marshal\.load)\b/g, 4, 12],
  [/\b(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}\b(FROM|INTO|SET|WHERE)\b|\.query\s*\(|\.raw\s*\(|executeQuery|cursor\.execute/gi, 2, 10],
  [/\b(innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write|v-html|\|\s*safe\b|mark_safe|render_template_string)\b/g, 3, 9],
  [/\b(createCipher\w*|createHash|md5|sha1|Math\.random|jwt\.(sign|verify|decode)|bcrypt|crypto\.)\b/g, 2, 8],
  [/\b(fs\.(read|write|unlink|createReadStream)\w*|open\s*\(|readFile|sendFile|path\.join|res\.download)\b/g, 1, 6],
  [/\b(fetch|axios|http\.request|requests\.(get|post)|urllib|HttpClient|redirect)\b/g, 1, 6],
  [/\b(password|secret|api[_-]?key|token|private[_-]?key)\b/gi, 1, 6],
];

function scoreUnit(u, keywords = []) {
  const p = String(u.label || u.path || '').replace(/\\/g, '/');
  const c = String(u.content || '').slice(0, 200000);
  let s = 0;
  const why = [];
  for (const [re, w] of PATH_HOT) if (re.test(p)) { s += w; why.push('path'); }
  if (ENTRY.test(p)) { s += 8; why.push('entry'); }
  for (const [re, w] of PATH_COLD) if (re.test(p)) s += w;
  for (const [re, per, cap] of CODE_SIGNALS) {
    const n = (c.match(re) || []).length;
    if (n) { s += Math.min(cap, n * per); why.push('code'); }
  }
  for (const k of keywords) if (k && (p.toLowerCase().includes(k) || c.toLowerCase().includes(k))) { s += 6; why.push('focus'); }
  // Manifeste und Konfig sind fuer Abhaengigkeiten/Fehlkonfiguration wichtig, aber kurz
  if (u.kind === 'manifest' || /(^|\/)(package\.json|requirements\.txt|pom\.xml|go\.mod|Cargo\.toml|Gemfile|composer\.json|Dockerfile)$/i.test(p)) s += 6;
  // sehr kleine Dateien enthalten selten Logik
  if (c.length < 200) s -= 4;
  return { score: s, why: [...new Set(why)] };
}

// Schluesselwoerter aus der eigenen Schwerpunkt-Vorgabe (ownfocus) ziehen
function focusKeywords(text) {
  return [...new Set(String(text || '').toLowerCase().match(/[a-zäöüß][\w-]{3,}/g) || [])]
    .filter((w) => !/^(bitte|achte|besonders|auf|alle|eine|einen|dass|wenn|oder|und|with|that|this|please|focus|check|especially|also|code|datei|dateien|files?)$/.test(w))
    .slice(0, 20);
}

// Units absteigend nach Relevanz; stabile Reihenfolge bei Gleichstand.
// embedScores (optional): Map label -> 0..1 (Aehnlichkeit zu sicherheitsrelevantem Code)
function rankUnits(units, { keywords = [], embedScores = null } = {}) {
  return units
    .map((u, i) => {
      const r = scoreUnit(u, keywords);
      const e = embedScores && embedScores.get(u.label);
      return { u, i, score: r.score + (e != null ? Math.round(e * 20) : 0), why: r.why };
    })
    .sort((a, b) => b.score - a.score || a.i - b.i);
}

// Auswahl innerhalb des Budgets: maxFiles (0 = alle) bzw. maxChars (0 = alle)
function selectByBudget(ranked, { maxFiles = 0, maxChars = 0 } = {}) {
  const keep = [], skipped = [];
  let chars = 0;
  for (const r of ranked) {
    const len = String(r.u.content || '').length;
    if ((maxFiles && keep.length >= maxFiles) || (maxChars && keep.length && chars + len > maxChars)) { skipped.push(r.u); continue; }
    keep.push(r.u); chars += len;
  }
  return { keep, skipped };
}

// --- Optionale lokale Embeddings (Ollama /api/embed) -----------------------
const QUERY = 'security sensitive code: authentication, authorization checks, user input from HTTP requests reaching SQL queries, shell commands, file paths, HTML output, deserialization, cryptography, secrets';
const isLocalUrl = (s) => { try { const h = new URL(s).hostname.replace(/^\[|\]$/g, ''); return h === 'localhost' || h === '127.0.0.1' || h === '::1'; } catch { return false; } };
const cosine = (a, b) => { let d = 0, x = 0, y = 0; for (let i = 0; i < a.length; i++) { d += a[i] * b[i]; x += a[i] * a[i]; y += b[i] * b[i]; } return x && y ? d / Math.sqrt(x * y) : 0; };
async function embedScores(units, { baseUrl = 'http://localhost:11434', model, signal, fetchImpl = fetch, max = 400 } = {}) {
  if (!model || !isLocalUrl(baseUrl)) return null; // nur lokal – Code geht nicht nach aussen
  const base = baseUrl.replace(/\/$/, '');
  const post = async (input) => {
    const r = await fetchImpl(`${base}/api/embed`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model, input }), signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(60000)]) : AbortSignal.timeout(60000) });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return (await r.json()).embeddings || [];
  };
  try {
    const [q] = await post([QUERY]);
    if (!q) return null;
    const list = units.slice(0, max);
    const out = new Map();
    for (let i = 0; i < list.length; i += 16) {
      const chunk = list.slice(i, i + 16);
      const vecs = await post(chunk.map((u) => `${u.label}\n${String(u.content || '').slice(0, 2000)}`));
      chunk.forEach((u, k) => { if (vecs[k]) out.set(u.label, Math.max(0, cosine(q, vecs[k]))); });
    }
    // auf 0..1 strecken
    const vals = [...out.values()];
    const lo = Math.min(...vals), hi = Math.max(...vals);
    if (hi > lo) for (const [k, v] of out) out.set(k, (v - lo) / (hi - lo));
    return out;
  } catch { return null; }
}

module.exports = { scoreUnit, rankUnits, selectByBudget, focusKeywords, embedScores };
