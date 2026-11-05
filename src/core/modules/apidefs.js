'use strict';

// API-Beschreibungen und -Server: OpenAPI/Swagger-Dateien (Operationen ohne Absicherung, fehlende
// Grenzen, Geheimnisse in Query-Parametern) und GraphQL-Server-Konfiguration (Introspection,
// fehlende Tiefen-/Komplexitaetsgrenze). Rein statisch.

const { parseYaml } = require('../miniyaml');
const { base, mk, isText } = require('./rulekit');

const M = 'api-spec-audit';
const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'];
const WRITE = new Set(['put', 'post', 'delete', 'patch']);
const SECRET_PARAM = /^(access[_-]?token|token|auth|api[_-]?key|apikey|key|secret|client[_-]?secret|password|passwd|pwd|session[_-]?id|sid|jwt|bearer)$/i;
const isLocal = (url) => /^https?:\/\/(localhost|127\.|0\.0\.0\.0|\[::1\]|[\w-]+\.local\b|[\w.-]+\.test\b|\{)/i.test(url);

function loadSpec(u) {
  const c = u.content || '';
  if (!/\.(ya?ml|json)$/i.test(base(u))) return null;
  if (!/["']?(openapi|swagger)["']?\s*:\s*["']?[23]\./.test(c.slice(0, 4000))) return null;
  let doc = null;
  try { doc = /\.json$/i.test(base(u)) ? JSON.parse(c) : parseYaml(c); } catch { return null; }
  return doc && typeof doc === 'object' && doc.paths && typeof doc.paths === 'object' ? doc : null;
}

const at = (c, needle) => { const i = needle ? c.indexOf(needle) : -1; return i < 0 ? null : i; };

// Schema-Objekte ohne Grenzen zaehlen (Strings ohne maxLength/enum/format, Listen ohne maxItems)
function unboundedSchemas(doc) {
  const out = { strings: 0, arrays: 0, examples: [] };
  const seen = new Set();
  const walk = (s, where, depth) => {
    if (!s || typeof s !== 'object' || depth > 12 || seen.has(s)) return;
    seen.add(s);
    if (s.$ref && typeof s.$ref === 'string') {
      const m = s.$ref.match(/^#\/(components\/schemas|definitions)\/(.+)$/);
      const tgt = m && (m[1] === 'definitions' ? (doc.definitions || {})[m[2]] : ((doc.components || {}).schemas || {})[m[2]]);
      if (tgt) walk(tgt, m[2], depth + 1);
      return;
    }
    if (s.type === 'string' && s.maxLength == null && !s.enum && !s.format && !s.pattern && s.const == null) { out.strings++; if (out.examples.length < 3) out.examples.push(where); }
    if (s.type === 'array' && s.maxItems == null) { out.arrays++; if (out.examples.length < 3) out.examples.push(where); }
    for (const k of ['properties', 'patternProperties']) if (s[k] && typeof s[k] === 'object') for (const [n, v] of Object.entries(s[k])) walk(v, n, depth + 1);
    if (s.items) walk(s.items, where, depth + 1);
    for (const k of ['allOf', 'anyOf', 'oneOf']) if (Array.isArray(s[k])) s[k].forEach((x) => walk(x, where, depth + 1));
  };
  for (const [p, item] of Object.entries(doc.paths || {})) {
    if (!item || typeof item !== 'object') continue;
    for (const meth of METHODS) {
      const op = item[meth];
      if (!op || typeof op !== 'object') continue;
      for (const prm of [...(item.parameters || []), ...(op.parameters || [])]) if (prm && typeof prm === 'object') walk(prm.schema || (prm.type ? prm : null), prm.name || p, 0);
      const rb = op.requestBody && op.requestBody.content;
      if (rb && typeof rb === 'object') for (const v of Object.values(rb)) walk(v && v.schema, `${meth.toUpperCase()} ${p}`, 0);
    }
  }
  return out;
}

function openapi(u, out) {
  const doc = loadSpec(u);
  if (!doc) return;
  const c = u.content || '';
  const schemes = { ...((doc.components || {}).securitySchemes || {}), ...(doc.securityDefinitions || {}) };
  const globalSec = Array.isArray(doc.security) && doc.security.some((s) => s && Object.keys(s).length);
  const open = [];
  let total = 0;
  const qsecret = [];
  for (const [p, item] of Object.entries(doc.paths || {})) {
    if (!item || typeof item !== 'object') continue;
    for (const meth of METHODS) {
      const op = item[meth];
      if (!op || typeof op !== 'object') continue;
      total++;
      const sec = Array.isArray(op.security) ? op.security.some((s) => s && Object.keys(s).length) : globalSec;
      if (!sec) open.push({ meth, p });
      for (const prm of [...(item.parameters || []), ...(op.parameters || [])]) {
        if (prm && prm.in === 'query' && SECRET_PARAM.test(String(prm.name || ''))) qsecret.push(`${meth.toUpperCase()} ${p} ?${prm.name}`);
      }
    }
  }
  if (open.length) {
    const writes = open.filter((o) => WRITE.has(o.meth));
    const list = open.slice(0, 4).map((o) => `${o.meth.toUpperCase()} ${o.p}`).join(', ') + (open.length > 4 ? ' …' : '');
    out.push(mk(M, u, at(c, open[0].p), {
      ruleId: 'openapi-no-security', severity: writes.length ? 'high' : 'medium', category: 'Auth',
      title: `${open.length} von ${total} API-Operation(en) ohne Absicherung (OpenAPI)`,
      description: `Für diese Operationen ist weder global noch einzeln ein security-Eintrag gesetzt: ${list}. Laut Beschreibung sind sie ohne Anmeldung nutzbar${writes.length ? ' – darunter ändernde Aufrufe (POST/PUT/PATCH/DELETE)' : ''}.`,
      remediation: 'Ein globales security-Feld mit dem passenden Verfahren (z. B. bearerAuth) setzen und nur bewusst öffentliche Operationen mit security: [] ausnehmen; die Absicherung muss auch im Code umgesetzt sein.',
      evidence: list,
    }));
  }
  for (const [name, s] of Object.entries(schemes)) {
    if (!s || typeof s !== 'object') continue;
    if (s.type === 'apiKey' && s.in === 'query') out.push(mk(M, u, at(c, name), {
      ruleId: 'openapi-apikey-in-query', severity: 'medium', category: 'Secrets',
      title: `API-Schlüssel wird in der URL übertragen (${name})`,
      description: 'Das Verfahren erwartet den Schlüssel als Query-Parameter. URLs landen in Server-Logs, im Browserverlauf, in Proxys und im Referer-Header – der Schlüssel wird dadurch leicht weitergegeben.',
      remediation: 'Den Schlüssel im Header übertragen (in: header, z. B. X-API-Key oder Authorization).',
      evidence: `${name}: apiKey in query (${s.name || '?'})`,
    }));
    if ((s.type === 'http' && String(s.scheme || '').toLowerCase() === 'basic') || s.type === 'basic') out.push(mk(M, u, at(c, name), {
      ruleId: 'openapi-basic-auth', severity: 'low', category: 'Auth',
      title: `HTTP-Basic-Anmeldung in der API (${name})`,
      description: 'Bei Basic-Auth wird bei jeder Anfrage das Passwort mitgeschickt (nur Base64-kodiert). Es gibt keine Ablaufzeit und kein einfaches Sperren einzelner Sitzungen.',
      remediation: 'Kurzlebige Tokens (OAuth2/OIDC, signierte Bearer-Tokens) verwenden; Basic höchstens intern und nur über HTTPS.',
      evidence: `${name}: basic`,
    }));
  }
  if (qsecret.length) out.push(mk(M, u, at(c, qsecret[0].split('?')[1]), {
    ruleId: 'openapi-secret-in-query', severity: 'medium', category: 'Secrets',
    title: 'Geheime Werte als Query-Parameter (OpenAPI)',
    description: `Tokens oder Passwörter werden in der URL erwartet: ${qsecret.slice(0, 4).join(', ')}. URLs werden protokolliert und weitergegeben (Logs, Verlauf, Referer).`,
    remediation: 'Geheime Werte im Header oder im Body einer POST-Anfrage übertragen.',
    evidence: qsecret.slice(0, 4).join(', '),
  }));
  const ub = unboundedSchemas(doc);
  if (ub.strings + ub.arrays >= 3) out.push(mk(M, u, null, {
    ruleId: 'openapi-no-limits', severity: 'low', category: 'DoS',
    title: 'Eingaben ohne Längen- oder Mengengrenze (OpenAPI)',
    description: `${ub.strings} Text-Feld(er) ohne maxLength und ${ub.arrays} Liste(n) ohne maxItems, z. B. ${ub.examples.join(', ')}. Ohne Grenzen kann ein Aufruf riesige Datenmengen schicken und den Dienst ausbremsen; Validierung aus der Beschreibung greift dann nicht.`,
    remediation: 'maxLength für Texte, maxItems für Listen und maximum für Zahlen (z. B. limit/pageSize) festlegen und serverseitig prüfen lassen.',
  }));
  const servers = [...(Array.isArray(doc.servers) ? doc.servers.map((s) => s && s.url) : []), ...(Array.isArray(doc.schemes) && doc.schemes.includes('http') && doc.host ? [`http://${doc.host}`] : [])].filter((x) => typeof x === 'string');
  const plain = servers.find((x) => /^http:\/\//i.test(x) && !isLocal(x));
  if (plain) out.push(mk(M, u, at(c, plain), {
    ruleId: 'openapi-http-server', severity: 'low', category: 'Transport',
    title: `API-Server ohne HTTPS: ${plain}`,
    description: 'Die Beschreibung nennt eine unverschlüsselte Server-Adresse. Anmeldedaten und Antworten können unterwegs mitgelesen werden.',
    remediation: 'Nur https://-Adressen angeben und HTTP auf HTTPS umleiten.',
  }));
}

// --- GraphQL-Server ---------------------------------------------------------
const GQL_SERVER = /new\s+ApolloServer\s*\(|\bgraphqlHTTP\s*\(|\bcreateYoga\s*\(|GraphQLModule\.forRoot|\bmercurius\b|\bcreateHandler\s*\(\s*\{\s*schema|GraphQLView\.as_view|\bGraphQLRouter\s*\(|strawberry\.Schema\s*\(|graphene\.Schema\s*\(|\bAddGraphQLServer\s*\(/;
const DEPTH_LIMIT = /depthLimit|depth[-_]limit|maxDepth|max_depth|createComplexityLimitRule|queryComplexity|query[-_]complexity|costAnalysis|graphql-armor|QueryDepthLimiter|MaxTokensLimiter|AddMaxExecutionDepthRule|MaxExecutionDepth|max_query_depth|validation_rules|maxComplexity/i;

function graphql(units, out) {
  const all = units.filter(isText).filter((u) => /\.(m?[jt]sx?|cjs|py|cs)$/i.test(base(u)));
  const servers = all.filter((u) => GQL_SERVER.test(u.content));
  if (!servers.length) return;
  const limited = units.some((u) => isText(u) && DEPTH_LIMIT.test(u.content));
  for (const u of servers) {
    const c = u.content;
    const i = c.search(GQL_SERVER);
    if (!limited) out.push(mk(M, u, i, {
      ruleId: 'graphql-no-depth-limit', severity: 'medium', category: 'DoS',
      title: 'GraphQL ohne Tiefen- oder Komplexitätsgrenze',
      description: 'Im Projekt ist keine Begrenzung der Abfragetiefe oder -komplexität zu finden. Eine einzelne, tief verschachtelte Abfrage kann den Server und die Datenbank stark belasten.',
      remediation: 'Eine Tiefengrenze (z. B. graphql-depth-limit mit 8–10 Ebenen) und eine Kostenbegrenzung als Validierungsregel einbauen.',
    }));
    const intro = c.search(/\bintrospection\s*:\s*true\b|\bgraphiql\s*[:=]\s*(true|True)\b|\bplayground\s*:\s*true\b/);
    if (intro >= 0) out.push(mk(M, u, intro, {
      ruleId: 'graphql-introspection-on', severity: 'medium', category: 'Config',
      title: 'GraphQL-Introspection bzw. GraphiQL fest eingeschaltet',
      description: 'Die API liefert ihre komplette Struktur aus bzw. bietet eine Abfrage-Oberfläche an – unabhängig von der Umgebung, also auch in Produktion. Angreifer finden so interne Felder und Mutationen.',
      remediation: 'Introspection und GraphiQL nur in der Entwicklung aktivieren: introspection: process.env.NODE_ENV !== "production".',
    }));
  }
}

function runApiDefs(units) {
  const out = [];
  for (const u of units) if (isText(u)) openapi(u, out);
  graphql(units, out);
  return out;
}

module.exports = { runApiDefs };
