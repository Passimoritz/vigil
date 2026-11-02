'use strict';

// Erreichbarkeit verwundbarer Pakete: Eine Luecke in einem Paket ist nur gefaehrlich, wenn
// der eigene Code das Paket (bzw. die betroffene Funktion) wirklich verwendet.
//
//  used            Paket wird im Code importiert
//  function-used   die laut Advisory betroffene Funktion wird aufgerufen
//  function-unused Paket wird genutzt, die betroffene Funktion aber nirgends aufgerufen
//  unused          direkte Abhaengigkeit, aber nirgends importiert (Altlast)
//  transitive      nur indirekt ueber ein anderes Paket enthalten
//  unknown         nicht sicher bestimmbar (keine Aenderung)
//
// Abwertung nur bei klaren Faellen; nie bei aktiv ausgenutzten Luecken (CISA-KEV).

const SEV_DOWN = { critical: 'high', high: 'medium', medium: 'low', low: 'low', info: 'info' };
const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const isTest = (u) => /(^|\/)(test|tests|__tests__|spec|e2e|fixtures?|mocks?)(\/|$)|\.(test|spec)\.[jt]sx?$/i.test(base(u));
const isCode = (u) => /\.(m?[jt]sx?|cjs|vue|svelte|py|go|rb|php|java|kt|cs|rs)$/i.test(base(u));

// Python: Paketname auf der Registry -> Modulname im Import
const PY_MODULE = { pyyaml: 'yaml', beautifulsoup4: 'bs4', pillow: 'pil', 'python-dateutil': 'dateutil', 'scikit-learn': 'sklearn', 'opencv-python': 'cv2', pyjwt: 'jwt', 'psycopg2-binary': 'psycopg2', 'python-jose': 'jose', pycryptodome: 'crypto', 'protobuf': 'google', 'msgpack-python': 'msgpack' };

function importsOf(units) {
  const npm = new Set(), py = new Set(), other = new Set();
  for (const u of units) {
    if (!isCode(u) || isTest(u)) continue;
    const c = u.content || '';
    for (const m of c.matchAll(/\brequire\(\s*['"]([^'"./][^'"]*)['"]\s*\)|\bfrom\s+['"]([^'"./][^'"]*)['"]|\bimport\s+['"]([^'"./][^'"]*)['"]|\bimport\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g)) {
      const spec = m[1] || m[2] || m[3] || m[4];
      const name = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0];
      npm.add(name.replace(/^node:/, '').toLowerCase());
    }
    if (/\.py$/i.test(base(u))) for (const m of c.matchAll(/^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+(?:\s*,\s*[\w.]+)*))/gm)) {
      for (const mod of (m[1] || m[2]).split(',')) py.add(mod.trim().split('.')[0].toLowerCase());
    }
    for (const m of c.matchAll(/^\s*(?:import|use)\s+["']?([\w./-]+)/gm)) other.add(m[1].toLowerCase());
  }
  return { npm, py, other };
}

// Ist das Paket eine direkte Abhaengigkeit (steht im Manifest des Projekts)?
function directDeps(units) {
  const npm = new Set(), py = new Set();
  for (const u of units) {
    const n = base(u).split('/').pop().toLowerCase();
    if (n === 'package.json' && !/node_modules/.test(base(u))) {
      try { const pj = JSON.parse(u.content || ''); for (const k of Object.keys({ ...(pj.dependencies || {}), ...(pj.devDependencies || {}), ...(pj.optionalDependencies || {}) })) npm.add(k.toLowerCase()); } catch { /* egal */ }
    }
    if (/^requirements.*\.txt$|^pyproject\.toml$|^pipfile$/.test(n)) for (const m of (u.content || '').matchAll(/^\s*["']?([A-Za-z0-9][\w.-]*)/gm)) py.add(m[1].toLowerCase());
  }
  return { npm, py };
}

const pyMod = (name) => PY_MODULE[name] || name.replace(/-/g, '_');

function symbolUsed(units, symbols) {
  const short = [...new Set(symbols.map((s) => String(s).split(/[.:#]/).pop()).filter((s) => s && s.length > 2))];
  if (!short.length) return null;
  const re = new RegExp(`\\b(${short.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})\\s*\\(`);
  return units.some((u) => isCode(u) && !isTest(u) && re.test(u.content || ''));
}

function reachOf(f, ctx) {
  const p = f.package;
  if (!p || !p.name) return null;
  const eco = String(p.ecosystem || '').toLowerCase();
  const name = p.name.toLowerCase();
  if (eco === 'npm') {
    const used = ctx.imports.npm.has(name);
    if (!used) return ctx.direct.npm.has(name) ? { status: 'unused' } : ctx.direct.npm.size ? { status: 'transitive' } : { status: 'unknown' };
    if (Array.isArray(f.vulnSymbols) && f.vulnSymbols.length) { const s = symbolUsed(ctx.units, f.vulnSymbols); if (s != null) return { status: s ? 'function-used' : 'function-unused' }; }
    return { status: 'used' };
  }
  if (eco === 'pypi') {
    const used = ctx.imports.py.has(pyMod(name));
    if (!used) return ctx.direct.py.has(name) ? (PY_MODULE[name] || !/[^a-z0-9_-]/.test(name) ? { status: 'unused' } : { status: 'unknown' }) : ctx.direct.py.size ? { status: 'transitive' } : { status: 'unknown' };
    if (Array.isArray(f.vulnSymbols) && f.vulnSymbols.length) { const s = symbolUsed(ctx.units, f.vulnSymbols); if (s != null) return { status: s ? 'function-used' : 'function-unused' }; }
    return { status: 'used' };
  }
  if (eco === 'go' && Array.isArray(f.vulnSymbols) && f.vulnSymbols.length) {
    const s = symbolUsed(ctx.units, f.vulnSymbols);
    if (s != null) return { status: s ? 'function-used' : 'function-unused' };
  }
  return { status: 'unknown' };
}

const NOTE = {
  used: 'Das Paket wird im eigenen Code verwendet.',
  'function-used': 'Die laut Hinweis betroffene Funktion wird im eigenen Code aufgerufen – die Lücke ist sehr wahrscheinlich erreichbar.',
  'function-unused': 'Das Paket wird verwendet, die betroffene Funktion aber nirgends aufgerufen. Das Risiko ist deshalb deutlich geringer – aktualisieren sollte man trotzdem.',
  unused: 'Das Paket steht in den Abhängigkeiten, wird im Code aber nirgends verwendet. Am einfachsten: das Paket entfernen.',
  transitive: 'Das Paket wird nicht direkt verwendet, sondern kommt über ein anderes Paket mit. Ob die Lücke erreichbar ist, hängt davon ab, wie dieses Paket es nutzt.',
};

function applyReachability(findings, units = []) {
  if (!units.some(isCode)) return findings;
  const ctx = { units, imports: importsOf(units), direct: directDeps(units) };
  return findings.map((f) => {
    if (f.category !== 'Dependencies' || !f.package) return f;
    const r = reachOf(f, ctx);
    if (!r || r.status === 'unknown') return f;
    const out = { ...f, reach: r.status, reachability: [NOTE[r.status], f.reachability].filter(Boolean).join(' ') };
    if (!f.inCisaKev && (r.status === 'unused' || r.status === 'function-unused')) {
      out.severity = SEV_DOWN[f.severity] || f.severity;
      if (out.contextualRiskScore != null) out.contextualRiskScore = Math.round(out.contextualRiskScore * 0.5 * 10) / 10;
    } else if (!f.inCisaKev && r.status === 'transitive' && out.contextualRiskScore != null) {
      out.contextualRiskScore = Math.round(out.contextualRiskScore * 0.8 * 10) / 10;
    } else if (r.status === 'function-used') {
      out.confidence = 'high';
      if (out.contextualRiskScore != null) out.contextualRiskScore = Math.min(100, Math.round(out.contextualRiskScore * 1.15 * 10) / 10);
    }
    return out;
  });
}

module.exports = { applyReachability, importsOf, directDeps, reachOf };
