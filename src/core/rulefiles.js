'use strict';

// Einfache Musterregeln aus YAML-/JSON-Dateien im Ordner rules/ laden (Zod-geprueft wie eigene Regeln).
//
//   rules:
//     - name: "Rails: html_safe"        # Anzeigename (auch fuer "Regel deaktivieren")
//       category: XSS                   # Kategorie wie bei Befunden
//       severity: medium                # critical | high | medium | low | info
//       regex: '\.html_safe\b'          # JavaScript-Regex (ohne Schraegstriche)
//       flags: g                        # optional, Standard "g" (erlaubt: g i m s u)
//       kind: pattern                   # pattern = Hinweis fuer die KI (Standard), finding = eigener Befund
//       description: "…"                # nur fuer kind: finding
//       remediation: "…"                # nur fuer kind: finding
//
// Ungueltige Dateien/Regeln werden uebersprungen und als Hinweis gemeldet.

const fs = require('fs');
const path = require('path');
const { z } = require('zod');
const { parseYaml } = require('./miniyaml');
const { CATEGORIES } = require('./schema');

const RULES_DIR = path.join(__dirname, '..', '..', 'rules');

const RuleSchema = z.object({
  name: z.string().trim().min(1).max(120),
  category: z.enum(CATEGORIES).default('Other'),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
  regex: z.string().min(1).max(500),
  flags: z.string().regex(/^[gimsu]*$/).max(6).optional(),
  kind: z.enum(['pattern', 'finding']).default('pattern'),
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{1,80}$/).optional(),
  description: z.string().max(1000).optional(),
  remediation: z.string().max(1000).optional(),
}).strict();
const FileSchema = z.object({ rules: z.array(z.unknown()).max(500) }).passthrough();

function parseFile(text, file) {
  return /\.json$/i.test(file) ? JSON.parse(text) : parseYaml(text);
}

// Liefert { patterns: [{cat,name,re,sev}], findings: [{...}], errors: [] }
function loadRuleFiles(dirs = [RULES_DIR]) {
  const patterns = [];
  const findings = [];
  const errors = [];
  for (const dir of dirs) {
    let files = [];
    try { files = fs.readdirSync(dir).filter((f) => /\.(ya?ml|json)$/i.test(f)).sort(); } catch { continue; }
    for (const f of files) {
      let doc;
      try { doc = parseFile(fs.readFileSync(path.join(dir, f), 'utf8'), f); } catch (e) { errors.push(`${f}: nicht lesbar (${e.message})`); continue; }
      const top = FileSchema.safeParse(doc);
      if (!top.success) { errors.push(`${f}: kein "rules:"-Eintrag`); continue; }
      top.data.rules.forEach((raw, i) => {
        const r = RuleSchema.safeParse(raw);
        if (!r.success) { errors.push(`${f} Regel ${i + 1}: ${r.error.issues.map((x) => (x.path.join('.') || 'Regel') + ' ' + x.message).join('; ')}`); return; }
        let flags = r.data.flags == null ? 'g' : r.data.flags;
        if (!flags.includes('g')) flags += 'g';
        let re;
        try { re = new RegExp(r.data.regex, flags); } catch (e) { errors.push(`${f} Regel ${i + 1}: ungültiger regulärer Ausdruck`); return; }
        const rule = { cat: r.data.category, name: r.data.name, re, sev: r.data.severity, file: f };
        if (r.data.kind === 'finding') findings.push({ ...rule, id: r.data.id, description: r.data.description, remediation: r.data.remediation });
        else patterns.push(rule);
      });
    }
  }
  return { patterns, findings, errors };
}

module.exports = { loadRuleFiles, RuleSchema, RULES_DIR };
