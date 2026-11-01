'use strict';

// Laufzeit-Validierung (Zod) fuer alles, was von aussen kommt: Eingaben aus UI/REST-API
// und die JSON-Ausgaben externer Scanner. Ungueltiges wird abgewiesen statt weiterverarbeitet.

const { z } = require('zod');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const FINDING_STATUSES = ['OPEN', 'IN_PROGRESS', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'RESOLVED'];
const TARGET_TYPES = ['path', 'url', 'endpoint', 'image'];

// Einheitliches Befund-Format (Vigil-Schreibweise der Spec "UnifiedFinding").
const UnifiedFindingSchema = z.object({
  source: z.string().min(1),
  ruleId: z.string().min(1).max(200),
  title: z.string().min(1).max(200),
  severity: z.enum(SEVERITIES),
  cvss: z.number().min(0).max(10).nullable(),
  category: z.string().min(1),
  location: z.string().max(300),
  description: z.string(),
  remediation: z.string(),
  evidence: z.string().max(500).optional(),
}).passthrough();

// Container-Image-Referenz, z. B. nginx:1.25, ghcr.io/org/app:2.1, app@sha256:…
const IMAGE_RE = /^(?:[a-z0-9.-]+(?::\d+)?\/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[\w][\w.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/;

const TargetSchema = z.object({
  type: z.enum(TARGET_TYPES),
  value: z.string().trim().min(1).max(2048),
  authorized: z.boolean().optional(),
}).superRefine((t, ctx) => {
  if (/[\0\r\n]/.test(t.value)) ctx.addIssue({ code: 'custom', message: 'Steuerzeichen sind nicht erlaubt.' });
  if (t.type === 'url' && !/^https?:\/\/[^\s/]+/i.test(t.value)) ctx.addIssue({ code: 'custom', message: 'Webadresse muss mit http:// oder https:// beginnen.' });
  if (t.type === 'image' && !IMAGE_RE.test(t.value)) ctx.addIssue({ code: 'custom', message: 'Ungültige Container-Image-Referenz.' });
  if (t.type === 'endpoint' && !/^[\w.\-:[\]]+$/.test(t.value)) ctx.addIssue({ code: 'custom', message: 'Ungültiger Hostname bzw. IP-Adresse.' });
});

const ScanRequestSchema = z.object({
  targets: z.array(TargetSchema).min(1).max(50),
  providerId: z.enum(['ollama', 'anthropic', 'openai', 'gemini', 'compat']).optional(),
});

const StatusUpdateSchema = z.object({ status: z.enum(FINDING_STATUSES), note: z.string().max(500).optional() });

// --- Rohausgaben externer Scanner (nur die Felder, die Vigil liest) --------
const TrivyOutputSchema = z.object({
  Results: z.array(z.object({
    Target: z.string().optional(),
    Vulnerabilities: z.array(z.object({ VulnerabilityID: z.string(), PkgName: z.string().optional(), InstalledVersion: z.string().optional(), FixedVersion: z.string().optional(), Severity: z.string().optional(), Title: z.string().optional(), Description: z.string().optional() }).passthrough()).nullish(),
    Misconfigurations: z.array(z.object({ ID: z.string().optional(), Title: z.string().optional(), Severity: z.string().optional() }).passthrough()).nullish(),
    Secrets: z.array(z.object({ RuleID: z.string().optional(), StartLine: z.number().optional(), Match: z.string().optional() }).passthrough()).nullish(),
  }).passthrough()).nullish(),
}).passthrough();

const SemgrepOutputSchema = z.object({
  results: z.array(z.object({ check_id: z.string(), path: z.string(), start: z.object({ line: z.number() }).partial().optional(), extra: z.object({}).passthrough().optional() }).passthrough()).default([]),
}).passthrough();

const GitleaksOutputSchema = z.array(z.object({ RuleID: z.string().optional(), File: z.string().optional(), StartLine: z.number().optional(), Secret: z.string().optional(), Match: z.string().optional(), Description: z.string().optional() }).passthrough());

// Ergebnis: { ok, data } oder { ok:false, error } mit lesbarer Meldung.
function check(schema, value) {
  const r = schema.safeParse(value);
  if (r.success) return { ok: true, data: r.data };
  return { ok: false, error: r.error.issues.map((i) => (i.path.length ? i.path.join('.') + ': ' : '') + i.message).join('; ') };
}

module.exports = {
  SEVERITIES, FINDING_STATUSES, TARGET_TYPES, IMAGE_RE,
  UnifiedFindingSchema, TargetSchema, ScanRequestSchema, StatusUpdateSchema,
  TrivyOutputSchema, SemgrepOutputSchema, GitleaksOutputSchema, check,
};
