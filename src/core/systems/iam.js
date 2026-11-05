'use strict';

// Tiefere Cloud-Berechtigungspruefung ueber die vorhandenen CLIs (aws, az, gcloud) mit der Anmeldung
// des Nutzers – nur list/get/describe. Ungenutzte und alte Zugriffsschluessel, Platzhalter-Richtlinien,
// Nutzung des Haupt-Kontos und ob Audit-Protokolle laufen.

const { run, json, mk, daysSince, list } = require('./common');

const opt = { viaCmd: true };
const IAM_USER = /^[\w+=,.@-]{1,64}$/;
const POLICY_ARN = /^arn:aws[\w-]*:iam::\d{12}:policy\/[\w+=,.@/-]{1,512}$/;
const SA_EMAIL = /^[a-z0-9-]{6,30}@[a-z0-9-]{4,63}\.iam\.gserviceaccount\.com$/;
const GCP_PROJECT = /^[a-z][a-z0-9-]{4,61}[a-z0-9]$/;

function parseCredentialReport(csv) {
  const lines = String(csv || '').trim().split(/\r?\n/);
  const head = (lines.shift() || '').split(',');
  return lines.map((l) => { const v = l.split(','); return Object.fromEntries(head.map((h, i) => [h, v[i]])); });
}
const recent = (d, now, days) => { const n = d && !/N\/A|no_information|not_supported/.test(d) ? daysSince(d, now) : null; return n != null && n <= days; };

function parseAwsIam({ report = [], policies = [], trails = [], trailStatus = {} }, now = Date.now()) {
  const out = [];
  const add = (o) => out.push(mk('iam', { category: 'AccessControl', ...o }));
  for (const u of report) {
    if (u.user === '<root_account>') {
      if (recent(u.password_last_used, now, 90)) add({ ruleId: 'iam-root-used', severity: 'medium', location: 'AWS root', title: `AWS-Haupt-Konto (root) vor ${daysSince(u.password_last_used, now)} Tagen benutzt`, description: 'Das root-Konto sollte nur für seltene Kontoaufgaben dienen. Alltägliche Nutzung erhöht das Risiko, dass genau dieser allmächtige Zugang abhanden kommt.', remediation: 'Für die tägliche Arbeit IAM-Benutzer oder IAM Identity Center mit eingeschränkten Rollen verwenden.' });
      continue;
    }
    if (u.password_enabled === 'true' && u.mfa_active === 'false') add({ ruleId: 'iam-user-no-mfa', severity: 'high', category: 'Auth', location: `AWS IAM ${u.user}`, title: `IAM-Benutzer mit Passwort, aber ohne MFA: ${u.user}`, description: 'Ein erratenes oder abgefischtes Passwort genügt für die Anmeldung an der Konsole.', remediation: 'MFA für den Benutzer einrichten und per Richtlinie für alle erzwingen.' });
    for (const k of ['1', '2']) {
      if (u[`access_key_${k}_active`] !== 'true') continue;
      const used = u[`access_key_${k}_last_used_date`];
      const age = daysSince(u[`access_key_${k}_last_rotated`], now);
      if (!recent(used, now, 90) && age != null && age > 90) add({ ruleId: 'iam-key-unused', severity: 'medium', category: 'Secrets', location: `AWS IAM ${u.user}`, title: `Zugriffsschlüssel seit über 90 Tagen ungenutzt: ${u.user} (Schlüssel ${k})`, description: 'Ein aktiver, aber nicht genutzter Schlüssel ist reines Risiko – er kann irgendwo in Code oder Backups liegen.', remediation: 'Schlüssel deaktivieren und nach einer Wartezeit löschen.' });
      else if (age != null && age > 90) add({ ruleId: 'iam-key-old', severity: 'low', category: 'Secrets', location: `AWS IAM ${u.user}`, title: `Zugriffsschlüssel ${age} Tage alt: ${u.user} (Schlüssel ${k})`, description: 'Langlebige Schlüssel werden mit der Zeit an immer mehr Stellen kopiert.', remediation: 'Schlüssel regelmäßig erneuern oder besser auf Rollen mit kurzlebigen Zugangsdaten umstellen.' });
    }
  }
  for (const p of policies) {
    const st = [].concat(((p.document || {}).Statement) || []);
    if (st.some((s) => s.Effect === 'Allow' && [].concat(s.Action || []).includes('*') && [].concat(s.Resource || []).includes('*'))) add({ ruleId: 'iam-wildcard-policy', severity: 'high', location: p.arn, title: `IAM-Richtlinie erlaubt alles („*“ auf „*“): ${p.name}`, description: 'Wer diese Richtlinie hat, ist faktisch Administrator des ganzen Kontos.', remediation: 'Aktionen und Ressourcen auf das Nötige beschränken (IAM Access Analyzer hilft beim Erzeugen passender Richtlinien).' });
  }
  if (!trails.length) add({ ruleId: 'iam-no-audit-log', severity: 'high', category: 'Logging', location: 'AWS CloudTrail', title: 'Kein CloudTrail-Protokoll eingerichtet (AWS)', description: 'Ohne CloudTrail lässt sich nach einem Vorfall nicht nachvollziehen, wer was im Konto getan hat.', remediation: 'Einen Trail für alle Regionen anlegen, der in einen geschützten S3-Bucket schreibt.' });
  else {
    for (const t of trails) if (trailStatus[t.TrailARN] === false) add({ ruleId: 'iam-trail-stopped', severity: 'high', category: 'Logging', location: t.TrailARN, title: `CloudTrail-Protokoll ist angehalten: ${t.Name}`, description: 'Der Trail existiert, zeichnet aber nichts auf.', remediation: 'Protokollierung für den Trail wieder starten und Alarm bei StopLogging einrichten.' });
    if (!trails.some((t) => t.IsMultiRegionTrail)) add({ ruleId: 'iam-trail-not-multiregion', severity: 'low', category: 'Logging', location: 'AWS CloudTrail', title: 'Kein CloudTrail-Protokoll über alle Regionen', description: 'Aktivitäten in anderen Regionen werden nicht aufgezeichnet – ein beliebter Ort für unbemerkte Krypto-Mining-Server.', remediation: 'Den Trail auf „alle Regionen“ umstellen.' });
  }
  return out;
}

function parseAzureIam({ assignments = [], customRoles = [], diag = null }) {
  const out = [];
  const add = (o) => out.push(mk('iam', { category: 'AccessControl', ...o }));
  const owners = assignments.filter((a) => a.roleDefinitionName === 'Owner' && /^\/subscriptions\/[^/]+$/.test(a.scope || ''));
  const guests = owners.filter((a) => /#EXT#/i.test(a.principalName || ''));
  for (const g of guests) add({ ruleId: 'iam-guest-owner', severity: 'high', location: g.scope, title: `Gastkonto ist Besitzer des Abonnements: ${g.principalName}`, description: 'Ein externes Konto hat volle Rechte. Dessen Sicherheit liegt außerhalb deiner Kontrolle.', remediation: 'Rolle entfernen oder auf eine eingeschränkte Rolle mit Ablaufdatum (PIM) umstellen.' });
  if (owners.length > 3) add({ ruleId: 'iam-many-owners', severity: 'medium', location: 'Azure-Abonnement', title: `${owners.length} Besitzer (Owner) auf dem Azure-Abonnement`, description: `Besitzer: ${list(owners.map((o) => o.principalName || o.principalId), 6)}. Jeder davon kann alles ändern und Rechte weitergeben.`, remediation: 'Höchstens 2–3 Besitzer; sonst Contributor bzw. eng gefasste Rollen vergeben.' });
  for (const r of customRoles) if ((r.permissions || []).some((p) => (p.actions || []).includes('*'))) add({ ruleId: 'iam-wildcard-policy', severity: 'high', location: r.id || r.roleName, title: `Eigene Azure-Rolle erlaubt alle Aktionen: ${r.roleName}`, description: 'Die Rolle enthält die Aktion „*“ und ist damit so mächtig wie Owner.', remediation: 'Nur die benötigten Aktionen in die Rolle aufnehmen.' });
  if (Array.isArray(diag) && !diag.length) add({ ruleId: 'iam-no-audit-log', severity: 'medium', category: 'Logging', location: 'Azure-Aktivitätsprotokoll', title: 'Aktivitätsprotokoll wird nicht dauerhaft gespeichert (Azure)', description: 'Ohne Diagnoseeinstellung hält Azure das Aktivitätsprotokoll nur 90 Tage vor. Spät entdeckte Vorfälle lassen sich dann nicht mehr aufklären.', remediation: 'Abonnement → Aktivitätsprotokoll → Diagnoseeinstellungen → an Log Analytics oder ein Speicherkonto senden.' });
  return out;
}

function parseGcpIam({ policy = null, keys = [] }, now = Date.now()) {
  const out = [];
  const add = (o) => out.push(mk('iam', { category: 'AccessControl', ...o }));
  const bindings = (policy && policy.bindings) || [];
  const owners = (bindings.find((b) => b.role === 'roles/owner') || {}).members || [];
  if (owners.filter((m) => /^user:/.test(m)).length > 3) add({ ruleId: 'iam-many-owners', severity: 'medium', location: 'GCP-Projekt', title: `${owners.length} Besitzer (roles/owner) im Google-Cloud-Projekt`, description: `Besitzer: ${list(owners, 6)}.`, remediation: 'Besitzer-Rolle auf wenige Konten beschränken, sonst vordefinierte Rollen mit weniger Rechten nutzen.' });
  const saPriv = bindings.filter((b) => /^roles\/(owner|editor)$/.test(b.role)).flatMap((b) => (b.members || []).filter((m) => /^serviceAccount:/.test(m)).map((m) => `${m.slice(15)} (${b.role.slice(6)})`));
  if (saPriv.length) add({ ruleId: 'iam-sa-owner', severity: 'medium', location: 'GCP-Projekt', title: 'Dienstkonten mit Besitzer- oder Bearbeiterrechten', description: `${list(saPriv, 5)}. Ein abgeflossener Schlüssel eines solchen Kontos gibt fast vollen Zugriff auf das Projekt.`, remediation: 'Dienstkonten nur die Rollen geben, die die Anwendung braucht.' });
  const pub = bindings.filter((b) => (b.members || []).some((m) => /^all(Authenticated)?Users$/.test(m))).map((b) => b.role);
  if (pub.length) add({ ruleId: 'iam-public-binding', severity: 'critical', location: 'GCP-Projekt', title: 'Projekt-Rollen für alle im Internet freigegeben', description: `allUsers bzw. allAuthenticatedUsers haben: ${list(pub, 5)}.`, remediation: 'Öffentliche Mitglieder aus der Projekt-IAM-Richtlinie entfernen.' });
  if (policy && !(policy.auditConfigs || []).length) add({ ruleId: 'iam-no-data-access-logs', severity: 'low', category: 'Logging', location: 'GCP-Projekt', title: 'Datenzugriffs-Protokolle sind aus (Google Cloud)', description: 'Admin-Aktivitäten werden immer protokolliert, Lesezugriffe auf Daten aber nicht. Ein Datenabfluss bliebe unsichtbar.', remediation: 'IAM & Verwaltung → Audit-Logs → für wichtige Dienste „Datenlesevorgänge“ einschalten.' });
  for (const k of keys) {
    const age = daysSince(k.validAfterTime, now);
    if (age != null && age > 90) add({ ruleId: 'iam-key-old', severity: 'medium', category: 'Secrets', location: `GCP ${k.account}`, title: `Dienstkonto-Schlüssel ${age} Tage alt: ${k.account}`, description: 'Von Hand erzeugte Schlüssel laufen nie ab und liegen oft in Repos oder auf Laptops.', remediation: 'Schlüssel ersetzen bzw. löschen und auf Workload Identity oder kurzlebige Tokens umstellen.' });
  }
  return out;
}

async function auditIam({ signal, say, run: r = run }) {
  const findings = [], notes = [];
  let any = false, partial = false;
  const j = async (cmd, args, o = {}) => { const res = await r(cmd, args, { signal, ...opt, ...o }); return res.ok ? json(res.stdout) : null; };
  // AWS
  if ((await r('aws', ['sts', 'get-caller-identity', '--output', 'json'], { signal, ...opt })).ok) {
    any = true;
    say('IAM: AWS-Benutzer, Schlüssel, Richtlinien, CloudTrail …');
    const rep = await j('aws', ['iam', 'get-credential-report', '--output', 'json']);
    let report = [];
    if (rep && rep.Content) report = parseCredentialReport(Buffer.from(rep.Content, 'base64').toString('utf8'));
    else { partial = true; notes.push('AWS: kein Anmeldedaten-Bericht vorhanden – bitte einmal „aws iam generate-credential-report“ ausführen.'); }
    const pols = ((await j('aws', ['iam', 'list-policies', '--scope', 'Local', '--only-attached', '--output', 'json'])) || {}).Policies || [];
    const policies = [];
    for (const p of pols.filter((x) => POLICY_ARN.test(x.Arn) && /^v\d+$/.test(x.DefaultVersionId)).slice(0, 40)) {
      const v = await j('aws', ['iam', 'get-policy-version', '--policy-arn', p.Arn, '--version-id', p.DefaultVersionId, '--output', 'json']);
      let doc = v && v.PolicyVersion && v.PolicyVersion.Document;
      if (typeof doc === 'string') doc = json(decodeURIComponent(doc));
      if (doc) policies.push({ arn: p.Arn, name: p.PolicyName, document: doc });
    }
    const trails = ((await j('aws', ['cloudtrail', 'describe-trails', '--output', 'json'])) || {}).trailList;
    const trailStatus = {};
    for (const t of (trails || []).filter((x) => /^arn:aws[\w-]*:cloudtrail:[\w-]+:\d{12}:trail\/[\w.-]+$/.test(x.TrailARN || '')).slice(0, 10)) {
      const s = await j('aws', ['cloudtrail', 'get-trail-status', '--name', t.TrailARN, '--output', 'json']);
      if (s) trailStatus[t.TrailARN] = !!s.IsLogging;
    }
    if (!trails) { partial = true; notes.push('AWS: CloudTrail nicht lesbar.'); }
    findings.push(...parseAwsIam({ report: report.filter((u) => u.user === '<root_account>' || IAM_USER.test(u.user)), policies, trails: trails || [{ IsMultiRegionTrail: true }], trailStatus }));
    notes.push(`AWS-IAM geprüft (${report.length} Benutzer, ${policies.length} eigene Richtlinien).`);
  }
  // Azure
  if ((await r('az', ['account', 'show', '--output', 'json'], { signal, ...opt })).ok) {
    any = true;
    say('IAM: Azure-Rollen und Aktivitätsprotokoll …');
    const assignments = await j('az', ['role', 'assignment', 'list', '--all', '--output', 'json'], { timeoutMs: 120000 });
    const customRoles = await j('az', ['role', 'definition', 'list', '--custom-role-only', 'true', '--output', 'json']);
    const diagRaw = await j('az', ['monitor', 'diagnostic-settings', 'subscription', 'list', '--output', 'json']);
    const diag = diagRaw ? (Array.isArray(diagRaw) ? diagRaw : diagRaw.value || []) : null;
    if (!assignments) { partial = true; notes.push('Azure: Rollenzuweisungen nicht lesbar.'); }
    findings.push(...parseAzureIam({ assignments: assignments || [], customRoles: customRoles || [], diag }));
    notes.push(`Azure-IAM geprüft (${(assignments || []).length} Rollenzuweisungen).`);
  }
  // Google Cloud
  const proj = await r('gcloud', ['config', 'get-value', 'project'], { signal, ...opt });
  const project = proj.ok ? proj.stdout.trim() : '';
  if (GCP_PROJECT.test(project)) {
    any = true;
    say('IAM: Google-Cloud-Rollen, Dienstkonto-Schlüssel, Audit-Logs …');
    const policy = await j('gcloud', ['projects', 'get-iam-policy', project, '--format=json']);
    const sas = (await j('gcloud', ['iam', 'service-accounts', 'list', '--format=json'])) || [];
    const keys = [];
    for (const sa of sas.filter((s) => SA_EMAIL.test(s.email || '')).slice(0, 25)) {
      for (const k of (await j('gcloud', ['iam', 'service-accounts', 'keys', 'list', `--iam-account=${sa.email}`, '--managed-by=user', '--format=json'])) || []) keys.push({ account: sa.email, validAfterTime: k.validAfterTime });
    }
    if (!policy) { partial = true; notes.push('Google Cloud: IAM-Richtlinie nicht lesbar.'); }
    findings.push(...parseGcpIam({ policy, keys }));
    notes.push(`Google-Cloud-IAM geprüft (Projekt ${project}).`);
  }
  if (!any) return { findings: [], notes: ['IAM-Prüfung nicht ausgeführt: weder aws, az noch gcloud ist installiert und angemeldet.'] };
  return { findings, notes, ok: !partial };
}

module.exports = { parseCredentialReport, parseAwsIam, parseAzureIam, parseGcpIam, auditIam };
