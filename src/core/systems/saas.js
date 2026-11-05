'use strict';

// Online-Konten ueber die offiziellen APIs mit vom Nutzer hinterlegten Tokens – nur lesende GET-Abrufe
// (einzige Ausnahme: OAuth-Token-Abruf fuer Microsoft 365 / Google Workspace):
//  - cicd:    GitHub, GitLab, Azure DevOps (Branch-Schutz, Secret-Scanning, 2FA, Deploy-Keys, Token-Rechte)
//  - m365:    Microsoft 365 (Graph) und Google Workspace (Admin SDK)
//  - hosting: Cloudflare, Hetzner Cloud, DigitalOcean, Vercel, Netlify
//  - hibp:    Have I Been Pwned – Datenlecks der eigenen, dort verifizierten Domain

const crypto = require('crypto');
const { mk, http, list, riskyPortIn, openToWorld, RISKY } = require('./common');

const enc = encodeURIComponent;
const SECRET_KEY = /SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|CREDENTIAL|_KEY$/i;
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|EXPO_PUBLIC_|GATSBY_)/;

// --- GitHub ----------------------------------------------------------------------------
const BROAD_GH = ['admin:org', 'delete_repo', 'admin:enterprise', 'admin:repo_hook', 'admin:org_hook', 'site_admin'];
function parseGithub({ scopes = null, org = null, no2fa = null, repos = [] }) {
  const out = [];
  const add = (o) => out.push(mk('cicd', { category: 'AccessControl', ...o }));
  const broad = (scopes || []).filter((s) => BROAD_GH.includes(s));
  if (broad.length) add({ ruleId: 'cicd-token-broad', severity: 'medium', category: 'Secrets', location: 'GitHub-Token', title: `GitHub-Token mit sehr weiten Rechten: ${broad.join(', ')}`, description: 'Gelangt dieses Token in falsche Hände, lassen sich Repositorys löschen oder die Organisation verwalten.', remediation: 'Ein Fine-grained-Token nur mit Leserechten für die Prüfung anlegen und das alte widerrufen.' });
  if (org && org.two_factor_requirement_enabled === false) add({ ruleId: 'cicd-org-no-2fa-required', severity: 'high', category: 'Auth', location: `github.com/${org.login}`, title: `GitHub-Organisation verlangt keine Zwei-Faktor-Anmeldung: ${org.login}`, description: 'Mitglieder dürfen sich nur mit Passwort anmelden. Ein abgefischtes Passwort genügt für Zugriff auf alle Repositorys.', remediation: 'Organisation → Settings → Authentication security → „Require two-factor authentication“ einschalten.' });
  if (no2fa && no2fa.length) add({ ruleId: 'cicd-members-no-2fa', severity: 'high', category: 'Auth', location: `github.com/${org && org.login}`, title: `${no2fa.length} Mitglieder ohne Zwei-Faktor-Anmeldung (GitHub)`, description: `Betroffen: ${list(no2fa)}.`, remediation: 'Die Mitglieder bitten, 2FA einzurichten, und danach 2FA für die Organisation erzwingen.' });
  for (const r of repos) {
    const loc = `github.com/${r.full_name}`;
    if (r.protected === false) add({ ruleId: 'cicd-no-branch-protection', severity: 'medium', location: loc, title: `Hauptzweig ohne Schutz: ${r.full_name} (${r.default_branch})`, description: 'Jeder mit Schreibrechten kann direkt auf den Hauptzweig pushen oder dessen Verlauf überschreiben – ohne Review und ohne Prüfungen.', remediation: 'Settings → Rules/Branches → für den Hauptzweig Pull-Requests mit Review verlangen und Force-Push verbieten.' });
    const sa = r.security_and_analysis;
    if (sa && sa.secret_scanning && sa.secret_scanning.status === 'disabled') add({ ruleId: 'cicd-no-secret-scanning', severity: r.private ? 'low' : 'medium', category: 'Secrets', location: loc, title: `Secret-Scanning ist aus: ${r.full_name}`, description: 'GitHub warnt nicht, wenn Zugangsdaten in den Code gelangen.', remediation: 'Settings → Code security → Secret scanning einschalten.' });
    if (sa && sa.secret_scanning_push_protection && sa.secret_scanning_push_protection.status === 'disabled') add({ ruleId: 'cicd-no-push-protection', severity: 'low', category: 'Secrets', location: loc, title: `Push-Schutz für Secrets ist aus: ${r.full_name}`, description: 'Pushes mit erkannten Zugangsdaten werden nicht blockiert.', remediation: 'Settings → Code security → Push protection einschalten.' });
    const wk = (r.keys || []).filter((k) => k.read_only === false).map((k) => k.title);
    if (wk.length) add({ ruleId: 'cicd-deploy-key-write', severity: 'medium', category: 'Secrets', location: loc, title: `Deploy-Key mit Schreibrecht: ${r.full_name}`, description: `Schlüssel: ${list(wk, 5)}. Wer den privaten Schlüssel hat, kann Code ändern – unabhängig von Benutzerkonten und 2FA.`, remediation: 'Deploy-Keys nur lesend anlegen, wenn kein Push nötig ist; ungenutzte Schlüssel löschen.' });
  }
  return out;
}

async function auditGithub(s, { signal, fetchImpl }) {
  const h = { Authorization: `Bearer ${s.githubToken}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  const get = (p) => http(`https://api.github.com${p}`, { headers: h, signal, fetchImpl });
  const me = await get('/user');
  if (!me.ok) return { error: `GitHub: Anmeldung fehlgeschlagen (HTTP ${me.status || me.error})` };
  const sc = me.header('x-oauth-scopes');
  const scopes = sc == null ? null : sc.split(',').map((x) => x.trim()).filter(Boolean);
  const orgName = String(s.githubOrg || '').trim();
  let org = null, no2fa = null;
  const notes = [];
  if (orgName && /^[\w.-]{1,39}$/.test(orgName)) {
    const o = await get(`/orgs/${enc(orgName)}`);
    if (o.ok) org = o.data;
    const m = await get(`/orgs/${enc(orgName)}/members?filter=2fa_disabled&per_page=100`);
    if (m.ok && Array.isArray(m.data)) no2fa = m.data.map((x) => x.login);
    else notes.push('GitHub: Mitglieder ohne 2FA nur für Organisations-Besitzer lesbar.');
  }
  const rl = await get(org ? `/orgs/${enc(orgName)}/repos?per_page=100&type=all` : '/user/repos?affiliation=owner&per_page=100');
  const repos = [];
  for (const r of (Array.isArray(rl.data) ? rl.data : []).filter((x) => !x.archived && !x.fork).slice(0, 50)) {
    const full = String(r.full_name || '');
    if (!/^[\w.-]+\/[\w.-]+$/.test(full)) continue;
    const det = await get(`/repos/${full}`);
    const rr = { full_name: full, default_branch: r.default_branch, private: r.private, security_and_analysis: (det.data || {}).security_and_analysis };
    const pr = await get(`/repos/${full}/branches/${enc(r.default_branch)}/protection`);
    const rules = await get(`/repos/${full}/rules/branches/${enc(r.default_branch)}`);
    if (pr.ok || (rules.ok && Array.isArray(rules.data) && rules.data.length)) rr.protected = true;
    else if (pr.status === 404) rr.protected = false;
    const k = await get(`/repos/${full}/keys`);
    if (k.ok && Array.isArray(k.data)) rr.keys = k.data;
    repos.push(rr);
  }
  notes.push(org ? `GitHub geprüft (${repos.length} Repositorys, Organisation ${org.login}).` : `GitHub geprüft (${repos.length} Repositorys).`);
  return { findings: parseGithub({ scopes, org, no2fa, repos }), notes };
}

// --- GitLab ----------------------------------------------------------------------------
function parseGitlab({ token = null, group = null, projects = [] }) {
  const out = [];
  const add = (o) => out.push(mk('cicd', { category: 'AccessControl', ...o }));
  const broad = ((token && token.scopes) || []).filter((x) => ['api', 'sudo', 'admin_mode', 'write_repository'].includes(x));
  if (broad.length) add({ ruleId: 'cicd-token-broad', severity: broad.includes('sudo') || broad.includes('admin_mode') ? 'high' : 'medium', category: 'Secrets', location: 'GitLab-Token', title: `GitLab-Token mit weiten Rechten: ${broad.join(', ')}`, description: 'Mit diesem Token lässt sich deutlich mehr als nur lesen – bis hin zum Ändern von Projekten und Einstellungen.', remediation: 'Für die Prüfung ein Token nur mit read_api anlegen und das alte widerrufen.' });
  if (token && !token.expires_at) add({ ruleId: 'cicd-token-no-expiry', severity: 'low', category: 'Secrets', location: 'GitLab-Token', title: 'GitLab-Token ohne Ablaufdatum', description: 'Ein Token ohne Ablauf bleibt gültig, bis jemand daran denkt, es zu widerrufen.', remediation: 'Tokens mit Ablaufdatum (höchstens ein Jahr) erstellen.' });
  if (group && group.require_two_factor_authentication === false) add({ ruleId: 'cicd-org-no-2fa-required', severity: 'high', category: 'Auth', location: `gitlab:${group.full_path}`, title: `GitLab-Gruppe verlangt keine Zwei-Faktor-Anmeldung: ${group.full_path}`, description: 'Mitglieder können sich nur mit Passwort anmelden.', remediation: 'Gruppe → Einstellungen → Allgemein → Berechtigungen → „Alle Benutzer dieser Gruppe müssen 2FA einrichten“.' });
  for (const p of projects) {
    const loc = `gitlab:${p.path_with_namespace}`;
    if (p.protected === false) add({ ruleId: 'cicd-no-branch-protection', severity: 'medium', location: loc, title: `Hauptzweig ohne Schutz: ${p.path_with_namespace} (${p.default_branch})`, description: 'Jeder Entwickler kann direkt auf den Hauptzweig pushen oder dessen Verlauf überschreiben.', remediation: 'Einstellungen → Repository → Geschützte Branches → Hauptzweig schützen, Push nur über Merge-Requests.' });
    const wk = (p.keys || []).filter((k) => k.can_push).map((k) => k.title);
    if (wk.length) add({ ruleId: 'cicd-deploy-key-write', severity: 'medium', category: 'Secrets', location: loc, title: `Deploy-Key mit Schreibrecht: ${p.path_with_namespace}`, description: `Schlüssel: ${list(wk, 5)}. Wer den privaten Schlüssel hat, kann Code ändern.`, remediation: 'Schreibrecht des Deploy-Keys entfernen, wenn kein Push nötig ist.' });
    if (p.pre_receive_secret_detection_enabled === false) add({ ruleId: 'cicd-no-push-protection', severity: 'low', category: 'Secrets', location: loc, title: `Push-Schutz für Secrets ist aus: ${p.path_with_namespace}`, description: 'Pushes mit erkannten Zugangsdaten werden nicht blockiert.', remediation: 'Einstellungen → Sicherheit → Secret Push Protection einschalten.' });
  }
  return out;
}

async function auditGitlab(s, { signal, fetchImpl }) {
  let base;
  try { base = new URL(String(s.gitlabUrl || 'https://gitlab.com').trim()); } catch { return { error: 'GitLab: ungültige Server-Adresse.' }; }
  if (base.protocol !== 'https:') return { error: 'GitLab: Server-Adresse muss mit https:// beginnen.' };
  const api = `${base.origin}/api/v4`;
  const get = (p) => http(api + p, { headers: { 'PRIVATE-TOKEN': s.gitlabToken }, signal, fetchImpl });
  const tok = await get('/personal_access_tokens/self');
  const me = tok.ok ? tok : await get('/user');
  if (!me.ok) return { error: `GitLab: Anmeldung fehlgeschlagen (HTTP ${me.status || me.error})` };
  const gpath = String(s.gitlabGroup || '').trim();
  let group = null;
  if (gpath && /^[\w./-]{1,255}$/.test(gpath)) { const g = await get(`/groups/${enc(gpath)}`); if (g.ok) group = g.data; }
  const pl = await get(group ? `/groups/${group.id}/projects?include_subgroups=true&archived=false&per_page=100` : '/projects?owned=true&archived=false&per_page=100');
  const projects = [];
  for (const p of (Array.isArray(pl.data) ? pl.data : []).slice(0, 50)) {
    if (!Number.isInteger(p.id)) continue;
    const pb = await get(`/projects/${p.id}/protected_branches`);
    const keys = await get(`/projects/${p.id}/deploy_keys`);
    projects.push({ path_with_namespace: p.path_with_namespace, default_branch: p.default_branch, pre_receive_secret_detection_enabled: p.pre_receive_secret_detection_enabled, protected: pb.ok && Array.isArray(pb.data) ? pb.data.some((b) => b.name === p.default_branch || (b.name.includes('*') && new RegExp('^' + b.name.split('*').map((x) => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$').test(p.default_branch))) : undefined, keys: keys.ok ? keys.data : [] });
  }
  return { findings: parseGitlab({ token: tok.ok ? tok.data : null, group, projects }), notes: [`GitLab geprüft (${projects.length} Projekte).`] };
}

// --- Azure DevOps ----------------------------------------------------------------------
const ADO_POLICY_REVIEWERS = 'fa4e907d-c16b-4a4c-9dfa-4906e5d171dd';
function parseAdo({ org, repos = [], policies = [] }) {
  const out = [];
  for (const r of repos) {
    if (!r.defaultBranch || r.isDisabled) continue;
    const covered = policies.some((p) => p.isEnabled && p.isBlocking && p.type && p.type.id === ADO_POLICY_REVIEWERS && ((p.settings || {}).scope || []).some((sc) => (!sc.repositoryId || sc.repositoryId === r.id) && (!sc.refName || sc.refName === r.defaultBranch || (sc.matchKind === 'Prefix' && r.defaultBranch.startsWith(sc.refName)))));
    if (!covered) out.push(mk('cicd', { ruleId: 'cicd-no-branch-protection', severity: 'medium', category: 'AccessControl', location: `dev.azure.com/${org}/${r.project}/${r.name}`, title: `Hauptzweig ohne Review-Pflicht: ${r.project}/${r.name}`, description: 'Für den Hauptzweig gibt es keine verbindliche Richtlinie mit Mindestanzahl an Prüfern. Änderungen landen ohne zweites Augenpaar im Code.', remediation: 'Repos → Branches → Hauptzweig → Branch policies → „Require a minimum number of reviewers“ einschalten.' }));
  }
  return out;
}
async function auditAdo(s, { signal, fetchImpl }) {
  const org = String(s.adoOrg || '').trim();
  if (!/^[\w.-]{1,50}$/.test(org)) return { error: 'Azure DevOps: ungültiger Organisationsname.' };
  const h = { Authorization: 'Basic ' + Buffer.from(':' + s.adoToken).toString('base64') };
  const get = (p) => http(`https://dev.azure.com/${enc(org)}${p}`, { headers: h, signal, fetchImpl });
  const pr = await get('/_apis/projects?api-version=7.1&$top=100');
  if (!pr.ok || !pr.data) return { error: `Azure DevOps: Anmeldung fehlgeschlagen (HTTP ${pr.status || pr.error})` };
  const repos = [], policies = [];
  for (const p of (pr.data.value || []).slice(0, 20)) {
    const rs = await get(`/${enc(p.name)}/_apis/git/repositories?api-version=7.1`);
    for (const r of (rs.data && rs.data.value) || []) repos.push({ ...r, project: p.name });
    const pc = await get(`/${enc(p.name)}/_apis/policy/configurations?api-version=7.1`);
    policies.push(...((pc.data && pc.data.value) || []));
  }
  return { findings: parseAdo({ org, repos, policies }), notes: [`Azure DevOps geprüft (${repos.length} Repositorys).`, 'Azure DevOps: 2FA wird über Microsoft Entra geregelt und ist hier nicht lesbar.'] };
}

async function auditCicd({ signal, say, settings: s = {}, fetchImpl }) {
  const parts = [['GitHub', s.githubToken, auditGithub], ['GitLab', s.gitlabToken, auditGitlab], ['Azure DevOps', s.adoToken && s.adoOrg, auditAdo]].filter((p) => p[1]);
  if (!parts.length) return { findings: [], notes: ['CI/CD-Prüfung übersprungen: kein GitHub-, GitLab- oder Azure-DevOps-Token hinterlegt.'] };
  const findings = [], notes = [];
  let ok = true;
  for (const [name, , fn] of parts) {
    say(`${name}: Branch-Schutz, Secret-Scanning, 2FA, Deploy-Keys (nur lesend) …`);
    const r = await fn(s, { signal, fetchImpl });
    if (r.error) { ok = false; notes.push(r.error); continue; }
    findings.push(...r.findings); notes.push(...r.notes);
  }
  return { findings, notes, ok };
}

// --- Microsoft 365 / Google Workspace ------------------------------------------------------
function parseM365({ secDefaults = null, caPolicies = [], regs = null, sharing = null }) {
  const out = [];
  const add = (o) => out.push(mk('m365', { category: 'Auth', location: 'Microsoft 365', ...o }));
  const active = caPolicies.filter((p) => p.state === 'enabled');
  const ctl = (p) => ((p.grantControls || {}).builtInControls || []);
  const mfaAll = active.some((p) => ctl(p).includes('mfa') && ((((p.conditions || {}).users || {}).includeUsers) || []).includes('All'));
  const legacyBlock = active.some((p) => ctl(p).includes('block') && (((p.conditions || {}).clientAppTypes) || []).some((x) => x === 'exchangeActiveSync' || x === 'other'));
  const sd = secDefaults && secDefaults.isEnabled === true;
  if (secDefaults && !sd && !mfaAll) add({ ruleId: 'm365-no-mfa-policy', severity: 'high', title: 'Keine Pflicht zur Mehrfaktor-Anmeldung für alle (Microsoft 365)', description: 'Weder Sicherheitsstandards noch eine Richtlinie für bedingten Zugriff verlangen MFA für alle Benutzer. Ein abgefischtes Passwort genügt für den Zugriff auf Postfach und Dateien.', remediation: 'Entra ID → Sicherheit → bedingter Zugriff → Richtlinie „MFA für alle Benutzer“ anlegen oder die Sicherheitsstandards einschalten.' });
  if (secDefaults && !sd && !legacyBlock) add({ ruleId: 'm365-legacy-auth', severity: 'high', title: 'Veraltete Anmeldeverfahren sind nicht blockiert (Microsoft 365)', description: 'Alte Protokolle (IMAP, POP, SMTP-Auth, ActiveSync mit Basic Auth) umgehen MFA. Passwort-Sprühangriffe nutzen genau diesen Weg.', remediation: 'Richtlinie für bedingten Zugriff: Client-Apps „Exchange ActiveSync“ und „Andere Clients“ blockieren.' });
  const users = (regs || []).filter((u) => u.isMfaRegistered === false && u.userType !== 'guest' && u.accountEnabled !== false);
  if (users.length) add({ ruleId: 'm365-users-no-mfa', severity: 'high', title: `${users.length} Benutzer ohne eingerichtete Mehrfaktor-Anmeldung (Microsoft 365)`, description: `Betroffen: ${list(users.map((u) => u.userPrincipalName))}.`, remediation: 'Benutzer zur MFA-Registrierung auffordern (Microsoft Authenticator) und per Richtlinie erzwingen.' });
  if (sharing && sharing.sharingCapability === 'externalUserAndGuestSharing') add({ ruleId: 'm365-anyone-links', severity: 'medium', category: 'AccessControl', location: 'SharePoint / OneDrive', title: 'Freigabe-Links für „Jeder“ ohne Anmeldung erlaubt (SharePoint/OneDrive)', description: 'Dateien können über Links geteilt werden, die jeder ohne Anmeldung öffnen kann – weitergeleitete Links landen schnell bei Fremden.', remediation: 'SharePoint Admin Center → Richtlinien → Freigabe → höchstens „Neue und vorhandene Gäste“ erlauben.' });
  return out;
}
function parseGws({ users = [] }) {
  const out = [];
  const act = users.filter((u) => !u.suspended && !u.archived);
  const no2sv = act.filter((u) => u.isEnrolledIn2Sv === false).map((u) => u.primaryEmail);
  if (no2sv.length) out.push(mk('m365', { ruleId: 'gws-users-no-2sv', severity: 'high', category: 'Auth', location: 'Google Workspace', title: `${no2sv.length} Benutzer ohne Bestätigung in zwei Schritten (Google Workspace)`, description: `Betroffen: ${list(no2sv)}.`, remediation: 'Admin-Konsole → Sicherheit → Bestätigung in zwei Schritten erzwingen und Benutzer zur Einrichtung auffordern.' }));
  if (act.length && !act.some((u) => u.isEnforcedIn2Sv)) out.push(mk('m365', { ruleId: 'gws-2sv-not-enforced', severity: 'medium', category: 'Auth', location: 'Google Workspace', title: 'Bestätigung in zwei Schritten wird nicht erzwungen (Google Workspace)', description: 'Benutzer dürfen sich weiterhin nur mit Passwort anmelden.', remediation: 'Admin-Konsole → Sicherheit → Authentifizierung → Bestätigung in zwei Schritten → „Erzwingen“ einschalten.' }));
  return out;
}

function googleJwt(sa, subject, scope, now = Math.floor(Date.now() / 1000)) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const body = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ iss: sa.client_email, sub: subject, scope, aud: sa.token_uri || 'https://oauth2.googleapis.com/token', iat: now, exp: now + 600 })}`;
  return `${body}.${crypto.createSign('RSA-SHA256').update(body).sign(sa.private_key).toString('base64url')}`;
}

async function auditM365({ signal, say, settings: s = {}, fetchImpl }) {
  const findings = [], notes = [];
  let ran = false, ok = true;
  const form = (o) => Object.entries(o).map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&');
  if (s.m365Tenant && s.m365ClientId && s.m365Secret) {
    ran = true;
    say('Microsoft 365: MFA, veraltete Anmeldung, externe Freigaben (nur lesend) …');
    const tenant = String(s.m365Tenant).trim();
    if (!/^[\w.-]{3,100}$/.test(tenant)) { ok = false; notes.push('Microsoft 365: ungültige Tenant-ID.'); }
    else {
      const t = await http(`https://login.microsoftonline.com/${enc(tenant)}/oauth2/v2.0/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ client_id: s.m365ClientId, client_secret: s.m365Secret, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }), signal, fetchImpl });
      const tok = t.data && t.data.access_token;
      if (!tok) { ok = false; notes.push(`Microsoft 365: Anmeldung der App fehlgeschlagen (HTTP ${t.status || t.error}).`); }
      else {
        const g = (p) => http(`https://graph.microsoft.com/v1.0${p}`, { headers: { Authorization: `Bearer ${tok}` }, signal, fetchImpl });
        const sd = await g('/policies/identitySecurityDefaultsEnforcementPolicy');
        const ca = await g('/identity/conditionalAccess/policies');
        const rg = await g('/reports/authenticationMethods/userRegistrationDetails?$top=999');
        const sh = await g('/admin/sharepoint/settings');
        for (const [n, r, perm] of [['Sicherheitsstandards', sd, 'Policy.Read.All'], ['bedingter Zugriff', ca, 'Policy.Read.All'], ['MFA-Registrierung', rg, 'AuditLog.Read.All'], ['SharePoint-Freigaben', sh, 'SharePointTenantSettings.Read.All']]) if (!r.ok) { ok = false; notes.push(`Microsoft 365: ${n} nicht lesbar (Berechtigung ${perm} fehlt?).`); }
        findings.push(...parseM365({ secDefaults: sd.ok ? sd.data : null, caPolicies: ca.ok ? ca.data.value || [] : [], regs: rg.ok ? rg.data.value || [] : null, sharing: sh.ok ? sh.data : null }));
        notes.push('Microsoft 365 geprüft.');
      }
    }
  }
  if (s.gwsServiceAccount && s.gwsAdmin) {
    ran = true;
    say('Google Workspace: Bestätigung in zwei Schritten (nur lesend) …');
    let sa = null;
    try { sa = JSON.parse(s.gwsServiceAccount); } catch { /* ungueltig */ }
    if (!sa || !sa.client_email || !sa.private_key || !/^https:\/\/oauth2\.googleapis\.com\/token$/.test(sa.token_uri || 'https://oauth2.googleapis.com/token')) { ok = false; notes.push('Google Workspace: Dienstkonto-Schlüssel (JSON) ist ungültig.'); }
    else {
      let assertion = null;
      try { assertion = googleJwt(sa, String(s.gwsAdmin).trim(), 'https://www.googleapis.com/auth/admin.directory.user.readonly'); } catch { /* falscher Schluessel */ }
      const t = assertion ? await http('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }), signal, fetchImpl }) : { status: 0, error: 'Schlüssel nicht lesbar' };
      const tok = t.data && t.data.access_token;
      if (!tok) { ok = false; notes.push(`Google Workspace: Anmeldung fehlgeschlagen (HTTP ${t.status || t.error}). Domainweite Delegierung eingerichtet?`); }
      else {
        const u = await http('https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic', { headers: { Authorization: `Bearer ${tok}` }, signal, fetchImpl });
        if (!u.ok) { ok = false; notes.push(`Google Workspace: Benutzer nicht lesbar (HTTP ${u.status}).`); }
        else { findings.push(...parseGws({ users: (u.data && u.data.users) || [] })); notes.push('Google Workspace geprüft.', 'Google Workspace: Freigabe-Einstellungen sind über die Admin-SDK nicht lesbar – bitte in der Admin-Konsole prüfen.'); }
      }
    }
  }
  if (!ran) return { findings: [], notes: ['Microsoft-365-/Google-Workspace-Prüfung übersprungen: keine App-Zugangsdaten hinterlegt.'] };
  return { findings, notes, ok };
}

// --- Hosting-Anbieter ------------------------------------------------------------------------
function parseHosting({ cloudflare = null, hetzner = null, digitalocean = null, vercel = null, netlify = null }) {
  const out = [];
  const add = (o) => out.push(mk('hosting', { ...o }));
  const fwHit = (prov, name, port) => add({ ruleId: 'cloud-firewall-open', severity: 'high', category: 'AccessControl', location: `${prov}: ${name}`, title: `${RISKY[port]}-Port ${port} in „${name}“ für das ganze Internet offen (${prov})`, description: 'Die Firewall-Regel nimmt Verbindungen von jeder Adresse an. Solche Ports werden ständig automatisiert angegriffen.', remediation: 'Quelle auf feste Adressen oder ein VPN beschränken.' });
  const envCheck = (prov, project, envs) => {
    for (const e of envs) {
      const key = String(e.key || '');
      if (!SECRET_KEY.test(key)) continue;
      if (PUBLIC_PREFIX.test(key)) add({ ruleId: 'hosting-secret-public-env', severity: 'high', category: 'Secrets', location: `${prov}: ${project}`, title: `Geheimnis in öffentlicher Variable: ${key} (${project})`, description: 'Variablen mit diesem Präfix werden in den Browser-Code eingebaut und sind für jeden Besucher lesbar.', remediation: 'Den Wert nur serverseitig verwenden (Präfix entfernen), den Schlüssel austauschen.' });
      else if (e.plain) add({ ruleId: 'hosting-secret-plain-env', severity: 'medium', category: 'Secrets', location: `${prov}: ${project}`, title: `Geheimnis als unverschlüsselte Variable gespeichert: ${key} (${project})`, description: 'Die Variable ist nicht als geheim markiert und für alle Teammitglieder und Integrationen im Klartext sichtbar.', remediation: 'Als „Sensitive“ bzw. „Secret“ speichern und den Wert austauschen.' });
    }
  };
  if (cloudflare) {
    if (cloudflare.user && cloudflare.user.two_factor_authentication_enabled === false) add({ ruleId: 'hosting-no-2fa', severity: 'high', category: 'Auth', location: 'Cloudflare-Konto', title: 'Cloudflare-Konto ohne Zwei-Faktor-Anmeldung', description: 'Wer das Passwort hat, kann DNS umleiten und damit Webseite und E-Mails übernehmen.', remediation: 'Cloudflare → Profil → Authentifizierung → Zwei-Faktor-Authentifizierung einrichten.' });
    for (const z of cloudflare.zones || []) {
      if (z.ssl === 'off' || z.ssl === 'flexible') add({ ruleId: 'cf-ssl-weak', severity: z.ssl === 'off' ? 'high' : 'medium', category: 'Transport', location: `Cloudflare: ${z.name}`, title: `SSL-Modus „${z.ssl}“ für ${z.name}`, description: z.ssl === 'off' ? 'Die Seite ist nur unverschlüsselt erreichbar.' : 'Zwischen Cloudflare und dem eigenen Server geht der Verkehr unverschlüsselt – Besucher sehen trotzdem ein Schloss.', remediation: 'SSL/TLS → Übersicht → „Full (strict)“ wählen und auf dem Server ein gültiges Zertifikat (z. B. Origin-Zertifikat) einrichten.' });
      if (z.alwaysHttps === 'off') add({ ruleId: 'cf-no-always-https', severity: 'low', category: 'Transport', location: `Cloudflare: ${z.name}`, title: `„Immer HTTPS verwenden“ ist aus für ${z.name}`, description: 'Besucher können die Seite weiterhin unverschlüsselt aufrufen.', remediation: 'SSL/TLS → Edge-Zertifikate → „Immer HTTPS verwenden“ einschalten.' });
      if (z.minTls && ['1.0', '1.1'].includes(z.minTls)) add({ ruleId: 'cf-old-tls', severity: 'low', category: 'Transport', location: `Cloudflare: ${z.name}`, title: `Veraltetes TLS ${z.minTls} erlaubt für ${z.name}`, description: 'TLS 1.0 und 1.1 gelten als unsicher.', remediation: 'SSL/TLS → Edge-Zertifikate → minimale TLS-Version 1.2.' });
    }
  }
  if (hetzner) {
    const protectedIds = new Set();
    for (const f of hetzner.firewalls || []) {
      for (const a of f.applied_to || []) if (a.server) protectedIds.add(a.server.id);
      for (const r of f.rules || []) { if (r.direction !== 'in' || !openToWorld(r.source_ips)) continue; const p = riskyPortIn(r.port); if (p && r.protocol !== 'icmp') { fwHit('Hetzner', f.name, p); break; } }
    }
    for (const s of hetzner.servers || []) if (s.public_net && s.public_net.ipv4 && !(s.public_net.firewalls || []).length && !protectedIds.has(s.id)) add({ ruleId: 'hosting-server-no-firewall', severity: 'medium', category: 'AccessControl', location: `Hetzner: ${s.name}`, title: `Server ohne Cloud-Firewall: ${s.name} (Hetzner)`, description: 'Alle Dienste des Servers sind direkt aus dem Internet erreichbar, sofern das Betriebssystem sie nicht selbst abschirmt.', remediation: 'Eine Hetzner-Firewall anlegen, nur benötigte Ports freigeben und dem Server zuweisen.' });
  }
  if (digitalocean) {
    const covered = new Set();
    for (const f of digitalocean.firewalls || []) {
      for (const id of f.droplet_ids || []) covered.add(id);
      for (const r of f.inbound_rules || []) { if (!openToWorld((r.sources || {}).addresses)) continue; const p = riskyPortIn(r.ports); if (p && r.protocol !== 'icmp') { fwHit('DigitalOcean', f.name, p); break; } }
    }
    for (const d of digitalocean.droplets || []) if (!covered.has(d.id) && !(d.tags || []).some((t) => (digitalocean.firewalls || []).some((f) => (f.tags || []).includes(t)))) add({ ruleId: 'hosting-server-no-firewall', severity: 'medium', category: 'AccessControl', location: `DigitalOcean: ${d.name}`, title: `Droplet ohne Cloud-Firewall: ${d.name} (DigitalOcean)`, description: 'Alle Dienste des Droplets sind direkt aus dem Internet erreichbar, sofern das Betriebssystem sie nicht selbst abschirmt.', remediation: 'Networking → Firewalls → Firewall anlegen und dem Droplet zuweisen.' });
    for (const db of digitalocean.databases || []) if (Array.isArray(db.rules) && !db.rules.length) add({ ruleId: 'hosting-db-public', severity: 'high', category: 'AccessControl', location: `DigitalOcean: ${db.name}`, title: `Datenbank ohne vertrauenswürdige Quellen: ${db.name} (DigitalOcean)`, description: 'Ohne „Trusted Sources“ nimmt die verwaltete Datenbank Verbindungen von jeder Adresse im Internet an.', remediation: 'Datenbank → Settings → Trusted sources → nur eigene Droplets bzw. Adressen eintragen.' });
  }
  if (vercel) for (const p of vercel.projects || []) {
    envCheck('Vercel', p.name, (p.env || []).map((e) => ({ key: e.key, plain: e.type === 'plain' })));
    if (p.ssoProtection == null && p.passwordProtection == null) add({ ruleId: 'hosting-preview-public', severity: 'low', category: 'AccessControl', location: `Vercel: ${p.name}`, title: `Vorschau-Versionen sind öffentlich: ${p.name} (Vercel)`, description: 'Jede Vorschau eines Branches ist ohne Anmeldung erreichbar – oft mit unfertigem Code, Test-Daten oder Debug-Ausgaben.', remediation: 'Project → Settings → Deployment Protection → Vercel Authentication für Vorschauen einschalten.' });
  }
  if (netlify) for (const s of netlify.sites || []) {
    envCheck('Netlify', s.name, (s.env || []).map((e) => ({ key: e.key, plain: e.is_secret === false })));
    if (s.ssl_url && s.force_ssl === false) add({ ruleId: 'hosting-no-force-https', severity: 'low', category: 'Transport', location: `Netlify: ${s.name}`, title: `HTTPS wird nicht erzwungen: ${s.name} (Netlify)`, description: 'Die Seite ist zusätzlich unverschlüsselt erreichbar.', remediation: 'Domain management → HTTPS → „Force HTTPS“ einschalten.' });
  }
  return out;
}

async function auditHosting({ signal, say, settings: s = {}, fetchImpl }) {
  const data = {}, notes = [];
  let ok = true;
  const bearer = (t) => ({ Authorization: `Bearer ${t}` });
  const fail = (n, r) => { ok = false; notes.push(`${n}: Abruf fehlgeschlagen (HTTP ${r.status || r.error}).`); };
  const idOk = (x) => /^[\w-]{1,80}$/.test(String(x));
  if (s.cloudflareToken) {
    say('Cloudflare: Konto und Zonen (nur lesend) …');
    const g = (p) => http(`https://api.cloudflare.com/client/v4${p}`, { headers: bearer(s.cloudflareToken), signal, fetchImpl });
    const zr = await g('/zones?per_page=50');
    if (!zr.ok) fail('Cloudflare', zr);
    else {
      const u = await g('/user');
      const zones = [];
      for (const z of ((zr.data && zr.data.result) || []).filter((x) => idOk(x.id)).slice(0, 20)) {
        const val = async (k) => { const r = await g(`/zones/${z.id}/settings/${k}`); return r.ok && r.data && r.data.result ? r.data.result.value : null; };
        zones.push({ name: z.name, ssl: await val('ssl'), alwaysHttps: await val('always_use_https'), minTls: await val('min_tls_version') });
      }
      data.cloudflare = { user: u.ok && u.data ? u.data.result : null, zones };
      notes.push(`Cloudflare geprüft (${zones.length} Zonen).`);
    }
  }
  if (s.hetznerToken) {
    say('Hetzner Cloud: Firewalls und Server (nur lesend) …');
    const g = (p) => http(`https://api.hetzner.cloud/v1${p}`, { headers: bearer(s.hetznerToken), signal, fetchImpl });
    const [f, sv] = [await g('/firewalls?per_page=50'), await g('/servers?per_page=50')];
    if (!f.ok || !sv.ok) fail('Hetzner', f.ok ? sv : f);
    else { data.hetzner = { firewalls: f.data.firewalls || [], servers: sv.data.servers || [] }; notes.push(`Hetzner Cloud geprüft (${data.hetzner.servers.length} Server).`); }
  }
  if (s.digitaloceanToken) {
    say('DigitalOcean: Firewalls, Droplets, Datenbanken (nur lesend) …');
    const g = (p) => http(`https://api.digitalocean.com/v2${p}`, { headers: bearer(s.digitaloceanToken), signal, fetchImpl });
    const [f, d, dbs] = [await g('/firewalls?per_page=200'), await g('/droplets?per_page=200'), await g('/databases')];
    if (!f.ok || !d.ok) fail('DigitalOcean', f.ok ? d : f);
    else {
      const databases = [];
      for (const db of ((dbs.data && dbs.data.databases) || []).filter((x) => /^[\w-]{1,80}$/.test(x.id)).slice(0, 20)) { const r = await g(`/databases/${db.id}/firewall`); databases.push({ name: db.name, rules: r.ok && r.data ? r.data.rules || [] : null }); }
      data.digitalocean = { firewalls: f.data.firewalls || [], droplets: d.data.droplets || [], databases };
      notes.push(`DigitalOcean geprüft (${data.digitalocean.droplets.length} Droplets).`);
    }
  }
  if (s.vercelToken) {
    say('Vercel: Projekte und Umgebungsvariablen (nur Namen, nur lesend) …');
    const g = (p) => http(`https://api.vercel.com${p}`, { headers: bearer(s.vercelToken), signal, fetchImpl });
    const pr = await g('/v9/projects?limit=50');
    if (!pr.ok) fail('Vercel', pr);
    else {
      const projects = [];
      for (const p of ((pr.data && pr.data.projects) || []).filter((x) => idOk(x.id)).slice(0, 30)) { const e = await g(`/v9/projects/${p.id}/env`); projects.push({ name: p.name, ssoProtection: p.ssoProtection, passwordProtection: p.passwordProtection, env: e.ok && e.data ? e.data.envs || [] : [] }); }
      data.vercel = { projects };
      notes.push(`Vercel geprüft (${projects.length} Projekte).`);
    }
  }
  if (s.netlifyToken) {
    say('Netlify: Seiten und Umgebungsvariablen (nur Namen, nur lesend) …');
    const g = (p) => http(`https://api.netlify.com/api/v1${p}`, { headers: bearer(s.netlifyToken), signal, fetchImpl });
    const st = await g('/sites?per_page=50');
    if (!st.ok) fail('Netlify', st);
    else {
      const sites = [];
      for (const x of (Array.isArray(st.data) ? st.data : []).filter((y) => idOk(y.id) && idOk(y.account_id)).slice(0, 30)) { const e = await g(`/accounts/${x.account_id}/env?site_id=${x.id}`); sites.push({ name: x.name, ssl_url: x.ssl_url, force_ssl: x.force_ssl, env: e.ok && Array.isArray(e.data) ? e.data : [] }); }
      data.netlify = { sites };
      notes.push(`Netlify geprüft (${sites.length} Seiten).`);
    }
  }
  if (!Object.keys(data).length && ok) return { findings: [], notes: ['Hosting-Prüfung übersprungen: kein Token für Cloudflare, Hetzner, DigitalOcean, Vercel oder Netlify hinterlegt.'] };
  return { findings: parseHosting(data), notes, ok };
}

// --- Have I Been Pwned -----------------------------------------------------------------------
function parseHibp(domain, byAlias = {}, catalog = []) {
  const per = {};
  for (const [alias, breaches] of Object.entries(byAlias || {})) for (const b of breaches || []) (per[b] = per[b] || []).push(alias);
  const meta = new Map((catalog || []).map((b) => [b.Name, b]));
  return Object.entries(per).sort((a, b) => b[1].length - a[1].length).slice(0, 25).map(([name, aliases]) => {
    const m = meta.get(name) || {};
    const pw = (m.DataClasses || []).includes('Passwords');
    const year = String(m.BreachDate || '').slice(0, 4);
    return mk('hibp', { ruleId: 'hibp-domain-breach', severity: pw ? 'high' : 'medium', category: 'Secrets', location: `${domain}: ${name}`, title: year ? `${aliases.length} Adressen von ${domain} im Datenleck „${m.Title || name}“ (${year})` : `${aliases.length} Adressen von ${domain} im Datenleck „${m.Title || name}“`, description: pw ? `Mit den Adressen wurden auch Passwörter erbeutet. Betroffen: ${list(aliases.map((a) => `${a}@${domain}`), 8)}.` : `Erbeutet wurden u. a. E-Mail-Adressen. Betroffen: ${list(aliases.map((a) => `${a}@${domain}`), 8)}.`, remediation: 'Betroffene informieren, Passwörter überall ändern lassen, wo sie wiederverwendet wurden, und Mehrfaktor-Anmeldung einschalten. Mit Phishing unter Bezug auf das Leck rechnen.' });
  });
}

async function auditHibp({ signal, say, settings: s = {}, fetchImpl }) {
  const domain = String(s.hibpDomain || '').trim().toLowerCase();
  if (!s.hibpKey || !domain) return { findings: [], notes: ['HIBP-Prüfung übersprungen: kein API-Schlüssel oder keine Domain hinterlegt.'] };
  if (!/^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(domain)) return { findings: [], notes: ['HIBP-Prüfung übersprungen: ungültige Domain.'] };
  say(`Have I Been Pwned: Datenlecks für ${domain} …`);
  const r = await http(`https://haveibeenpwned.com/api/v3/breacheddomain/${enc(domain)}`, { headers: { 'hibp-api-key': s.hibpKey }, signal, fetchImpl });
  if (r.status === 404) return { findings: [], notes: [`HIBP: keine bekannten Datenlecks für ${domain}.`], ok: true };
  if (r.status === 401) return { findings: [], notes: ['HIBP-Prüfung fehlgeschlagen: API-Schlüssel ungültig.'] };
  if (r.status === 403) return { findings: [], notes: [`HIBP-Prüfung fehlgeschlagen: ${domain} ist im HIBP-Dashboard nicht als eigene Domain verifiziert.`] };
  if (!r.ok || !r.data) return { findings: [], notes: [`HIBP-Prüfung fehlgeschlagen (HTTP ${r.status || r.error}).`] };
  const cat = await http('https://haveibeenpwned.com/api/v3/breaches', { signal, fetchImpl });
  const findings = parseHibp(domain, r.data, cat.ok && Array.isArray(cat.data) ? cat.data : []);
  return { findings, notes: [`HIBP: ${findings.length} Datenlecks für ${domain}.`], ok: true };
}

module.exports = { parseGithub, auditGithub, parseGitlab, parseAdo, auditCicd, parseM365, parseGws, googleJwt, auditM365, parseHosting, auditHosting, parseHibp, auditHibp };
