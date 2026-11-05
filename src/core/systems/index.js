'use strict';

// Erweiterte System-Pruefungen (Zielart "system"). hostaudit.js ruft diese Tabelle fuer alle
// Arten auf, die es nicht selbst kennt. Jede Pruefung ist nur lesend und liefert
// { findings, notes, ok } – ok nur, wenn sie vollstaendig gelaufen ist (sonst keine "Behebung").

const local = require('./local');
const network = require('./network');
const remote = require('./remote');
const iam = require('./iam');
const saas = require('./saas');

const LABELS = {
  winapps: 'Installierte Programme',
  browserext: 'Browser-Erweiterungen',
  backup: 'Datensicherung (Windows)',
  macos: 'Dieser Mac',
  router: 'Router (Standard-Gateway)',
  lan: 'Geräte im lokalen Netz',
  linuxssh: 'Linux-Server (SSH)',
  dbdirect: 'Datenbanken',
  k8s: 'Kubernetes-Cluster (kubectl)',
  iam: 'Cloud-Berechtigungen (IAM)',
  cicd: 'GitHub / GitLab / Azure DevOps',
  m365: 'Microsoft 365 / Google Workspace',
  hosting: 'Cloudflare, Hetzner, DigitalOcean, Vercel, Netlify',
  hibp: 'Datenlecks der Domain (HIBP)',
};

const AUDITS = {
  winapps: local.auditWinApps,
  browserext: local.auditBrowserExt,
  backup: local.auditBackup,
  macos: local.auditMacos,
  router: network.auditRouter,
  lan: network.auditLan,
  linuxssh: remote.auditLinuxSsh,
  dbdirect: remote.auditDb,
  k8s: remote.auditK8s,
  iam: iam.auditIam,
  cicd: saas.auditCicd,
  m365: saas.auditM365,
  hosting: saas.auditHosting,
  hibp: saas.auditHibp,
};

// Einstellungen der Pruefungen: Geheimnisse liegen verschluesselt (safeStorage), der Rest im Klartext.
const SECRET_FIELDS = ['dbUrls', 'githubToken', 'gitlabToken', 'adoToken', 'm365Secret', 'gwsServiceAccount', 'cloudflareToken', 'hetznerToken', 'digitaloceanToken', 'vercelToken', 'netlifyToken', 'hibpKey'];
const PLAIN_FIELDS = ['sshTarget', 'sshKeyPath', 'githubOrg', 'gitlabUrl', 'gitlabGroup', 'adoOrg', 'm365Tenant', 'm365ClientId', 'gwsAdmin', 'hibpDomain'];
const BOOL_FIELDS = ['lanPortCheck'];

async function auditExtended(kind, { signal, onProgress = () => {}, settings = {}, ...deps } = {}) {
  const fn = AUDITS[kind];
  if (!fn) return null;
  const say = (m) => onProgress({ phase: 'webscan', message: m });
  return fn({ signal, say, settings: settings || {}, ...deps });
}

module.exports = { LABELS, AUDITS, SECRET_FIELDS, PLAIN_FIELDS, BOOL_FIELDS, auditExtended };
