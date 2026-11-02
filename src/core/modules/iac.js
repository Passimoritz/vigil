'use strict';

// Server-Einrichtung als Code: Terraform, Kubernetes, Helm, CloudFormation, Ansible.
// Rein statisch und zeilenbasiert (kein YAML/HCL-Parser noetig): jede Regel sucht ein
// eindeutiges Muster im passenden Dateityp und meldet die Zeile.

const { normalizeFinding } = require('../schema');

const M = 'iac-audit';
const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');
const lineOf = (text, idx) => text.slice(0, idx).split('\n').length;

function mk(u, idx, o) {
  return normalizeFinding({
    category: 'Config', confidence: 'high', ...o,
    location: idx == null || idx < 0 ? base(u) : `${base(u)}:${lineOf(u.content, idx)}`,
    sourceModule: M,
  }, M);
}

// Ports, die nie offen fuer 0.0.0.0/0 sein sollten
const RISKY = { 22: 'SSH', 3389: 'Remotedesktop', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 23: 'Telnet', 21: 'FTP', 445: 'SMB' };

// Ein HCL-Block "resource "typ" "name" { ... }" mit Klammerzaehlung
function hclBlocks(c) {
  const out = [];
  const re = /^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{/gm; let m;
  while ((m = re.exec(c))) {
    let depth = 0, i = m.index + m[0].length - 1;
    for (; i < c.length; i++) { if (c[i] === '{') depth++; else if (c[i] === '}' && --depth === 0) break; }
    out.push({ type: m[1], name: m[2], at: m.index, body: c.slice(m.index, i + 1) });
  }
  return out;
}

function terraform(u) {
  const out = [];
  const c = u.content || '';
  for (const b of hclBlocks(c)) {
    const at = (re) => { const k = re ? b.body.search(re) : -1; return k < 0 ? b.at : b.at + k; };
    const add = (ruleId, severity, title, description, remediation, re, extra) => out.push(mk(u, at(re), { ruleId, severity, title: `${title} (${b.type}.${b.name})`, description, remediation, ...extra }));
    if (b.type === 'aws_s3_bucket' || b.type === 'aws_s3_bucket_acl') {
      if (/acl\s*=\s*"public-read(-write)?"/.test(b.body)) add('iac-s3-public-acl', 'high', 'Speicher-Bucket ist öffentlich lesbar', 'Jeder im Internet kann die Dateien in diesem Bucket abrufen. So gelangen immer wieder Kundendaten und Backups an die Öffentlichkeit.', 'acl = "private" setzen und den Zugriff über eine Bucket-Policy auf bestimmte Rollen beschränken.', /acl\s*=/, { category: 'AccessControl' });
    }
    if (b.type === 'aws_s3_bucket_public_access_block' && /(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false/.test(b.body)) add('iac-s3-public-block-off', 'medium', 'Sperre gegen öffentliche Freigabe abgeschaltet', 'Ein Teil der Schutzschalter gegen versehentliche öffentliche Freigaben ist aus. Ein einziger Fehler in einer Policy macht den Bucket dann öffentlich.', 'Alle vier Werte auf true setzen.', /=\s*false/);
    if (b.type === 'aws_security_group' || b.type === 'aws_security_group_rule' || b.type === 'aws_vpc_security_group_ingress_rule') {
      const open = /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"|cidr_ipv4\s*=\s*"0\.0\.0\.0\/0"|ipv6_cidr_blocks\s*=\s*\[[^\]]*"::\/0"/.test(b.body);
      const ports = [...b.body.matchAll(/from_port\s*=\s*(\d+)[\s\S]{0,80}?to_port\s*=\s*(\d+)/g)].map((m) => [Number(m[1]), Number(m[2])]);
      if (open && !/type\s*=\s*"egress"/.test(b.body)) {
        const hit = Object.keys(RISKY).map(Number).find((p) => ports.some(([a, z]) => (a === 0 && z === 0) || (p >= a && p <= z)));
        if (hit) add('iac-sg-open-admin', 'high', `${RISKY[hit]}-Port ${hit} für das ganze Internet offen`, `Die Firewall-Regel erlaubt Verbindungen von jeder Adresse (0.0.0.0/0) auf Port ${hit}. Solche Ports werden ständig automatisch nach schwachen Passwörtern und Lücken abgesucht.`, 'Quelle auf feste Adressen (Büro, VPN) beschränken oder den Dienst nur intern erreichbar machen.', /0\.0\.0\.0\/0|::\/0/);
      }
    }
    if (/^aws_(db_instance|rds_cluster)$/.test(b.type)) {
      if (/publicly_accessible\s*=\s*true/.test(b.body)) add('iac-db-public', 'high', 'Datenbank aus dem Internet erreichbar', 'Die Datenbank bekommt eine öffentliche Adresse. Zusammen mit einem schwachen oder geleakten Passwort ist das ein direkter Weg zu allen Daten.', 'publicly_accessible = false und den Zugriff nur aus dem eigenen Netz erlauben.', /publicly_accessible/);
      if (!/storage_encrypted\s*=\s*true/.test(b.body)) add('iac-db-unencrypted', 'medium', 'Datenbank-Speicher nicht verschlüsselt', 'Ohne Verschlüsselung sind Daten in Snapshots und auf ausgemusterten Datenträgern lesbar.', 'storage_encrypted = true setzen.', /storage_encrypted/, { category: 'Crypto' });
    }
    if (b.type === 'aws_ebs_volume' && /encrypted\s*=\s*false/.test(b.body)) add('iac-disk-unencrypted', 'medium', 'Festplatte nicht verschlüsselt', 'Daten auf der Festplatte und ihren Snapshots liegen unverschlüsselt.', 'encrypted = true setzen.', /encrypted/, { category: 'Crypto' });
    if (/^aws_iam_(policy|role_policy|user_policy|group_policy)$/.test(b.type) && /"Action"\s*[:=]\s*"\*"|actions\s*=\s*\[\s*"\*"\s*\]/.test(b.body) && /"Resource"\s*[:=]\s*"\*"|resources\s*=\s*\[\s*"\*"\s*\]/.test(b.body)) add('iac-iam-wildcard', 'high', 'Berechtigung erlaubt alles auf allem', 'Die Richtlinie gibt jede Aktion auf jeder Ressource frei. Wer diese Rolle erlangt, hat das ganze Konto in der Hand.', 'Nur die wirklich benötigten Aktionen und Ressourcen eintragen.', /\*/, { category: 'AccessControl' });
    if (b.type === 'azurerm_storage_account') {
      if (/(allow_blob_public_access|allow_nested_items_to_be_public)\s*=\s*true/.test(b.body)) add('iac-azure-blob-public', 'high', 'Azure-Speicher erlaubt öffentliche Container', 'Container in diesem Speicherkonto können ohne Anmeldung gelesen werden.', 'allow_nested_items_to_be_public = false setzen.', /public/, { category: 'AccessControl' });
      if (/(enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*false/.test(b.body)) add('iac-azure-http', 'medium', 'Azure-Speicher erlaubt unverschlüsseltes HTTP', 'Daten können unverschlüsselt übertragen und unterwegs mitgelesen werden.', 'https_traffic_only_enabled = true setzen.', /https/, { category: 'Transport' });
      if (/min_tls_version\s*=\s*"TLS1_[01]"/.test(b.body)) add('iac-azure-old-tls', 'medium', 'Azure-Speicher erlaubt veraltetes TLS', 'TLS 1.0 und 1.1 gelten als unsicher.', 'min_tls_version = "TLS1_2" setzen.', /min_tls_version/, { category: 'Transport' });
    }
    if (/^google_storage_bucket_iam_(member|binding)$/.test(b.type) && /"allUsers"|"allAuthenticatedUsers"/.test(b.body)) add('iac-gcs-public', 'high', 'Google-Speicher für alle freigegeben', 'allUsers bzw. allAuthenticatedUsers macht den Bucket für jeden lesbar.', 'Mitglied auf konkrete Konten oder Gruppen beschränken.', /all(Authenticated)?Users/, { category: 'AccessControl' });
  }
  // Fest eingetragene Passwoerter in .tf (keine Variable, kein Verweis)
  const re = /^\s*(password|master_password|admin_password|client_secret|secret_key|access_key)\s*=\s*"(?!\$\{)([^"]{4,})"/gim; let m;
  while ((m = re.exec(c))) out.push(mk(u, m.index, { ruleId: 'iac-hardcoded-secret', severity: 'high', category: 'Secrets', title: `Passwort fest im Terraform-Code (${m[1]})`, description: 'Das Passwort steht im Klartext im Code und damit in Git, in Logs und im Terraform-State.', remediation: 'Über eine Variable mit sensitive = true oder einen Secret-Manager (Vault, AWS Secrets Manager) übergeben.' }));
  return out;
}

const K8S_KIND = /^\s*kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\s*$/m;
function kubernetes(u) {
  const out = [];
  const c = u.content || '';
  // Mehrere Dokumente in einer Datei getrennt pruefen
  const docs = [];
  const sep = /^---\s*$/gm; let last = 0, s;
  while ((s = sep.exec(c))) { docs.push({ start: last, text: c.slice(last, s.index) }); last = s.index + s[0].length; }
  docs.push({ start: last, text: c.slice(last) });
  for (const { start, text: doc } of docs) {
    if (!K8S_KIND.test(doc)) continue;
    const name = (doc.match(/^\s*name:\s*["']?([\w.-]+)/m) || [])[1] || 'unbenannt';
    const at = (re) => { const k = re ? doc.search(re) : -1; return k < 0 ? start + Math.max(0, doc.search(K8S_KIND)) : start + k; };
    const add = (ruleId, severity, title, description, remediation, re) => out.push(mk(u, at(re), { ruleId, severity, title: `${title} („${name}“)`, description, remediation }));
    if (/privileged:\s*true/.test(doc)) add('k8s-privileged', 'critical', 'Container läuft privilegiert', 'Ein privilegierter Container hat fast vollen Zugriff auf den Server darunter. Eine Lücke in der App reicht dann für die Übernahme des ganzen Knotens.', 'privileged: true entfernen.', /privileged:/);
    for (const [k, t] of [['hostNetwork', 'das Netzwerk'], ['hostPID', 'die Prozesse'], ['hostIPC', 'den Speicher-Austausch']]) {
      if (new RegExp(`${k}:\\s*true`).test(doc)) add(`k8s-${k.toLowerCase()}`, 'high', `Container teilt ${t} mit dem Server`, `${k}: true hebt die Trennung zwischen Container und Server für ${t} auf.`, `${k}: true entfernen.`, new RegExp(k));
    }
    if (/allowPrivilegeEscalation:\s*true/.test(doc)) add('k8s-priv-escalation', 'medium', 'Rechte-Ausweitung im Container erlaubt', 'Prozesse im Container dürfen sich mehr Rechte verschaffen.', 'allowPrivilegeEscalation: false setzen.', /allowPrivilegeEscalation/);
    if (/runAsUser:\s*0\b/.test(doc)) add('k8s-run-as-root', 'high', 'Container läuft ausdrücklich als root', 'Der Prozess läuft mit Administratorrechten im Container.', 'runAsNonRoot: true und eine Benutzer-ID über 10000 setzen.', /runAsUser/);
    else if (!/runAsNonRoot:\s*true/.test(doc)) add('k8s-no-run-as-non-root', 'low', 'Nicht festgelegt, dass der Container ohne root läuft', 'Ohne runAsNonRoot entscheidet das Image, und viele Images laufen als root.', 'securityContext: { runAsNonRoot: true } setzen.');
    if (/hostPath:/.test(doc)) add('k8s-hostpath', 'high', 'Ordner des Servers in den Container eingebunden', 'Über hostPath kann der Container Dateien des Servers lesen oder ändern.', 'Stattdessen ein PersistentVolume oder emptyDir verwenden.', /hostPath:/);
    if (/add:\s*\[[^\]\n]*\b(SYS_ADMIN|NET_ADMIN|ALL)\b/.test(doc) || /add:\s*\n\s*-\s*["']?(SYS_ADMIN|NET_ADMIN|ALL)\b/.test(doc)) add('k8s-dangerous-cap', 'high', 'Gefährliche Zusatzrechte (Capabilities)', 'SYS_ADMIN, NET_ADMIN oder ALL geben dem Container Rechte, mit denen er aus seiner Umgebung ausbrechen kann.', 'capabilities: { drop: [ALL] } und nur einzeln benötigte Rechte hinzufügen.', /add:/);
    const img = doc.match(/^\s*-?\s*image:\s*["']?([^\s"']+)/m);
    if (img && !/\{\{/.test(img[1]) && (/:latest$/.test(img[1]) || !/[:@]/.test(img[1].split('/').pop()))) add('k8s-image-latest', 'medium', `Image ohne feste Version: ${img[1]}`, 'Mit :latest oder ohne Tag kann bei jedem Neustart ein anderes Image laufen – auch ein manipuliertes.', 'Feste Version oder besser den sha256-Digest angeben.', /image:/);
    if (!/limits:/.test(doc)) add('k8s-no-limits', 'low', 'Keine Grenzen für Speicher und Rechenzeit', 'Ohne limits kann ein einzelner Container den ganzen Knoten auslasten.', 'resources.limits für cpu und memory setzen.');
  }
  // Rollenbindung an cluster-admin
  const crb = c.search(/kind:\s*ClusterRoleBinding[\s\S]{0,400}?name:\s*cluster-admin/);
  if (crb >= 0) out.push(mk(u, crb, { ruleId: 'k8s-cluster-admin-binding', severity: 'high', category: 'AccessControl', title: 'Konto bekommt volle Cluster-Rechte (cluster-admin)', description: 'Wer dieses Konto nutzt, darf im ganzen Cluster alles – auch Secrets lesen und neue privilegierte Container starten.', remediation: 'Eigene Rolle mit nur den nötigen Rechten anlegen und daran binden.' }));
  return out;
}

function cloudformation(u) {
  const out = [];
  const c = u.content || '';
  const add = (re, o) => { const i = c.search(re); if (i >= 0) out.push(mk(u, i, o)); };
  add(/AccessControl["']?\s*:\s*["']?PublicRead(Write)?/, { ruleId: 'iac-s3-public-acl', severity: 'high', category: 'AccessControl', title: 'Speicher-Bucket ist öffentlich lesbar (CloudFormation)', description: 'AccessControl: PublicRead macht alle Dateien im Bucket für jeden abrufbar.', remediation: 'AccessControl entfernen und PublicAccessBlockConfiguration setzen.' });
  add(/PubliclyAccessible["']?\s*:\s*["']?true/i, { ruleId: 'iac-db-public', severity: 'high', title: 'Datenbank aus dem Internet erreichbar (CloudFormation)', description: 'PubliclyAccessible: true gibt der Datenbank eine öffentliche Adresse.', remediation: 'PubliclyAccessible: false setzen.' });
  const sg = /CidrIp["']?\s*:\s*["']?0\.0\.0\.0\/0["']?[\s\S]{0,160}?(?:FromPort|ToPort)["']?\s*:\s*["']?(\d+)|(?:FromPort|ToPort)["']?\s*:\s*["']?(\d+)[\s\S]{0,160}?CidrIp["']?\s*:\s*["']?0\.0\.0\.0\/0/g; let m;
  const seen = new Set();
  while ((m = sg.exec(c))) { const p = Number(m[1] || m[2]); if (RISKY[p] && !seen.has(p)) { seen.add(p); out.push(mk(u, m.index, { ruleId: 'iac-sg-open-admin', severity: 'high', title: `${RISKY[p]}-Port ${p} für das ganze Internet offen (CloudFormation)`, description: `Die Regel erlaubt Verbindungen von jeder Adresse auf Port ${p}.`, remediation: 'CidrIp auf feste Adressen beschränken.' })); } }
  add(/["']?Action["']?\s*:\s*["']\*["'][\s\S]{0,200}?["']?Resource["']?\s*:\s*["']\*["']/, { ruleId: 'iac-iam-wildcard', severity: 'high', category: 'AccessControl', title: 'Berechtigung erlaubt alles auf allem (CloudFormation)', description: 'Action "*" auf Resource "*" gibt das ganze Konto frei.', remediation: 'Aktionen und Ressourcen einzeln eintragen.' });
  return out;
}

function ansible(u) {
  const out = [];
  const c = u.content || '';
  const each = (re, o) => { re.lastIndex = 0; let m, n = 0; while ((m = re.exec(c)) && n++ < 5) out.push(mk(u, m.index, o)); };
  each(/validate_certs:\s*(no|false)\b/gi, { ruleId: 'ansible-no-cert-check', severity: 'medium', category: 'Transport', title: 'Ansible prüft Zertifikate nicht', description: 'Downloads und API-Aufrufe akzeptieren jedes Zertifikat. Jemand im Netz kann sich dazwischenschalten und manipulierte Dateien unterschieben.', remediation: 'validate_certs entfernen (Standard ist yes).' });
  each(/(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b/g, { ruleId: 'ansible-curl-pipe-sh', severity: 'high', category: 'Dependencies', title: 'Skript aus dem Internet wird direkt ausgeführt', description: 'curl … | sh führt ungeprüft aus, was der Server gerade liefert – ohne Prüfsumme und als Admin.', remediation: 'Datei herunterladen, Prüfsumme kontrollieren (get_url mit checksum) und dann ausführen.' });
  each(/mode:\s*["']?0?777["']?/g, { ruleId: 'ansible-world-writable', severity: 'medium', title: 'Datei für alle beschreibbar (mode 0777)', description: 'Jeder Benutzer auf dem Server kann diese Datei ändern.', remediation: 'mode: "0644" bzw. "0755" für Programme verwenden.' });
  // Aufgaben einzeln betrachten: Passwort-Aufgabe ohne no_log
  const tasks = c.split(/^(?=\s*-\s*name:)/m);
  let off = 0;
  for (const t of tasks) {
    if (/^\s*-\s*name:/.test(t) && /password|passwort|secret|token/i.test(t) && !/no_log:\s*(true|yes)/.test(t)) out.push(mk(u, off, { ruleId: 'ansible-secret-logged', severity: 'low', category: 'Logging', title: 'Aufgabe mit Passwort ohne no_log', description: 'Ansible schreibt Werte dieser Aufgabe ins Protokoll – inklusive Passwort.', remediation: 'no_log: true bei der Aufgabe setzen.' }));
    off += t.length;
  }
  return out;
}

function runIac(units) {
  const out = [];
  for (const u of units) {
    const p = base(u).toLowerCase();
    const c = u.content || '';
    if (/\.(tf|tf\.json|hcl)$/.test(p)) { out.push(...terraform(u)); continue; }
    if (!/\.(ya?ml|json|template)$/.test(p)) continue;
    if (/AWSTemplateFormatVersion|"?Type"?\s*:\s*"?AWS::/.test(c)) { out.push(...cloudformation(u)); continue; }
    if (/^\s*apiVersion:\s*\S+/m.test(c) && /^\s*kind:\s*\w+/m.test(c)) { out.push(...kubernetes(u)); continue; }
    if ((/^\s*-?\s*hosts:\s*\S+/m.test(c) && /^\s*(tasks|roles):/m.test(c)) || /(^|\/)(roles\/[^/]+\/(tasks|handlers)|playbooks?)\//.test(p)) out.push(...ansible(u));
  }
  return out;
}

module.exports = { runIac, hclBlocks };
