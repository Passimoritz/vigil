'use strict';

// Lizenzen der genutzten Pakete: Quelle ist package-lock.json (npm 7+ fuehrt "license"
// je Paket) bzw. node_modules/<paket>/package.json neben dem Projekt. Gemeldet wird nur,
// was zur eigenen Projektlizenz nicht passt – keine Rechtsberatung, sondern ein Hinweis.

const fs = require('fs');
const path = require('path');
const { normalizeFinding } = require('../schema');

const M = 'license-audit';
const base = (u) => String(u.label || u.path || '').replace(/\\/g, '/');

// Starke Copyleft-Lizenzen: abgeleitete Werke muessen unter derselben Lizenz stehen.
const STRONG = /\b(AGPL|SSPL|GPL|EUPL|OSL|CPAL|RPL)\b/i;
const NETWORK = /\b(AGPL|SSPL)\b/i;             // gilt schon bei Nutzung uebers Netz
const WEAK = /\b(LGPL|MPL|EPL|CDDL|CPL)\b/i;      // nur Aenderungen an der Bibliothek selbst
const NONCOMMERCIAL = /\b(CC-BY-NC|BUSL|Commons Clause|Elastic-2\.0|PolyForm-Noncommercial)\b/i;

function licenseText(v) {
  if (!v) return '';
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v.map(licenseText).join(' OR ');
  if (typeof v === 'object') return String(v.type || v.name || '');
  return '';
}

// Projektlizenz: package.json "license", sonst erste Zeilen einer LICENSE-Datei.
function projectLicense(units, pj) {
  const l = licenseText(pj && pj.license);
  if (l) return l;
  const lic = units.find((u) => /(^|\/)(LICEN[CS]E|COPYING)(\.\w+)?$/i.test(base(u)));
  if (!lic) return '';
  const head = (lic.content || '').slice(0, 400);
  if (/GNU AFFERO/i.test(head)) return 'AGPL-3.0';
  if (/GNU LESSER/i.test(head)) return 'LGPL';
  if (/GNU GENERAL PUBLIC/i.test(head)) return 'GPL';
  if (/MIT License|Permission is hereby granted/i.test(head)) return 'MIT';
  if (/Apache License/i.test(head)) return 'Apache-2.0';
  if (/BSD/i.test(head)) return 'BSD';
  return 'eigene';
}

// Ergibt die Kombination ein Problem? (Copyleft in permissivem/proprietaerem Projekt)
function conflict(dep, proj) {
  const d = dep.toUpperCase();
  // SPDX "A OR B": wenn eine der Wahlmoeglichkeiten unproblematisch ist, kein Konflikt
  if (/\bOR\b/.test(d) && d.split(/\s+OR\s+/).some((x) => !STRONG.test(x) && !NONCOMMERCIAL.test(x))) return null;
  const projCopyleft = STRONG.test(proj);
  if (NONCOMMERCIAL.test(dep)) return { severity: 'medium', kind: 'nichtkommerziell', text: 'Diese Lizenz verbietet oder beschränkt die kommerzielle Nutzung.' };
  if (STRONG.test(dep) && !WEAK.test(dep) && !projCopyleft) {
    return NETWORK.test(dep)
      ? { severity: 'high', kind: 'stark (Netz)', text: 'Schon wer die Software über das Netz nutzt, hat Anspruch auf den vollständigen Quellcode des Gesamtprojekts.' }
      : { severity: 'medium', kind: 'stark', text: 'Wer das Programm weitergibt, muss den gesamten Quellcode unter derselben Lizenz offenlegen.' };
  }
  return null;
}

function depsFromLock(lockText) {
  let pl; try { pl = JSON.parse(lockText); } catch { return []; }
  return Object.entries(pl.packages || {})
    .filter(([k]) => k.startsWith('node_modules/') || k.includes('/node_modules/'))
    .map(([k, v]) => ({ name: k.replace(/^.*node_modules\//, ''), version: v.version || '', license: licenseText(v.license), dev: !!v.dev }));
}

function depsFromNodeModules(dir, pj) {
  const names = [...Object.keys(pj.dependencies || {}).map((n) => [n, false]), ...Object.keys(pj.devDependencies || {}).map((n) => [n, true])];
  const out = [];
  for (const [name, dev] of names) {
    try {
      const p = JSON.parse(fs.readFileSync(path.join(dir, 'node_modules', name, 'package.json'), 'utf8'));
      out.push({ name, version: p.version || '', license: licenseText(p.license || p.licenses), dev });
    } catch { /* nicht installiert */ }
  }
  return out;
}

function runLicense(units) {
  const out = [];
  for (const u of units) {
    if (!/(^|\/)package\.json$/i.test(base(u)) || /node_modules/.test(base(u))) continue;
    let pj; try { pj = JSON.parse(u.content || ''); } catch { continue; }
    if (pj.private && !pj.license && !units.some((x) => /(^|\/)LICEN[CS]E/i.test(base(x)))) pj.license = 'proprietär';
    const proj = projectLicense(units, pj) || 'keine angegeben';
    const dir = base(u).replace(/package\.json$/i, '');
    const lock = units.find((x) => base(x).toLowerCase() === (dir + 'package-lock.json').toLowerCase());
    let deps = lock ? depsFromLock(lock.content || '') : [];
    if (!deps.some((d) => d.license) && u.path) deps = depsFromNodeModules(path.dirname(u.path), pj);
    if (!deps.length) continue;
    const bad = [];
    const unknown = [];
    for (const d of deps) {
      if (!d.license) { if (!d.dev) unknown.push(d); continue; }
      const c = conflict(d.license, proj);
      if (c) bad.push({ ...d, ...c });
    }
    // Je Paket ein Befund, aber hoechstens 15 – sonst ein Sammelbefund
    for (const d of bad.slice(0, 15)) {
      out.push(normalizeFinding({
        ruleId: 'license-copyleft', severity: d.dev ? 'info' : d.severity, category: 'License', confidence: 'high',
        title: `Paket „${d.name}“ hat eine Lizenz, die nicht zum Projekt passt (${d.license})`,
        description: `Das Projekt steht unter „${proj}“, das Paket ${d.name}${d.version ? ' ' + d.version : ''} unter ${d.license}. ${d.text}`,
        impact: d.dev ? 'Nur ein Entwicklungswerkzeug – es wird normalerweise nicht mit ausgeliefert, deshalb meist unkritisch.' : 'Wer das nicht beachtet, verstößt gegen die Lizenz und kann abgemahnt oder zur Offenlegung des Quellcodes verpflichtet werden.',
        remediation: 'Prüfen, ob das Paket wirklich ausgeliefert wird. Wenn ja: durch ein Paket mit freizügiger Lizenz (MIT, BSD, Apache-2.0) ersetzen oder die Lizenzbedingungen erfüllen. Im Zweifel rechtlich beraten lassen.',
        location: `${base(u)} → ${d.name}`, devOnly: d.dev, package: { ecosystem: 'npm', name: d.name, version: d.version },
        sourceModule: M,
      }, M));
    }
    if (unknown.length >= 1) {
      out.push(normalizeFinding({
        ruleId: 'license-unknown', severity: 'low', category: 'License', confidence: 'medium',
        title: `Paket${unknown.length > 1 ? 'e' : ''} ohne angegebene Lizenz: ${unknown.slice(0, 3).map((d) => d.name).join(', ')}${unknown.length > 3 ? ' …' : ''}`,
        description: `Für ${unknown.length} Paket${unknown.length > 1 ? 'e' : ''} ist keine Lizenz eingetragen. Ohne Lizenz darf man den Code rechtlich gesehen gar nicht nutzen.`,
        remediation: 'Lizenz beim Autor nachfragen oder das Paket ersetzen.',
        location: base(u), sourceModule: M,
      }, M));
    }
  }
  return out;
}

module.exports = { runLicense, conflict, projectLicense };
