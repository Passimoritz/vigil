'use strict';

// .vigilignore: schliesst Pfade/Muster vom Scan aus (gitignore-aehnlich,
// bewusst vereinfacht). Eine Zeile = ein Glob-Muster; '#' leitet einen
// Kommentar ein, Leerzeilen werden ignoriert, '/' am Ende meint einen Ordner.

const fs = require('fs');
const path = require('path');

// Ein einzelnes Glob-Muster in einen regulaeren Ausdruck uebersetzen.
function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; } // ** = beliebig tief
      else re += '[^/]*';                            // *  = ein Pfadsegment
    } else if (c === '?') re += '[^/]';
    else if ('\\^$+.()|{}[]'.includes(c)) re += '\\' + c;
    else re += c;
  }
  return new RegExp('^' + re + '$', 'i');
}

// Baut aus Mustern einen Matcher. relPath = Pfad relativ zum Scan-Wurzelordner
// (mit '/'), name = reiner Datei-/Ordnername.
function makeMatcher(patterns) {
  const compiled = (patterns || [])
    .map((p) => String(p || '').trim())
    .filter((p) => p && !p.startsWith('#'))
    .map((p) => {
      const dirOnly = p.endsWith('/');
      const body = (dirOnly ? p.slice(0, -1) : p).replace(/^\/+/, '').replace(/\\/g, '/');
      return { dirOnly, hasSlash: body.includes('/'), re: globToRegExp(body) };
    });
  return function matches(relPath, name) {
    const rp = String(relPath || '').replace(/\\/g, '/').replace(/^\/+/, '');
    const nm = String(name || '');
    for (const c of compiled) {
      if (c.re.test(rp)) return true;
      if (!c.hasSlash && c.re.test(nm)) return true; // Muster ohne '/' trifft jeden Namen
    }
    return false;
  };
}

// .vigilignore aus einem Ordner lesen (leeres Array, wenn keine da ist).
function loadIgnore(dir) {
  try {
    const raw = fs.readFileSync(path.join(dir, '.vigilignore'), 'utf8');
    return raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  } catch { return []; }
}

module.exports = { globToRegExp, makeMatcher, loadIgnore };
