'use strict';

// Drosselung externer Anfragen: Mindestabstand je Ziel und begrenzte Parallelitaet.
// Damit bleiben Web-Checks und Datenbank-Abfragen schonend fuer die Gegenseite.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const lastAt = new Map();

// Wartet, bis seit der letzten Anfrage an `key` mindestens `gapMs` vergangen sind.
async function throttle(key, gapMs = 300) {
  const now = Date.now();
  const slot = Math.max(now, (lastAt.get(key) || 0) + gapMs);
  lastAt.set(key, slot);
  if (slot > now) await sleep(slot - now);
}

// Liefert run(fn): fuehrt hoechstens `max` fn gleichzeitig aus, der Rest wartet.
function limiter(max = 2) {
  let active = 0;
  const queue = [];
  return async function run(fn) {
    while (active >= max) await new Promise((r) => queue.push(r));
    active++;
    try { return await fn(); }
    finally { active--; const next = queue.shift(); if (next) next(); }
  };
}

module.exports = { throttle, limiter, sleep };
