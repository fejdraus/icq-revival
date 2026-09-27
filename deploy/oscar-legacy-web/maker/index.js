// Constructed avatars as files: /icq/avatars/c-<code>.swf and its pictures,
// made on the first request from the code alone (maker/avatar.js) and kept
// in memory, the least recently used dropped first. Nothing is stored: the
// code is the avatar, and the same code always gives the same bytes, so a
// file dropped from the cache comes back identical.

'use strict';

const A = require('./avatar.js');

// The files of one avatar: the movie, the still ICQ takes as a buddy icon,
// the large picture and the gallery-size thumbnail.
const FILE = /^(c-[0-9a-z]+)(\.swf|-still\.jpg|-large\.png|\.png)$/;
const TYPES = {
  '.swf': 'application/x-shockwave-flash',
  '-still.jpg': 'image/jpeg',
  '-large.png': 'image/png',
  '.png': 'image/png',
};

// A byte-capped LRU: a Map keeps insertion order, and a hit moves to the end.
function lru(maxBytes) {
  const map = new Map();
  let bytes = 0;
  return {
    get(key) {
      const v = map.get(key);
      if (v) { map.delete(key); map.set(key, v); }
      return v;
    },
    set(key, body) {
      if (map.has(key)) { bytes -= map.get(key).length; map.delete(key); }
      map.set(key, body);
      bytes += body.length;
      for (const [k, v] of map) {
        if (bytes <= maxBytes) break;
        map.delete(k);
        bytes -= v.length;
      }
    },
    get size() { return map.size; },
    get bytes() { return bytes; },
  };
}

const CACHE_BYTES = Math.max(1, Number(process.env.MAKER_CACHE_MB) || 32) * 1024 * 1024;
const cache = lru(CACHE_BYTES);

// What is under the key, made by make() when it is not there (or null).
function cached(key, make) {
  let body = cache.get(key);
  if (!body) {
    body = make();
    if (body) cache.set(key, body);
  }
  return body || null;
}

function isName(name) {
  const m = FILE.exec(String(name).toLowerCase());
  return !!(m && A.parseCode(m[1]));
}

// One file as { body, type }, or null for a name that is not a valid code's.
// A large picture may show another emotion than the idle one (the preview
// of the constructor page where the movie cannot play).
function file(name, emotion = '') {
  const m = FILE.exec(String(name).toLowerCase());
  if (!m) return null;
  const params = A.parseCode(m[1]);
  if (!params) return null;
  const kind = m[2];
  if (emotion && (kind !== '-large.png' || !A.EMOTIONS.includes(emotion))) return null;
  const body = cached(`${m[1]}${kind}${emotion ? `?${emotion}` : ''}`, () => {
    if (kind === '.swf') return A.buildMovie(params);
    if (kind === '-still.jpg') return A.still(params);
    if (kind === '-large.png') return A.large(params, emotion || 'stam');
    return A.thumb(params);
  });
  return { body, type: TYPES[kind] };
}

// The gallery-style entry of a constructed avatar (see avatars.json), by its
// movie's name or code; null when it is not one.
function entry(name) {
  const code = String(name).toLowerCase().replace(/\.swf$/, '');
  if (!A.parseCode(code)) return null;
  return {
    file: `${code}.swf`,
    thumb: `${code}.png`,
    still: `${code}-still.jpg`,
    large: `${code}-large.png`,
    largeSize: [A.LARGE.w, A.LARGE.h],
    author: 'maker',
    labels: A.EMOTIONS.slice(),
    title: { en: 'Your own avatar', uk: 'Власний аватар' },
  };
}

module.exports = {
  FIELDS: A.FIELDS, DEFAULTS: A.DEFAULTS, EMOTIONS: A.EMOTIONS, LARGE: A.LARGE,
  parseCode: A.parseCode, encode: A.encode, isName, file, entry, cached, lru,
};
