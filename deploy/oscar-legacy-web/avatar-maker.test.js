// Tests for the avatar constructor's files (maker/): node --test "deploy/oscar-legacy-web/*.test.js"
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const A = require('./maker/avatar.js');
const maker = require('./maker');

const DEFAULT = A.encode(A.DEFAULTS);

// ------------------------------------------------------------------- a reader

// The tags of a SWF, sprites with their own tags inside.
function readTags(body, pos, end) {
  const tags = [];
  while (pos + 2 <= end) {
    const head = body.readUInt16LE(pos);
    const code = head >> 6;
    let len = head & 0x3f;
    pos += 2;
    if (len === 0x3f) { len = body.readUInt32LE(pos); pos += 4; }
    const data = body.subarray(pos, pos + len);
    const tag = { code, data };
    if (code === 39) {
      tag.id = data.readUInt16LE(0);
      tag.frames = data.readUInt16LE(2);
      tag.tags = readTags(data, 4, data.length);
    }
    tags.push(tag);
    pos += len;
    if (code === 0) break;
  }
  return tags;
}

function readSwf(buf) {
  assert.equal(buf.toString('latin1', 0, 3), 'CWS');
  const body = zlib.inflateSync(buf.subarray(8));
  assert.equal(buf.readUInt32LE(4), body.length + 8);
  const nbits = body[0] >> 3;
  let bitpos = 5;
  const read = (n) => {
    let v = 0;
    for (let i = 0; i < n; i++, bitpos++) v = (v << 1) | ((body[bitpos >> 3] >> (7 - (bitpos & 7))) & 1);
    return v >= 2 ** (n - 1) ? v - 2 ** n : v;
  };
  const rect = [read(nbits), read(nbits), read(nbits), read(nbits)];
  const pos = Math.ceil(bitpos / 8);
  return {
    version: buf[3],
    rect,
    fps: body[pos + 1] + body[pos] / 256,
    frameCount: body.readUInt16LE(pos + 2),
    tags: readTags(body, pos + 4, body.length),
  };
}

const all = (tags) => tags.flatMap((t) => [t, ...(t.tags ? all(t.tags) : [])]);
const cstr = (data, at = 0) => data.toString('latin1', at, data.indexOf(0, at));

// The AVM1 actions of a DoAction body: opcodes and the strings pushed.
function actions(data) {
  const ops = [];
  const strings = [];
  let i = 0;
  while (i < data.length) {
    const op = data[i++];
    ops.push(op);
    if (op === 0) break;
    if (op >= 0x80) {
      const len = data.readUInt16LE(i);
      const rec = data.subarray(i + 2, i + 2 + len);
      i += 2 + len;
      if (op === 0x96) {
        for (let k = 0; k < rec.length;) {
          const type = rec[k++];
          if (type === 0) { const s = cstr(rec, k); strings.push(s); k += s.length + 1; } else if (type === 7) k += 4;
          else if (type === 5) k += 1;
          else if (type !== 3 && type !== 2) throw new Error(`push type ${type}`);
        }
      }
      if (op === 0x9b) {
        // The function's name and parameters are strings too; its body
        // follows as ordinary actions.
        let k = 0;
        const name = cstr(rec, k); k += name.length + 1;
        const n = rec.readUInt16LE(k); k += 2;
        for (let p = 0; p < n; p++) { const s = cstr(rec, k); strings.push(s); k += s.length + 1; }
      }
    }
  }
  return { ops, strings };
}

// ------------------------------------------------------------------- codes

test('codes: the defaults round-trip, the code is a plain file name', () => {
  assert.match(DEFAULT, /^c-1[0-9a-z]{13}$/);
  assert.match(`/icq/avatars/${DEFAULT}.swf`, /^\/icq\/avatars\/([A-Za-z0-9_-]+)\.swf$/); // the IM server's still-finder
  assert.deepEqual(A.parseCode(DEFAULT), A.DEFAULTS);
  for (const f of A.FIELDS) {
    for (let v = 0; v < f.count; v++) {
      const p = { ...A.DEFAULTS, [f.key]: v };
      assert.deepEqual(A.parseCode(A.encode(p)), p, `${f.key}=${v}`);
    }
  }
});

test('codes: anything but the exact form is refused', () => {
  const bad = [
    '', 'c-', 'c-1', DEFAULT.slice(0, -1), `${DEFAULT}0`, DEFAULT.replace('c-1', 'c-2'), DEFAULT.replace('c-', 'd-'),
    DEFAULT.toUpperCase(), ` ${DEFAULT}`, `${DEFAULT}.swf`, '../server.js', 'c-1zzzzzzzzzzzzz', null, undefined, 42, {},
  ];
  for (const code of bad) assert.equal(A.parseCode(code), null, String(code));
  // Each field one past its last option.
  A.FIELDS.forEach((f, i) => {
    const code = DEFAULT.slice(0, 3 + i) + '0123456789abcdefghijklmnopqrstuvwxyz'[f.count] + DEFAULT.slice(4 + i);
    assert.equal(A.parseCode(code), null, f.key);
  });
  assert.throws(() => A.encode({ ...A.DEFAULTS, hat: 99 }));
  assert.throws(() => A.encode({ ...A.DEFAULTS, skin: -1 }));
  assert.throws(() => A.encode({ ...A.DEFAULTS, eyes: 1.5 }));
});

test('files: only the four names of a valid code', () => {
  assert.ok(maker.isName(`${DEFAULT}.swf`));
  assert.ok(maker.isName(`${DEFAULT}-still.jpg`));
  assert.ok(maker.isName(`${DEFAULT}-large.png`));
  assert.ok(maker.isName(`${DEFAULT}.png`));
  for (const n of [`${DEFAULT}.gif`, `${DEFAULT}-still.png`, `${DEFAULT}`, 'pirate.swf', 'c-19999999999999.swf', `x${DEFAULT}.swf`]) {
    assert.equal(maker.isName(n), false, n);
    assert.equal(maker.file(n), null, n);
  }
  assert.equal(maker.file(`${DEFAULT}-large.png`, 'nope'), null);
  assert.equal(maker.file(`${DEFAULT}.swf`, 'smile'), null);
  assert.equal(maker.file(`${DEFAULT}-large.png`, 'love').type, 'image/png');
});

// ------------------------------------------------------------------- the movie

const ALLOWED_TAGS = new Set([0, 1, 9, 12, 26, 28, 32, 39, 43]);
// End, Stop, Not, Pop, GetVariable, SetVariable, Return, Equals2, GetMember,
// SetMember, CallMethod, Push, DefineFunction, If.
const ALLOWED_OPS = new Set([0x00, 0x07, 0x12, 0x17, 0x1c, 0x1d, 0x3e, 0x49, 0x4e, 0x4f, 0x52, 0x96, 0x9b, 0x9d]);

test('movie: AVM1, SWF 6, 53x65 at 24 fps, one root frame', () => {
  const swf = readSwf(A.buildMovie(A.DEFAULTS));
  assert.equal(swf.version, 6);
  assert.deepEqual(swf.rect, [0, 53 * 20, 0, 65 * 20]);
  assert.equal(swf.fps, 24);
  assert.equal(swf.frameCount, 1);
});

test('movie: a clip named face with the nine emotion labels, each an animation that stops the face', () => {
  const swf = readSwf(A.buildMovie(A.DEFAULTS));
  const sprites = new Map(all(swf.tags).filter((t) => t.code === 39).map((t) => [t.id, t]));
  const place = swf.tags.find((t) => t.code === 26 && t.data[0] & 0x20);
  assert.ok(place, 'a named placement');
  const faceId = place.data.readUInt16LE(3);
  assert.equal(cstr(place.data, place.data.length - 5), 'face');
  const face = sprites.get(faceId);
  assert.equal(face.frames, 9);
  const labels = face.tags.filter((t) => t.code === 43).map((t) => cstr(t.data));
  assert.deepEqual(labels, ['stam', 'smile', 'sad', 'laugh', 'mad', 'cry', 'love', 'busy', 'offline']);
  // Every frame of the face stops, and places one animation.
  assert.equal(face.tags.filter((t) => t.code === 12 && t.data[0] === 0x07).length, 9);
  const anims = face.tags.filter((t) => t.code === 26).map((t) => t.data.readUInt16LE(3));
  assert.equal(anims.length, 9);
  for (const id of anims) {
    assert.ok(sprites.has(id), `animation ${id}`);
    assert.ok(sprites.get(id).frames >= 1);
  }
  // The moods move: all but offline have more than one frame.
  assert.deepEqual(anims.map((id) => sprites.get(id).frames > 1), [true, true, true, true, true, true, true, true, false]);
});

test('movie: the emotion property, and nothing that reaches outside', () => {
  const swf = readSwf(A.buildMovie(A.DEFAULTS));
  const tags = all(swf.tags);
  for (const t of tags) assert.ok(ALLOWED_TAGS.has(t.code), `tag ${t.code}`);
  const code = tags.filter((t) => t.code === 12).map((t) => actions(t.data));
  for (const { ops } of code) for (const op of ops) assert.ok(ALLOWED_OPS.has(op), `op 0x${op.toString(16)}`);
  const strings = code.flatMap((c) => c.strings);
  for (const s of ['face', 'emotion', 'addProperty', 'gotoAndPlay', 'initEmo', 'stam', '_root', 'this']) {
    assert.ok(strings.includes(s), s);
  }
  for (const s of strings) {
    assert.doesNotMatch(s, /url|load|fscommand|xml|socket|connection|netstream|sound|external|shared|local|security/i, s);
  }
});

test('movie: the same code gives the same bytes, another code other bytes', () => {
  assert.ok(A.buildMovie(A.DEFAULTS).equals(A.buildMovie({ ...A.DEFAULTS })));
  assert.ok(!A.buildMovie(A.DEFAULTS).equals(A.buildMovie({ ...A.DEFAULTS, hat: 1 })));
  assert.ok(A.still(A.DEFAULTS).equals(A.still({ ...A.DEFAULTS })));
  assert.ok(A.large(A.DEFAULTS, 'love').equals(A.large({ ...A.DEFAULTS }, 'love')));
});

test('movie and pictures: every option of every part builds', () => {
  for (const f of A.FIELDS) {
    for (let v = 0; v < f.count; v++) {
      const p = { ...A.DEFAULTS, [f.key]: v };
      const swf = readSwf(A.buildMovie(p));
      assert.equal(swf.frameCount, 1, `${f.key}=${v}`);
      assert.ok(A.still(p).length > 500, `${f.key}=${v}`);
    }
  }
});

// ------------------------------------------------------------------- pictures

function jpegSize(b) {
  assert.equal(b.readUInt16BE(0), 0xffd8);
  assert.equal(b.readUInt16BE(b.length - 2), 0xffd9);
  let i = 2;
  while (i < b.length) {
    const marker = b.readUInt16BE(i);
    const len = b.readUInt16BE(i + 2);
    if (marker === 0xffc0) return { w: b.readUInt16BE(i + 7), h: b.readUInt16BE(i + 5), comps: b[i + 9] };
    i += 2 + len;
  }
  throw new Error('no SOF0');
}

function pngInfo(b) {
  assert.equal(b.toString('latin1', 1, 4), 'PNG');
  assert.equal(b.toString('latin1', 12, 16), 'IHDR');
  // Every chunk's CRC holds.
  for (let i = 8; i < b.length;) {
    const len = b.readUInt32BE(i);
    assert.equal(b.readUInt32BE(i + 8 + len), zlib.crc32(b.subarray(i + 4, i + 8 + len)) >>> 0);
    i += 12 + len;
  }
  return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
}

test('pictures: a 52x64 baseline JPEG still, well under the IM server limit', () => {
  const still = A.still(A.DEFAULTS);
  assert.deepEqual(jpegSize(still), { w: 52, h: 64, comps: 3 });
  assert.ok(still.length < 256 * 1024);
});

test('pictures: the large PNG at twice the stage, the thumbnail at 52x64, their pixels decode', () => {
  const large = A.large(A.DEFAULTS);
  assert.deepEqual(pngInfo(large), { w: 106, h: 130 });
  assert.deepEqual(pngInfo(A.thumb(A.DEFAULTS)), { w: 52, h: 64 });
  // The image data inflates to the rows it should have.
  const idat = [];
  for (let i = 8; i < large.length;) {
    const len = large.readUInt32BE(i);
    if (large.toString('latin1', i + 4, i + 8) === 'IDAT') idat.push(large.subarray(i + 8, i + 8 + len));
    i += 12 + len;
  }
  const raw = zlib.inflateSync(Buffer.concat(idat));
  assert.equal(raw.length, (106 * 3 + 1) * 130);
  // Not a blank picture: the face is drawn over the background.
  const colours = new Set();
  for (let y = 0; y < 130; y += 5) for (let x = 0; x < 106; x += 5) {
    const k = y * (106 * 3 + 1) + 1 + x * 3;
    colours.add(raw.readUIntBE(k, 3));
  }
  assert.ok(colours.size > 10, `${colours.size} colours`);
});

test('pictures: each emotion has its own large picture', () => {
  const seen = new Set(A.EMOTIONS.map((e) => A.large(A.DEFAULTS, e).toString('base64')));
  assert.equal(seen.size, A.EMOTIONS.length);
});

// ------------------------------------------------------------------- cache

test('cache: capped by bytes, the least recently used goes first', () => {
  const c = maker.lru(10);
  c.set('a', Buffer.alloc(4));
  c.set('b', Buffer.alloc(4));
  c.get('a');
  c.set('c', Buffer.alloc(4));
  assert.ok(c.get('a'));
  assert.equal(c.get('b'), undefined);
  assert.ok(c.get('c'));
  assert.equal(c.bytes, 8);
});
