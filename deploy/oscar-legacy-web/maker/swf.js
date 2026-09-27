// A small SWF writer: just what a constructed avatar needs, and nothing that
// reaches outside the movie.
//
//   shapes    DefineShape3 from our own vector primitives (maker/vector.js),
//             painted in order: every primitive after the first opens a new
//             style group, so a later one covers an earlier one as it does
//             on the raster pictures.
//   sprites   DefineSprite whose frames are display lists (depth -> the
//             character, where it stands, its colour transform); the writer
//             places, moves, replaces and removes to get from one frame to
//             the next.
//   actions   a tiny AVM1 assembler for the emotion property (see avatar.js).
//
// The output is deterministic: the same description gives the same bytes.

'use strict';

const zlib = require('node:zlib');

// ------------------------------------------------------------------- bits

class Bits {
  constructor() { this.bytes = []; this.acc = 0; this.n = 0; }

  put(value, width) {
    for (let i = width - 1; i >= 0; i--) {
      this.acc = (this.acc << 1) | ((value >>> i) & 1);
      this.n += 1;
      if (this.n === 8) { this.bytes.push(this.acc & 0xff); this.acc = 0; this.n = 0; }
    }
  }

  // A signed value in `width` bits, two's complement.
  sput(value, width) {
    this.put(width === 32 ? value >>> 0 : (value & ((1 << width) - 1)) >>> 0, width);
  }

  align() {
    if (this.n > 0) this.put(0, 8 - this.n);
  }

  // Whole bytes; aligns first.
  raw(buf) {
    this.align();
    for (const b of buf) this.bytes.push(b);
  }

  buffer() {
    this.align();
    return Buffer.from(this.bytes);
  }
}

// Bits needed for a signed value (at least 1).
function sbits(...values) {
  let n = 1;
  for (const v of values) {
    const x = v < 0 ? ~v : v;
    let b = 1;
    while (x >= 2 ** (b - 1)) b += 1;
    n = Math.max(n, b);
  }
  return n;
}

function ubits(v) {
  let b = 0;
  while (v >= 2 ** b) b += 1;
  return b;
}

const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; };
const cstr = (s) => Buffer.from(`${s}\0`, 'latin1');

// ------------------------------------------------------------------- records

function rect(bits, xmin, xmax, ymin, ymax) {
  const n = sbits(xmin, xmax, ymin, ymax);
  bits.put(n, 5);
  for (const v of [xmin, xmax, ymin, ymax]) bits.sput(v, n);
}

// { sx, sy, tx, ty }: scale (1 = none) and translation in twips.
function matrix(m) {
  const bits = new Bits();
  const sx = Math.round((m.sx ?? 1) * 65536);
  const sy = Math.round((m.sy ?? 1) * 65536);
  if (sx !== 65536 || sy !== 65536) {
    const n = sbits(sx, sy);
    bits.put(1, 1); bits.put(n, 5); bits.sput(sx, n); bits.sput(sy, n);
  } else {
    bits.put(0, 1);
  }
  bits.put(0, 1); // no rotation
  const tx = m.tx || 0;
  const ty = m.ty || 0;
  if (tx === 0 && ty === 0) {
    bits.put(0, 5);
  } else {
    const n = sbits(tx, ty);
    bits.put(n, 5); bits.sput(tx, n); bits.sput(ty, n);
  }
  return bits.buffer();
}

// { mul: [r,g,b,a], add: [r,g,b,a] } in 8.8 fixed (256 = 1) and -255..255.
function cxform(c) {
  const bits = new Bits();
  const mul = c.mul || [256, 256, 256, 256];
  const add = c.add || [0, 0, 0, 0];
  const hasMul = mul.some((v) => v !== 256);
  const hasAdd = add.some((v) => v !== 0);
  const n = sbits(...(hasMul ? mul : []), ...(hasAdd ? add : []), 0);
  bits.put(hasAdd ? 1 : 0, 1);
  bits.put(hasMul ? 1 : 0, 1);
  bits.put(n, 4);
  if (hasMul) for (const v of mul) bits.sput(v, n);
  if (hasAdd) for (const v of add) bits.sput(v, n);
  return bits.buffer();
}

function tag(code, body) {
  if (body.length < 0x3f && code !== 2 && code !== 32 && code !== 39) {
    return Buffer.concat([u16((code << 6) | body.length), body]);
  }
  return Buffer.concat([u16((code << 6) | 0x3f), u32(body.length), body]);
}

// ------------------------------------------------------------------- shapes

const TW = 20; // twips per pixel

// The styles of one primitive as a byte-aligned style array pair.
function styleArrays(prim) {
  const out = [];
  if (prim.fill) {
    out.push(1, 0x00, ...prim.fill.map((v) => v & 0xff));
  } else {
    out.push(0);
  }
  if (prim.line) {
    out.push(1, ...u16(Math.max(1, Math.round(prim.line.width * TW))), ...prim.line.color.map((v) => v & 0xff));
  } else {
    out.push(0);
  }
  return Buffer.from(out);
}

// DefineShape3 of a list of primitives (see vector.js). Contours of a filled
// primitive are made clockwise on screen and filled on their right, as the
// Flash authoring tool writes them.
function defineShape(id, prims) {
  const bits = new Bits();
  let xmin = Infinity; let ymin = Infinity; let xmax = -Infinity; let ymax = -Infinity;
  for (const p of prims) {
    const pad = p.line ? p.line.width / 2 : 0;
    for (const c of p.contours) {
      for (const pt of c.points()) {
        xmin = Math.min(xmin, pt[0] - pad); xmax = Math.max(xmax, pt[0] + pad);
        ymin = Math.min(ymin, pt[1] - pad); ymax = Math.max(ymax, pt[1] + pad);
      }
    }
  }
  if (!Number.isFinite(xmin)) { xmin = 0; ymin = 0; xmax = 0; ymax = 0; }
  const head = new Bits();
  head.raw(u16(id));
  rect(head, Math.floor(xmin * TW), Math.ceil(xmax * TW), Math.floor(ymin * TW), Math.ceil(ymax * TW));
  const headBuf = head.buffer();

  let x = 0; let y = 0;
  prims.forEach((p, i) => {
    const styles = styleArrays(p);
    const fillBits = p.fill ? 1 : 0;
    const lineBits = p.line ? 1 : 0;
    if (i === 0) {
      bits.raw(styles);
    } else {
      // A record with new styles only: the arrays, then their bit counts.
      bits.put(0, 1); bits.put(1, 1); bits.put(0, 4);
      bits.raw(styles);
    }
    bits.put(fillBits, 4); bits.put(lineBits, 4);
    let first = true;
    for (const contour0 of p.contours) {
      const contour = p.fill ? contour0.clockwise() : contour0;
      const sx = Math.round(contour.start[0] * TW);
      const sy = Math.round(contour.start[1] * TW);
      // Style change: move to the start, and on the first contour set all
      // three styles (fill on the right: fill style 1). A style this
      // primitive does not have is set to 0 explicitly, in zero bits: the
      // previous primitive's must not carry over into the new arrays.
      bits.put(0, 1); bits.put(0, 1);
      bits.put(first ? 1 : 0, 1); // line style
      bits.put(first ? 1 : 0, 1); // fill style 1
      bits.put(first ? 1 : 0, 1); // fill style 0
      bits.put(1, 1);
      const n = sbits(sx, sy);
      bits.put(n, 5); bits.sput(sx, n); bits.sput(sy, n);
      if (first) {
        bits.put(0, fillBits); // fill style 0: none
        bits.put(fillBits, fillBits); // fill style 1: the fill, or none
        bits.put(lineBits, lineBits); // the line, or none
      }
      first = false;
      x = sx; y = sy;
      for (const seg of contour.segs) {
        const ax = Math.round(seg.p[0] * TW);
        const ay = Math.round(seg.p[1] * TW);
        if (seg.c) {
          const cx = Math.round(seg.c[0] * TW);
          const cy = Math.round(seg.c[1] * TW);
          const d = [cx - x, cy - y, ax - cx, ay - cy];
          if (d.every((v) => v === 0)) continue;
          const nb = Math.max(2, sbits(...d));
          bits.put(1, 1); bits.put(0, 1); bits.put(nb - 2, 4);
          for (const v of d) bits.sput(v, nb);
        } else {
          const dx = ax - x;
          const dy = ay - y;
          if (dx === 0 && dy === 0) continue;
          const nb = Math.max(2, sbits(dx, dy));
          bits.put(1, 1); bits.put(1, 1); bits.put(nb - 2, 4);
          bits.put(1, 1); // general line
          bits.sput(dx, nb); bits.sput(dy, nb);
        }
        x = ax; y = ay;
      }
    }
  });
  bits.put(0, 6); // end of shape
  return tag(32, Buffer.concat([headBuf, bits.buffer()]));
}

// ------------------------------------------------------------------- display

function placeObject2({ depth, id, move, m, cx, name }) {
  let flags = 0;
  if (move) flags |= 0x01;
  if (id != null) flags |= 0x02;
  if (m) flags |= 0x04;
  if (cx) flags |= 0x08;
  if (name) flags |= 0x20;
  const parts = [Buffer.from([flags]), u16(depth)];
  if (id != null) parts.push(u16(id));
  if (m) parts.push(matrix(m));
  if (cx) parts.push(cxform(cx));
  if (name) parts.push(cstr(name));
  return tag(26, Buffer.concat(parts));
}

const removeObject2 = (depth) => tag(28, u16(depth));
const showFrame = () => tag(1, Buffer.alloc(0));
const frameLabel = (name) => tag(43, cstr(name));
const doAction = (bytes) => tag(12, bytes);
const endTag = () => tag(0, Buffer.alloc(0));

const sameM = (a, b) => JSON.stringify(a || null) === JSON.stringify(b || null);

// The control tags for a list of frames, each a Map depth -> { id, m, cx,
// name } plus optional { label, actions } on the frame. The first frame is
// written in full, so that a loop back to it starts clean.
function timeline(frames) {
  const out = [];
  let prev = new Map();
  for (const f of frames) {
    if (f.label) out.push(frameLabel(f.label));
    const now = f.list;
    for (const depth of [...prev.keys()].sort((a, b) => a - b)) {
      if (!now.has(depth)) out.push(removeObject2(depth));
    }
    for (const depth of [...now.keys()].sort((a, b) => a - b)) {
      const want = now.get(depth);
      const had = prev.get(depth);
      if (!had || had.id !== want.id) {
        if (had) out.push(removeObject2(depth));
        out.push(placeObject2({ depth, id: want.id, m: want.m, cx: want.cx, name: want.name }));
      } else if (!sameM(had.m, want.m) || !sameM(had.cx, want.cx)) {
        out.push(placeObject2({
          depth, move: true,
          m: want.m || { sx: 1, sy: 1, tx: 0, ty: 0 },
          cx: want.cx || (had.cx ? {} : undefined),
        }));
      }
    }
    if (f.actions) out.push(doAction(f.actions));
    out.push(showFrame());
    prev = now;
  }
  return out;
}

function defineSprite(id, frames) {
  return tag(39, Buffer.concat([u16(id), u16(frames.length), ...timeline(frames), endTag()]));
}

// ------------------------------------------------------------------- actions

// An AVM1 assembler: push values, name ops, labels and branches.
const OP = {
  End: 0x00, Stop: 0x07, Pop: 0x17, GetVariable: 0x1c, SetVariable: 0x1d,
  Not: 0x12, Equals2: 0x49, GetMember: 0x4e, SetMember: 0x4f,
  CallMethod: 0x52, Return: 0x3e,
};

class Asm {
  constructor() { this.parts = []; this.labels = new Map(); this.fixups = []; }

  op(name) { this.parts.push(Buffer.from([OP[name]])); return this; }

  // Strings, integers, undefined (undefined) and booleans.
  push(...values) {
    const data = Buffer.concat(values.map((v) => {
      if (v === undefined) return Buffer.from([3]);
      if (typeof v === 'boolean') return Buffer.from([5, v ? 1 : 0]);
      if (typeof v === 'number') { const b = Buffer.alloc(5); b[0] = 7; b.writeInt32LE(v, 1); return b; }
      return Buffer.concat([Buffer.from([0]), cstr(v)]);
    }));
    this.parts.push(Buffer.concat([Buffer.from([0x96]), u16(data.length), data]));
    return this;
  }

  // If (0x9D) to a label: taken when the value on the stack is true.
  ifTrue(label) {
    const b = Buffer.from([0x9d, 2, 0, 0, 0]);
    this.parts.push(b);
    this.fixups.push({ at: this.parts.length - 1, label });
    return this;
  }

  label(name) { this.labels.set(name, this.parts.length); return this; }

  // DefineFunction (0x9B), anonymous: pushes the function.
  fn(params, body) {
    const code = body.bytes(false);
    const head = Buffer.concat([
      Buffer.from([0]), // no name
      u16(params.length), ...params.map(cstr), u16(code.length),
    ]);
    this.parts.push(Buffer.concat([Buffer.from([0x9b]), u16(head.length), head]), code);
    return this;
  }

  bytes(end = true) {
    // Resolve branches: offsets count from the end of the If.
    const offsetOf = (idx) => this.parts.slice(0, idx).reduce((n, p) => n + p.length, 0);
    for (const f of this.fixups) {
      const from = offsetOf(f.at + 1);
      const to = offsetOf(this.labels.get(f.label));
      this.parts[f.at].writeInt16LE(to - from, 3);
    }
    return Buffer.concat([...this.parts, ...(end ? [Buffer.from([0])] : [])]);
  }
}

// ------------------------------------------------------------------- movie

// The whole file: header, then tags, CWS (zlib) compressed.
function movie({ width, height, fps, frameCount, tags, version = 6 }) {
  const head = new Bits();
  rect(head, 0, width * TW, 0, height * TW);
  const body = Buffer.concat([
    head.buffer(),
    Buffer.from([Math.round((fps % 1) * 256), Math.floor(fps)]),
    u16(frameCount),
    ...tags,
  ]);
  const packed = zlib.deflateSync(body, { level: 9 });
  return Buffer.concat([Buffer.from('CWS', 'latin1'), Buffer.from([version]), u32(body.length + 8), packed]);
}

const setBackgroundColor = (rgb) => tag(9, Buffer.from(rgb));

module.exports = {
  TW, Bits, sbits, ubits, matrix, cxform, tag, defineShape, defineSprite, placeObject2,
  removeObject2, showFrame, frameLabel, doAction, endTag, timeline, Asm, movie, setBackgroundColor,
};
