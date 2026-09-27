// The vector primitives both pictures of a constructed avatar are made from:
// the movie (maker/swf.js) and the stills (maker/raster.js).
//
// A primitive is { contours, fill, line }: contours in stage pixels (the
// movie's 53x65), made of straight and quadratic segments, which is all a
// SWF shape has; fill an [r, g, b, a] colour or null; line { width, color }
// or null. Primitives are painted in order.

'use strict';

class Contour {
  constructor(start, segs = [], closed = false) {
    this.start = start;
    this.segs = segs; // { p: [x, y], c?: [x, y] }
    this.closed = closed;
  }

  end() {
    return this.segs.length ? this.segs[this.segs.length - 1].p : this.start;
  }

  // Every point, control points included: enough for bounds.
  points() {
    const out = [this.start];
    for (const s of this.segs) { if (s.c) out.push(s.c); out.push(s.p); }
    return out;
  }

  // Straight pieces, with each curve cut into `steps` pieces.
  flatten(steps = 8) {
    const out = [this.start];
    let p0 = this.start;
    for (const s of this.segs) {
      if (s.c) {
        for (let i = 1; i <= steps; i++) {
          const t = i / steps;
          const u = 1 - t;
          out.push([u * u * p0[0] + 2 * u * t * s.c[0] + t * t * s.p[0],
            u * u * p0[1] + 2 * u * t * s.c[1] + t * t * s.p[1]]);
        }
      } else {
        out.push(s.p);
      }
      p0 = s.p;
    }
    return out;
  }

  // The same contour, clockwise on screen (y grows down).
  clockwise() {
    const pts = this.flatten(4);
    let area = 0;
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i];
      const b = pts[(i + 1) % pts.length];
      area += a[0] * b[1] - b[0] * a[1];
    }
    return area >= 0 ? this : this.reversed();
  }

  reversed() {
    const nodes = [this.start, ...this.segs.map((s) => s.p)];
    const segs = [];
    for (let i = this.segs.length - 1; i >= 0; i--) {
      segs.push(this.segs[i].c ? { p: nodes[i], c: this.segs[i].c } : { p: nodes[i] });
    }
    return new Contour(this.end(), segs, this.closed);
  }

  map(fn) {
    return new Contour(fn(this.start), this.segs.map((s) => (s.c ? { p: fn(s.p), c: fn(s.c) } : { p: fn(s.p) })), this.closed);
  }
}

// Contours from a path string with absolute M, L, Q and Z, numbers separated
// by spaces or commas. A filled contour is closed back to its start anyway.
function path(d) {
  const tokens = String(d).trim().split(/[\s,]+|(?=[MLQZ])|(?<=[MLQZ])/i).filter(Boolean);
  const contours = [];
  let cur = null;
  let i = 0;
  const num = () => Number(tokens[i++]);
  let cmd = '';
  while (i < tokens.length) {
    if (/^[MLQZ]$/i.test(tokens[i])) cmd = tokens[i++].toUpperCase();
    if (cmd === 'M') {
      cur = new Contour([num(), num()]);
      contours.push(cur);
      cmd = 'L';
    } else if (cmd === 'L') {
      cur.segs.push({ p: [num(), num()] });
    } else if (cmd === 'Q') {
      const c = [num(), num()];
      cur.segs.push({ c, p: [num(), num()] });
    } else if (cmd === 'Z') {
      const e = cur.end();
      if (e[0] !== cur.start[0] || e[1] !== cur.start[1]) cur.segs.push({ p: cur.start.slice() });
      cur.closed = true;
    } else {
      throw new Error(`path: unexpected ${tokens[i]}`);
    }
  }
  return contours;
}

// An ellipse as eight quadratic curves (the control points on the corners of
// the octagon around it).
function ellipse(cx, cy, rx, ry) {
  const segs = [];
  for (let i = 1; i <= 8; i++) {
    const a = (i * Math.PI) / 4;
    const m = a - Math.PI / 8;
    segs.push({
      c: [cx + (rx * Math.cos(m)) / Math.cos(Math.PI / 8), cy + (ry * Math.sin(m)) / Math.cos(Math.PI / 8)],
      p: [cx + rx * Math.cos(a), cy + ry * Math.sin(a)],
    });
  }
  return [new Contour([cx + rx, cy], segs, true)];
}

const circle = (cx, cy, r) => ellipse(cx, cy, r, r);

function poly(points, closed = true) {
  const c = new Contour(points[0], points.slice(1).map((p) => ({ p })), closed);
  if (closed) c.segs.push({ p: points[0].slice() });
  return [c];
}

// A primitive. fill/line colours are [r, g, b] or [r, g, b, a].
function prim(contours, fill, line) {
  const rgba = (c) => (c.length === 3 ? [...c, 255] : c);
  return {
    contours,
    fill: fill ? rgba(fill) : null,
    line: line ? { width: line.width, color: rgba(line.color) } : null,
  };
}

// Primitives moved and scaled: p -> [x * s + dx, y * s + dy].
function transform(prims, { dx = 0, dy = 0, s = 1 } = {}) {
  const fn = (p) => [p[0] * s + dx, p[1] * s + dy];
  return prims.map((p) => ({
    contours: p.contours.map((c) => c.map(fn)),
    fill: p.fill,
    line: p.line ? { width: p.line.width * s, color: p.line.color } : null,
  }));
}

// Every colour through fn (the grey face of "offline").
function recolor(prims, fn) {
  return prims.map((p) => ({
    contours: p.contours,
    fill: p.fill ? fn(p.fill) : null,
    line: p.line ? { width: p.line.width, color: fn(p.line.color) } : null,
  }));
}

module.exports = { Contour, path, ellipse, circle, poly, prim, transform, recolor };
