// The still pictures of a constructed avatar, drawn from the same primitives
// as its movie (maker/vector.js), with no Flash and no dependencies: a small
// anti-aliased rasteriser, and PNG and baseline JPEG encoders.

'use strict';

const zlib = require('node:zlib');

// Four sample rows per pixel row; across a row the coverage is exact.
const SUB = 4;

class Canvas {
  // The stage (w x h pixels of the movie) drawn at sx, sy.
  constructor(width, height, sx = 1, sy = sx) {
    this.w = width;
    this.h = height;
    this.sx = sx;
    this.sy = sy;
    this.px = new Float32Array(width * height * 3).fill(255);
  }

  fillRGB(rgb) {
    for (let i = 0; i < this.w * this.h; i++) {
      this.px[i * 3] = rgb[0]; this.px[i * 3 + 1] = rgb[1]; this.px[i * 3 + 2] = rgb[2];
    }
  }

  blend(i, cov, color) {
    const a = cov * (color[3] / 255);
    if (a <= 0) return;
    const k = i * 3;
    this.px[k] += (color[0] - this.px[k]) * a;
    this.px[k + 1] += (color[1] - this.px[k + 1]) * a;
    this.px[k + 2] += (color[2] - this.px[k + 2]) * a;
  }

  // Non-zero fill of closed polygons (canvas pixels).
  fillPolys(polys, color) {
    const edges = [];
    let ymin = Infinity; let ymax = -Infinity;
    for (const pts of polys) {
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i];
        const b = pts[(i + 1) % pts.length];
        if (a[1] === b[1]) continue;
        edges.push(a[1] < b[1] ? [a[0], a[1], b[0], b[1], 1] : [b[0], b[1], a[0], a[1], -1]);
        ymin = Math.min(ymin, a[1], b[1]); ymax = Math.max(ymax, a[1], b[1]);
      }
    }
    if (!edges.length) return;
    const y0 = Math.max(0, Math.floor(ymin));
    const y1 = Math.min(this.h - 1, Math.ceil(ymax));
    const row = new Float32Array(this.w + 2);
    for (let y = y0; y <= y1; y++) {
      row.fill(0);
      let any = false;
      for (let s = 0; s < SUB; s++) {
        const sy = y + (s + 0.5) / SUB;
        const xs = [];
        for (const e of edges) {
          if (sy < e[1] || sy >= e[3]) continue;
          xs.push([e[0] + ((sy - e[1]) * (e[2] - e[0])) / (e[3] - e[1]), e[4]]);
        }
        if (xs.length < 2) continue;
        xs.sort((p, q) => p[0] - q[0]);
        let wind = 0;
        for (let j = 0; j < xs.length - 1; j++) {
          wind += xs[j][1];
          if (wind !== 0) { this.span(row, xs[j][0], xs[j + 1][0], 1 / SUB); any = true; }
        }
      }
      if (!any) continue;
      for (let x = 0; x < this.w; x++) {
        if (row[x] > 0) this.blend(y * this.w + x, Math.min(1, row[x]), color);
      }
    }
  }

  // Adds `weight` times the covered part of each pixel between xa and xb.
  span(row, xa, xb, weight) {
    const a = Math.max(0, xa);
    const b = Math.min(this.w, xb);
    if (b <= a) return;
    const ia = Math.floor(a);
    const ib = Math.floor(b);
    if (ia === ib) { row[ia] += (b - a) * weight; return; }
    row[ia] += (ia + 1 - a) * weight;
    for (let x = ia + 1; x < ib; x++) row[x] += weight;
    if (ib < this.w) row[ib] += (b - ib) * weight;
  }

  // A line of the given width with round ends and joins, by the distance of
  // each pixel from the polyline.
  strokePolyline(pts, width, color) {
    const hw = width / 2;
    let xmin = Infinity; let ymin = Infinity; let xmax = -Infinity; let ymax = -Infinity;
    for (const p of pts) {
      xmin = Math.min(xmin, p[0]); xmax = Math.max(xmax, p[0]);
      ymin = Math.min(ymin, p[1]); ymax = Math.max(ymax, p[1]);
    }
    const x0 = Math.max(0, Math.floor(xmin - hw - 1));
    const x1 = Math.min(this.w - 1, Math.ceil(xmax + hw + 1));
    const y0 = Math.max(0, Math.floor(ymin - hw - 1));
    const y1 = Math.min(this.h - 1, Math.ceil(ymax + hw + 1));
    // A line thinner than a pixel is drawn one pixel wide and fainter.
    const faint = Math.min(1, width);
    const r = Math.max(hw, 0.5);
    for (let y = y0; y <= y1; y++) {
      for (let x = x0; x <= x1; x++) {
        const px = x + 0.5;
        const py = y + 0.5;
        let d = Infinity;
        for (let i = 0; i < pts.length - 1; i++) {
          const a = pts[i];
          const b = pts[i + 1];
          const vx = b[0] - a[0];
          const vy = b[1] - a[1];
          const len = vx * vx + vy * vy;
          let t = len ? ((px - a[0]) * vx + (py - a[1]) * vy) / len : 0;
          t = Math.max(0, Math.min(1, t));
          const dx = px - (a[0] + t * vx);
          const dy = py - (a[1] + t * vy);
          d = Math.min(d, Math.sqrt(dx * dx + dy * dy));
        }
        const cov = Math.max(0, Math.min(1, r + 0.5 - d)) * faint;
        if (cov > 0) this.blend(y * this.w + x, cov, color);
      }
    }
  }

  // Primitives in stage pixels, painted in order.
  draw(prims) {
    const toCanvas = (p) => [p[0] * this.sx, p[1] * this.sy];
    const scale = (this.sx + this.sy) / 2;
    for (const p of prims) {
      const steps = 10;
      if (p.fill) {
        this.fillPolys(p.contours.map((c) => c.flatten(steps).map(toCanvas)), p.fill);
      }
      if (p.line) {
        for (const c of p.contours) {
          this.strokePolyline(c.flatten(steps).map(toCanvas), p.line.width * scale, p.line.color);
        }
      }
    }
  }

  rgb() {
    const out = Buffer.alloc(this.w * this.h * 3);
    for (let i = 0; i < out.length; i++) out[i] = Math.max(0, Math.min(255, Math.round(this.px[i])));
    return out;
  }
}

// ------------------------------------------------------------------- PNG

function png(width, height, rgb) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(td) >>> 0);
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 2; // 8-bit RGB
  const raw = Buffer.alloc((width * 3 + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width * 3 + 1)] = 0;
    rgb.copy(raw, y * (width * 3 + 1) + 1, y * width * 3, (y + 1) * width * 3);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// ------------------------------------------------------------------- JPEG
//
// Baseline JPEG, YCbCr without subsampling, the example tables of the
// standard (ITU T.81 Annex K) scaled for the quality as libjpeg does.

const ZIGZAG = [
  0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21,
  28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61,
  54, 47, 55, 62, 63,
];
const Q_LUMA = [
  16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51,
  87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92, 49, 64, 78, 87, 103, 121, 120,
  101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const Q_CHROMA = [
  17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99,
  99, 99, 99, ...new Array(32).fill(99),
];
const DC_LUMA = { bits: [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0], vals: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] };
const DC_CHROMA = { bits: [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0], vals: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] };
const AC_LUMA = {
  bits: [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d],
  vals: [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07, 0x22, 0x71,
    0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3,
    0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
  ],
};
const AC_CHROMA = {
  bits: [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77],
  vals: [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71, 0x13, 0x22,
    0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0, 0x15, 0x62, 0x72, 0xd1,
    0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
    0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
    0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
  ],
};

// symbol -> [code, length] from the counts per length.
function huffCodes({ bits, vals }) {
  const codes = new Map();
  let code = 0;
  let k = 0;
  for (let len = 1; len <= 16; len++) {
    for (let i = 0; i < bits[len - 1]; i++) codes.set(vals[k++], [code++, len]);
    code <<= 1;
  }
  return codes;
}

function scaledTable(base, quality) {
  const q = Math.max(1, Math.min(100, quality));
  const s = q < 50 ? 5000 / q : 200 - q * 2;
  return base.map((v) => Math.max(1, Math.min(255, Math.floor((v * s + 50) / 100))));
}

const COS = [];
for (let x = 0; x < 8; x++) for (let u = 0; u < 8; u++) COS.push(Math.cos(((2 * x + 1) * u * Math.PI) / 16));
const C = (u) => (u === 0 ? Math.SQRT1_2 : 1);

// The 2-D DCT of an 8x8 block (row major), by rows then columns.
function dct(block) {
  const tmp = new Float64Array(64);
  const out = new Float64Array(64);
  for (let y = 0; y < 8; y++) {
    for (let u = 0; u < 8; u++) {
      let s = 0;
      for (let x = 0; x < 8; x++) s += block[y * 8 + x] * COS[x * 8 + u];
      tmp[y * 8 + u] = s * C(u) / 2;
    }
  }
  for (let u = 0; u < 8; u++) {
    for (let v = 0; v < 8; v++) {
      let s = 0;
      for (let y = 0; y < 8; y++) s += tmp[y * 8 + u] * COS[y * 8 + v];
      out[v * 8 + u] = s * C(v) / 2;
    }
  }
  return out;
}

function jpeg(width, height, rgb, quality = 92) {
  const qt = [scaledTable(Q_LUMA, quality), scaledTable(Q_CHROMA, quality)];
  const huff = [
    { dc: huffCodes(DC_LUMA), ac: huffCodes(AC_LUMA) },
    { dc: huffCodes(DC_CHROMA), ac: huffCodes(AC_CHROMA) },
  ];
  const out = [];
  const seg = (marker, data) => {
    out.push(0xff, marker, ((data.length + 2) >> 8) & 0xff, (data.length + 2) & 0xff, ...data);
  };
  out.push(0xff, 0xd8);
  seg(0xe0, [0x4a, 0x46, 0x49, 0x46, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0]);
  // DQT: the tables in zigzag order.
  seg(0xdb, [0, ...ZIGZAG.map((i) => qt[0][i]), 1, ...ZIGZAG.map((i) => qt[1][i])]);
  seg(0xc0, [8, height >> 8, height & 0xff, width >> 8, width & 0xff, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]);
  const dht = (cls, id, t) => [(cls << 4) | id, ...t.bits, ...t.vals];
  seg(0xc4, [...dht(0, 0, DC_LUMA), ...dht(1, 0, AC_LUMA), ...dht(0, 1, DC_CHROMA), ...dht(1, 1, AC_CHROMA)]);
  seg(0xda, [3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]);

  // The entropy-coded data, with 0xFF stuffed.
  let acc = 0; let nacc = 0;
  const data = [];
  const put = (code, len) => {
    for (let i = len - 1; i >= 0; i--) {
      acc = (acc << 1) | ((code >> i) & 1);
      if (++nacc === 8) { data.push(acc); if (acc === 0xff) data.push(0); acc = 0; nacc = 0; }
    }
  };
  const category = (v) => { let a = Math.abs(v); let n = 0; while (a) { n++; a >>= 1; } return n; };
  const bitsOf = (v, n) => (v >= 0 ? v : v + (1 << n) - 1);

  // Colour planes, level-shifted.
  const planes = [new Float64Array(width * height), new Float64Array(width * height), new Float64Array(width * height)];
  for (let i = 0; i < width * height; i++) {
    const r = rgb[i * 3]; const g = rgb[i * 3 + 1]; const b = rgb[i * 3 + 2];
    planes[0][i] = 0.299 * r + 0.587 * g + 0.114 * b - 128;
    planes[1][i] = -0.168736 * r - 0.331264 * g + 0.5 * b;
    planes[2][i] = 0.5 * r - 0.418688 * g - 0.081312 * b;
  }
  const pred = [0, 0, 0];
  const block = new Float64Array(64);
  for (let by = 0; by < height; by += 8) {
    for (let bx = 0; bx < width; bx += 8) {
      for (let c = 0; c < 3; c++) {
        // Edge blocks repeat the last row and column.
        for (let y = 0; y < 8; y++) {
          for (let x = 0; x < 8; x++) {
            const sx = Math.min(width - 1, bx + x);
            const sy = Math.min(height - 1, by + y);
            block[y * 8 + x] = planes[c][sy * width + sx];
          }
        }
        const f = dct(block);
        const t = c === 0 ? 0 : 1;
        const q = ZIGZAG.map((i) => Math.round(f[i] / qt[t][i]));
        const h = huff[t];
        const diff = q[0] - pred[c];
        pred[c] = q[0];
        const dcn = category(diff);
        put(...h.dc.get(dcn));
        if (dcn) put(bitsOf(diff, dcn), dcn);
        let run = 0;
        for (let k = 1; k < 64; k++) {
          if (q[k] === 0) { run++; continue; }
          while (run > 15) { put(...h.ac.get(0xf0)); run -= 16; }
          const n = category(q[k]);
          put(...h.ac.get((run << 4) | n));
          put(bitsOf(q[k], n), n);
          run = 0;
        }
        if (run) put(...h.ac.get(0x00));
      }
    }
  }
  if (nacc) put((1 << (8 - nacc)) - 1, 8 - nacc);
  return Buffer.from([...out, ...data, 0xff, 0xd9]);
}

module.exports = { Canvas, png, jpeg };
