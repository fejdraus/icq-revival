// The avatar constructor's parts and motions, and the movie and pictures made
// from them.
//
// An avatar is its parameters: one choice per field below. Everything is
// drawn from these data, so the same parameters always give the same files.
// The movie is laid out the way ICQ's devils are (see the devil kit's
// how-to): a 53x65 stage, a background, and a clip named `face` with one
// frame per emotion label. The client sets face.emotion; here a property
// of our own on the clip turns that into gotoAndPlay(label), and the frame
// holds that emotion's animation, which loops.
//
// Adding options: append to a list (a new index keeps every existing code
// valid). Changing how an existing option looks changes every avatar that
// uses it, including ones already set and cached by clients for a day.

'use strict';

const V = require('./vector.js');
const SWF = require('./swf.js');
const { Canvas, png, jpeg } = require('./raster.js');

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a, b, t) => a.map((v, i) => (i < 3 ? Math.round(v + (b[i] - v) * t) : v));
const alpha = (c, a) => [c[0], c[1], c[2], Math.round(a * 255)];

// ------------------------------------------------------------------- fields

const SKIN = ['#FFE1C6', '#F5C49B', '#E0A472', '#B77A4B', '#85532F', '#A9DC77', '#F4876C', '#9FCCF2'];
const HAIR = ['#2F2620', '#5B3A21', '#9C6333', '#F2CB57', '#E27B35', '#F48DB5', '#58A5E6', '#ECECEC'];
const EYE = ['#7A4A22', '#3C7FD8', '#39A04B', '#B5842E', '#8F5BD8', '#D23C3C'];
const ACCENT = ['#E53935', '#FB8C00', '#FDD835', '#43A047', '#1E88E5', '#8E24AA', '#F06292', '#37474F'];
const SHIRT = ['#E53935', '#FB8C00', '#FDD835', '#43A047', '#26A69A', '#1E88E5', '#8E24AA', '#78909C'];
const BG = ['#FFF3B0', '#FFD6D6', '#D6F5D6', '#D4E8FF', '#E6DAFF', '#FFE0B8', '#C8F0F0', '#E4E4E4'];

const opt = (en, uk) => ({ en, uk });

// The fields in the order of the code. `colors` marks a colour field (its
// options are swatches); the others are named.
const FIELDS = [
  { key: 'head', name: opt('Head', 'Голова'), options: [opt('Round', 'Кругла'), opt('Oval', 'Овальна'), opt('Chubby', 'Щокаста')] },
  { key: 'skin', name: opt('Skin', 'Шкіра'), colors: SKIN },
  { key: 'hair', name: opt('Hair', 'Волосся'), options: [opt('None', 'Немає'), opt('Short', 'Коротке'), opt('Spiky', 'Їжачок'), opt('Bob', 'Каре'), opt('Long', 'Довге'), opt('Curl', 'Чубчик')] },
  { key: 'hairColor', name: opt('Hair colour', 'Колір волосся'), colors: HAIR },
  { key: 'eyes', name: opt('Eyes', 'Очі'), options: [opt('Dots', 'Крапки'), opt('Big', 'Великі'), opt('Lashes', 'З віями'), opt('Buttons', 'Ґудзики')] },
  { key: 'eyeColor', name: opt('Eye colour', 'Колір очей'), colors: EYE },
  { key: 'mouth', name: opt('Mouth', 'Рот'), options: [opt('Classic', 'Звичайний'), opt('Fang', 'З іклом'), opt('Bunny teeth', 'Зайчик')] },
  { key: 'cheeks', name: opt('Cheeks', 'Щічки'), options: [opt('Plain', 'Звичайні'), opt('Blush', 'Рум’янець')] },
  { key: 'hat', name: opt('On top', 'Зверху'), options: [opt('Nothing', 'Нічого'), opt('Horns', 'Ріжки'), opt('Cap', 'Кепка'), opt('Crown', 'Корона'), opt('Bow', 'Бантик'), opt('Headphones', 'Навушники'), opt('Glasses', 'Окуляри'), opt('Party hat', 'Ковпачок')] },
  { key: 'hatColor', name: opt('Its colour', 'Його колір'), colors: ACCENT },
  { key: 'shirt', name: opt('Shirt', 'Сорочка'), colors: SHIRT },
  { key: 'bg', name: opt('Background', 'Тло'), options: [opt('White', 'Біле'), opt('Plain', 'Однотонне'), opt('Stripes', 'Смужки'), opt('Dots', 'Горошок'), opt('Rays', 'Промені')] },
  { key: 'bgColor', name: opt('Background colour', 'Колір тла'), colors: BG },
];
for (const f of FIELDS) f.count = f.colors ? f.colors.length : f.options.length;

const VERSION = '1';
const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz';
// c-<version><one digit per field>: short, and a plain file name the IM
// server's still-finder accepts.
const CODE = new RegExp(`^c-${VERSION}[0-9a-z]{${FIELDS.length}}$`);

const DEFAULTS = { head: 0, skin: 1, hair: 1, hairColor: 2, eyes: 1, eyeColor: 1, mouth: 0, cheeks: 1, hat: 0, hatColor: 0, shirt: 5, bg: 1, bgColor: 3 };

// The parameters of a code, or null: the exact form only, every field in its
// range.
function parseCode(code) {
  if (typeof code !== 'string' || !CODE.test(code)) return null;
  const params = {};
  for (let i = 0; i < FIELDS.length; i++) {
    const v = DIGITS.indexOf(code[3 + i]);
    if (v < 0 || v >= FIELDS[i].count) return null;
    params[FIELDS[i].key] = v;
  }
  return params;
}

function encode(params) {
  let out = `c-${VERSION}`;
  for (const f of FIELDS) {
    const v = params[f.key];
    if (!Number.isInteger(v) || v < 0 || v >= f.count) throw new Error(`bad ${f.key}`);
    out += DIGITS[v];
  }
  return out;
}

// ------------------------------------------------------------------- drawing

const INK = hex('#3A2718');
const W = 53;
const H = 65;
const LINE = { width: 1.1, color: INK };
const THIN = { width: 0.8, color: INK };

const n2 = (v) => Math.round(v * 100) / 100;
// Path strings from numbers: P`M ${x} ${y}` rounds each value.
const P = (strings, ...vals) => V.path(strings.reduce((s, str, i) => s + str + (i < vals.length ? n2(vals[i]) : ''), ''));
const heart = (x, y, s) => P`M ${x} ${y + 0.95 * s} Q ${x - 0.55 * s} ${y + 0.45 * s} ${x - 0.95 * s} ${y - 0.05 * s}
  Q ${x - 1.25 * s} ${y - 0.55 * s} ${x - 0.85 * s} ${y - 0.85 * s} Q ${x - 0.4 * s} ${y - 1.1 * s} ${x} ${y - 0.55 * s}
  Q ${x + 0.4 * s} ${y - 1.1 * s} ${x + 0.85 * s} ${y - 0.85 * s} Q ${x + 1.25 * s} ${y - 0.55 * s} ${x + 0.95 * s} ${y - 0.05 * s}
  Q ${x + 0.55 * s} ${y + 0.45 * s} ${x} ${y + 0.95 * s} Z`;

// The head and where the face sits on it.
function headOf(p) {
  const cx = 26.5;
  const cy = 35;
  const shapes = [
    { rx: 18.5, ry: 17.5, contours: V.ellipse(cx, cy, 18.5, 17.5) },
    { rx: 16.5, ry: 19, contours: V.ellipse(cx, cy, 16.5, 19) },
    { rx: 19.5, ry: 17, contours: P`M ${cx} ${cy - 17} Q ${cx + 17} ${cy - 17} ${cx + 19} ${cy - 1} Q ${cx + 20.5} ${cy + 17} ${cx} ${cy + 17} Q ${cx - 20.5} ${cy + 17} ${cx - 19} ${cy - 1} Q ${cx - 17} ${cy - 17} ${cx} ${cy - 17} Z` },
  ];
  const s = shapes[p.head];
  return {
    cx, cy, rx: s.rx, ry: s.ry, top: cy - s.ry, contours: s.contours,
    ex: p.head === 1 ? 7 : 7.5, ey: cy + 0.5, my: cy + 9, by: cy - 6,
  };
}

function background(p) {
  const b = hex(BG[p.bgColor]);
  const b2 = mix(b, hex('#FFFFFF'), -0.12);
  const all = V.poly([[0, 0], [W, 0], [W, H], [0, H]]);
  if (p.bg === 0) return [V.prim(all, [255, 255, 255])];
  const out = [V.prim(all, b)];
  if (p.bg === 2) {
    const bands = [];
    for (let y = 2; y < H; y += 9) bands.push(...V.poly([[0, y], [W, y], [W, y + 4.5], [0, y + 4.5]]));
    out.push(V.prim(bands, b2));
  } else if (p.bg === 3) {
    const dots = [];
    for (let row = 0, y = 3; y < H + 3; y += 7.5, row++) {
      for (let x = row % 2 ? 7.5 : 3.75; x < W + 3; x += 7.5) dots.push(...V.circle(x, y, 1.9));
    }
    out.push(V.prim(dots, b2));
  } else if (p.bg === 4) {
    const rays = [];
    const cx = 26.5; const cy = 36; const r = 60;
    for (let i = 0; i < 12; i++) {
      const a0 = (i * 2 * Math.PI) / 12;
      const a1 = a0 + Math.PI / 12;
      rays.push(...V.poly([[cx, cy], [cx + r * Math.cos(a0), cy + r * Math.sin(a0)], [cx + r * Math.cos(a1), cy + r * Math.sin(a1)]]));
    }
    out.push(V.prim(rays, b2));
  }
  return out;
}

function hairBack(p, h) {
  const c = hex(HAIR[p.hairColor]);
  const { cx, cy, rx, top } = h;
  if (p.hair === 3) {
    return [V.prim(P`M ${cx - rx - 3.5} ${cy - 1} Q ${cx - rx - 4} ${top - 3.5} ${cx} ${top - 3.5} Q ${cx + rx + 4} ${top - 3.5} ${cx + rx + 3.5} ${cy - 1}
      L ${cx + rx + 3.5} ${cy + 9} Q ${cx + rx + 3.5} ${cy + 12} ${cx + rx} ${cy + 12} L ${cx - rx} ${cy + 12} Q ${cx - rx - 3.5} ${cy + 12} ${cx - rx - 3.5} ${cy + 9} Z`, c, LINE)];
  }
  if (p.hair === 4) {
    return [V.prim(P`M ${cx - rx - 4} ${cy} Q ${cx - rx - 4.5} ${top - 3.5} ${cx} ${top - 3.5} Q ${cx + rx + 4.5} ${top - 3.5} ${cx + rx + 4} ${cy}
      L ${cx + rx + 5} ${cy + 20} Q ${cx + rx + 2} ${cy + 23} ${cx + rx - 3} ${cy + 21} L ${cx - rx + 3} ${cy + 21} Q ${cx - rx - 2} ${cy + 23} ${cx - rx - 5} ${cy + 20} Z`, c, LINE)];
  }
  return [];
}

function hairFront(p, h) {
  const c = hex(HAIR[p.hairColor]);
  const { cx, cy, rx, top } = h;
  switch (p.hair) {
    case 1: return [V.prim(P`M ${cx - rx - 0.3} ${cy - 3} Q ${cx - rx - 1} ${top - 2} ${cx} ${top - 2.2} Q ${cx + rx + 1} ${top - 2} ${cx + rx + 0.3} ${cy - 3}
      L ${cx + rx - 2.2} ${cy - 3.5} Q ${cx + rx - 3} ${cy - 9} ${cx + 11} ${cy - 9.5}
      Q ${cx + 8.5} ${cy - 6.5} ${cx + 5.5} ${cy - 9.8} Q ${cx + 3} ${cy - 6.8} ${cx} ${cy - 10} Q ${cx - 3} ${cy - 6.8} ${cx - 5.5} ${cy - 9.8}
      Q ${cx - 8.5} ${cy - 6.5} ${cx - 11} ${cy - 9.5} Q ${cx - rx + 3} ${cy - 9} ${cx - rx + 2.2} ${cy - 3.5} Z`, c, LINE)];
    case 2: return [V.prim(P`M ${cx - rx - 0.3} ${cy - 3} L ${cx - rx + 0.5} ${top + 3} L ${cx - rx - 2} ${top - 3} L ${cx - 9} ${top - 0.5}
      L ${cx - 8} ${top - 7} L ${cx - 3} ${top - 1.5} L ${cx + 1} ${top - 8.5} L ${cx + 4.5} ${top - 1.5} L ${cx + 9} ${top - 6.5}
      L ${cx + 10.5} ${top} L ${cx + rx + 2.5} ${top - 1.5} L ${cx + rx - 0.5} ${top + 4} L ${cx + rx + 0.3} ${cy - 3}
      L ${cx + rx - 2.5} ${cy - 4} L ${cx + 11} ${cy - 9.5} L ${cx + 8} ${cy - 6.5} L ${cx + 5} ${cy - 10} L ${cx + 2} ${cy - 6.5}
      L ${cx - 1.5} ${cy - 10} L ${cx - 4.5} ${cy - 6.5} L ${cx - 8} ${cy - 10} L ${cx - 10.5} ${cy - 7} L ${cx - rx + 2.5} ${cy - 4} Z`, c, LINE)];
    case 3: return [V.prim(P`M ${cx - rx - 3.5} ${cy + 9} L ${cx - rx - 3.5} ${cy - 1} Q ${cx - rx - 4} ${top - 3.5} ${cx} ${top - 3.5}
      Q ${cx + rx + 4} ${top - 3.5} ${cx + rx + 3.5} ${cy - 1} L ${cx + rx + 3.5} ${cy + 9} Q ${cx + rx + 2} ${cy + 11.5} ${cx + rx - 1} ${cy + 10}
      L ${cx + rx - 2.8} ${cy - 2} Q ${cx + rx - 3.5} ${cy - 9.5} ${cx + 7} ${cy - 9.5} L ${cx - 7} ${cy - 9.5}
      Q ${cx - rx + 3.5} ${cy - 9.5} ${cx - rx + 2.8} ${cy - 2} L ${cx - rx + 1} ${cy + 10} Q ${cx - rx - 2} ${cy + 11.5} ${cx - rx - 3.5} ${cy + 9} Z`, c, LINE)];
    case 4: return [V.prim(P`M ${cx - rx - 4} ${cy + 18} L ${cx - rx - 4} ${cy} Q ${cx - rx - 4.5} ${top - 3.5} ${cx} ${top - 3.5}
      Q ${cx + rx + 4.5} ${top - 3.5} ${cx + rx + 4} ${cy} L ${cx + rx + 5} ${cy + 18} Q ${cx + rx + 3} ${cy + 20} ${cx + rx + 1} ${cy + 17}
      L ${cx + rx - 2.6} ${cy - 1} Q ${cx + rx - 3} ${cy - 10} ${cx + 5} ${cy - 10.5} Q ${cx - 6} ${cy - 9} ${cx - rx + 2.6} ${cy - 3}
      L ${cx - rx + 1} ${cy + 17} Q ${cx - rx - 2} ${cy + 20} ${cx - rx - 4} ${cy + 18} Z`, c, LINE)];
    case 5: {
      const curl = P`M ${cx - 1} ${top + 0.8} Q ${cx - 2.5} ${top - 5.5} ${cx + 2.5} ${top - 6} Q ${cx + 6} ${top - 5.5} ${cx + 4.5} ${top - 2.8} Q ${cx + 3} ${top - 1.5} ${cx + 2} ${top - 3}`;
      return [V.prim(curl, null, { width: 3.2, color: INK }), V.prim(curl, null, { width: 1.6, color: c })];
    }
    default: return [];
  }
}

// Eyes in a state: open, closed, happy, squeeze, half, mad, love.
function eyes(p, h, state, skin) {
  const out = [];
  const iris = hex(EYE[p.eyeColor]);
  const white = [255, 255, 255];
  for (const side of [-1, 1]) {
    const x = h.cx + side * h.ex;
    const y = h.ey;
    const outer = side; // the outer corner is away from the middle
    if (state === 'closed') {
      out.push(V.prim(P`M ${x - 3.2} ${y} Q ${x} ${y + 2.8} ${x + 3.2} ${y}`, null, { width: 1.2, color: INK }));
    } else if (state === 'happy') {
      out.push(V.prim(P`M ${x - 3.2} ${y + 1.3} Q ${x} ${y - 3.3} ${x + 3.2} ${y + 1.3}`, null, { width: 1.3, color: INK }));
    } else if (state === 'squeeze') {
      const t = -side; // > on the left, < on the right
      out.push(V.prim(P`M ${x - t * 2.6} ${y - 2.4} L ${x + t * 2.2} ${y} L ${x - t * 2.6} ${y + 2.4}`, null, { width: 1.3, color: INK }));
    } else if (state === 'love') {
      out.push(V.prim(heart(x, y + 0.3, 3.4), hex('#FF4D6D'), THIN));
      out.push(V.prim(V.ellipse(x - 1.3, y - 1.1, 0.8, 0.6), alpha(white, 0.85)));
    } else {
      // Open, before any lid.
      if (p.eyes === 0) {
        out.push(V.prim(V.ellipse(x, y, 2.3, 3), INK));
        out.push(V.prim(V.circle(x - 0.8, y - 1.1, 0.9), white));
      } else if (p.eyes === 3) {
        out.push(V.prim(V.circle(x, y, 3.1), iris, THIN));
        out.push(V.prim(V.circle(x, y + 0.2, 1.6), INK));
        out.push(V.prim(V.circle(x - 1, y - 1, 0.8), white));
      } else {
        const k = p.eyes === 2 ? 0.88 : 1;
        out.push(V.prim(V.ellipse(x, y, 4 * k, 4.8 * k), white, THIN));
        out.push(V.prim(V.circle(x + 0.3 * side * -1, y + 0.6, 2.8 * k), iris));
        out.push(V.prim(V.circle(x + 0.3 * side * -1, y + 0.7, 1.5 * k), INK));
        out.push(V.prim(V.circle(x - 0.7, y - 0.8, 1.1 * k), white));
        out.push(V.prim(V.circle(x + 1.1, y + 1.7, 0.5 * k), white));
      }
      if (state === 'half') {
        out.push(V.prim(V.poly([[x - 5.2, y - 6.5], [x + 5.2, y - 6.5], [x + 5.2, y - 0.2], [x - 5.2, y - 0.2]]), skin));
        out.push(V.prim(P`M ${x - 4.2} ${y - 0.2} L ${x + 4.2} ${y - 0.2}`, null, { width: 1.2, color: INK }));
      } else if (state === 'mad') {
        const i = -side; // the inner corner
        const xi = x + 5.2 * i;
        const xo = x - 5.2 * i;
        out.push(V.prim(V.poly([[xo, y - 6.5], [xi, y - 6.5], [xi, y - 1.2], [xo, y - 4]]), skin));
        out.push(V.prim(P`M ${x - 4.3 * i} ${y - 3.8} L ${x + 4.3 * i} ${y - 1.4}`, null, { width: 1.2, color: INK }));
      }
    }
    if (p.eyes === 2 && state !== 'love') {
      out.push(V.prim(P`M ${x + outer * 2.9} ${y - 3} L ${x + outer * 4.6} ${y - 4.8} M ${x + outer * 3.7} ${y - 1.8} L ${x + outer * 5.6} ${y - 2.9}`, null, THIN));
    }
  }
  return out;
}

// Brows in a state: neutral, raised, sad, mad. Darker than the hair.
function brows(p, h, state) {
  const c = p.hair === 0 ? INK : mix(hex(HAIR[p.hairColor]), INK, 0.45);
  const line = { width: 1.3, color: c };
  const out = [];
  for (const side of [-1, 1]) {
    const x = h.cx + side * h.ex;
    const y = state === 'raised' ? h.by - 1.4 : h.by;
    const i = -side; // towards the middle
    let d;
    if (state === 'sad') d = P`M ${x - i * 3} ${y + 0.8} Q ${x} ${y + 0.3} ${x + i * 3} ${y - 1.6}`;
    else if (state === 'mad') d = P`M ${x - i * 3} ${y - 1.4} Q ${x} ${y - 0.6} ${x + i * 3.2} ${y + 1.5}`;
    else d = P`M ${x - 3} ${y + 0.6} Q ${x} ${y - 1.3} ${x + 3} ${y + 0.6}`;
    out.push(V.prim(d, null, line));
  }
  return out;
}

// Mouths in a state: stam, smile, laugh, frown, grit, wail, flat, o.
function mouth(p, h, state) {
  const { cx } = h;
  const y = h.my;
  const dark = hex('#7B2230');
  const tongue = hex('#F27D8E');
  const white = [255, 255, 255];
  const out = [];
  const fang = (x0, y0) => out.push(V.prim(V.poly([[x0, y0], [x0 + 2.3, y0 - 0.3], [x0 + 1.2, y0 + 2.6]]), white, THIN));
  const buck = (y0) => out.push(V.prim(V.poly([[cx - 1.7, y0], [cx + 1.7, y0], [cx + 1.7, y0 + 2.3], [cx - 1.7, y0 + 2.3]]), white, THIN),
    V.prim(P`M ${cx} ${y0} L ${cx} ${y0 + 2.3}`, null, { width: 0.6, color: INK }));
  switch (state) {
    case 'smile':
      out.push(V.prim(P`M ${cx - 6} ${y - 1.5} Q ${cx} ${y} ${cx + 6} ${y - 1.5} Q ${cx + 4.8} ${y + 6} ${cx} ${y + 6.2} Q ${cx - 4.8} ${y + 6} ${cx - 6} ${y - 1.5} Z`, dark, LINE));
      out.push(V.prim(P`M ${cx - 3.2} ${y + 5.2} Q ${cx} ${y + 2.4} ${cx + 3.4} ${y + 5.1} Q ${cx} ${y + 6.4} ${cx - 3.2} ${y + 5.2} Z`, tongue));
      if (p.mouth === 1) fang(cx + 2, y - 0.7);
      if (p.mouth === 2) buck(y - 0.8);
      break;
    case 'laugh':
      out.push(V.prim(P`M ${cx - 7.5} ${y - 2.5} Q ${cx} ${y - 1} ${cx + 7.5} ${y - 2.5} Q ${cx + 6.5} ${y + 8} ${cx} ${y + 8.2} Q ${cx - 6.5} ${y + 8} ${cx - 7.5} ${y - 2.5} Z`, dark, LINE));
      out.push(V.prim(P`M ${cx - 6.6} ${y - 1.9} Q ${cx} ${y - 0.6} ${cx + 6.6} ${y - 1.9} L ${cx + 6.2} ${y + 0.2} Q ${cx} ${y + 1.4} ${cx - 6.2} ${y + 0.2} Z`, white));
      out.push(V.prim(P`M ${cx - 4} ${y + 6.6} Q ${cx} ${y + 3} ${cx + 4.2} ${y + 6.5} Q ${cx} ${y + 8.4} ${cx - 4} ${y + 6.6} Z`, tongue));
      if (p.mouth === 1) fang(cx + 2.4, y - 0.9);
      break;
    case 'frown':
      out.push(V.prim(P`M ${cx - 4} ${y + 2.2} Q ${cx} ${y - 1.8} ${cx + 4} ${y + 2.2}`, null, { width: 1.3, color: INK }));
      break;
    case 'grit':
      out.push(V.prim(P`M ${cx - 5.5} ${y} Q ${cx - 5.5} ${y - 1} ${cx - 4.5} ${y - 1} L ${cx + 4.5} ${y - 1} Q ${cx + 5.5} ${y - 1} ${cx + 5.5} ${y}
        L ${cx + 5.5} ${y + 3} Q ${cx + 5.5} ${y + 4} ${cx + 4.5} ${y + 4} L ${cx - 4.5} ${y + 4} Q ${cx - 5.5} ${y + 4} ${cx - 5.5} ${y + 3} Z`, white, LINE));
      out.push(V.prim(P`M ${cx - 5.3} ${y + 1.5} L ${cx + 5.3} ${y + 1.5} M ${cx - 2.7} ${y - 0.9} L ${cx - 2.7} ${y + 3.9} M ${cx} ${y - 0.9} L ${cx} ${y + 3.9} M ${cx + 2.7} ${y - 0.9} L ${cx + 2.7} ${y + 3.9}`, null, { width: 0.6, color: INK }));
      break;
    case 'wail':
      out.push(V.prim(P`M ${cx - 5} ${y + 4.5} Q ${cx - 4.5} ${y - 2.5} ${cx} ${y - 2.5} Q ${cx + 4.5} ${y - 2.5} ${cx + 5} ${y + 4.5} Q ${cx} ${y + 3.2} ${cx - 5} ${y + 4.5} Z`, dark, LINE));
      out.push(V.prim(P`M ${cx - 3} ${y + 3.9} Q ${cx} ${y + 1.4} ${cx + 3} ${y + 3.9} Q ${cx} ${y + 3.3} ${cx - 3} ${y + 3.9} Z`, tongue));
      break;
    case 'flat':
      out.push(V.prim(P`M ${cx - 3.8} ${y + 1} Q ${cx} ${y + 0.2} ${cx + 3.8} ${y + 1}`, null, { width: 1.3, color: INK }));
      break;
    case 'o':
      out.push(V.prim(V.ellipse(cx, y + 1.5, 1.5, 1.8), dark, THIN));
      break;
    default: // stam: a small smile
      out.push(V.prim(P`M ${cx - 4} ${y - 0.8} Q ${cx} ${y + 2.8} ${cx + 4} ${y - 0.8}`, null, { width: 1.3, color: INK }));
      if (p.mouth === 1) fang(cx + 1.4, y + 0.8);
      if (p.mouth === 2) buck(y + 1);
  }
  return out;
}

function accessory(p, h) {
  const a = hex(ACCENT[p.hatColor]);
  const white = [255, 255, 255];
  const { cx, cy, rx, top } = h;
  const out = [];
  switch (p.hat) {
    case 1:
      for (const s of [-1, 1]) {
        out.push(V.prim(P`M ${cx + s * 9} ${top + 3.2} Q ${cx + s * 13.5} ${top - 3} ${cx + s * 13} ${top - 8.5} Q ${cx + s * 9} ${top - 4.5} ${cx + s * 5.5} ${top + 1.5} Z`, a, LINE));
      }
      break;
    case 2:
      out.push(V.prim(P`M ${cx - rx + 0.5} ${cy - 8} Q ${cx - rx} ${top - 4.5} ${cx} ${top - 4.5} Q ${cx + rx} ${top - 4.5} ${cx + rx - 0.5} ${cy - 8} Q ${cx} ${cy - 10.5} ${cx - rx + 0.5} ${cy - 8} Z`, a, LINE));
      out.push(V.prim(P`M ${cx + 2} ${cy - 9.2} Q ${cx + 14} ${cy - 12} ${cx + rx + 7.5} ${cy - 7.5} Q ${cx + rx + 4} ${cy - 4.5} ${cx + rx - 2} ${cy - 6.5} Q ${cx + 10} ${cy - 8.8} ${cx + 2} ${cy - 9.2} Z`, mix(a, INK, 0.25), LINE));
      out.push(V.prim(V.circle(cx, top - 4.3, 1.3), mix(a, INK, 0.25), THIN));
      break;
    case 3:
      out.push(V.prim(P`M ${cx - 10} ${top + 2} L ${cx - 11} ${top - 8} L ${cx - 5.5} ${top - 3} L ${cx} ${top - 10} L ${cx + 5.5} ${top - 3} L ${cx + 11} ${top - 8} L ${cx + 10} ${top + 2} Q ${cx} ${top + 0.5} ${cx - 10} ${top + 2} Z`, a, LINE));
      for (const [x, y] of [[cx - 11, top - 8], [cx, top - 10], [cx + 11, top - 8]]) out.push(V.prim(V.circle(x, y, 1.1), a, THIN));
      for (const [x, y] of [[cx - 6, top - 0.3], [cx, top - 1.3], [cx + 6, top - 0.3]]) out.push(V.prim(V.circle(x, y, 1.1), white, THIN));
      break;
    case 4: {
      const bx = cx + 10.5;
      const by = top + 3;
      out.push(V.prim(P`M ${bx} ${by} Q ${bx - 7} ${by - 6.5} ${bx - 7} ${by} Q ${bx - 7} ${by + 6.5} ${bx} ${by} Z`, a, LINE));
      out.push(V.prim(P`M ${bx} ${by} Q ${bx + 7} ${by - 6.5} ${bx + 7} ${by} Q ${bx + 7} ${by + 6.5} ${bx} ${by} Z`, a, LINE));
      out.push(V.prim(V.circle(bx, by, 1.9), mix(a, INK, 0.2), THIN));
      break;
    }
    case 5: {
      const band = P`M ${cx - rx - 0.5} ${cy - 1} Q ${cx} ${2 * (top - 3) - (cy - 1)} ${cx + rx + 0.5} ${cy - 1}`;
      out.push(V.prim(band, null, { width: 3.4, color: INK }), V.prim(band, null, { width: 2, color: a }));
      for (const s of [-1, 1]) {
        out.push(V.prim(V.ellipse(cx + s * (rx + 0.3), cy + 1, 3.2, 5.2), a, LINE));
        out.push(V.prim(V.ellipse(cx + s * (rx + 0.3), cy + 1, 1.5, 3), mix(a, INK, 0.35)));
      }
      break;
    }
    case 6:
      for (const s of [-1, 1]) {
        out.push(V.prim(V.circle(cx + s * h.ex, h.ey, 5.1), alpha(white, 0.28), { width: 1.2, color: a }));
        out.push(V.prim(P`M ${cx + s * (h.ex + 5)} ${h.ey - 1} L ${cx + s * (rx - 0.5)} ${h.ey - 2.2}`, null, { width: 1.2, color: a }));
      }
      out.push(V.prim(P`M ${cx - h.ex + 5} ${h.ey - 0.8} Q ${cx} ${h.ey - 2.6} ${cx + h.ex - 5} ${h.ey - 0.8}`, null, { width: 1.2, color: a }));
      break;
    case 7:
      out.push(V.prim(P`M ${cx - 8} ${top + 2} L ${cx + 3} ${top - 13} L ${cx + 10} ${top + 1} Q ${cx + 1} ${top + 3.5} ${cx - 8} ${top + 2} Z`, a, LINE));
      for (const [x, y] of [[cx - 1.5, top - 1], [cx + 5, top - 2], [cx + 2.5, top - 7]]) out.push(V.prim(V.circle(x, y, 1), white));
      out.push(V.prim(V.circle(cx + 3, top - 13, 2), white, THIN));
      break;
    default:
  }
  return out;
}

// The whole character in one pose: { eyes, brows, mouth, grey }.
function character(p, pose) {
  const h = headOf(p);
  const skin = hex(SKIN[p.skin]);
  const shirt = hex(SHIRT[p.shirt]);
  const { cx, cy, rx } = h;
  const out = [];
  out.push(V.prim(P`M 7 66 Q 7.5 54 19.5 52.5 L 33.5 52.5 Q 45.5 54 46 66 Z`, shirt, LINE));
  out.push(V.prim(P`M 21 52.6 L 26.5 57.5 L 32 52.6`, null, { width: 1, color: mix(shirt, INK, 0.45) }));
  out.push(...hairBack(p, h));
  for (const s of [-1, 1]) {
    out.push(V.prim(V.ellipse(cx + s * (rx - 0.5), cy + 1, 3.3, 4.3), skin, LINE));
    out.push(V.prim(V.ellipse(cx + s * (rx - 0.2), cy + 1, 1.5, 2.4), mix(skin, INK, 0.18)));
  }
  out.push(V.prim(h.contours, skin, LINE));
  out.push(V.prim(V.ellipse(cx - rx * 0.5, cy - h.ry * 0.58, 3.2, 2), alpha([255, 255, 255], 0.35)));
  if (p.cheeks === 1 || pose.blush) {
    for (const s of [-1, 1]) out.push(V.prim(V.ellipse(cx + s * 11.5, cy + 5.5, 3, 1.8), alpha(hex('#FF6E6E'), 0.45)));
  }
  out.push(...eyes(p, h, pose.eyes, skin));
  out.push(...brows(p, h, pose.brows));
  out.push(...mouth(p, h, pose.mouth));
  out.push(...hairFront(p, h));
  out.push(...accessory(p, h));
  if (!pose.grey) return out;
  const grey = (c) => {
    const l = 0.3 * c[0] + 0.59 * c[1] + 0.11 * c[2];
    const g = Math.round(l * 0.8 + 40);
    return [g, g, g, c[3]];
  };
  return V.recolor(out, grey);
}

// ------------------------------------------------------------------- extras

const EXTRAS = {
  tear: () => [
    V.prim(P`M 0 -2.4 Q 2 0.4 1.7 1.3 Q 1.1 2.7 0 2.7 Q -1.1 2.7 -1.7 1.3 Q -2 0.4 0 -2.4 Z`, hex('#8FD3FF'), { width: 0.6, color: hex('#2E7FC0') }),
    V.prim(V.circle(-0.6, 1, 0.5), [255, 255, 255]),
  ],
  heart: () => [
    V.prim(heart(0, 0, 2.6), hex('#FF4D6D'), { width: 0.6, color: hex('#9E1B32') }),
    V.prim(V.ellipse(-1, -1, 0.6, 0.45), alpha([255, 255, 255], 0.8)),
  ],
  zee: () => {
    const z = P`M -1.6 -1.6 L 1.6 -1.6 L -1.6 1.6 L 1.6 1.6`;
    return [V.prim(z, null, { width: 2.6, color: [255, 255, 255, 200] }), V.prim(z, null, { width: 1.1, color: hex('#3F6DB5') })];
  },
  anger: () => {
    const d = [];
    for (const [sx, sy] of [[-1, -1], [1, -1], [-1, 1], [1, 1]]) {
      d.push(...P`M ${sx * 0.7} ${sy * 2.6} Q ${sx * 0.8} ${sy * 0.8} ${sx * 2.6} ${sy * 0.7}`);
    }
    return [V.prim(d, null, { width: 2.6, color: [255, 255, 255, 200] }), V.prim(d, null, { width: 1.2, color: hex('#E53950') })];
  },
};

// ------------------------------------------------------------------- motions

// The frame labels ICQ's devils have, in their order.
const EMOTIONS = ['stam', 'smile', 'sad', 'laugh', 'mad', 'cry', 'love', 'busy', 'offline'];

const POSES = {
  stam: { eyes: 'open', brows: 'neutral', mouth: 'stam' },
  stamBlink: { eyes: 'closed', brows: 'neutral', mouth: 'stam' },
  smile: { eyes: 'open', brows: 'raised', mouth: 'smile' },
  smileBlink: { eyes: 'closed', brows: 'raised', mouth: 'smile' },
  laugh: { eyes: 'happy', brows: 'raised', mouth: 'laugh' },
  sad: { eyes: 'open', brows: 'sad', mouth: 'frown' },
  sadBlink: { eyes: 'closed', brows: 'sad', mouth: 'frown' },
  mad: { eyes: 'mad', brows: 'mad', mouth: 'grit' },
  cry: { eyes: 'squeeze', brows: 'sad', mouth: 'wail' },
  love: { eyes: 'love', brows: 'raised', mouth: 'smile', blush: true },
  busy: { eyes: 'half', brows: 'neutral', mouth: 'flat' },
  offline: { eyes: 'closed', brows: 'neutral', mouth: 'o', grey: true },
};

const wave = (f, period) => Math.abs(Math.sin((Math.PI * f) / period));

// One emotion as frames: { pose, dx, dy, tint, extras: [{ kind, x, y, s, a }] }.
function motion(p, emotion) {
  const h = headOf(p);
  const frames = [];
  const add = (n, fn) => { for (let f = 0; f < n; f++) frames.push({ dx: 0, dy: 0, extras: [], ...fn(f) }); };
  const cycle = (f, phase, len) => (f + phase) % len;
  switch (emotion) {
    case 'smile':
      add(48, (f) => ({ pose: f >= 40 && f < 43 ? 'smileBlink' : 'smile', dy: f < 24 ? -1.5 * wave(f, 12) : 0 }));
      break;
    case 'laugh':
      add(36, (f) => ({ pose: 'laugh', dy: -2.2 * wave(f, 6) }));
      break;
    case 'sad':
      add(72, (f) => ({ pose: f >= 56 && f < 59 ? 'sadBlink' : 'sad', dy: 1 + 0.5 * Math.sin((2 * Math.PI * f) / 72) }));
      break;
    case 'mad':
      add(36, (f) => {
        const heat = 0.5 - 0.5 * Math.cos((2 * Math.PI * f) / 36);
        return {
          pose: 'mad',
          dx: f < 12 ? (Math.floor(f / 2) % 2 ? -0.7 : 0.7) : 0,
          tint: [Math.round(45 * heat), -Math.round(15 * heat), -Math.round(15 * heat)],
          extras: [{ kind: 'anger', x: h.cx + 11, y: h.top + 5, s: 0.85 + 0.3 * wave(f, 9), a: 1 }],
        };
      });
      break;
    case 'cry':
      add(36, (f) => {
        const extras = [];
        for (const [side, phase] of [[-1, 0], [1, 18]]) {
          const t = cycle(f, phase, 36);
          if (t >= 24) continue;
          extras.push({
            kind: 'tear',
            x: h.cx + side * (h.ex + 3) + side * 1.5 * (t / 24),
            y: h.ey + 3 + 12 * (t / 24) ** 1.5,
            s: 0.6 + 0.4 * Math.min(1, t / 6),
            a: t < 18 ? 1 : (24 - t) / 6,
          });
        }
        return { pose: 'cry', dy: 0.7 * wave(f, 9), extras };
      });
      break;
    case 'love':
      add(60, (f) => {
        const extras = [];
        for (const [x0, y0, phase] of [[h.cx - 15, h.cy + 8, 0], [h.cx + 15, h.cy + 6, 20], [h.cx + 12, h.cy - 8, 40]]) {
          const t = cycle(f, phase, 60);
          if (t >= 40) continue;
          extras.push({
            kind: 'heart',
            x: x0 + 1.5 * Math.sin((t / 40) * 2 * Math.PI),
            y: y0 - 18 * (t / 40),
            s: 0.5 + 0.5 * Math.min(1, t / 10),
            a: t < 30 ? 1 : (40 - t) / 10,
          });
        }
        return { pose: 'love', dy: -1 * wave(f, 15), extras };
      });
      break;
    case 'busy':
      add(72, (f) => {
        const extras = [];
        for (const phase of [0, 24, 48]) {
          const t = cycle(f, phase, 72);
          if (t >= 48) continue;
          extras.push({
            kind: 'zee', x: h.cx + 10 + 8 * (t / 48), y: h.top + 2 - 14 * (t / 48),
            s: 0.6 + 0.8 * (t / 48), a: t < 36 ? 1 : (48 - t) / 12,
          });
        }
        return { pose: 'busy', extras };
      });
      break;
    case 'offline':
      add(1, () => ({ pose: 'offline' }));
      break;
    default: // stam
      add(84, (f) => ({ pose: f >= 74 && f < 77 ? 'stamBlink' : 'stam' }));
  }
  return frames;
}

// ------------------------------------------------------------------- movie

const TW = SWF.TW;
const tw = (v) => Math.round(v * TW);
const q8 = (a) => Math.max(0, Math.min(256, Math.round(a * 256)));

// The action that gives the face clip its emotion property and its first
// mood. Our own code; the behaviour is the devil kit's avatar class:
//
//   var pre = face.emotion;   // set by the host before this ran, if at all
//   face.addProperty("emotion",
//     function () { return this._emo; },
//     function (v) { this._emo = v; this.gotoAndPlay(1); this.gotoAndPlay(v); });
//   var e = _root.initEmo;
//   if (e == undefined) e = pre;
//   if (e == undefined) e = "stam";
//   face.emotion = e;
//
// gotoAndPlay(1) first, so that the same emotion set again starts over.
function initActions() {
  const setter = new SWF.Asm()
    .push('this').op('GetVariable').push('_emo', 'v').op('GetVariable').op('SetMember')
    .push(1, 1, 'this').op('GetVariable').push('gotoAndPlay').op('CallMethod').op('Pop')
    .push('v').op('GetVariable').push(1, 'this').op('GetVariable').push('gotoAndPlay').op('CallMethod').op('Pop');
  const getter = new SWF.Asm()
    .push('this').op('GetVariable').push('_emo').op('GetMember').op('Return');
  return new SWF.Asm()
    .push('_pre', 'face').op('GetVariable').push('emotion').op('GetMember').op('SetVariable')
    .fn(['v'], setter)
    .fn([], getter)
    .push('emotion', 3, 'face').op('GetVariable').push('addProperty').op('CallMethod').op('Pop')
    .push('_e', '_root').op('GetVariable').push('initEmo').op('GetMember').op('SetVariable')
    .push('_e').op('GetVariable').push(undefined).op('Equals2').op('Not').ifTrue('a')
    .push('_e', '_pre').op('GetVariable').op('SetVariable')
    .label('a')
    .push('_e').op('GetVariable').push(undefined).op('Equals2').op('Not').ifTrue('b')
    .push('_e', 'stam').op('SetVariable')
    .label('b')
    .push('face').op('GetVariable').push('emotion', '_e').op('GetVariable').op('SetMember')
    .bytes();
}

const STOP = new SWF.Asm().op('Stop').bytes();

function buildMovie(p) {
  const tags = [SWF.setBackgroundColor([255, 255, 255])];
  let nextId = 1;
  const shapeIds = new Map();
  const shape = (key, prims) => {
    if (!shapeIds.has(key)) {
      const id = nextId++;
      shapeIds.set(key, id);
      tags.push(SWF.defineShape(id, prims));
    }
    return shapeIds.get(key);
  };
  const bgId = shape('bg', background(p));
  const anims = [];
  for (const emotion of EMOTIONS) {
    const frames = motion(p, emotion).map((fr) => {
      const list = new Map();
      const pose = shape(`pose:${fr.pose}`, character(p, POSES[fr.pose]));
      const m = { tx: tw(fr.dx), ty: tw(fr.dy) };
      const entry = { id: pose, m };
      if (fr.tint) entry.cx = { add: [...fr.tint, 0] };
      list.set(1, entry);
      fr.extras.forEach((e, i) => {
        const id = shape(`x:${e.kind}`, EXTRAS[e.kind]());
        const s = Math.round(e.s * 256) / 256;
        const item = { id, m: { sx: s, sy: s, tx: tw(e.x), ty: tw(e.y) } };
        if (e.a < 1) item.cx = { mul: [256, 256, 256, q8(e.a)] };
        list.set(2 + i, item);
      });
      return { list };
    });
    const id = nextId++;
    tags.push(SWF.defineSprite(id, frames));
    anims.push(id);
  }
  // The face: one frame per emotion, each holding its animation and
  // stopping there.
  const faceId = nextId++;
  tags.push(SWF.defineSprite(faceId, EMOTIONS.map((label, i) => ({
    label, list: new Map([[1, { id: anims[i] }]]), actions: STOP,
  }))));
  tags.push(SWF.placeObject2({ depth: 1, id: bgId }));
  tags.push(SWF.placeObject2({ depth: 2, id: faceId, name: 'face' }));
  tags.push(SWF.doAction(initActions()));
  tags.push(SWF.showFrame());
  tags.push(SWF.endTag());
  return SWF.movie({ width: W, height: H, fps: 24, frameCount: 1, tags });
}

// ------------------------------------------------------------------- pictures

// The first frame of an emotion, drawn at sx, sy.
function picture(p, emotion, width, height) {
  const canvas = new Canvas(width, height, width / W, height / H);
  canvas.draw(background(p));
  const fr = motion(p, emotion)[0];
  canvas.draw(V.transform(character(p, POSES[fr.pose]), { dx: fr.dx, dy: fr.dy }));
  for (const e of fr.extras) {
    const prims = V.transform(EXTRAS[e.kind](), { dx: e.x, dy: e.y, s: e.s });
    canvas.draw(e.a < 1 ? V.recolor(prims, (c) => [c[0], c[1], c[2], Math.round(c[3] * e.a)]) : prims);
  }
  return canvas.rgb();
}

// The pictures the server hands out: the still ICQ takes as a buddy icon
// (52x64 JPEG), the large one (twice the stage) and the gallery-size
// thumbnail (52x64 PNG).
const LARGE = { w: W * 2, h: H * 2 };

function still(p) { return jpeg(52, 64, picture(p, 'stam', 52, 64), 92); }
function large(p, emotion = 'stam') { return png(LARGE.w, LARGE.h, picture(p, emotion, LARGE.w, LARGE.h)); }
function thumb(p) { return png(52, 64, picture(p, 'stam', 52, 64)); }

module.exports = {
  FIELDS, DEFAULTS, EMOTIONS, VERSION, LARGE, parseCode, encode,
  buildMovie, still, large, thumb, initActions,
  // For the tests.
  _internal: { character, motion, POSES, background },
};
