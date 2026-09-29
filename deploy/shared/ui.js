// Shared look for every web page of the project.
//
// Registration and the admin panel used to have one look (a Windows 98 window
// on a teal background) and the pages the client opens had another. Here there
// is one theme for all: a green header with the ICQ flower and a white sheet.
//
// Three services use this file - oscar-register, oscar-admin and
// oscar-legacy-web - so on deployment it is copied into the directory of each
// of them. It has no dependencies.
//
// The class names are kept as they were (window, titlebar, body, hero, msg,
// statusbar, toolbar and the rest) so the services' markup does not have to
// be rewritten: only their appearance changes.

'use strict';

const fs = require('node:fs');
const path = require('node:path');

// The palette. The one place where the project's colours are set.
const TOKENS = {
  green: '#3c6e1f',
  greenLight: '#4a8526',
  greenDark: '#35601a',
  greenRule: '#8bc34a',
  greenInk: '#2e7d32',
  leaf: '#5aa832',
  petalInk: '#c6e39a',
  page: '#d4d0c8',
  sheet: '#ffffff',
  soft: '#eeeae1',
  card: '#f4f2ec',
  line: '#b5b0a4',
  lineHard: '#9a9a9a',
  ink: '#1a1a1a',
  dim: '#767065',
  link: '#0a3d91',
  warn: '#a06000',
  bad: '#c00000',
  badBg: '#fff0f0',
  okBg: '#eefaee',
};

const FONT_STACK = 'Tahoma, "MS Sans Serif", Geneva, Verdana, sans-serif';

// The ICQ Revival badge - the flower from the logo (logo.png next to this
// file, with the lettering), without the lettering, 192x192 on a transparent
// background. It sits alongside as a separate file: there is no reason to keep
// the image as a string in the code. On deployment flower.png is copied into
// the service's directory together with ui.js. It is served at
// /ui/flower.png, see serveAsset.
const FLOWER_PNG = fs.readFileSync(path.join(__dirname, 'flower.png'));

const FLOWER_ASSET = '/ui/flower.png';
// A version derived from the content: the image is cached for a day, and
// without this the browser would keep showing the old logo after the file is
// replaced.
const FLOWER_TAG = require('node:crypto')
  .createHash('sha1').update(FLOWER_PNG).digest('hex').slice(0, 8);

// The site icon is the same flower. Browsers ask for /favicon.ico on their
// own, even with no link in <head>, so it is served there too: an .ico file
// with this PNG inside (every browser since Vista can read that). The FAVICON
// link in the <head> of every page points to the PNG.
const FAVICON_ICO = (() => {
  const head = Buffer.alloc(22);
  head.writeUInt16LE(0, 0);      // reserved
  head.writeUInt16LE(1, 2);      // an icon
  head.writeUInt16LE(1, 4);      // one image
  head.writeUInt8(FLOWER_PNG.readUInt32BE(16) & 0xff, 6);  // width, 0 = 256
  head.writeUInt8(FLOWER_PNG.readUInt32BE(20) & 0xff, 7);  // height
  head.writeUInt16LE(1, 10);     // planes
  head.writeUInt16LE(32, 12);    // bits per pixel
  head.writeUInt32LE(FLOWER_PNG.length, 14);
  head.writeUInt32LE(22, 18);    // the PNG follows the header
  return Buffer.concat([head, FLOWER_PNG]);
})();
const FAVICON = `<link rel="icon" type="image/png" href="${FLOWER_ASSET}?v=${FLOWER_TAG}">`;

function flowerImg(size) {
  return `<img src="${FLOWER_ASSET}?v=${FLOWER_TAG}" width="${size}" height="${size}" alt=""`
    + ` style="border:0;vertical-align:middle">`;
}

// The whole ICQ Revival logo, lettering and all, for the top of the pages
// people open first (registration, downloads): logo-page.png, made from
// logo.png at 440 px wide in 256 colours, shown at half that size so that it
// stays sharp on high-density screens. Served at /ui/logo.png.
const LOGO_PNG = fs.readFileSync(path.join(__dirname, 'logo-page.png'));
const LOGO_ASSET = '/ui/logo.png';
const LOGO_TAG = require('node:crypto')
  .createHash('sha1').update(LOGO_PNG).digest('hex').slice(0, 8);

function logoBlock() {
  const w = LOGO_PNG.readUInt32BE(16), h = LOGO_PNG.readUInt32BE(20);
  return `<div class="logo"><img src="${LOGO_ASSET}?v=${LOGO_TAG}" width="${w / 2}"`
    + ` height="${h / 2}" alt="ICQ Revival"></div>`;
}

// Services call this first thing in their request handler: it returns true if
// the request was for an image and has already been served.
function serveAsset(req, res) {
  const url = String(req.url).split('?')[0];
  const asset = url === FLOWER_ASSET ? { type: 'image/png', body: FLOWER_PNG }
    : url === LOGO_ASSET ? { type: 'image/png', body: LOGO_PNG }
      : url === '/favicon.ico' ? { type: 'image/x-icon', body: FAVICON_ICO }
        : null;
  if (!asset) return false;
  res.writeHead(200, {
    'content-type': asset.type,
    'content-length': asset.body.length,
    'cache-control': 'public, max-age=86400',
  });
  res.end(asset.body);
  return true;
}



const STYLE = `
/* The variables are kept for convenient editing in the browser. Rules must
   not rely on them: the client's built-in engine does not understand var()
   and drops the whole declaration. The values are filled in from TOKENS. */
:root {
  --green: ${TOKENS.green};
  --green-light: ${TOKENS.greenLight};
  --green-dark: ${TOKENS.greenDark};
  --rule: ${TOKENS.greenRule};
  --leaf: ${TOKENS.leaf};
  --page: ${TOKENS.page};
  --sheet: ${TOKENS.sheet};
  --soft: ${TOKENS.soft};
  --card: ${TOKENS.card};
  --line: ${TOKENS.line};
  --line-hard: ${TOKENS.lineHard};
  --ink: ${TOKENS.ink};
  --dim: ${TOKENS.dim};
  --link: ${TOKENS.link};
}
* { box-sizing: border-box; }

body {
  margin: 0;
  padding: 18px 12px;
  font-family: ${FONT_STACK};
  font-size: 15px;
  line-height: 1.5;
  color: ${TOKENS.ink};
  background: ${TOKENS.page};
}
/* A centred column without flexbox: the client's built-in engine lacks it. */
.window { margin: 0 auto; }
/* The logo at the top of the pages people open first; it never grows wider
   than the sheet on a phone. */
.logo { text-align: center; margin: 2px 0 14px; }
.logo img { max-width: 70%; height: auto; border: 0; }
/* The client's window is small - the same rules, but tighter. */
body.compact { padding: 6px; font-size: 13px; line-height: 1.45; }
body.compact .titlebar td { padding-top: 5px; padding-bottom: 5px; }
body.compact .label { font-size: 16px; }
body.compact .body { padding: 8px 10px; }
body.compact .statusbar td { padding-top: 4px; padding-bottom: 4px; }
body.compact p { margin: 0 0 5px; }
body.compact h2 { margin: 7px 0 3px; }

/* The sheet. The old name .window is kept, but there is no window frame any
   more. It spans the full width of the browser window: body gives the
   margins. */
.window {
  width: 100%;
  background: ${TOKENS.sheet};
  border: 1px solid ${TOKENS.line};
  border-radius: 6px;
  box-shadow: 0 2px 8px rgba(0,0,0,.14);
  overflow: hidden;
}

/* A header with the flower instead of the blue window title bar. */
.titlebar {
  background: ${TOKENS.green};
  background-image: linear-gradient(${TOKENS.greenLight}, ${TOKENS.greenDark});
  border-bottom: 4px solid ${TOKENS.greenRule};
}
.titlebar td { padding: 9px 4px 9px 0; }
/* The header and footer contain nested tables (the flower): the padding of
   the outer cells must not apply to them, or they get stretched. */
.titlebar td td, .statusbar td td { padding: 0; }
.titlebar td.flowercell { padding-left: 12px; }
.titlebar td:last-child { padding-right: 12px; }
.label { color: #fff; font-weight: bold; font-size: 20px; letter-spacing: .2px; }
.box { font-weight: normal; font-size: 13px; color: ${TOKENS.petalInk}; }

.body, .content { padding: 14px 16px; }

.hero {
  background: ${TOKENS.soft};
  border: 1px solid ${TOKENS.line};
  border-radius: 4px;
  padding: 10px 12px;
  margin-bottom: 12px;
}
.hero h1 { margin: 0 0 3px; font-size: 17px; }
.hero p { margin: 0; font-size: 14px; color: #444; }

fieldset { border: 1px solid ${TOKENS.line}; border-radius: 4px; margin: 0 0 12px; padding: 10px 12px; }
legend { padding: 0 5px; font-weight: bold; }
label { display: block; margin-bottom: 3px; }
.label { font-weight: bold; }

input[type=text], input[type=password], input[type=email], select, textarea {
  width: 100%;
  font-family: inherit;
  font-size: 15px;
  padding: 6px 8px;
  color: ${TOKENS.ink};
  background: #fff;
  border: 1px solid ${TOKENS.lineHard};
  border-radius: 3px;
}
input:focus, select:focus, textarea:focus {
  outline: 2px solid ${TOKENS.leaf};
  outline-offset: -1px;
}
.row + .row { margin-top: 10px; }
.hint { font-size: 13px; color: ${TOKENS.dim}; margin-top: 3px; }

.actions { margin-top: 12px; }
.actions > * { margin-right: 8px; }
button {
  font-family: inherit;
  font-size: 15px;
  padding: 7px 16px;
  color: ${TOKENS.ink};
  background: #f2f0ea;
  border: 1px solid ${TOKENS.lineHard};
  border-radius: 3px;
  cursor: pointer;
}
button:hover:not(:disabled) { background: #e8e5dd; }
button:active:not(:disabled) { transform: translateY(1px); }
button:disabled { color: #9a9a9a; cursor: default; }
button.primary {
  color: #fff;
  background: ${TOKENS.green};
  background-image: linear-gradient(${TOKENS.greenLight}, ${TOKENS.greenDark});
  border-color: ${TOKENS.greenDark};
}
button.primary:hover:not(:disabled) { background-image: linear-gradient(#54932b, ${TOKENS.green}); }
button.danger { color: #fff; background: ${TOKENS.bad}; border-color: #8f0000; }

.msg {
  border: 1px solid ${TOKENS.line};
  border-radius: 4px;
  background: ${TOKENS.soft};
  padding: 10px 12px;
  margin-bottom: 12px;
}
.msg.err { background: ${TOKENS.badBg}; border-color: #e0a0a0; }
.msg.ok { background: ${TOKENS.okBg}; border-color: #a6d3a6; }
.msg h2 { margin: 0 0 5px; font-size: 16px; }
.msg p { margin: 0 0 6px; }
.msg p:last-child { margin-bottom: 0; }
.msg .uin, .uin { font-family: "Courier New", monospace; font-weight: bold; }

.setup { background: #fff; border: 1px solid ${TOKENS.line}; border-radius: 4px; padding: 10px 12px; }
.setup code, .msg code, code {
  font-family: "Courier New", monospace;
  background: #f4f2ec;
  border: 1px solid ${TOKENS.line};
  border-radius: 2px;
  padding: 0 3px;
}

/* Data tables (the admin panel's lists). The class is required: otherwise the
   rules spill onto the tables used to lay out cards and link lists. */
table.data { width: 100%; border-collapse: collapse; }
table.data thead th {
  text-align: left;
  font-size: 13px;
  color: ${TOKENS.dim};
  border-bottom: 1px solid ${TOKENS.line};
  padding: 5px 8px 5px 0;
}
table.data tbody td { padding: 5px 8px 5px 0; border-bottom: 1px solid #e6e2d9; }
table.data tbody tr:hover td { background: #f7f5f0; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
.dot.on { background: ${TOKENS.greenInk}; }
.dot.off { background: #b8b2a6; }
.tag {
  display: inline-block;
  font-size: 11px;
  padding: 1px 6px;
  border-radius: 9px;
  background: ${TOKENS.soft};
  border: 1px solid ${TOKENS.line};
}
.tag.blocked { background: ${TOKENS.badBg}; border-color: #e0a0a0; color: ${TOKENS.bad}; }
.rowactions > * { margin-right: 5px; }
.rowactions button { padding: 3px 8px; font-size: 12px; }
.scroll { overflow-x: auto; }
.toolbar { margin-bottom: 10px; }
.toolbar > * { margin-right: 8px; }
.toolbar .grow, .statusbar .grow { flex: 1; }
.note { font-size: 13px; color: ${TOKENS.dim}; }
.empty { padding: 16px 0; color: ${TOKENS.dim}; text-align: center; }

.statusbar, .foot {
  border-top: 1px solid ${TOKENS.line};
  background: #f7f5f0;
  font-size: 12px;
  color: ${TOKENS.dim};
}
.statusbar td { padding: 6px 4px; }
.statusbar td:first-child { padding-left: 12px; }
.statusbar td:last-child { padding-right: 12px; }
.langs { white-space: nowrap; }
.langs a, .langs b, .langs button { margin-left: 5px; }
.langs button { padding: 2px 8px; font-size: 13px; border-radius: 9px; }
.langs button[aria-current="true"] { color: #fff; background: ${TOKENS.green}; border-color: ${TOKENS.greenDark}; }
/* In services without scripts the switcher is links, not buttons. Same look. */
.langs a, .langs b {
  display: inline-block;
  padding: 2px 9px;
  font-size: 13px;
  font-weight: normal;
  border-radius: 9px;
  border: 1px solid ${TOKENS.lineHard};
  background: #f2f0ea;
  color: ${TOKENS.ink};
  text-decoration: none;
}
.langs a:hover { background: #e8e5dd; color: ${TOKENS.ink}; }
.langs b { color: #fff; background: ${TOKENS.green}; border-color: ${TOKENS.greenDark}; }

.card {
  background: ${TOKENS.card};
  border: 1px solid ${TOKENS.line};
  border-radius: 4px;
  padding: 8px 11px;
  margin-bottom: 10px;
}
.soft {
  background: ${TOKENS.soft};
  border: 1px solid ${TOKENS.line};
  border-radius: 4px;
  padding: 8px 11px;
}
.sheet { background: ${TOKENS.sheet}; }
.bul {
  background: ${TOKENS.leaf};
  width: 5px; height: 5px;
  font-size: 0; line-height: 0;
}
.dim { color: ${TOKENS.dim}; }
.ok { color: ${TOKENS.greenInk}; }
.warn { color: ${TOKENS.warn}; }
.bad { color: ${TOKENS.bad}; }
h2 { margin: 14px 0 6px; font-size: 16px; }

.nav { margin-top: 12px; }
.nav > * { margin-right: 12px; }
a, .nav a { color: ${TOKENS.link}; }
a:hover { color: #a01010; }

/* Narrow screen: the admin tables and columns must not spread apart. */
@media (max-width: 520px) {
  body { padding: 10px 8px; }
  .titlebar { font-size: 16px; padding: 8px 10px; }
  .body, .content { padding: 10px 11px; }
  .hide-sm { display: none; }
}
`;

// ---------------------------------------------------------- header and footer
//
// The header and footer markup lives here rather than in each service:
// otherwise they inevitably drift apart in small things like the letter case
// in the language switcher.

// The language label in the switcher. The same everywhere: UK, EN.
function langLabel(code) {
  return String(code).toUpperCase();
}

// title and subtitle are inserted as is, so the caller escapes them.
// attrs is for services that translate the page on the fly (data-i18n).
function header(title, subtitle, attrs) {
  return `<table class="titlebar" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td width="34" align="left" valign="middle" class="flowercell">${flowerImg(24)}</td>
    <td valign="middle"><span class="label"${attrs ? ' ' + attrs : ''}>${title}</span></td>
    <td align="right" valign="middle">${subtitle ? `<span class="box">${subtitle}</span>` : ''}</td>
  </tr>
</table>`;
}

// status goes on the left, extra is any insert before the languages
// (counters), langs is ready switcher markup or an id for a script to fill.
function footer(opts) {
  const o = opts || {};
  const statusId = o.statusId ? ` id="${o.statusId}"` : '';
  const langsId = o.langsId ? ` id="${o.langsId}"` : '';
  return `<table class="statusbar" width="100%" cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td valign="middle"><span class="grow"${statusId}>${o.status || ''}</span></td>
    <td align="right" valign="middle" nowrap>${o.extra || ''}
      <span class="langs"${langsId}>${o.langs || ''}</span></td>
  </tr>
</table>`;
}

// ------------------------------------------------------------------ languages

const LANGS = ['uk', 'en'];
const FALLBACK_LANG = 'en';

// Picks the language from the Accept-Language header, honouring q weights.
function pickLang(header) {
  if (!header) return FALLBACK_LANG;
  const ranked = String(header)
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params
        .map((x) => x.trim())
        .filter((x) => x.startsWith('q='))
        .map((x) => Number(x.slice(2)))[0];
      return { tag: tag.trim().toLowerCase(), q: Number.isFinite(q) ? q : 1 };
    })
    .filter((x) => x.tag)
    .sort((a, b) => b.q - a.q);

  for (const { tag } of ranked) {
    const base = tag.split('-')[0];
    if (LANGS.includes(base)) return base;
  }
  return FALLBACK_LANG;
}

module.exports = {
  STYLE, TOKENS, FONT_STACK,
  LANGS, FALLBACK_LANG, pickLang, langLabel,
  header, footer, flowerImg, logoBlock, serveAsset, FAVICON,
};
