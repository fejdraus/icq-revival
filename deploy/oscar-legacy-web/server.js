// Stand-in for the dead ICQ web services.
//
// Clients from 98 to 5.1 talk HTTP to cf.icq.com, web.icq.com, wwp.icq.com and
// other AOL hosts. None of them answer any more, yet DNS still resolves them, so
// the client hangs until the TCP timeout instead of failing fast. This service
// answers for them: some pages are genuinely restored, the rest return a clear
// stub instead of a hang.
//
// It runs in two modes, both described in services.json; no address is hard
// coded here:
//
//   by path  - the client points at an arbitrary server address (/icq/today and
//              so on). The Host header can be anything; the address is chosen by
//              whoever runs the client. This is the main mode.
//   by name  - the original ICQ.com names are intercepted through DNS or hosts.
//              Needed when the address is baked into the client and no config
//              can change it.
//
// The route is the first matching rule: paths first, then names.
//
// No dependencies, the standard library only.

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const child_process = require('node:child_process');
const zlib = require('node:zlib');
// The shared look of the project, the same as registration and the admin page.
const { STYLE: SHARED_STYLE, LANGS, FALLBACK_LANG, pickLang,
  langLabel, header, footer, serveAsset } = require('./ui.js');
// Miranda NG's PluginUpdater through this server, with our plugins in its list.
const { createMirror } = require('./miranda-updates.js');
// Avatars made in the constructor, /icq/avatar/maker: c-<code>.swf and its
// pictures, drawn from the code on request (see maker/index.js).
const maker = require('./maker');
// The picture editor's geometry, shared with the page (see picture-crop.js).
const { pictureCrop, parseCropParams, ICON_W, ICON_H, ZOOM_MAX } = require('./picture-crop.js');

const PORT = Number(process.env.PORT || 8101);
// Clients connect to the address written in their own config, so the service has
// to be reachable on the network. The default is still the loopback: opening it
// up should be a deliberate act.
const BIND = process.env.BIND || '127.0.0.1';
const CONFIG_PATH = process.env.CONFIG || path.join(__dirname, 'services.json');

// The ICQ code books (countries, interests), the same ones the profile page
// uses. Without the file a card simply shows no decoded names instead of
// failing.
// The Xtraz list ICQ 6 fills its own windows from. It is the original list with
// one entry of ours added: serving a shorter one replaces the client's own
// categories, and the strip at the top loses everything it had.
let xtrazList = '<xtrazList majorVer="1" minorVer="0"><groups/><xtraz/></xtrazList>';
try {
  xtrazList = fs.readFileSync(path.join(__dirname, 'xtrazlist.xml'), 'utf8');
} catch {
  // Without the file the gallery stays as it was: the client reports a problem.
}

// tZers: the short movies with sound ICQ 6.5 plays over the message window,
// and their thumbnails (the client has its own copies and asks only for a
// missing one). The ICQ 6.5 patch points ConfigFiles\tzer.xml at
// /icq/tzers/ here and lists only the tZers this folder has (the list in
// tools/patcher/Icq65/Icq65Client.cs; the files come from
// tools/icq65/tzers/make_tzers.py). The receiving client fetches the movie by
// the address the sender's list gave, so it has to be reachable from anywhere.
//
// Only the names found in the folder are served, read once at start and again
// on SIGHUP: a request names a file, never a path, so there is nothing to walk
// out of the folder with.
const TZER_DIR = path.join(__dirname, 'tzers');
const TZER_TYPES = {
  '.swf': 'application/x-shockwave-flash',
  '.png': 'image/png',
  '.gif': 'image/gif',
};
let tzerFiles = new Map();

// A plain file name: letters, digits, _ and -, one extension.
const PLAIN_NAME = /^[a-z0-9_-]+\.[a-z]+$/i;

// The files of one folder with a known type and a plain name, in memory.
// Without the folder the map is empty and every request is a 404.
function loadFolder(dir, types, names = PLAIN_NAME) {
  const files = new Map();
  try {
    for (const name of fs.readdirSync(dir)) {
      const type = types[path.extname(name).toLowerCase()];
      if (!type || !names.test(name)) continue;
      files.set(name.toLowerCase(), { body: fs.readFileSync(path.join(dir, name)), type });
    }
  } catch {
    // No folder, no files.
  }
  return files;
}

// The files /icq/download offers, served from /icq/files/: the client
// patches and the Miranda NG plugins, built by tools/make-downloads.py and
// copied to the machine by hand (the Flash engine in them is 15 MB, not kept
// in git). Read at start and on SIGHUP, like the tZers.
const FILES_DIR = process.env.DOWNLOADS_DIR || path.join(__dirname, 'files');
const FILE_TYPES = {
  '.exe': 'application/vnd.microsoft.portable-executable',
  '.zip': 'application/zip',
};
let downloadFiles = new Map();

function loadDownloads() {
  downloadFiles = loadFolder(FILES_DIR, FILE_TYPES);
}

function loadTzers() {
  tzerFiles = loadFolder(TZER_DIR, TZER_TYPES);
}

// Animated avatars: the Flash "devils" ICQ 6 shows in place of a buddy
// picture. The picture page offers them, and picking one hands the client
// the movie's address here (SetBartItem, BART type 8); every contact's client
// then fetches the movie from that address itself, over plain HTTP, so like
// the tZers it has to be reachable from anywhere. The folder and its
// avatars.json (titles, groups, thumbnails) come from
// tools/icq65/avatars/fetch_avatars.py. Same rules as the tZers: exact file
// names only, read at start and on SIGHUP.
const AVATAR_DIR = path.join(__dirname, 'avatars');
const AVATAR_TYPES = {
  '.swf': 'application/x-shockwave-flash',
  '.gif': 'image/gif',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
};
let avatarFiles = new Map();
let avatarList = [];

function loadAvatars() {
  const files = loadFolder(AVATAR_DIR, AVATAR_TYPES);
  let list = [];
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(AVATAR_DIR, 'avatars.json'), 'utf8'));
    // Only the entries whose movie and thumbnail are really there.
    list = (manifest.avatars || []).filter((a) => a && typeof a.file === 'string'
      && files.has(a.file.toLowerCase()) && files.has(String(a.thumb || '').toLowerCase()));
  } catch {
    // No list, no gallery: the page shows the picture tab only.
  }
  avatarFiles = files;
  avatarList = list;
  moodMovies = new Map();
}

// An avatar by its movie's file name: one of the gallery, or one made in the
// constructor (c-<code>.swf); null otherwise.
function lookupAvatar(file) {
  const name = String(file || '').toLowerCase();
  return avatarList.find((a) => a.file.toLowerCase() === name) || maker.entry(name);
}

// One file of an avatar as { body, type }: from the folder, or made from a
// constructor code; null when there is no such file.
function avatarAsset(name) {
  const lower = String(name || '').toLowerCase();
  return avatarFiles.get(lower) || (maker.isName(lower) ? maker.file(lower) : null);
}

// An animated avatar stands still until it is told its owner's mood: the
// client sets face.emotion, and the face clip's class goes to the frame label
// of that name (stam, idle; smile, sad, ... offline), where a short gesture
// plays once and stops. A browser player has nobody to do that, so the card
// is served a copy of the movie that does it itself, with one DoAction at the
// end of the first frame, run once the face clip is on the stage and its
// class is registered:
//   face.emotion = "stam";
//   setInterval(function () { face.emotion = "<other>"; face.emotion = "stam"; }, 4000);
// The detour through another label within the same frame is never drawn; it
// only makes the face start its gesture over, so the card keeps moving.
// The copies are made on first request and kept.
let moodMovies = new Map();

// How often the card's face starts its gesture over.
const REPLAY_MS = 4000;

// The movie with its face on `emotion`, replayed through `other`, another of
// its labels (see above); null when the movie cannot be read.
function moodMovie(swf, emotion, other) {
  let body;
  try {
    body = swf.toString('latin1', 0, 3) === 'CWS' ? zlib.inflateSync(swf.subarray(8)) : swf.subarray(8);
  } catch {
    return null;
  }
  // After the stage's rectangle, the frame rate and the frame count come the
  // tags; the new one goes in front of the first frame's ShowFrame.
  const bits = body[0] >> 3;
  let pos = Math.ceil((5 + 4 * bits) / 8) + 4;
  for (;;) {
    if (pos + 2 > body.length) return null;
    const head = body.readUInt16LE(pos);
    const code = head >> 6;
    let len = head & 0x3f;
    let headLen = 2;
    if (len === 0x3f) {
      if (pos + 6 > body.length) return null;
      len = body.readUInt32LE(pos + 2);
      headLen = 6;
    }
    if (code === 1) break;
    if (code === 0) return null;
    pos += headLen + len;
  }
  const str = (s) => Buffer.from(`${s}\0`, 'latin1');
  const push = (...values) => {
    const data = Buffer.concat(values.map((v) => (typeof v === 'number'
      ? Buffer.from([7, v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]) // int
      : Buffer.concat([Buffer.from([0]), str(v)])))); // string
    const head = Buffer.from([0x96, 0, 0]);
    head.writeUInt16LE(data.length, 1);
    return Buffer.concat([head, data]);
  };
  const setEmotion = (label) => Buffer.concat([
    push('face'), Buffer.from([0x1c]), // GetVariable
    push('emotion', label), Buffer.from([0x4f]), // SetMember
  ]);
  const replay = Buffer.concat([setEmotion(other), setEmotion(emotion)]);
  // DefineFunction with no name and no parameters: pushes the function.
  const define = Buffer.from([0x9b, 5, 0, 0, 0, 0, 0, 0]);
  define.writeUInt16LE(replay.length, 6);
  const actions = Buffer.concat([
    setEmotion(emotion),
    push(REPLAY_MS), define, replay, // the arguments, last first
    push(2, 'setInterval'), Buffer.from([0x3d, 0x17]), // CallFunction, Pop
    Buffer.from([0x00]), // End
  ]);
  const tag = Buffer.alloc(6);
  tag.writeUInt16LE((12 << 6) | 0x3f, 0); // DoAction, long length
  tag.writeUInt32LE(actions.length, 2);
  const out = Buffer.concat([body.subarray(0, pos), tag, actions, body.subarray(pos)]);
  const header = Buffer.from([0x46, 0x57, 0x53, swf[3], 0, 0, 0, 0]); // FWS, version
  header.writeUInt32LE(out.length + 8, 4);
  return Buffer.concat([header, out]);
}

// GET /icq/avatars/<movie>.swf?emotion=<label>: that copy, for one of the
// gallery's movies and one of the labels it has; anything else is a 404.
function serveMoodMovie(ctx) {
  const name = ctx.path.replace(/^\/icq\/avatars\//i, '').toLowerCase();
  const emotion = ctx.url.searchParams.get('emotion') || '';
  // A constructed avatar's large picture of one emotion: the constructor's
  // preview where the movie cannot play.
  if (maker.isName(name) && !name.endsWith('.swf')) {
    serveMakerFile(ctx, name, emotion);
    return;
  }
  const avatar = lookupAvatar(name);
  const key = `${name}?${emotion}`;
  const labels = (avatar && avatar.labels) || [];
  const other = labels.find((l) => l !== emotion);
  const make = () => {
    const file = avatarAsset(name);
    return file && other && labels.includes(emotion) ? moodMovie(file.body, emotion, other) : null;
  };
  let body;
  if (maker.isName(name)) {
    // Kept with the other made files, so that no code adds for good.
    body = maker.cached(key, make);
  } else {
    body = moodMovies.get(key);
    if (!body) {
      body = make();
      if (body) moodMovies.set(key, body);
    }
  }
  if (!body || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) {
    ctx.res.writeHead(404, { 'content-length': 0 });
    ctx.res.end();
    return;
  }
  ctx.res.writeHead(200, {
    'content-type': 'application/x-shockwave-flash',
    'content-length': body.length,
    'cache-control': 'public, max-age=86400',
  });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : body);
}

// GET /icq/avatars/c-<code>.swf (-still.jpg, -large.png, .png): a file of
// an avatar made in the constructor, drawn on first request and cached; any
// other name under c- is a 404. They never change, like the gallery's.
function serveMakerFile(ctx, name, emotion = '') {
  const file = maker.file(name, emotion);
  if (!file || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) {
    ctx.res.writeHead(404, { 'content-length': 0 });
    ctx.res.end();
    return;
  }
  ctx.res.writeHead(200, {
    'content-type': file.type,
    'content-length': file.body.length,
    'cache-control': 'public, max-age=86400',
  });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : file.body);
}

// Ruffle, the Flash player written in Rust, in its web build
// (@ruffle-rs/ruffle 0.6.0 from npm): the user card plays the animated avatar
// with it in a browser of today, which has no Flash of its own. Only what the
// card needs is kept: the loader, ruffle.js, and the build for browsers with
// the WebAssembly extensions - every current one. A browser without them asks
// for the other build, gets a 404, and the card keeps its still picture.
//
// The loader is fetched only by pages that show an animated avatar, and the
// WebAssembly (14 MB, about 4 MB compressed) only once the player starts.
// Served by exact name like the tZers; the chunk names carry a content hash
// and are cached for good, ruffle.js is linked with its own hash as ?v=.
// Compressed copies are made in the background at start.
const RUFFLE_DIR = path.join(__dirname, 'ruffle');
const RUFFLE_TYPES = {
  '.js': 'text/javascript; charset=utf-8',
  '.wasm': 'application/wasm',
};
// Ruffle's chunks are named like core.ruffle.<hash>.js, with dots inside.
const RUFFLE_NAME = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.[a-z]+$/i;
const HASHED_NAME = /(^|\.)[0-9a-f]{20}\.[a-z]+$/i;
let ruffleFiles = new Map();
let ruffleTag = '';

function loadRuffle() {
  const files = loadFolder(RUFFLE_DIR, RUFFLE_TYPES, RUFFLE_NAME);
  const loader = files.get('ruffle.js');
  ruffleTag = loader ? crypto.createHash('sha1').update(loader.body).digest('hex').slice(0, 8) : '';
  for (const file of files.values()) {
    file.etag = `"${crypto.createHash('sha1').update(file.body).digest('hex').slice(0, 20)}"`;
    zlib.brotliCompress(file.body, {
      params: {
        [zlib.constants.BROTLI_PARAM_QUALITY]: 9,
        [zlib.constants.BROTLI_PARAM_SIZE_HINT]: file.body.length,
      },
    }, (err, out) => { if (!err) file.br = out; });
    zlib.gzip(file.body, { level: 9 }, (err, out) => { if (!err) file.gzip = out; });
  }
  ruffleFiles = files;
}

// GET /icq/ruffle/<name>: one file of Ruffle's web build, compressed when the
// browser takes it and the copy is ready.
function serveRuffle(ctx) {
  const name = ctx.path.replace(/^\/icq\/ruffle\//i, '');
  const file = RUFFLE_NAME.test(name) ? ruffleFiles.get(name.toLowerCase()) : null;
  if (!file || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) {
    ctx.res.writeHead(404, { 'content-length': 0 });
    ctx.res.end();
    return;
  }
  // A hashed name, or the loader asked for by its current hash, never changes.
  const forever = HASHED_NAME.test(name)
    || (name.toLowerCase() === 'ruffle.js' && ctx.url.searchParams.get('v') === ruffleTag);
  const headers = {
    'content-type': file.type,
    'cache-control': forever ? 'public, max-age=31536000, immutable' : 'public, max-age=3600',
    'x-content-type-options': 'nosniff',
    etag: file.etag,
    vary: 'accept-encoding',
  };
  if (ctx.req.headers['if-none-match'] === file.etag) {
    ctx.res.writeHead(304, headers);
    ctx.res.end();
    return;
  }
  const accepts = String(ctx.req.headers['accept-encoding'] || '');
  let body = file.body;
  if (file.br && /\bbr\b/.test(accepts)) {
    body = file.br;
    headers['content-encoding'] = 'br';
  } else if (file.gzip && /\bgzip\b/.test(accepts)) {
    body = file.gzip;
    headers['content-encoding'] = 'gzip';
  }
  headers['content-length'] = body.length;
  ctx.res.writeHead(200, headers);
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : body);
}

let CODES = {};
try {
  CODES = JSON.parse(fs.readFileSync(path.join(__dirname, 'icq-codes.json'), 'utf8'));
} catch {
  CODES = {};
}

// ------------------------------------------------------------------- config

function loadConfig() {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  if (!Array.isArray(cfg.routes) || cfg.routes.length === 0) {
    throw new Error(`${CONFIG_PATH}: routes is empty`);
  }
  for (const [i, r] of cfg.routes.entries()) {
    if (!r.action) throw new Error(`${CONFIG_PATH}: route #${i} has no action`);
    if (!ACTIONS[r.action]) {
      throw new Error(`${CONFIG_PATH}: route #${i}: unknown action "${r.action}"`);
    }
    // Compile the regular expressions once; this also catches typos at startup.
    r._path = r.path ? new RegExp(r.path, 'i') : null;
  }
  // Environment variables override the file, which is handy under systemd.
  cfg.mgmtApi = process.env.MGMT_API || cfg.mgmtApi || 'http://127.0.0.1:8090';
  cfg.registerBase = process.env.REGISTER_BASE || cfg.registerBase || '';
  cfg.serverName = process.env.SERVER_NAME || cfg.serverName || 'ICQ Revival';
  cfg.oscarHost = process.env.OSCAR_HOST || cfg.oscarHost || '';
  cfg.contact = process.env.CONTACT || cfg.contact || '';
  cfg.downloads = cfg.downloads || {};
  return cfg;
}

// Filled in at the end of the file: loadConfig validates actions against the
// ACTIONS table, which is a const and, unlike a function, is not hoisted.
let config;

// The ICQ.com help topics: what each one was and what replaces it. Lives next to
// the config and is reloaded together with it.
let topics = {};

function loadTopics() {
  const file = path.join(path.dirname(CONFIG_PATH), 'topics.json');
  try {
    topics = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`topics not loaded (${err.message}), falling back to the generic stub`);
    topics = {};
  }
}

function hostMatches(pattern, host) {
  if (!pattern || pattern === '*') return true;
  if (pattern.startsWith('*.')) return host === pattern.slice(2) || host.endsWith(pattern.slice(1));
  return host === pattern.toLowerCase();
}

// Match the path together with the query string: several services name the
// topic in the parameters, e.g. /cgi-bin/support.pl5?topic=Registration_2001b.
function pickRoute(host, pathAndQuery) {
  return config.routes.find(
    (r) => hostMatches(r.host, host) && (!r._path || r._path.test(pathAndQuery)),
  );
}

function expand(target, vars) {
  return String(target || '').replace(/\{(\w+)\}/g, (all, key) => (
    key in vars ? vars[key] : all
  ));
}

// ---------------------------------------------------------------- management

async function mgmt(apiPath, options = {}) {
  const res = await fetch(config.mgmtApi + apiPath, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) {
    throw new Error(`${options.method || 'GET'} ${apiPath}: HTTP ${res.status}`);
  }
  // Some routes answer with plain text ("Message sent") rather than JSON.
  const type = res.headers.get('content-type') || '';
  if (res.status === 204 || !type.includes('json')) {
    await res.arrayBuffer();
    return null;
  }
  return res.json();
}

// The raw bytes of a management API answer with their content type, for the
// routes that return a file rather than JSON (the user's picture). A 404 is an
// answer - there is no such file - and comes back as null.
async function mgmtBytes(apiPath) {
  const res = await fetch(config.mgmtApi + apiPath, { signal: AbortSignal.timeout(5000) });
  if (res.status === 404) {
    await res.arrayBuffer();
    return null;
  }
  if (!res.ok) {
    throw new Error(`GET ${apiPath}: HTTP ${res.status}`);
  }
  return {
    type: (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase(),
    body: Buffer.from(await res.arrayBuffer()),
  };
}

// ---------------------------------------------------------------- translations
//
// The languages are the ones registration and the admin page use, taken from the
// shared module. Chosen by the ?lang= parameter, otherwise by Accept-Language.

const I18N = {
  en: {
    poweredBy: 'powered by ICQ Revival',
    welcomeTitle: 'Welcome',
    welcomeSub: 'the old ICQ, back on the air',
    // The picture page ICQ 6.5 opens to set your buddy icon.
    picTitle: 'Your picture',
    picSub: 'shown next to your name',
    picLead: 'Pick an image, then move and zoom it in the frame. Nothing is sent '
      + 'until you say so.',
    // The picture editor.
    picInProfile: 'profile',
    picInList: 'list',
    picZoom: 'Zoom',
    picZoomIn: 'Zoom in',
    picZoomOut: 'Zoom out',
    picMoveLeft: 'Move left',
    picMoveUp: 'Move up',
    picMoveDown: 'Move down',
    picMoveRight: 'Move right',
    picCentre: 'Centre',
    picEditHint: 'Drag the picture in the frame; the wheel or the slider zooms.',
    picSetPicture: 'Set as my picture',
    picCutFailed: 'The server could not cut the picture. Try uploading it again.',
    picOpenInBrowser: 'The client could not open your browser. Copy this address into it:',
    picCurrent: 'Current picture',
    picCurrentNote: 'as your contacts see it now',
    picPreview: 'This is how it will look',
    picUpload: 'Upload to the server',
    picCancel: 'Cancel',
    picOnlyInIcq: 'This page only works inside ICQ.',
    picNoClient: 'Could not reach the client: ',
    picPreparing: 'Preparing the preview...',
    picSendFailed: 'Could not send the file: ',
    picPrepareFailed: 'Could not prepare the picture: ',
    picNoAnswer: 'The server did not take the file. Is it larger than 16 MB?',
    picReady: 'ready to upload',
    picUploading: 'Uploading...',
    picRefused: 'The client refused the picture: ',
    picReadFailed: 'Could not read the current picture: ',
    picSaved: 'Saved. Everyone sees it from now on.',
    picDone: 'Done.',
    picServerRefused: 'The server did not take the picture.',
    picErrNotForm: 'not a form upload',
    picErrTooLarge: 'the file is larger than 16 MB',
    picErrMalformed: 'the upload is malformed',
    picErrEmpty: 'the file is empty',
    // The animated tab: the Flash faces of ICQ 6.
    picTabPicture: 'Picture',
    picTabAnimated: 'Animated',
    picAnimLead: 'A moving face instead of a still picture. ICQ 6 plays it next to '
      + 'your name, and it changes with your mood and status. Pick one, then set it.',
    picAnimNote: 'Contacts on other clients or older ICQ versions cannot play the '
      + 'animation: they see a still picture of it instead, which the server provides.',
    picAnimNow: 'Now set:',
    picAnimNone: 'none',
    picAnimOther: 'one that is not on this server',
    picAnimIcq: 'ICQ',
    picAnimUser: 'User created',
    picAnimChosen: 'Chosen:',
    picAnimSet: 'Use this animation',
    picAnimSetting: 'Setting the animation...',
    picAnimSaved: 'Set. Your contacts see it from now on.',
    picAnimRefused: 'The client refused the animation: ',
    picAnimServerRefused: 'The server did not take the animation.',
    picAnimTry: 'See it move',
    picAnimTester: 'Try every avatar in the tester',
    // The avatar tester, /icq/avatar/tester.
    tstTitle: 'Avatar tester',
    tstSub: 'see a face move before you set it',
    tstLead: 'The animated avatars of this server, played the way ICQ 6.5 plays them. '
      + 'The buttons show how an avatar reacts to your mood and status.',
    tstFaces: 'Faces:',
    tstMood: {
      stam: 'Idle', smile: 'Smile', sad: 'Sad', laugh: 'Laugh', mad: 'Angry',
      cry: 'Cry', love: 'Love', busy: 'Busy', offline: 'Offline',
    },
    tstByIcq: 'by ICQ',
    tstByUser: 'made by a user',
    tstPictures: 'The pictures the server hands out for it',
    tstStill: 'Still',
    tstStillNote: 'contacts on other clients and older ICQ versions',
    tstLarge: 'Large',
    tstLargeNote: 'the user card on these pages',
    tstThumb: 'Thumbnail',
    tstThumbNote: 'the galleries in ICQ 6.5 and Miranda NG',
    tstNoPlayer: 'This window cannot play Flash movies, so it shows the still picture. '
      + 'To see the avatar move and try its faces, open this page in a current browser:',
    tstPlayerFailed: 'The player could not start here, so the still picture is shown.',
    tstHowToSet: 'To use an avatar, open your picture in ICQ 6.5 (the Animated tab), '
      + 'or the avatar picker of the ICQ Revival plugin in Miranda NG.',
    tstAll: 'All avatars',
    tstNone: 'This server has no animated avatars.',
    tstUnknown: 'There is no such avatar here; showing the first one.',
    tstByMaker: 'made in the avatar constructor',
    tstEditInMaker: 'Change it in the constructor',
    tstMakeOwn: 'Make your own avatar in the constructor',
    // The avatar constructor, /icq/avatar/maker.
    mkTitle: 'Avatar constructor',
    mkSub: 'an animated face of your own',
    mkFaces: 'Faces:',
    mkSet: 'Set as my avatar',
    mkSetting: 'Setting the avatar...',
    mkSaved: 'Set. Your contacts see it from now on.',
    mkRefused: 'The client refused the avatar: ',
    mkServerRefused: 'The server did not take the avatar.',
    mkRandom: 'Surprise me',
    mkTry: 'Open in the tester',
    mkBack: 'Back to your picture',
    mkBackShort: 'Back',
    mkShow: 'Show',
    mkAddress: 'The address of this avatar:',
    mkHowTo: 'To use it, open the constructor from ICQ 6.5 (your picture, the Animated tab, '
      + '"Make your own") and press "Set as my avatar". Miranda NG\'s picker offers the '
      + 'gallery only, but Miranda contacts see a constructed avatar like any other.',
    picAnimMake: 'Make your own',
    picAnimOwn: 'your own, from the constructor',
    picReduced: (from, to) => `${from} reduced to ${to}`,
    picBytes: (n) => (n < 1024 ? `${n} bytes` : `${Math.round(n / 1024)} KB`),
    signedInAs: (u) => `Signed in as <b>${u}</b>`,
    signedIn: 'Signed in',
    dirDown: 'the server directory is not answering',
    nobodyElse: 'nobody else is online',
    othersOnline: (n) => `<b>${n}</b> other${n === 1 ? '' : 's'} online`,
    intro: 'A private ICQ server: the same protocol and the same clients you '
      + 'remember, talking to something that answers again. Contact list, offline '
      + 'messages, statuses, search and file transfer all work. ICQ.com itself is '
      + 'long gone, so the menu items that pointed there now point here.',
    lnkToday: 'Who is online right now',
    lnkFind: 'Look up a user by number',
    lnkPager: 'Send a message from the web pager',
    lnkPwd: 'Change or recover your password',
    lnkProfile: 'Your profile: details, password, email',
    lnkAccount: 'Change your number, or close your account',
    lnkSendSomeone: 'Send a message to someone',

    todayTitle: 'Who Is Online',
    colNumber: 'Number',
    colStatus: 'Status',
    colOnlineFor: 'Online for',
    nobodyOnline: 'Nobody is online right now.',
    onlineNow: (n) => `Online now: ${n}`,
    loadFailed: (e) => `Could not load the list: ${e}`,

    findTitle: 'Find a User',
    icqNumber: 'ICQ number:',
    searchBtn: 'Search',
    notRegistered: (u) => `Number <b>${u}</b> is not registered on this server.`,
    serverSilent: (e) => `The server did not respond: ${e}`,
    sendViaPager: 'Send a message with the Web Pager',

    pagerTitle: 'Web Pager',
    toNumber: 'To (number):',
    fromLabel: 'From:',
    sendBtn: 'Send',
    sendAMessage: 'Send a message',
    offlineNote: 'If the recipient is offline, the message arrives at their next sign-in.',
    badNumber: 'That number is not valid.',
    emptyMessage: 'The message is empty.',
    tooOften: 'Too many messages. Please wait a minute.',
    notSent: (e) => `Not sent: ${e}`,
    accepted: (u) => `Message for <b>${u}</b> accepted.`,
    writeAnother: 'Write another',

    cSignedInFor: 'Signed in for',
    cAbout: 'About',
    cAnimatedAvatar: (title) => `animated avatar: ${title}`,
    cAccount: 'Account',
    cSuspended: 'suspended',
    cNick: 'Nickname',
    cName: 'Name',
    cGender: 'Gender',
    cMale: 'male',
    cFemale: 'female',
    cAge: 'Age',
    cYears: (n) => `${n}`,
    cCity: 'City',
    cCountry: 'Country',
    cFrom: 'Originally from',
    cHomepage: 'Homepage',
    cInterests: 'Interests',
    cEmail: 'E-mail',
    sOnline: 'online',
    sOffline: 'offline',
    sAway: 'away',
    sIdleFor: (d) => `idle for ${d}`,

    centreTitle: 'Messaging Centre',
    centreSub: 'your account on this server',
    centreAbout: 'About this page',
    centreText: 'The original messaging centre gathered what people sent you through '
      + 'the ICQ.com web page, by e-mail and by SMS. Those gateways are gone. Messages '
      + 'sent from a client arrive in the client itself, including the ones sent while '
      + 'you were offline.',

    howtoTitle: 'How to start',
    howtoSub: 'the short version',
    howtoYou: (u) => `Your number is <b>${u}</b> — that is what people need to add you.`,
    howtoSteps: 'Getting going',
    howtoAdd: 'Add a friend with the <b>Add</b> button in the contact list: type their '
      + 'number and wait for them to accept. The number is the address here, there is '
      + 'no search by e-mail.',
    howtoInvite: 'Your friend has no number yet? Send them the registration page — it '
      + 'takes a minute.',
    howtoOffline: 'Write to people who are not online. The message waits on the server '
      + 'and arrives the moment they sign in.',
    howtoFiles: 'File transfer, statuses and away messages work as they always did.',
    howtoSettings: 'Server settings, should you ever need them again',
    howtoPorts: 'Clients of that era knew no encryption and need the plain port with SSL '
      + 'switched off. If your client does support SSL, turn it on and use the SSL port.',
    howtoPlain: 'plain port',
    howtoSsl: 'port with SSL',
    howtoServer: 'Server',
    lnkRegister: 'Get a number for a friend',
    stubTitle: 'Service Unavailable',
    stubWorks: 'What does work here',
    topicUse: 'How to use it',
    topicSub: 'what this was',
    topicSubNow: 'how it works here',
    stubP1: (n) => `The <b>${n}</b> section was hosted on ICQ.com servers and no longer exists.`,
    stubP2: 'This client runs against its own server, which does not provide that '
      + 'service. The contact list, messages and statuses are unaffected.',
    errorTitle: 'Error',
    unit: { h: 'h', m: 'm', s: 's' },

    // The information pages: help, about, legal, terms, downloads.
    lnkHelp: 'Help',
    lnkAbout: 'About this service',
    lnkLegal: 'Legal notice and privacy',
    lnkTerms: 'Terms of use',
    lnkDownload: 'Clients and patches',
    lnkRecover: 'Recover a forgotten password',

    helpTitle: 'Help',
    helpSub: 'ICQ Revival',
    helpIntro: (name) => `<b>${name}</b> is a server for the classic ICQ and AIM `
      + 'clients. Below is what you need to get going, and what no longer exists.',
    helpSignIn: 'Signing in',
    helpSignInSteps: [
      'You need a number registered on this server. A number from the old ICQ is '
        + 'not carried over: take a new one on the registration page.',
      '<b>ICQ 6.5</b> and <b>ICQ Pro 2003b</b>: close the client, run the patch for '
        + 'it and type the server\'s domain. The patch points the sign-in and the menu '
        + 'links at this server; nothing else needs to be set.',
      '<b>Miranda NG</b>: install our ICQ plugin and give it the server below.',
      '<b>AIM</b> and other clients: enter the server and port below in the '
        + 'client\'s connection settings.',
    ],
    helpAccount: 'Your number and password',
    helpAccountSteps: (reg, profile, recover) => [
      reg ? `A new number: <a href="${reg}">the registration page</a>.` : '',
      profile ? `Nickname, details, password and recovery e-mail: `
        + `<a href="${profile}">your profile page</a>.` : '',
      recover ? `Forgot the password? <a href="${recover}">The recovery page</a> sends `
        + 'a link to your recovery e-mail. It can only do that if you added an e-mail '
        + 'on your profile page and confirmed it, so do that now, while you still '
        + 'remember the password.' : '',
    ],
    helpCalls: 'Voice calls in ICQ 6.5',
    helpCallsSteps: [
      'Calls go straight between the two computers. The server only passes the '
        + 'invitation; the sound does not go through it and is not recorded.',
      'Before a call, ICQ asks the server on <b>UDP port 3478</b> (STUN) how it is '
        + 'seen from the Internet, so that the other side can reach it through the '
        + 'router. The patch points ICQ at this server for that.',
      'There is no relay. If both of you are behind routers or firewalls that let '
        + 'no incoming UDP through, the call may connect and stay silent. Allowing '
        + 'ICQ through the firewall usually helps.',
    ],
    helpGone: 'What no longer exists',
    helpGoneText: 'These lived on ICQ.com and AOL servers and died with them. The '
      + 'patches take them out of the interface; anything left over opens a short '
      + 'page that says so.',
    helpGoneList: [
      '<b>Xtraz</b>: the gallery, animated greetings and mini-games.',
      '<b>SMS</b> and phone calls to real phone numbers.',
      '<b>tZers</b>, except in ICQ 6.5: there the "tZers without Flash" option of '
        + 'the patch brings back all twelve, with a player that needs no Flash.',
      '<b>Advertising</b>: the banners, the news ticker and the ad windows.',
      'The ICQ.com web services: e-mail, news, the chat directory, the web '
        + 'version of the contact list.',
    ],
    helpPatches: 'Where to get the patches',
    helpPatchesText: (href) => `The patches, the Miranda NG plugin and the list of `
      + `clients that work are on the <a href="${href}">downloads page</a>.`,
    helpMore: 'More',

    aboutTitle: 'About',
    aboutSub: 'ICQ Revival',
    aboutP1: 'ICQ Revival is a private, non-commercial server for the classic ICQ '
      + 'and AIM clients: ICQ Pro 2003b, ICQ 6.5, Miranda NG, AIM and the others '
      + 'that speak the OSCAR protocol. The old clients sign in, keep their contact '
      + 'lists and talk to each other again.',
    aboutP2: 'It is independent: not affiliated with, endorsed by or connected to '
      + 'ICQ, AOL, Yahoo or VK. ICQ and AIM are trademarks of their owners and are '
      + 'named here only to say which clients the server works with.',
    aboutP3: (href) => 'No advertising and no fees. The software is open source, '
      + `built on <a href="${href}">Open OSCAR Server</a>.`,
    aboutThis: 'This server',
    aboutName: 'Name',
    aboutAddress: 'Address',
    aboutContact: 'Contact',

    legalTitle: 'Legal notice and privacy',
    legalSub: 'what is kept, and the rules',
    legalWho: 'Who runs it',
    legalWhoText: (name) => `<b>${name}</b> is run privately, as a non-commercial `
      + 'hobby project. It is not a company and sells nothing.',
    legalContact: (c) => `Questions about the server or your data: ${c}.`,
    legalStored: 'What the server keeps',
    legalStoredList: [
      '<b>Your account</b>: the number, the password in the form the old clients\' '
        + 'sign-in needs, and the e-mail addresses you gave (for recovery and for '
        + 'signing in by e-mail).',
      '<b>Your profile</b>: what you filled in yourself (nickname, name, city, '
        + 'interests, "about") and your picture.',
      '<b>Your contact list</b> and your privacy settings (visible, invisible and '
        + 'ignore lists), and authorization requests that are still waiting.',
      '<b>Offline messages</b>: a message sent while you were offline is kept until '
        + 'you sign in, and deleted once it is delivered.',
    ],
    legalNotStored: 'What it does not keep',
    legalNotStoredList: [
      'Messages between people who are online pass through the server and are not '
        + 'saved. There is no message archive or history on the server; your client '
        + 'keeps its own history on your computer.',
      'Group chats are not saved.',
      'Voice calls and file transfers go straight between the two computers.',
    ],
    legalLogs: 'Logs and backups',
    legalLogsText: 'To keep the server running and to deal with abuse, it writes '
      + 'technical logs: sign-ins, the network addresses connections come from, '
      + 'errors. Message text is not written to them. The logs rotate and are '
      + 'overwritten after a short time. The database is copied once a day and each '
      + 'copy is kept for two weeks, so something deleted today can remain in a '
      + 'backup for up to fourteen days.',
    legalSeen: 'What other people see',
    legalSeenText: 'Your number, profile and online status are visible to other '
      + 'users of the server, in search and in "who is online" (unless you are '
      + 'invisible). Your e-mail address is shown only if you allowed that in your '
      + 'profile.',
    legalNoTrack: 'No ads, no tracking',
    legalNoTrackText: 'There is no advertising, no analytics and no third-party '
      + 'tracking, and nothing is sold or handed to anyone. One thing leaves the '
      + 'server by your own action: the search box in the client sends your query '
      + 'to Google, and the "Map" button opens Google Maps, under their own terms.',
    legalDelete: 'Deleting your data',
    legalDeleteText: (href) => `You can close your account yourself on `
      + `<a href="${href}">the account page</a>. That removes the account, the `
      + 'profile, the contact list and the privacy settings; the daily backups age '
      + 'out within two weeks.',

    termsTitle: 'Terms of use',
    termsSub: 'short and plain',
    termsList: [
      'The service is free and provided as is, with no guarantee that it is '
        + 'available or that your data is kept. It may change or stop at any time.',
      'Do not use it for spam, harassment, fraud, malware or anything illegal, and '
        + 'do not try to get into other people\'s accounts or into the server.',
      'You are responsible for what you send. Accounts that break these rules may '
        + 'be suspended or removed without notice.',
      'The old clients protect the password poorly, and without SSL they send '
        + 'everything unencrypted. Do not reuse a password you use anywhere else.',
      'By using the server you accept these terms and the privacy notice.',
    ],
    termsPrivacy: (href) => `What the server keeps about you: <a href="${href}">legal `
      + 'notice and privacy</a>.',

    dlTitle: 'Clients and patches',
    dlSub: 'what works, and what it needs',
    dlIntro: 'These clients are known to work. The patches only accept the exact '
      + 'builds listed: they check every file before changing it and refuse '
      + 'another build rather than damage it.',
    dlClient: 'Client',
    dlBuild: 'Build',
    dlNeeds: 'What it needs',
    dlGet: 'Download',
    dlSoon: 'not published yet',
    dlAny: 'any',
    dlIcq2003b: 'the ICQ 2003b patch',
    dlIcq65: 'the ICQ 6.5 patch',
    dlMiranda: 'our ICQ plugin (32 and 64 bit)',
    dlByHand: 'nothing: set the server by hand',
    dlOthers: 'AIM 5.x and other OSCAR clients',
    dlHow: 'How to apply a patch',
    dlHowSteps: (host) => [
      'Close the client.',
      'Run the patch and allow it administrator rights: the client lives in '
        + 'Program Files. If the patch does not find the client there, point it at '
        + 'the client\'s folder.',
      host ? `Type the server's domain: <code>${host}</code>. Only the domain; the `
        + 'patch fills in the ports itself.'
        : 'Type the server\'s domain. Only the domain; the patch fills in the ports '
        + 'itself.',
      'Leave the ticks as they are, or clear what you want to keep, and press '
        + '<b>Apply</b>.',
      'Start the client and sign in with your number.',
    ],
    dlHowNote: 'Every file is backed up before it is changed. <b>Restore original</b> '
      + 'puts the client back exactly as it was. To move to another server, apply '
      + 'the patch again with the new domain.',
    dlMirandaNote: 'Miranda NG: the archive has a <code>Miranda32</code> and a '
      + '<code>Miranda64</code> folder. With Miranda closed, copy the contents of the '
      + 'one for your Miranda over its folder, restart it and create an ICQ account '
      + 'with this server as the login server. From then on the plugin updater keeps '
      + 'our plugins up to date from this server.',
  },

  uk: {
    poweredBy: 'працює на ICQ Revival',
    welcomeTitle: 'Ласкаво просимо',
    welcomeSub: 'стара ICQ знову в ефірі',
    picTitle: 'Ваша картинка',
    picSub: 'поруч із вашим імʼям',
    picLead: 'Оберіть зображення, потім посуньте й наблизьте його в рамці. Нічого не '
      + 'надсилається, доки ви не скажете.',
    picInProfile: 'профіль',
    picInList: 'список',
    picZoom: 'Масштаб',
    picZoomIn: 'Наблизити',
    picZoomOut: 'Віддалити',
    picMoveLeft: 'Ліворуч',
    picMoveUp: 'Угору',
    picMoveDown: 'Униз',
    picMoveRight: 'Праворуч',
    picCentre: 'По центру',
    picEditHint: 'Перетягніть зображення в рамці; коліщатко чи повзунок змінює масштаб.',
    picSetPicture: 'Встановити як мою картинку',
    picCutFailed: 'Сервер не зміг вирізати картинку. Спробуйте завантажити її знову.',
    picOpenInBrowser: 'Клієнт не зміг відкрити ваш браузер. Скопіюйте цю адресу в нього:',
    picCurrent: 'Поточна картинка',
    picCurrentNote: 'такою її зараз бачать ваші контакти',
    picPreview: 'Ось як вона виглядатиме',
    picUpload: 'Завантажити на сервер',
    picCancel: 'Скасувати',
    picOnlyInIcq: 'Ця сторінка працює лише всередині ICQ.',
    picNoClient: 'Не вдалося звʼязатися з клієнтом: ',
    picPreparing: 'Готуємо попередній перегляд...',
    picSendFailed: 'Не вдалося надіслати файл: ',
    picPrepareFailed: 'Не вдалося підготувати картинку: ',
    picNoAnswer: 'Сервер не прийняв файл. Можливо, він більший за 16 МБ?',
    picReady: 'готово до завантаження',
    picUploading: 'Завантажуємо...',
    picRefused: 'Клієнт не прийняв картинку: ',
    picReadFailed: 'Не вдалося прочитати поточну картинку: ',
    picSaved: 'Збережено. Відтепер її бачать усі.',
    picDone: 'Готово.',
    picServerRefused: 'Сервер не прийняв картинку.',
    picErrNotForm: 'це не завантаження з форми',
    picErrTooLarge: 'файл більший за 16 МБ',
    picErrMalformed: 'завантаження пошкоджене',
    picErrEmpty: 'файл порожній',
    picTabPicture: 'Картинка',
    picTabAnimated: 'Анімація',
    picAnimLead: 'Живе обличчя замість нерухомої картинки. ICQ 6 програє його поруч '
      + 'із вашим імʼям, і воно змінюється разом із вашим настроєм і статусом. '
      + 'Оберіть і встановіть.',
    picAnimNote: 'Контакти в інших клієнтах чи старіших версіях ICQ не програють '
      + 'анімацію: вони бачать її нерухоме зображення, яке дає сервер.',
    picAnimNow: 'Зараз встановлено:',
    picAnimNone: 'нічого',
    picAnimOther: 'анімація не з цього сервера',
    picAnimIcq: 'ICQ',
    picAnimUser: 'Створені користувачами',
    picAnimChosen: 'Обрано:',
    picAnimSet: 'Встановити цю анімацію',
    picAnimSetting: 'Встановлюємо анімацію...',
    picAnimSaved: 'Встановлено. Відтепер її бачать ваші контакти.',
    picAnimRefused: 'Клієнт не прийняв анімацію: ',
    picAnimServerRefused: 'Сервер не прийняв анімацію.',
    picAnimTry: 'Подивитися в русі',
    picAnimTester: 'Спробувати всі аватари',
    tstTitle: 'Перегляд аватарів',
    tstSub: 'подивіться, як рухається обличчя, перш ніж обрати',
    tstLead: 'Анімовані аватари цього сервера, програні так, як їх програє ICQ 6.5. '
      + 'Кнопки показують, як аватар відповідає на ваш настрій і статус.',
    tstFaces: 'Обличчя:',
    tstMood: {
      stam: 'Спокій', smile: 'Усмішка', sad: 'Сум', laugh: 'Сміх', mad: 'Злість',
      cry: 'Плач', love: 'Кохання', busy: 'Зайнятий', offline: 'Не в мережі',
    },
    tstByIcq: 'від ICQ',
    tstByUser: 'створений користувачем',
    tstPictures: 'Зображення, які сервер дає для нього',
    tstStill: 'Нерухоме',
    tstStillNote: 'контакти в інших клієнтах і старіших версіях ICQ',
    tstLarge: 'Велике',
    tstLargeNote: 'картка користувача на цих сторінках',
    tstThumb: 'Мініатюра',
    tstThumbNote: 'галереї в ICQ 6.5 і Miranda NG',
    tstNoPlayer: 'Це вікно не програє Flash, тому показано нерухоме зображення. '
      + 'Щоб побачити аватар у русі й спробувати його обличчя, відкрийте сторінку '
      + 'в сучасному браузері:',
    tstPlayerFailed: 'Програвач тут не запустився, тому показано нерухоме зображення.',
    tstHowToSet: 'Щоб встановити аватар, відкрийте свою картинку в ICQ 6.5 (вкладка '
      + '«Анімація») або вибір аватара в плагіні ICQ Revival для Miranda NG.',
    tstAll: 'Усі аватари',
    tstNone: 'На цьому сервері немає анімованих аватарів.',
    tstUnknown: 'Такого аватара тут немає; показано перший.',
    tstByMaker: 'створений у конструкторі аватарів',
    tstEditInMaker: 'Змінити в конструкторі',
    tstMakeOwn: 'Створити власний аватар у конструкторі',
    mkTitle: 'Конструктор аватарів',
    mkSub: 'власне живе обличчя',
    mkFaces: 'Обличчя:',
    mkSet: 'Встановити як мій аватар',
    mkSetting: 'Встановлюємо аватар...',
    mkSaved: 'Встановлено. Відтепер його бачать ваші контакти.',
    mkRefused: 'Клієнт не прийняв аватар: ',
    mkServerRefused: 'Сервер не прийняв аватар.',
    mkRandom: 'Навмання',
    mkTry: 'Відкрити в перегляді',
    mkBack: 'Назад до картинки',
    mkBackShort: 'Назад',
    mkShow: 'Показати',
    mkAddress: 'Адреса цього аватара:',
    mkHowTo: 'Щоб встановити його, відкрийте конструктор з ICQ 6.5 (ваша картинка, вкладка '
      + '«Анімація», «Створити свій») і натисніть «Встановити як мій аватар». Вибір аватара '
      + 'в Miranda NG пропонує лише галерею, але контакти в Miranda бачать створений аватар, '
      + 'як і будь-який інший.',
    picAnimMake: 'Створити свій',
    picAnimOwn: 'власний, з конструктора',
    picReduced: (from, to) => `${from} стиснуто до ${to}`,
    picBytes: (n) => (n < 1024 ? `${n} байт` : `${Math.round(n / 1024)} КБ`),
    signedInAs: (u) => `Ви увійшли як <b>${u}</b>`,
    signedIn: 'Ви увійшли',
    dirDown: 'каталог сервера не відповідає',
    nobodyElse: 'більше нікого немає в мережі',
    othersOnline: (n) => `<b>${n}</b> ${n === 1 ? 'інший' : 'інших'} у мережі`,
    intro: 'Приватний сервер ICQ: той самий протокол і ті самі клієнти, що ви '
      + 'пам’ятаєте, знову мають із ким розмовляти. Список контактів, повідомлення '
      + 'офлайн, статуси, пошук і передавання файлів працюють. Самої ICQ.com давно '
      + 'немає, тож пункти меню, які вели туди, тепер ведуть сюди.',
    lnkToday: 'Хто зараз у мережі',
    lnkFind: 'Знайти користувача за номером',
    lnkPager: 'Надіслати повідомлення з веб-пейджера',
    lnkPwd: 'Змінити або відновити пароль',
    lnkProfile: 'Ваш профіль: анкета, пароль, пошта',
    lnkAccount: 'Змінити номер або видалити обліковий запис',
    lnkSendSomeone: 'Надіслати комусь повідомлення',

    todayTitle: 'Хто в мережі',
    colNumber: 'Номер',
    colStatus: 'Статус',
    colOnlineFor: 'У мережі',
    nobodyOnline: 'Зараз нікого немає в мережі.',
    onlineNow: (n) => `У мережі: ${n}`,
    loadFailed: (e) => `Не вдалося отримати список: ${e}`,

    findTitle: 'Пошук користувача',
    icqNumber: 'Номер ICQ:',
    searchBtn: 'Знайти',
    notRegistered: (u) => `Номер <b>${u}</b> не зареєстрований на цьому сервері.`,
    serverSilent: (e) => `Сервер не відповів: ${e}`,
    sendViaPager: 'Надіслати повідомлення через веб-пейджер',

    pagerTitle: 'Веб-пейджер',
    toNumber: 'Кому (номер):',
    fromLabel: 'Від кого:',
    sendBtn: 'Надіслати',
    sendAMessage: 'Надіслати повідомлення',
    offlineNote: 'Якщо одержувач не в мережі, повідомлення надійде під час наступного входу.',
    badNumber: 'Номер вказано неправильно.',
    emptyMessage: 'Повідомлення порожнє.',
    tooOften: 'Занадто часто. Зачекайте хвилину.',
    notSent: (e) => `Не надіслано: ${e}`,
    accepted: (u) => `Повідомлення для <b>${u}</b> прийнято.`,
    writeAnother: 'Написати ще',

    cSignedInFor: 'У мережі вже',
    cAbout: 'Про себе',
    cAnimatedAvatar: (title) => `анімований аватар: ${title}`,
    cAccount: 'Обліковий запис',
    cSuspended: 'заблоковано',
    cNick: 'Нік',
    cName: "Ім'я",
    cGender: 'Стать',
    cMale: 'чоловіча',
    cFemale: 'жіноча',
    cAge: 'Вік',
    cYears: (n) => `${n}`,
    cCity: 'Місто',
    cCountry: 'Країна',
    cFrom: 'Родом з',
    cHomepage: 'Домашня сторінка',
    cInterests: 'Інтереси',
    cEmail: 'Пошта',
    sOnline: 'у мережі',
    sOffline: 'не в мережі',
    sAway: 'відійшов',
    sIdleFor: (d) => `неактивний ${d}`,

    centreTitle: 'Центр повідомлень',
    centreSub: 'ваш обліковий запис на цьому сервері',
    centreAbout: 'Про цю сторінку',
    centreText: 'Первісний центр повідомлень збирав те, що вам надсилали через '
      + 'вебсторінку ICQ.com, електронною поштою та в SMS. Тих шлюзів більше немає. '
      + 'Повідомлення з клієнта надходять просто в клієнт, зокрема й надіслані, '
      + 'поки вас не було в мережі.',

    howtoTitle: 'Як почати',
    howtoSub: 'коротко',
    howtoYou: (u) => `Ваш номер — <b>${u}</b>, саме його потрібно знати тим, хто вас додає.`,
    howtoSteps: 'З чого почати',
    howtoAdd: 'Додайте друга кнопкою <b>Add</b> у списку контактів: введіть '
      + 'його номер і зачекайте підтвердження. Адресою тут є номер, пошуку '
      + 'за поштою немає.',
    howtoInvite: 'У друга ще немає номера? Надішліть йому сторінку '
      + 'реєстрації — це справа однієї хвилини.',
    howtoOffline: 'Пишіть тим, кого немає в мережі: повідомлення '
      + 'зачекає на сервері й надійде, тільки вони увійдуть.',
    howtoFiles: 'Передавання файлів, статуси та повідомлення про відсутність '
      + 'працюють як і раніше.',
    howtoSettings: 'Налаштування сервера, якщо знадобляться знову',
    howtoPorts: 'Клієнти тих років шифрування не знали: їм потрібен '
      + 'звичайний порт із вимкненим SSL. Якщо клієнт уміє SSL, увімкніть '
      + 'його та вкажіть порт із SSL.',
    howtoPlain: 'звичайний порт',
    howtoSsl: 'порт із SSL',
    howtoServer: 'Сервер',
    lnkRegister: 'Отримати номер для друга',
    stubTitle: 'Служба недоступна',
    stubWorks: 'Що тут працює',
    topicUse: 'Як користуватися',
    topicSub: 'що це було',
    topicSubNow: 'як це працює',
    stubP1: (n) => `Розділ <b>${n}</b> розміщувався на серверах ICQ.com і більше не існує.`,
    stubP2: 'Клієнт працює через власний сервер, у якого цієї служби немає. '
      + 'На список контактів, повідомлення та статуси це не впливає.',
    errorTitle: 'Помилка',
    unit: { h: 'год', m: 'хв', s: 'с' },

    lnkHelp: 'Довідка',
    lnkAbout: 'Про сервіс',
    lnkLegal: 'Правова інформація та приватність',
    lnkTerms: 'Умови користування',
    lnkDownload: 'Клієнти та патчі',
    lnkRecover: 'Відновити забутий пароль',

    helpTitle: 'Довідка',
    helpSub: 'ICQ Revival',
    helpIntro: (name) => `<b>${name}</b> — сервер для класичних клієнтів ICQ та AIM. `
      + 'Нижче — усе, що потрібно для початку, і те, чого більше немає.',
    helpSignIn: 'Вхід',
    helpSignInSteps: [
      'Потрібен номер, зареєстрований на цьому сервері. Номер зі старої ICQ сюди '
        + 'не переноситься: візьміть новий на сторінці реєстрації.',
      '<b>ICQ 6.5</b> та <b>ICQ Pro 2003b</b>: закрийте клієнт, запустіть патч для '
        + 'нього й введіть домен сервера. Патч спрямовує на цей сервер і вхід, і '
        + 'посилання з меню; більше нічого налаштовувати не треба.',
      '<b>Miranda NG</b>: встановіть наш плагін ICQ і вкажіть у ньому сервер, '
        + 'наведений нижче.',
      '<b>AIM</b> та інші клієнти: впишіть сервер і порт, наведені нижче, у '
        + 'налаштування зʼєднання клієнта.',
    ],
    helpAccount: 'Ваш номер і пароль',
    helpAccountSteps: (reg, profile, recover) => [
      reg ? `Новий номер: <a href="${reg}">сторінка реєстрації</a>.` : '',
      profile ? 'Нік, анкета, пароль і пошта для відновлення: '
        + `<a href="${profile}">ваш профіль</a>.` : '',
      recover ? `Забули пароль? <a href="${recover}">Сторінка відновлення</a> надішле `
        + 'посилання на пошту для відновлення. Це можливо, лише якщо ви додали пошту '
        + 'в профілі й підтвердили її, тож зробіть це зараз, поки пароль ще '
        + 'памʼятаєте.' : '',
    ],
    helpCalls: 'Голосові дзвінки в ICQ 6.5',
    helpCallsSteps: [
      'Дзвінок іде напряму між двома компʼютерами. Сервер лише передає '
        + 'запрошення; звук через нього не проходить і не записується.',
      'Перед дзвінком ICQ питає сервер через <b>UDP-порт 3478</b> (STUN), як її '
        + 'видно з інтернету, щоб співрозмовник міг достукатися крізь роутер. Патч '
        + 'спрямовує ICQ для цього на цей сервер.',
      'Ретранслятора немає. Якщо ви обидва за роутерами чи брандмауерами, які не '
        + 'пропускають вхідний UDP, дзвінок може зʼєднатися, але без звуку. Зазвичай '
        + 'допомагає дозволити ICQ у брандмауері.',
    ],
    helpGone: 'Чого більше немає',
    helpGoneText: 'Це жило на серверах ICQ.com та AOL і зникло разом із ними. '
      + 'Патчі прибирають це з інтерфейсу; те, що лишилося, відкриває коротку '
      + 'сторінку з поясненням.',
    helpGoneList: [
      '<b>Xtraz</b>: галерея, анімовані привітання та міні-ігри.',
      '<b>SMS</b> і дзвінки на звичайні телефони.',
      '<b>tZers</b>, крім ICQ 6.5: там опція патча «tZers without Flash» '
        + 'повертає всі дванадцять, із програвачем, якому не потрібен Flash.',
      '<b>Реклама</b>: банери, стрічка новин і рекламні вікна.',
      'Вебслужби ICQ.com: пошта, новини, каталог чатів, веб-версія списку контактів.',
    ],
    helpPatches: 'Де взяти патчі',
    helpPatchesText: (href) => 'Патчі, плагін для Miranda NG і перелік клієнтів, '
      + `що працюють, — на <a href="${href}">сторінці завантажень</a>.`,
    helpMore: 'Ще',

    aboutTitle: 'Про сервіс',
    aboutSub: 'ICQ Revival',
    aboutP1: 'ICQ Revival — приватний некомерційний сервер для класичних клієнтів '
      + 'ICQ та AIM: ICQ Pro 2003b, ICQ 6.5, Miranda NG, AIM та інших, що говорять '
      + 'протоколом OSCAR. Старі клієнти знову входять, зберігають списки контактів '
      + 'і спілкуються між собою.',
    aboutP2: 'Сервіс незалежний: не повʼязаний з ICQ, AOL, Yahoo чи VK і не '
      + 'схвалений ними. ICQ та AIM — торговельні марки їхніх власників; тут вони '
      + 'згадуються лише для того, щоб назвати клієнти, з якими працює сервер.',
    aboutP3: (href) => 'Без реклами й без плати. Програмне забезпечення відкрите, '
      + `побудоване на <a href="${href}">Open OSCAR Server</a>.`,
    aboutThis: 'Цей сервер',
    aboutName: 'Назва',
    aboutAddress: 'Адреса',
    aboutContact: 'Контакт',

    legalTitle: 'Правова інформація та приватність',
    legalSub: 'що зберігається і правила',
    legalWho: 'Хто це веде',
    legalWhoText: (name) => `<b>${name}</b> ведеться приватно, як некомерційний `
      + 'аматорський проєкт. Це не компанія, і вона нічого не продає.',
    legalContact: (c) => `Питання щодо сервера чи ваших даних: ${c}.`,
    legalStored: 'Що зберігає сервер',
    legalStoredList: [
      '<b>Обліковий запис</b>: номер, пароль у тому вигляді, якого потребує вхід '
        + 'старих клієнтів, і адреси пошти, які ви вказали (для відновлення та для '
        + 'входу за поштою).',
      '<b>Профіль</b>: те, що ви заповнили самі (нік, імʼя, місто, інтереси, '
        + '«про себе»), і ваша картинка.',
      '<b>Список контактів</b> і налаштування приватності (списки видимості, '
        + 'невидимості та ігнорування), а також запити на авторизацію, що чекають '
        + 'відповіді.',
      '<b>Повідомлення офлайн</b>: надіслане, поки вас не було в мережі, '
        + 'зберігається до вашого входу й видаляється, щойно його доставлено.',
    ],
    legalNotStored: 'Чого він не зберігає',
    legalNotStoredList: [
      'Повідомлення між тими, хто в мережі, проходять через сервер і не '
        + 'зберігаються. Архіву чи історії повідомлень на сервері немає; клієнт '
        + 'веде власну історію на вашому компʼютері.',
      'Групові чати не зберігаються.',
      'Голосові дзвінки й передавання файлів ідуть напряму між двома компʼютерами.',
    ],
    legalLogs: 'Журнали та резервні копії',
    legalLogsText: 'Щоб сервер працював і щоб протидіяти зловживанням, він веде '
      + 'технічні журнали: входи, мережеві адреси, з яких приходять зʼєднання, '
      + 'помилки. Текст повідомлень туди не пишеться. Журнали ротуються й '
      + 'перезаписуються за короткий час. Базу даних копіюють раз на добу, і кожна '
      + 'копія зберігається два тижні, тож видалене сьогодні може лишатися в '
      + 'резервній копії до чотирнадцяти днів.',
    legalSeen: 'Що бачать інші',
    legalSeenText: 'Ваш номер, профіль і статус бачать інші користувачі сервера — у '
      + 'пошуку та в списку «хто в мережі» (якщо ви не невидимі). Адресу пошти '
      + 'видно, лише якщо ви це дозволили в профілі.',
    legalNoTrack: 'Без реклами й стеження',
    legalNoTrackText: 'Реклами, аналітики та стороннього стеження немає, нічого не '
      + 'продається й нікому не передається. Одне залишає сервер лише з вашої дії: '
      + 'поле пошуку в клієнті надсилає запит до Google, а кнопка «Map» відкриває '
      + 'Google Maps — на їхніх власних умовах.',
    legalDelete: 'Видалення даних',
    legalDeleteText: (href) => 'Закрити обліковий запис можна самостійно на '
      + `<a href="${href}">сторінці облікового запису</a>. Це видаляє обліковий `
      + 'запис, профіль, список контактів і налаштування приватності; щоденні '
      + 'резервні копії зникають упродовж двох тижнів.',

    termsTitle: 'Умови користування',
    termsSub: 'коротко й просто',
    termsList: [
      'Сервіс безкоштовний і надається «як є», без гарантій доступності чи '
        + 'збереження ваших даних. Він може змінитися або припинити роботу будь-коли.',
      'Не використовуйте його для спаму, цькування, шахрайства, шкідливих програм '
        + 'чи будь-чого незаконного й не намагайтеся проникнути в чужі облікові '
        + 'записи чи на сервер.',
      'За надіслане відповідаєте ви. Облікові записи, що порушують ці правила, '
        + 'можуть бути заблоковані або видалені без попередження.',
      'Старі клієнти погано захищають пароль, а без SSL надсилають усе '
        + 'незашифрованим. Не використовуйте пароль, який маєте деінде.',
      'Користуючись сервером, ви приймаєте ці умови та положення про приватність.',
    ],
    termsPrivacy: (href) => `Що сервер зберігає про вас: <a href="${href}">правова `
      + 'інформація та приватність</a>.',

    dlTitle: 'Клієнти та патчі',
    dlSub: 'що працює і що для цього треба',
    dlIntro: 'Ці клієнти перевірено. Патчі приймають лише саме ці збірки: вони '
      + 'перевіряють кожен файл перед зміною й відмовляються від іншої збірки, '
      + 'щоб її не зіпсувати.',
    dlClient: 'Клієнт',
    dlBuild: 'Збірка',
    dlNeeds: 'Що потрібно',
    dlGet: 'Завантажити',
    dlSoon: 'ще не опубліковано',
    dlAny: 'будь-яка',
    dlIcq2003b: 'патч для ICQ 2003b',
    dlIcq65: 'патч для ICQ 6.5',
    dlMiranda: 'наш плагін ICQ (32 і 64 біти)',
    dlByHand: 'нічого: сервер вказується вручну',
    dlOthers: 'AIM 5.x та інші клієнти OSCAR',
    dlHow: 'Як застосувати патч',
    dlHowSteps: (host) => [
      'Закрийте клієнт.',
      'Запустіть патч і дозвольте йому права адміністратора: клієнт лежить у '
        + 'Program Files. Якщо патч не знайде клієнт там, вкажіть йому теку клієнта.',
      host ? `Введіть домен сервера: <code>${host}</code>. Лише домен; порти патч `
        + 'підставить сам.'
        : 'Введіть домен сервера. Лише домен; порти патч підставить сам.',
      'Залиште позначки як є або зніміть те, що хочете зберегти, і натисніть '
        + '<b>Apply</b>.',
      'Запустіть клієнт і увійдіть зі своїм номером.',
    ],
    dlHowNote: 'Кожен файл перед зміною зберігається в резервну копію. '
      + '<b>Restore original</b> повертає клієнт точно таким, яким він був. Щоб '
      + 'перейти на інший сервер, застосуйте патч ще раз із новим доменом.',
    dlMirandaNote: 'Miranda NG: в архіві є теки <code>Miranda32</code> і '
      + '<code>Miranda64</code>. Закрийте Miranda, скопіюйте вміст теки своєї '
      + 'розрядності поверх її теки, перезапустіть і створіть обліковий запис ICQ '
      + 'з цим сервером як сервером входу. Далі засіб оновлення плагінів сам '
      + 'оновлює наші плагіни з цього сервера.',
  },
};

function dict(lang) {
  return I18N[lang] || I18N[FALLBACK_LANG];
}

// The switcher links: pages are served without scripts, so we simply reload the
// same page with a different ?lang=.
function langSwitch(lang, selfUrl) {
  const parts = LANGS.map((code) => {
    const url = new URL(selfUrl || '/', 'http://x');
    url.searchParams.set('lang', code);
    const href = escapeHtml(url.pathname + url.search);
    return code === lang
      ? `<b>${langLabel(code)}</b>`
      : `<a href="${href}">${langLabel(code)}</a>`;
  });
  return parts.join(' ');
}

// ----------------------------------------------------------------------- layout

// The pages are rendered by an embedded Internet Explorer 5-6. No flexbox, no
// custom properties, no external files: tables and inline styles, or it breaks.
const FONT = 'font-family:Tahoma,Arial,sans-serif;font-size:13px';

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// The shell shared by every page: the same green header with the flower as the
// welcome screen. The styling lives in a style sheet rather than inline: even
// IE 5 understands classes and borders, and simply skips rounded corners and
// shadows. The layout is still built on tables, because the Today panel is drawn
// by the embedded engine.

// compact is for the pages the client draws itself in its small fixed-size
// window (the welcome screen, the Today panel). Everything else opens in an
// external browser, which needs no cramping.
// Two shells for two consumers.
//
// roomy   - the page is opened by an ordinary browser. The markup and style
//           sheet are the ones registration and the admin page use: one look
//           across the services.
// compact - the page is drawn by the client's own embedded engine in a small
//           window: tables instead of blocks, a pixel flower instead of SVG.
// One shell for everybody, the same as registration and the admin page. The only
// difference is density: inside the client the window is small, so body gets the
// compact class and the shared style sheet tightens the spacing.
function page(title, bodyHtml, subtitle, compact, u) {
  const langs = u ? langSwitch(u.lang, u.selfUrl) : '';
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${SHARED_STYLE}</style>
</head>
<body${compact ? ' class="compact"' : ''}>
<main class="window">
  ${header(escapeHtml(title), subtitle)}
  <div class="body">${bodyHtml}</div>
  ${footer({ langs })}
</main>
</body>
</html>`;
}

function send(res, status, html) {
  const body = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': body.length,
    // IE caches aggressively, and Today has to be fresh.
    'cache-control': 'no-cache, no-store',
    'pragma': 'no-cache',
  });
  res.end(body);
}

function sendText(res, text) {
  const body = Buffer.from(text, 'utf8');
  res.writeHead(200, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': body.length,
  });
  res.end(body);
}

// --- the "Map" button of ICQ 2003b ------------------------------------------
//
// The client appends the address to the link itself: ?countrycode= &country=
// &state= &city= &zip= &address=, in its code page (windows-1251 here), and
// mangles part of it: some letters it escapes with a stray byte in place of the
// first hex digit - "к" (0xEA) arrives as "%" 0x8A "A". The stray byte stands
// for the high half of the letter, one byte per half, so the letter can be read
// back. The browser then encodes the lot again as UTF-8.

const CP1251 = (() => {
  const dec = new TextDecoder('windows-1251');
  const toChar = [];
  const toByte = new Map();
  for (let b = 0; b < 256; b++) {
    const c = dec.decode(Uint8Array.of(b));
    toChar[b] = c;
    if (!toByte.has(c)) toByte.set(c, b);
  }
  return { toChar, toByte };
})();

// The stray byte ICQ 2003b writes, and the high half of the letter it stands for.
const MANGLED_HIGH = new Map([[0x72, 0x8], [0x8c, 0xc], [0xe7, 0xd], [0x8a, 0xe], [0x24, 0xf]]);

const isHex = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66);

// One value of the client's query, as it arrived, back to readable text.
function clientText(raw) {
  // The browser's escapes; a "%" without two hex digits after it is the client's own.
  const bytes = [];
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === '%' && /^[0-9a-f]{2}$/i.test(raw.slice(i + 1, i + 3))) {
      bytes.push(parseInt(raw.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (c === '+') {
      bytes.push(0x20);
    } else {
      bytes.push(...Buffer.from(c, 'utf8'));
    }
  }
  // Back to the bytes the client sent, in its code page.
  const sent = [...Buffer.from(bytes).toString('utf8')].map((ch) => (CP1251.toByte.has(ch) ? CP1251.toByte.get(ch) : 0x3f));
  // The client's own escapes, the mangled ones included.
  const out = [];
  for (let i = 0; i < sent.length; i++) {
    const b = sent[i];
    if (b === 0x25 && i + 2 < sent.length && isHex(sent[i + 2])) {
      const hi = MANGLED_HIGH.get(sent[i + 1]);
      const lo = parseInt(String.fromCharCode(sent[i + 2]), 16);
      if (hi !== undefined) { out.push((hi << 4) | lo); i += 2; continue; }
      if (isHex(sent[i + 1])) { out.push(parseInt(String.fromCharCode(sent[i + 1], sent[i + 2]), 16)); i += 2; continue; }
    }
    out.push(b);
  }
  return out.map((b) => CP1251.toChar[b]).join('').trim();
}

// Google Maps, searching for the address the client sent.
function mapUrl(reqUrl) {
  const q = String(reqUrl).split('?')[1] || '';
  const f = {};
  for (const pair of q.split('&')) {
    const at = pair.indexOf('=');
    if (at > 0) f[pair.slice(0, at).toLowerCase()] = clientText(pair.slice(at + 1));
  }
  const place = [f.address, f.city, f.state, f.zip, f.country].filter(Boolean).join(', ');
  return place
    ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(place)}`
    : 'https://www.google.com/maps/';
}

function redirect(res, url) {
  res.writeHead(302, { location: url, 'content-length': 0 });
  res.end();
}

// One file of a folder loaded by loadFolder, by its exact name after the
// prefix. The name is looked up, never joined to a path, so a request cannot
// walk out of the folder; anything else is a 404.
function serveFolderFile(ctx, prefix, files, names = PLAIN_NAME) {
  const name = ctx.path.replace(prefix, '');
  const file = names.test(name) ? files.get(name.toLowerCase()) : null;
  if (!file || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) {
    ctx.res.writeHead(404, { 'content-length': 0 });
    ctx.res.end();
    return;
  }
  ctx.res.writeHead(200, {
    'content-type': file.type,
    'content-length': file.body.length,
    // The files never change once published.
    'cache-control': 'public, max-age=86400',
  });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : file.body);
}

// The animated avatar gallery as data, /icq/avatars/list.json, for the
// picker of Miranda NG's IcqRevivalFlash plugin: the movies this folder has,
// with their thumbnails, author group (icq or user) and titles. The client
// builds the movie and thumbnail addresses on /icq/avatars/ itself.
function serveAvatarListJson(ctx) {
  if (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD') {
    ctx.res.writeHead(404, { 'content-length': 0 });
    ctx.res.end();
    return;
  }
  const body = Buffer.from(JSON.stringify({
    avatars: avatarList.map((a) => ({
      file: a.file,
      thumb: a.thumb,
      author: a.author,
      title: { en: (a.title && a.title.en) || a.file, uk: (a.title && a.title.uk) || '' },
    })),
  }));
  ctx.res.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'public, max-age=300',
  });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : body);
}

function formatDuration(seconds, t) {
  const unit = (t || dict(FALLBACK_LANG)).unit;
  const s = Number(seconds) || 0;
  if (s < 60) return `${s}${unit.s}`;
  if (s < 3600) return `${Math.floor(s / 60)}${unit.m}`;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return m ? `${h}${unit.h} ${m}${unit.m}` : `${h}${unit.h}`;
}

// ------------------------------------------------------------------- actions

// The simplest rate limit: the web pager is open to everyone on the tailnet.
const pagerHits = new Map();

function pagerAllowed(ip) {
  const now = Date.now();
  const hits = (pagerHits.get(ip) || []).filter((t) => now - t < 60_000);
  hits.push(now);
  pagerHits.set(ip, hits);
  if (pagerHits.size > 500) pagerHits.clear();
  return hits.length <= 5;
}

// selfPath is the address this very page was opened at. Forms post back to it so
// the service works both under the ICQ.com names and at whatever server address
// the client's config points to.
function pagerForm(uin, message, note, selfPath, cardHtml, u) {
  const t = u.t;
  return page(t.pagerTitle, `
    ${note || ''}
    ${cardHtml || ''}
    ${cardHtml ? '<p style="' + FONT + ';margin:10px 0 4px 0"><b>' + t.sendAMessage + '</b></p>' : ''}
    <form method="post" action="${escapeHtml(selfPath || '')}">
      <table cellpadding="0" cellspacing="0" border="0">
        <tr><td style="${FONT};padding:0 6px 4px 0">${t.toNumber}</td>
            <td style="padding:0 0 4px 0"><input type="text" name="uin" size="14"
                value="${escapeHtml(uin || '')}" style="${FONT}"></td></tr>
        <tr><td style="${FONT};padding:0 6px 4px 0">${t.fromLabel}</td>
            <td style="padding:0 0 4px 0"><input type="text" name="from" size="14"
                value="WebPager" style="${FONT}"></td></tr>
      </table>
      <p><textarea name="text" rows="5" cols="46" style="${FONT}">${escapeHtml(message || '')}</textarea></p>
      <p><input type="submit" value="${t.sendBtn}" style="${FONT}"></p>
    </form>
    <p><font color="#808080">${t.offlineNote}</font></p>`, '', false, u);
}

async function pagerSend(body, ip, selfPath, u) {
  const t = u.t;
  const params = new URLSearchParams(body);
  const uin = (params.get('uin') || '').trim();
  const from = (params.get('from') || 'WebPager').trim().slice(0, 32) || 'WebPager';
  const text = (params.get('text') || '').trim();

  if (!/^\d{4,10}$/.test(uin)) {
    return pagerForm(uin, text, `<p><font color="#c00000">${t.badNumber}</font></p>`, selfPath, null, u);
  }
  if (!text) {
    return pagerForm(uin, text, `<p><font color="#c00000">${t.emptyMessage}</font></p>`, selfPath, null, u);
  }
  if (!pagerAllowed(ip)) {
    return pagerForm(uin, text,
      `<p><font color="#c00000">${t.tooOften}</font></p>`, selfPath, null, u);
  }

  try {
    await mgmt('/instant-message', {
      method: 'POST',
      body: JSON.stringify({ from, to: uin, text: text.slice(0, 2000) }),
    });
  } catch (err) {
    return pagerForm(uin, text,
      `<p><font color="#c00000">${t.notSent(escapeHtml(err.message))}</font></p>`, selfPath, null, u);
  }

  return page(t.pagerTitle, `
    <p>${t.accepted(escapeHtml(uin))}</p>
    <p><a href="${escapeHtml(selfPath || '')}" style="${FONT}">${t.writeAnother}</a></p>`,
    '', false, u);
}

async function todayPage(u) {
  const t = u.t;
  let sessions;
  try {
    const data = await mgmt('/session');
    sessions = (data.sessions || []).filter((s) => !s.is_invisible);
  } catch (err) {
    return page(t.todayTitle, `<p>${t.loadFailed(escapeHtml(err.message))}</p>`,
      '', true, u);
  }

  if (sessions.length === 0) {
    return page(t.todayTitle, `<p>${t.nobodyOnline}</p>`, '', true, u);
  }

  const rows = sessions.map((s) => {
    const status = s.is_away ? t.sAway : s.idle_seconds > 0 ? t.sIdleFor('').trim() : t.sOnline;
    const cls = s.is_away || s.idle_seconds > 0 ? 'warn' : 'ok';
    return `<tr>
      <td style="padding:3px 8px 3px 0;${FONT}"><b>${escapeHtml(s.screen_name)}</b></td>
      <td style="padding:3px 8px 3px 0;${FONT}"><span class="${cls}">${status}</span></td>
      <td style="padding:3px 0"><span class="dim">${formatDuration(s.online_seconds, t)}</span></td>
    </tr>`;
  }).join('');

  return page(t.todayTitle, `
    <table cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:0 8px 4px 0;${FONT}"><span class="dim">${t.colNumber}</span></td>
        <td style="padding:0 8px 4px 0;${FONT}"><span class="dim">${t.colStatus}</span></td>
        <td style="padding:0 0 4px 0;${FONT}"><span class="dim">${t.colOnlineFor}</span></td>
      </tr>
      ${rows}
    </table>
    <p><span class="dim">${t.onlineNow(sessions.length)}</span></p>`, '', true, u);
}

// A user card: number, state, profile. Shown both in the white pages and above
// the pager form - writing blindly to a number is awkward.
// Returns { exists, html } or { error }.
// Country codes 0 and 0xFFFF mean "unspecified" in an ICQ profile.
function countryName(code) {
  if (!code || code === 65535) return '';
  const table = CODES.countries || {};
  return table[String(code)] || String(code);
}

function ageFrom(y, m, d) {
  if (!y) return 0;
  const now = new Date();
  let age = now.getFullYear() - y;
  const month = (m || 1) - 1;
  const day = d || 1;
  if (now.getMonth() < month || (now.getMonth() === month && now.getDate() < day)) age--;
  return age > 0 && age < 130 ? age : 0;
}

function interestNames(interests) {
  if (!interests) return [];
  const table = CODES.interests || {};
  const out = [];
  for (let i = 1; i <= 4; i++) {
    const code = interests[`code${i}`];
    const word = (interests[`keyword${i}`] || '').trim();
    const name = code ? (table[String(code)] || '') : '';
    if (name && word) out.push(`${name}: ${word}`);
    else if (name) out.push(name);
    else if (word) out.push(word);
  }
  return out;
}

// The profile rows of a card. Empty values are left out: in the ICQ white pages
// an empty field looked exactly like a missing one.
function profileRows(icq, t, row) {
  if (!icq) return [];

  const basic = icq.basic_info || {};
  const more = icq.more_info || {};
  const out = [];

  const add = (label, value) => { if (value) out.push(row(label, escapeHtml(value))); };

  add(t.cNick, (basic.nickname || '').trim());
  add(t.cName, [basic.first_name, basic.last_name].map((v) => (v || '').trim()).filter(Boolean).join(' '));

  if (more.gender === 1 || more.gender === 2) {
    out.push(row(t.cGender, more.gender === 2 ? t.cMale : t.cFemale));
  }

  const age = ageFrom(more.birth_year, more.birth_month, more.birth_day);
  if (age) out.push(row(t.cAge, t.cYears(age)));

  add(t.cCity, (basic.city || '').trim());
  add(t.cCountry, countryName(basic.country_code));

  const from = [(basic.origin_city || '').trim(), countryName(basic.origin_country_code)]
    .filter(Boolean).join(', ');
  add(t.cFrom, from);

  // The address is shown only if the owner allowed it: that is their own profile
  // setting, not ours.
  if (basic.publish_email) add(t.cEmail, (basic.email || '').trim());

  const home = (more.homepage || '').trim();
  if (home && /^https?:\/\//i.test(home)) {
    out.push(row(t.cHomepage,
      `<a href="${escapeHtml(home)}" style="${FONT}">${escapeHtml(home.slice(0, 80))}</a>`));
  } else {
    add(t.cHomepage, home);
  }

  add(t.cInterests, interestNames(icq.interests).join(', '));

  return out;
}

// ---------------------------------------------------------------- user picture
//
// A user has a static picture (the buddy icon), an animated Flash avatar, both
// or neither. The card shows the animated one when it is one of ours, and
// otherwise the static picture. The animated one is drawn at twice the
// gallery's size, as a still picture first; a browser of today then plays the
// movie over it with Ruffle (see loadRuffle). The client's own embedded IE,
// which opens the card for "My page", and any browser with scripts off or
// without WebAssembly keep the still picture.

// The picture types every browser the pages are made for shows in an <img>.
const CARD_ICON_TYPES = new Set(['image/gif', 'image/jpeg', 'image/png', 'image/bmp']);
const CARD_ICON_BOX = 64;

// The user's static picture as { type, body }, or null when there is none or
// it is not something a browser can show.
async function staticIcon(uin) {
  const icon = await mgmtBytes(`/user/${encodeURIComponent(uin)}/icon`);
  return icon && icon.body.length && CARD_ICON_TYPES.has(icon.type) ? icon : null;
}

// The gallery entry of the user's animated avatar, or null when they have none
// or it is not one of ours. The stored item is a small XML document with the
// movie's address: <DOCUMENT><RESSET TYPE="ICQ_EXTRAS"><URL>...</URL>.
async function animatedAvatar(uin) {
  const doc = await mgmtBytes(`/user/${encodeURIComponent(uin)}/icon?type=8`);
  if (!doc) return null;
  const m = /<URL>\s*([^<]+?)\s*<\/URL>/i.exec(doc.body.toString('utf8'));
  if (!m) return null;
  let pathname;
  try {
    pathname = new URL(m[1].replace(/&amp;/g, '&')).pathname;
  } catch {
    return null;
  }
  const file = /^\/icq\/avatars\/([a-z0-9_-]+\.swf)$/i.exec(pathname);
  if (!file) return null;
  return lookupAvatar(file[1]);
}

// The width and height of a GIF, PNG, BMP or JPEG picture, or null.
function imageSize(b) {
  if (b.length >= 10 && b.toString('latin1', 0, 4) === 'GIF8') {
    return { w: b.readUInt16LE(6), h: b.readUInt16LE(8) };
  }
  if (b.length >= 24 && b.readUInt32BE(0) === 0x89504e47 && b.toString('latin1', 12, 16) === 'IHDR') {
    return { w: b.readUInt32BE(16), h: b.readUInt32BE(20) };
  }
  if (b.length >= 26 && b.toString('latin1', 0, 2) === 'BM') {
    return { w: Math.abs(b.readInt32LE(18)), h: Math.abs(b.readInt32LE(22)) };
  }
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) return null;
      const marker = b[i + 1];
      if (marker === 0xff) { i += 1; continue; }
      const len = b.readUInt16BE(i + 2);
      // SOF0..SOF15 carry the size; C4, C8 and CC are other segments.
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { w: b.readUInt16BE(i + 7), h: b.readUInt16BE(i + 5) };
      }
      i += 2 + len;
    }
  }
  return null;
}

// width/height attributes that fit the picture into the card's box, keeping
// its proportions (old IE knows no max-width). Empty when the size is unknown.
function iconSizeAttrs(body) {
  const size = imageSize(body);
  if (!size || !size.w || !size.h) return '';
  const scale = Math.min(1, CARD_ICON_BOX / Math.max(size.w, size.h));
  const w = Math.max(1, Math.round(size.w * scale));
  const h = Math.max(1, Math.round(size.h * scale));
  return ` width="${w}" height="${h}"`;
}

// How Ruffle is set up for the card: the movie starts on its own, silently,
// with none of the player's own screens - no splash, no "click to unmute", no
// menu - and it may not open anything. The movie is transparent, over the
// white of its frame, like the still picture under it. Nothing in the page is
// taken over: the card makes the one player itself.
const CARD_RUFFLE_CONFIG = {
  publicPath: '/icq/ruffle/',
  polyfills: false,
  autoplay: 'on',
  unmuteOverlay: 'hidden',
  splashScreen: false,
  contextMenu: 'off',
  letterbox: 'off',
  wmode: 'transparent',
  backgroundColor: null,
  quality: 'high',
  allowFullscreen: false,
  allowNetworking: 'none',
  openUrlMode: 'deny',
  showSwfDownload: false,
  warnOnUnsupportedContent: false,
  favorFlash: false,
  logLevel: 'error',
};

// The script that turns the card's still picture into the playing movie. It
// has to be harmless in the embedded IE the client opens the card in: plain
// old JavaScript, no syntax that engine cannot parse, and it stops at once
// where there is no WebAssembly. Only then is Ruffle fetched. The player is
// kept hidden over the picture until the movie has loaded, and is taken away
// again if it never does, so the still picture stays whatever goes wrong.
function cardAvatarScript(boxId, swf) {
  return `<script type="text/javascript">
(function () {
  var box = document.getElementById(${scriptJson(boxId)});
  if (!box || typeof WebAssembly != 'object' || typeof Promise == 'undefined'
      || !window.fetch || !box.addEventListener) { return; }
  var img = box.getElementsByTagName('img')[0];
  var player = null;
  var shown = false;
  function giveUp() {
    if (shown || !player) { return; }
    try { box.removeChild(player); } catch (e) {}
    player = null;
  }
  function start() {
    if (!window.RufflePlayer || !window.RufflePlayer.newest) { return; }
    player = window.RufflePlayer.newest().createPlayer();
    var s = player.style;
    s.position = 'absolute'; s.left = '0'; s.top = '0';
    s.width = box.offsetWidth + 'px'; s.height = box.offsetHeight + 'px';
    s.visibility = 'hidden';
    box.appendChild(player);
    player.addEventListener('loadeddata', function () {
      // A moment for the first frame to be drawn before it replaces the picture.
      setTimeout(function () {
        if (!player) { return; }
        shown = true;
        player.style.visibility = 'visible';
        if (img) { img.style.visibility = 'hidden'; }
      }, 250);
    });
    var api = player.ruffle ? player.ruffle() : player;
    api.load({ url: ${scriptJson(swf)} }).then(null, giveUp);
    setTimeout(giveUp, 20000);
  }
  window.RufflePlayer = window.RufflePlayer || {};
  window.RufflePlayer.config = ${scriptJson(CARD_RUFFLE_CONFIG)};
  var script = document.createElement('script');
  script.src = ${scriptJson(`/icq/ruffle/ruffle.js?v=${ruffleTag}`)};
  script.onload = function () { try { start(); } catch (e) { giveUp(); } };
  document.getElementsByTagName('head')[0].appendChild(script);
})();
</script>`;
}

// The picture cell of a user card as { html, width }, or null when the user
// has no picture.
async function cardPicture(uin, t, lang) {
  let avatar = null;
  try {
    avatar = await animatedAvatar(uin);
  } catch {
    // The card makes sense without the picture.
  }
  if (avatar) {
    const stem = avatar.file.replace(/\.[a-z]+$/i, '');
    const title = (avatar.title && (avatar.title[lang] || avatar.title.en)) || stem;
    // The title links to the tester, where the avatar shows all its faces.
    const label = `<div class="dim" style="font-size:11px;line-height:13px;margin-top:3px">`
      + `${t.cAnimatedAvatar(`<a href="${escapeHtml(testerUrl(avatar, lang, ''))}">${escapeHtml(title)}</a>`)}</div>`;
    // The large still, when the folder has it; the gallery's thumbnail
    // otherwise, as before.
    const large = avatar.large && avatarAsset(avatar.large);
    const size = large && imageSize(large.body);
    if (!size) {
      return {
        width: 72,
        html: `<img src="/icq/avatars/${escapeHtml(avatar.thumb)}" width="52" height="64"`
          + ` alt="${escapeHtml(title)}" title="${escapeHtml(title)}" border="0">${label}`,
      };
    }
    // The movie plays only where Ruffle is here to play it, on its idle loop
    // (see moodMovie).
    const playable = ruffleFiles.has('ruffle.js') && (avatar.labels || []).includes('stam');
    return {
      width: Math.max(72, size.w),
      html: `<div id="cardAvatar" style="position:relative;width:${size.w}px;height:${size.h}px;`
        + `background:#fff;overflow:hidden">`
        + `<img src="/icq/avatars/${escapeHtml(avatar.large)}" width="${size.w}" height="${size.h}"`
        + ` alt="${escapeHtml(title)}" title="${escapeHtml(title)}" border="0" style="display:block"></div>`
        + label
        + (playable ? cardAvatarScript('cardAvatar', `/icq/avatars/${avatar.file}?emotion=stam`) : ''),
    };
  }
  // The static picture comes through our own route: the management API it is
  // stored behind is reachable only from this machine.
  if (!/^\d{4,10}$/.test(uin)) return null;
  let icon = null;
  try {
    icon = await staticIcon(uin);
  } catch {
    // As above.
  }
  if (!icon) return null;
  return {
    width: 72,
    html: `<img src="/icq/whitepages/icon?icq=${escapeHtml(uin)}"${iconSizeAttrs(icon.body)}`
      + ' alt="" border="0">',
  };
}

// GET /icq/whitepages/icon?icq=<uin>: the user's static picture, relayed from
// the management API. Only a number, only a picture; anything else is a 404.
async function serveCardIcon(ctx) {
  const uin = ctx.url.searchParams.get('icq') || '';
  const notFound = () => {
    ctx.res.writeHead(404, { 'content-length': 0, 'cache-control': 'no-store' });
    ctx.res.end();
  };
  if (!/^\d{4,10}$/.test(uin) || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) {
    notFound();
    return;
  }
  let icon;
  try {
    icon = await staticIcon(uin);
  } catch {
    ctx.res.writeHead(502, { 'content-length': 0, 'cache-control': 'no-store' });
    ctx.res.end();
    return;
  }
  if (!icon) {
    notFound();
    return;
  }
  // The picture can change at any time, so the browser asks again every time
  // and gets a 304 while it is the same.
  const etag = `"${crypto.createHash('sha1').update(icon.body).digest('hex').slice(0, 20)}"`;
  if (ctx.req.headers['if-none-match'] === etag) {
    ctx.res.writeHead(304, { etag, 'cache-control': 'no-cache' });
    ctx.res.end();
    return;
  }
  ctx.res.writeHead(200, {
    'content-type': icon.type,
    'content-length': icon.body.length,
    'cache-control': 'no-cache',
    'x-content-type-options': 'nosniff',
    etag,
  });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : icon.body);
}

async function userCard(uin, t, lang = FALLBACK_LANG) {
  let account;
  try {
    account = await mgmt(`/user/${encodeURIComponent(uin)}/account`);
  } catch (err) {
    // A 404 on a number that does not exist is an answer, not a failure.
    if (/HTTP 404/.test(err.message)) return { exists: false };
    return { error: err.message };
  }
  if (!account) return { exists: false };

  let session = null;
  try {
    const data = await mgmt(`/session/${encodeURIComponent(uin)}`);
    session = (data.sessions || []).find((s) => !s.is_invisible) || null;
  } catch {
    // The card still makes sense without the presence state.
  }

  let state;
  if (!session) {
    state = `<span class="dim">${t.sOffline}</span>`;
  } else if (session.is_away) {
    state = `<span class="warn">${t.sAway}</span>`
      + (session.away_message
        ? ` &#8212; ${escapeHtml(session.away_message.replace(/<[^>]*>/g, '').slice(0, 120))}`
        : '');
  } else if (session.idle_seconds > 0) {
    state = `<span class="warn">${t.sIdleFor(formatDuration(session.idle_seconds, t))}</span>`;
  } else {
    state = `<span class="ok">${t.sOnline}</span>`;
  }

  // The profile is stored apart from the account: `/account` knows only the
  // number, the e-mail and the state, while the nickname, name and city live in
  // `/icq`. Without the second request the card showed a number and a status.
  let icq = null;
  if (account.is_icq) {
    try {
      icq = await mgmt(`/user/${encodeURIComponent(uin)}/icq`);
    } catch {
      // There may be no profile at all; the card then lacks these rows.
    }
  }

  const row = (label, value) => `<tr>
    <td valign="top" style="padding:1px 10px 1px 0"><span class="dim">${label}</span></td>
    <td valign="top" style="padding:1px 0">${value}</td></tr>`;

  const about = (account.profile || '').trim() || ((icq && icq.notes) || '').trim();

  const rows = [
    row(t.colNumber, `<b>${escapeHtml(uin)}</b>`),
    row(t.colStatus, state),
    session ? row(t.cSignedInFor, formatDuration(session.online_seconds, t)) : '',
    ...profileRows(icq, t, row),
    // "About" lives in the profile for AIM and in the profile notes for ICQ.
    about ? row(t.cAbout, escapeHtml(about.replace(/<[^>]*>/g, '').slice(0, 400))) : '',
    account.suspended_status ? row(t.cAccount, `<span class="bad">${t.cSuspended}</span>`) : '',
  ].join('');

  const table = `<table cellpadding="0" cellspacing="0" border="0">${rows}</table>`;
  const picture = await cardPicture(uin, t, lang);

  return {
    exists: true,
    // The picture sits left of the details, like a photo on a profile.
    html: picture
      ? `<div class="card">
      <table cellpadding="0" cellspacing="0" border="0"><tr>
        <td valign="top" align="center" width="${picture.width}" style="padding:0 12px 0 0">${picture.html}</td>
        <td valign="top">${table}</td>
      </tr></table>
    </div>`
      : `<div class="card">
      ${table}
    </div>`,
  };
}

async function whitepagesPage(uin, selfPath, u) {
  const t = u.t;
  if (!uin) {
    return page(t.findTitle, `
      <form method="get" action="${escapeHtml(selfPath || '')}">
        <p>${t.icqNumber}
        <input type="text" name="icq" size="14" style="${FONT}">
        <input type="submit" value="${t.searchBtn}" style="${FONT}"></p>
      </form>`, '', false, u);
  }

  const card = await userCard(uin, t, u.lang);
  if (card.error) {
    return page(t.findTitle, `<p>${t.serverSilent(escapeHtml(card.error))}</p>`, '', false, u);
  }
  if (!card.exists) {
    return page(t.findTitle, `<p>${t.notRegistered(escapeHtml(uin))}</p>`, '', false, u);
  }

  return page(t.findTitle, `
    ${card.html}
    <p style="margin:10px 0 0 0"><a href="${escapeHtml(pagerLink(uin))}"
       style="${FONT}">${t.sendViaPager}</a></p>`, '', false, u);
}

// The link from a user card to the web pager. The address comes from the config:
// http://wwp.icq.com/wwp/ when the ICQ.com names are intercepted, a plain path
// when the server has an address of its own.
function pagerLink(uin) {
  const base = (config.links && config.links.pager) || '/icq/wwp';
  return base + (base.includes('?') ? '&' : '?') + 'Uin=' + encodeURIComponent(uin);
}

// The "ICQ Welcome" window opens after sign-in. It used to carry ICQ.com
// advertising; now it greets the user and reports the state of their server.
async function welcomePage(uin, selfPath, u) {
  const t = u.t;
  let online = null;
  try {
    const data = await mgmt('/session');
    // There is no point listing yourself among "who else is online".
    online = (data.sessions || [])
      .filter((s) => !s.is_invisible && s.screen_name !== uin);
  } catch {
    // The management server is unreachable; greet the user anyway.
  }

  const base = selfPath.replace(/\/welcome.*$/, '');
  const item = (href, text) => `<tr>
    <td valign="top" width="13" style="padding:3px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:1px 0 2px 0">
      <a href="${escapeHtml(base + href)}">${text}</a>
    </td></tr>`;

  const who = uin ? t.signedInAs(escapeHtml(uin)) : t.signedIn;

  let status;
  if (online === null) {
    status = `<span class="warn">${t.dirDown}</span>`;
  } else if (online.length === 0) {
    status = `<span class="dim">${t.nobodyElse}</span>`;
  } else {
    // Only the count: the numbers themselves are on the "who is online" page,
    // linked right here, so repeating them in the status line adds nothing.
    status = t.othersOnline(online.length);
  }

  return page(t.welcomeTitle, `
    <div class="panel">${who} &#183; ${status}</div>

    <p>${t.intro}</p>

    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">
        ${item('/today', t.lnkToday)}
        ${item('/whitepages', t.lnkFind)}
        ${item('/wwp', t.lnkPager)}
        ${item('/password', t.lnkPwd)}
        ${item('/account', t.lnkAccount)}
      </table>
    </div>`, t.welcomeSub, true, u);
}

// "User's Unified Messaging Center" is a button in the message window. It used
// to collect the messages that reached the number's owner over the web, e-mail
// and SMS. Those services are gone, so we show the state of the account.
async function centerPage(uin, selfPath, u) {
  const t = u.t;
  const base = selfPath.replace(/\/center.*$/, '');
  const item = (href, text) => `<tr>
    <td valign="top" width="13" style="padding:3px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:1px 0 2px 0"><a href="${escapeHtml(base + href)}">${text}</a></td>
  </tr>`;

  const card = /^\d{4,10}$/.test(uin) ? await userCard(uin, t, u.lang) : { exists: false };
  const head = card.exists
    ? card.html
    : `<div class="card">${t.colNumber} <b>${escapeHtml(uin || '&#8212;')}</b></div>`;

  return page(t.centreTitle, `
    ${head}

    <h2>${t.centreAbout}</h2>
    <p>${t.centreText}</p>

    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">
        ${item('/wwp', t.lnkSendSomeone)}
        ${item('/today', t.lnkToday)}
        ${item('/whitepages', t.lnkFind)}
        ${item('/password', t.lnkPwd)}
        ${item('/account', t.lnkAccount)}
      </table>
    </div>`, t.centreSub, false, u);
}

// "How to Start" from the contact list. It used to lead to a stub; now it is a
// short guide: the owner's number, how to add a buddy, how to invite a new one.
function howtoPage(uin, selfPath, u) {
  const t = u.t;
  const base = selfPath.replace(/\/howto.*$/, '');
  const item = (text) => `<tr>
    <td valign="top" width="14" style="padding:4px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:1px 0 6px 0">${text}</td></tr>`;

  const reg = config.registerBase
    ? `<p><a href="${escapeHtml(config.registerBase)}">${t.lnkRegister}</a></p>`
    : '';

  const host = config.oscarHost || '';
  const ports = serverCard(t);

  return page(t.howtoTitle, `
    <div class="panel">${uin ? t.howtoYou(escapeHtml(uin)) : ''}</div>

    <h2>${t.howtoSteps}</h2>
    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">
        ${item(t.howtoAdd)}
        ${item(t.howtoInvite)}
        ${item(t.howtoOffline)}
        ${item(t.howtoFiles)}
      </table>
    </div>
    ${reg}

    ${host ? `<h2>${t.howtoSettings}</h2>` : ''}
    ${ports}`, t.howtoSub, false, u);
}

// The server address and ports, for a client that is set up by hand. Empty
// when the config names no address.
function serverCard(t) {
  const host = config.oscarHost || '';
  if (!host) return '';
  return `<div class="card">
        <table cellpadding="0" cellspacing="0" border="0">
          <tr><td style="padding:1px 10px 1px 0"><span class="dim">${t.howtoServer}</span></td>
              <td><code>${escapeHtml(host)}</code></td></tr>
          <tr><td style="padding:1px 10px 1px 0"><span class="dim">${t.howtoPlain}</span></td>
              <td><code>5190</code></td></tr>
          <tr><td style="padding:1px 10px 1px 0"><span class="dim">${t.howtoSsl}</span></td>
              <td><code>5193</code></td></tr>
        </table>
      </div>
      <p><span class="dim">${t.howtoPorts}</span></p>`;
}

// ------------------------------------------------------------ information pages
//
// Help, about, legal, terms and downloads: the pages ICQ 6.5's Help menu and
// sign-in window open once the patch points them here. Plain text pages, the
// same shell as the rest.

// A list with the green square bullets the other pages use. Empty lines are
// left out, so a caller can drop an item by passing ''.
function bullets(lines) {
  const rows = lines.filter(Boolean).map((line) => `<tr>
    <td valign="top" width="14" style="padding:5px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:2px 0 4px 0">${line}</td></tr>`).join('');
  return `<div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">${rows}</table>
    </div>`;
}

// A link to one of our own pages that keeps the language the reader chose: the
// pages carry no cookies, so the switch would be lost on every click.
function ownLink(path, u) {
  return escapeHtml(`/icq${path}?lang=${u.lang}`);
}

// The pages on the registration service, reached through our own redirects.
// Without a registration service there is nothing to link to.
function accountLink(path, u) {
  return config.registerBase ? ownLink(path, u) : '';
}

// The contact for questions about the server, from the config: an e-mail
// address, a web page or plain text. Empty when none is configured.
function contactHtml() {
  const c = String(config.contact || '').trim();
  if (!c) return '';
  if (/^[^@\s]+@[^@\s]+$/.test(c)) {
    return `<a href="mailto:${escapeHtml(c)}">${escapeHtml(c)}</a>`;
  }
  if (/^https?:\/\//i.test(c)) return `<a href="${escapeHtml(c)}">${escapeHtml(c)}</a>`;
  return escapeHtml(c);
}

// A download from the config. A value that is empty or still says TODO is not
// a link yet, and the page says so instead of sending the reader nowhere.
function downloadLink(key, t) {
  const url = String((config.downloads || {})[key] || '').trim();
  if (!url || /^todo/i.test(url)) return `<span class="dim">${t.dlSoon}</span>`;
  return `<a href="${escapeHtml(url)}">${t.dlGet}</a>`;
}

// The links at the foot of every information page, minus the page itself.
function infoLinks(self, u) {
  const t = u.t;
  const all = [
    ['/help/', t.lnkHelp],
    ['/about', t.lnkAbout],
    ['/download', t.lnkDownload],
    ['/legal/', t.lnkLegal],
    ['/terms', t.lnkTerms],
  ];
  return bullets(all.filter(([p]) => p !== self)
    .map(([p, text]) => `<a href="${ownLink(p, u)}">${text}</a>`));
}

function helpPage(u) {
  const t = u.t;
  const name = escapeHtml(config.serverName);
  const more = [
    `<a href="${ownLink('/howto', u)}">${t.howtoTitle}</a>`,
    accountLink('/profile', u) ? `<a href="${accountLink('/profile', u)}">${t.lnkProfile}</a>` : '',
    `<a href="${ownLink('/whitepages', u)}">${t.lnkFind}</a>`,
    `<a href="${ownLink('/wwp', u)}">${t.lnkPager}</a>`,
    `<a href="${ownLink('/today', u)}">${t.lnkToday}</a>`,
    `<a href="${ownLink('/about', u)}">${t.lnkAbout}</a>`,
    `<a href="${ownLink('/legal/', u)}">${t.lnkLegal}</a>`,
  ];

  return page(t.helpTitle, `
    <p>${t.helpIntro(name)}</p>

    <h2>${t.helpSignIn}</h2>
    ${bullets(t.helpSignInSteps)}
    <div style="margin-top:10px">${serverCard(t)}</div>

    <h2>${t.helpAccount}</h2>
    ${bullets(t.helpAccountSteps(accountLink('/register', u),
      accountLink('/profile', u), accountLink('/password', u)))}

    <h2>${t.helpCalls}</h2>
    ${bullets(t.helpCallsSteps)}

    <h2>${t.helpGone}</h2>
    <p>${t.helpGoneText}</p>
    ${bullets(t.helpGoneList)}

    <h2>${t.helpPatches}</h2>
    <p>${t.helpPatchesText(ownLink('/download', u))}</p>

    <h2>${t.helpMore}</h2>
    ${bullets(more)}`, t.helpSub, false, u);
}

function aboutPage(u) {
  const t = u.t;
  const row = (label, value) => (value ? `<tr>
    <td valign="top" style="padding:1px 10px 1px 0"><span class="dim">${label}</span></td>
    <td valign="top" style="padding:1px 0">${value}</td></tr>` : '');
  const host = config.oscarHost ? `<code>${escapeHtml(config.oscarHost)}</code>` : '';

  return page(t.aboutTitle, `
    <p>${t.aboutP1}</p>
    <p>${t.aboutP2}</p>
    <p>${t.aboutP3('https://github.com/mk6i/open-oscar-server')}</p>

    <h2>${t.aboutThis}</h2>
    <div class="card">
      <table cellpadding="0" cellspacing="0" border="0">
        ${row(t.aboutName, `<b>${escapeHtml(config.serverName)}</b>`)}
        ${row(t.aboutAddress, host)}
        ${row(t.aboutContact, contactHtml())}
      </table>
    </div>

    ${infoLinks('/about', u)}`, t.aboutSub, false, u);
}

// The terms, shared by their own page and the legal page.
function termsBody(u) {
  return bullets(u.t.termsList);
}

function legalPage(u) {
  const t = u.t;
  const contact = contactHtml();
  const account = accountLink('/account', u);

  return page(t.legalTitle, `
    <h2>${t.legalWho}</h2>
    <p>${t.legalWhoText(escapeHtml(config.serverName))}</p>
    ${contact ? `<p>${t.legalContact(contact)}</p>` : ''}

    <h2>${t.legalStored}</h2>
    ${bullets(t.legalStoredList)}

    <h2>${t.legalNotStored}</h2>
    ${bullets(t.legalNotStoredList)}

    <h2>${t.legalLogs}</h2>
    <p>${t.legalLogsText}</p>

    <h2>${t.legalSeen}</h2>
    <p>${t.legalSeenText}</p>

    <h2>${t.legalNoTrack}</h2>
    <p>${t.legalNoTrackText}</p>

    ${account ? `<h2>${t.legalDelete}</h2>
    <p>${t.legalDeleteText(account)}</p>` : ''}

    <h2>${t.termsTitle}</h2>
    ${termsBody(u)}

    <h2>${t.helpMore}</h2>
    ${infoLinks('/legal/', u)}`, t.legalSub, false, u);
}

function termsPage(u) {
  const t = u.t;
  return page(t.termsTitle, `
    ${termsBody(u)}
    <p>${t.termsPrivacy(ownLink('/legal/', u))}</p>

    <h2>${t.helpMore}</h2>
    ${infoLinks('/terms', u)}`, t.termsSub, false, u);
}

function downloadPage(u) {
  const t = u.t;
  const row = (client, build, needs, link) => `<tr>
    <td valign="top">${client}</td>
    <td valign="top">${build}</td>
    <td valign="top">${needs}</td>
    <td valign="top" nowrap>${link}</td></tr>`;
  const host = config.oscarHost ? escapeHtml(config.oscarHost) : '';

  return page(t.dlTitle, `
    <p>${t.dlIntro}</p>

    <div class="scroll">
    <table class="data" cellpadding="0" cellspacing="0" border="0">
      <thead><tr>
        <th>${t.dlClient}</th><th>${t.dlBuild}</th><th>${t.dlNeeds}</th><th></th>
      </tr></thead>
      <tbody>
        ${row('<b>ICQ Pro 2003b</b>', '3916', t.dlIcq2003b, downloadLink('icq2003bPatch', t))}
        ${row('<b>ICQ 6.5</b>', '2024', t.dlIcq65, downloadLink('icq65Patch', t))}
        ${row('<b>Miranda NG</b>', '0.96.7', t.dlMiranda, downloadLink('mirandaPlugin', t))}
        ${row(`<b>${t.dlOthers}</b>`, t.dlAny, t.dlByHand,
          `<a href="${ownLink('/help/', u)}">${t.lnkHelp}</a>`)}
      </tbody>
    </table>
    </div>

    <h2>${t.dlHow}</h2>
    ${bullets(t.dlHowSteps(host))}
    <p><span class="dim">${t.dlHowNote}</span></p>
    <p><span class="dim">${t.dlMirandaNote}</span></p>

    <h2>${t.helpMore}</h2>
    ${infoLinks('/download', u)}`, t.dlSub, false, u);
}

function stubPage(topic, u, compact = false) {
  const t = u.t;
  const slug = topic.replace(/\.html?$/i, '').trim().toLowerCase();

  // Aliases: several ICQ.com addresses led to one and the same topic.
  let entry = topics[slug];
  if (entry && entry.alias_topic) entry = topics[entry.alias_topic];

  const item = (href, text) => `<tr>
    <td valign="top" width="14" style="padding:5px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:2px 0 4px 0"><a href="${escapeHtml('/icq' + href)}">${text}</a></td>
  </tr>`;

  const LABEL = {
    '/howto': t.howtoTitle,
    '/today': t.lnkToday,
    '/whitepages': t.lnkFind,
    '/wwp': t.lnkPager,
    '/password': t.lnkPwd,
    '/profile': t.lnkProfile,
    '/account': t.lnkAccount,
  };

  if (entry && entry[u.lang]) {
    const e = entry[u.lang];
    const links = (entry.links || []).map((h) => item(h, LABEL[h] || h)).join('');
    // If the service works, describe it and how to use it. If not, say what it
    // was and what replaces it. The "on this server" caveats fit only the
    // latter case.
    const steps = (e.use || [])
      .map((line) => `<tr>
        <td valign="top" width="14" style="padding:5px 0 0 0">
          <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
        </td>
        <td style="padding:2px 0 4px 0">${line}</td></tr>`).join('');
    const body = steps
      ? `<h2>${t.topicUse}</h2>
         <div class="soft">
           <table cellpadding="0" cellspacing="0" border="0">${steps}</table>
         </div>
         ${e.note ? `<p><span class="dim">${e.note}</span></p>` : ''}`
      : `<p>${e.here}</p>`;
    return page(e.title, `
      <p>${e.text}</p>
      ${body}
      ${links ? `<h2>${t.stubWorks}</h2>
      <div class="soft">
        <table cellpadding="0" cellspacing="0" border="0">${links}</table>
      </div>` : ''}`, entry.now ? t.topicSubNow : t.topicSub, compact, u);
  }

  // The topic is missing from the dictionary: a generic page, still with links.
  let nice = topic.replace(/\.html?$/i, '').replace(/[_\-]+/g, ' ').trim();
  if (!/[a-zа-яё]{3}/i.test(nice)) nice = '';
  const all = ['/howto', '/today', '/whitepages', '/wwp', '/profile', '/password', '/account']
    .map((h) => item(h, LABEL[h])).join('');
  return page(t.stubTitle, `
    <p>${t.stubP1(escapeHtml(nice || 'ICQ.com'))}</p>
    <p>${t.stubP2}</p>

    <h2>${t.stubWorks}</h2>
    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">${all}</table>
    </div>`, '', false, u);
}

function hostsFileText(serviceAddress) {
  const names = (config.hostsFile && config.hostsFile.names) || [];
  const lines = names.map((n) => `${serviceAddress}\t${n}`);
  return [
    '# Dead ICQ web services, intercepted by a local server.',
    '# Add to %SystemRoot%\System32\drivers\etc\hosts as administrator.',
    '# To undo, delete this whole block.',
    '',
    ...lines,
    '',
  ].join('\r\n');
}

// The table of known actions. loadConfig checks against it so that a typo in the
// config surfaces at startup rather than on the first request.
// The page that sets the user's own picture, served to the client as an Xtra.
// Read once at startup like the other data files next to this one.
const avatarTemplate = fs.readFileSync(path.join(__dirname, 'pages', 'avatar.html'), 'utf8');

// The picture page, in the same frame as every other page - the green title bar
// and the UK/EN switch - and in the reader's language. It is a template rather
// than markup built here because of its script: the plugin object and the
// handlers for its events. {{KEY}} is a text from the dictionary, escaped;
// {{STRINGS}} hands the script the messages it shows; the rest is the shell.
// JSON inside a script: "</" would end the script early.
function scriptJson(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

// The animated tab: the thumbnails in a table, ICQ's own first, then the
// ones users made. A thumbnail is a link that picks the movie; the page's
// script does the rest. Empty when the server has no avatars, and the page
// then shows no tabs at all.
function animatedGallery(u) {
  const t = u.t;
  const cols = 6;
  const group = (author, heading) => {
    const items = avatarList.filter((a) => a.author === author);
    if (!items.length) return '';
    const cells = items.map((a) => {
      const stem = a.file.replace(/\.[a-z]+$/i, '');
      const title = (a.title && (a.title[u.lang] || a.title.en)) || stem;
      return `<td class="anim" id="av-${escapeHtml(stem)}" valign="top" align="center">`
        + `<a href="#" onclick="choose('${escapeHtml(a.file)}'); return false;">`
        + `<img class="thumb" src="/icq/avatars/${escapeHtml(a.thumb)}" width="52" height="64" alt="" border="0"><br>`
        + `${escapeHtml(title)}</a></td>`;
    });
    const rows = [];
    for (let i = 0; i < cells.length; i += cols) {
      const row = cells.slice(i, i + cols);
      while (row.length < cols) row.push('<td class="anim"></td>');
      rows.push(`<tr>${row.join('')}</tr>`);
    }
    return {
      author,
      heading,
      count: items.length,
      html: `<div id="grp-${author}" class="grp">
      <table class="gallery" cellpadding="0" cellspacing="0" border="0">${rows.join('')}</table></div>`,
    };
  };
  // The two groups are switched like the tabs above rather than stacked: the
  // client's window cannot scroll, and each group fits it on its own.
  const groups = [group('icq', t.picAnimIcq), group('user', t.picAnimUser)].filter(Boolean);
  if (!groups.length) return '';
  const switcher = groups.map((g, i) => `<a href="#" id="grpTab-${g.author}"${i === 0 ? ' class="on"' : ''}`
    + ` onclick="group('${g.author}'); return false;">${escapeHtml(g.heading)} (${g.count})</a>`).join('');
  const bodies = groups.map((g, i) => (i === 0 ? g.html : g.html.replace('class="grp"', 'class="grp" style="display:none"')));
  return `<div class="tabs grptabs">${switcher}</div>${bodies.join('')}`;
}

function avatarPage(u, req) {
  const t = u.t;
  const keys = Object.keys(t).filter((k) => k.startsWith('pic') && typeof t[k] === 'string');
  const strings = {};
  for (const k of keys) strings[k] = t[k];
  // What the script needs to know about each movie: the title it shows as
  // "now set", and the address it hands the client. That address is plain
  // HTTP on this service's own port whichever way the page came in: the
  // client fetches the movie with its own loader, and so does every
  // contact's client, and none of them speaks HTTPS. The still picture of
  // each face (<name>-still.jpg) is not the page's business: the IM server
  // takes it from here and shows it to the clients that cannot play the movie.
  const avatars = avatarList.map((a) => ({
    file: a.file,
    title: (a.title && (a.title[u.lang] || a.title.en)) || a.file,
    thumb: a.thumb,
  }));
  const hasAnimated = avatars.length > 0;
  return avatarTemplate
    .replace('{{STYLE}}', () => SHARED_STYLE)
    .replace('{{HEADER}}', () => header(escapeHtml(t.picTitle), escapeHtml(t.picSub)))
    .replace('{{FOOTER}}', () => footer({ langs: langSwitch(u.lang, u.selfUrl) }))
    .replace('{{TABS_STYLE}}', () => (hasAnimated ? '' : 'display:none'))
    .replace('{{ANIMATED}}', () => animatedGallery(u))
    .replace('{{STRINGS}}', () => scriptJson(strings))
    .replace('{{AVATARS}}', () => scriptJson(avatars))
    .replace('{{AVATAR_BASE}}', () => scriptJson(`${plainBase(req)}/icq/avatars/`))
    // The editor's geometry: the server's own function, as source.
    .replace('{{PICTURE_CROP}}', () => pictureCrop.toString())
    .replace('{{ZOOM_MAX}}', () => String(ZOOM_MAX))
    .replace('{{MAKER_FRAME_H}}', () => String(MAKER_FRAME_H))
    .replace(/\{\{LANG\}\}/g, () => u.lang)
    .replace(/\{\{(pic[A-Za-z]+)\}\}/g, (m, k) => (typeof t[k] === 'string' ? escapeHtml(t[k]) : m));
}

// ---------------------------------------------------------------- avatar tester
//
// /icq/avatar/tester?name=<movie>: any avatar of the gallery playing in the
// browser with Ruffle, with a button for each face its `face` clip has (its
// labels), next to the pictures the server hands out for it. The picture page
// and the user card link here. A face is shown by loading the copy of the
// movie with that face preset (serveMoodMovie), which also starts the
// gesture over every few seconds.
//
// The page itself works without scripts: a face button is a link to the same
// page with &emotion=, and the script only saves the reload. Where Ruffle
// cannot run - the client's embedded IE first of all - the stage keeps the
// large still picture and a note says where the movie can be seen.

// The stage is the movie's 53x65 drawn at four times its size, the large
// still's own size twice over; Ruffle draws it sharp at any size.
const TESTER_SCALE = 2;

// The gallery entry by the movie's name, with or without .swf; null for a
// name the gallery does not have.
function galleryAvatar(name) {
  const stem = String(name || '').toLowerCase().replace(/\.swf$/i, '');
  if (!/^[a-z0-9_-]+$/.test(stem)) return null;
  return lookupAvatar(`${stem}.swf`);
}

function avatarStem(a) {
  return a.file.replace(/\.[a-z]+$/i, '');
}

function avatarTitle(a, lang) {
  return (a.title && (a.title[lang] || a.title.en)) || avatarStem(a);
}

// The address of the tester for one avatar (and one of its faces).
function testerUrl(a, lang, emotion) {
  return `/icq/avatar/tester?name=${encodeURIComponent(avatarStem(a))}`
    + (emotion ? `&emotion=${encodeURIComponent(emotion)}` : '')
    + `&lang=${encodeURIComponent(lang)}`;
}

// The movie address for one face: the preset copy when the movie has another
// label to replay through (serveMoodMovie needs one), the movie as it is
// otherwise.
function testerMovie(a, emotion) {
  const labels = a.labels || [];
  return emotion && labels.length > 1 && labels.includes(emotion)
    ? `/icq/avatars/${a.file}?emotion=${encodeURIComponent(emotion)}`
    : `/icq/avatars/${a.file}`;
}

// The Ruffle setup of the card, with the movie's own screens off; the tester
// only differs in the player it makes.
const TESTER_RUFFLE_CONFIG = { ...CARD_RUFFLE_CONFIG, backgroundColor: '#FFFFFF', wmode: 'opaque' };

// The script of the stage. Like the card's (cardAvatarScript), it has to be
// harmless in the embedded IE: old JavaScript only, and it stops at once where
// there is no WebAssembly - showing the note instead. The player is put over
// the still picture once the movie has loaded; a face button then loads that
// face's copy into the same player instead of reloading the page.
function testerScript(movies, emotion) {
  return `<script type="text/javascript">
var avMood = (function () {
  var MOVIES = ${scriptJson(movies)};
  var current = ${scriptJson(emotion)};
  var box = document.getElementById('avStage');
  var player = null, api = null, shown = false;
  function el(id) { return document.getElementById(id); }
  function note(id) {
    var n = el(id);
    if (n) { n.style.display = ''; }
    var m = el('avMoods');
    if (m) { m.style.display = 'none'; }
  }
  function mark(label) {
    for (var k in MOVIES) {
      var b = el('mood-' + k);
      if (b) { b.className = k === label ? 'mood on' : 'mood'; }
    }
  }
  function giveUp() {
    if (shown) { return; }
    if (player) { try { box.removeChild(player); } catch (e) {} }
    player = null; api = null;
    note('avFailed');
  }
  if (!box || typeof WebAssembly != 'object' || typeof Promise == 'undefined'
      || !window.fetch || !box.addEventListener) {
    note('avNoPlayer');
    return function () { return true; };
  }
  function start() {
    if (!window.RufflePlayer || !window.RufflePlayer.newest) { giveUp(); return; }
    player = window.RufflePlayer.newest().createPlayer();
    var s = player.style;
    s.position = 'absolute'; s.left = '0'; s.top = '0';
    s.width = box.offsetWidth + 'px'; s.height = box.offsetHeight + 'px';
    s.visibility = 'hidden';
    box.appendChild(player);
    player.addEventListener('loadeddata', function () {
      setTimeout(function () {
        if (!player) { return; }
        shown = true;
        player.style.visibility = 'visible';
        var img = el('avStill');
        if (img) { img.style.visibility = 'hidden'; }
      }, 250);
    });
    api = player.ruffle ? player.ruffle() : player;
    api.load({ url: MOVIES[current] }).then(null, giveUp);
    setTimeout(giveUp, 20000);
  }
  window.RufflePlayer = window.RufflePlayer || {};
  window.RufflePlayer.config = ${scriptJson(TESTER_RUFFLE_CONFIG)};
  var script = document.createElement('script');
  script.src = ${scriptJson(`/icq/ruffle/ruffle.js?v=${ruffleTag}`)};
  script.onload = function () { try { start(); } catch (e) { giveUp(); } };
  script.onerror = giveUp;
  document.getElementsByTagName('head')[0].appendChild(script);
  // A face button: false keeps the browser from following the link.
  return function (label) {
    if (!api || !MOVIES[label]) { return true; }
    current = label;
    mark(label);
    api.load({ url: MOVIES[label] }).then(null, giveUp);
    return false;
  };
})();
</script>`;
}

function testerPage(u, req, url) {
  const t = u.t;
  const lang = u.lang;
  const style = `<style>${SHARED_STYLE}
.stage { position: relative; background: #fff; border: 1px solid #cfe3d5; overflow: hidden; }
.moods { margin: 6px 0 4px; }
.moods a.mood {
  display: inline-block; padding: 2px 10px; margin: 0 5px 5px 0;
  font-size: 13px; text-decoration: none; color: #1a1a1a;
  border: 1px solid #9a9a9a; border-radius: 9px; background: #f2f0ea;
}
.moods a.mood.on { color: #fff; background: #3c6e1f; border-color: #35601a; }
table.pics td { padding: 0 14px 0 0; font-size: 12px; line-height: 1.3; }
table.pics img { border: 1px solid #cfe3d5; background: #fbfdfb; }
/* The thumbnails wrap to the width there is, a phone's included; IE 6-7
   learn inline-block from display:inline with layout (zoom). */
.gallery a.anim {
  display: inline-block; *display: inline; zoom: 1; vertical-align: top;
  width: 84px; margin: 0 4px 8px 0; text-align: center;
  font-size: 12px; line-height: 1.25; text-decoration: none; color: #1a1a1a;
}
.gallery a.anim img { border: 2px solid #e6e2d9; background: #fff; }
.gallery a.anim.on img { border-color: #3c6e1f; }
.gallery a.anim.on { font-weight: bold; }
</style>`;
  const shell = (bodyHtml) => `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(t.tstTitle)}</title>
${style}
</head>
<body>
<main class="window">
  ${header(escapeHtml(t.tstTitle), escapeHtml(t.tstSub))}
  <div class="body">${bodyHtml}</div>
  ${footer({ langs: langSwitch(lang, u.selfUrl) })}
</main>
</body>
</html>`;

  if (!avatarList.length) return shell(`<p>${escapeHtml(t.tstNone)}</p>`);

  const asked = url.searchParams.get('name') || '';
  let avatar = galleryAvatar(asked);
  const unknown = asked && !avatar;
  if (!avatar) avatar = avatarList[0];
  const stem = avatarStem(avatar);
  const title = avatarTitle(avatar, lang);
  const labels = (avatar.labels || []).filter((l) => /^[a-z0-9_]+$/i.test(l));
  const askedMood = url.searchParams.get('emotion') || '';
  const emotion = labels.includes(askedMood) ? askedMood
    : labels.includes('stam') ? 'stam' : (labels[0] || '');

  // The pictures, each at its own size; the large one also stands on the
  // stage until the movie plays over it.
  const still = avatar.still && avatarAsset(avatar.still);
  const large = avatar.large && avatarAsset(avatar.large);
  const thumb = avatarAsset(avatar.thumb);
  const stillSize = still && imageSize(still.body);
  const largeSize = large && imageSize(large.body);
  const thumbSize = (thumb && imageSize(thumb.body)) || { w: 52, h: 64 };
  const stageImg = largeSize ? { src: avatar.large, ...largeSize }
    : stillSize ? { src: avatar.still, ...stillSize } : { src: avatar.thumb, ...thumbSize };
  const stage = { w: (largeSize ? largeSize.w : 104) * TESTER_SCALE, h: (largeSize ? largeSize.h : 127) * TESTER_SCALE };
  const pic = (file, size, name, note) => (file && size ? `<td valign="bottom" align="center">`
    + `<img src="/icq/avatars/${escapeHtml(file)}" width="${size.w}" height="${size.h}" alt=""><br>`
    + `<b>${escapeHtml(name)}</b>, ${size.w}&times;${size.h}<br><span class="dim">${escapeHtml(note)}</span></td>` : '');

  const playable = ruffleFiles.has('ruffle.js');
  const movies = {};
  for (const l of labels) movies[l] = testerMovie(avatar, l);
  if (!labels.length) movies[''] = testerMovie(avatar, '');
  const moodName = (l) => (t.tstMood && t.tstMood[l]) || l;
  const moods = labels.map((l) => `<a href="${escapeHtml(testerUrl(avatar, lang, l))}" id="mood-${escapeHtml(l)}"`
    + ` class="mood${l === emotion ? ' on' : ''}"`
    + (playable ? ` onclick="return avMood(${escapeHtml(JSON.stringify(l))});"` : '') + '>'
    + `${escapeHtml(moodName(l))}</a>`).join('');
  const openHere = `${selfBase(req)}${testerUrl(avatar, lang, emotion)}`;

  const group = (author, heading) => {
    const items = avatarList.filter((a) => a.author === author);
    if (!items.length) return '';
    const cells = items.map((a) => `<a class="anim${a === avatar ? ' on' : ''}" href="${escapeHtml(testerUrl(a, lang, ''))}">`
      + `<img src="/icq/avatars/${escapeHtml(a.thumb)}" width="52" height="64" alt="" border="0"><br>`
      + `${escapeHtml(avatarTitle(a, lang))}</a>`);
    return `<h2>${escapeHtml(heading)} (${items.length})</h2>
    <div class="gallery">${cells.join('\n')}</div>`;
  };

  return shell(`
    ${unknown ? `<p class="warn">${escapeHtml(t.tstUnknown)}</p>` : ''}
    <p>${escapeHtml(t.tstLead)}</p>
    <table cellpadding="0" cellspacing="0" border="0" width="100%"><tr>
      <td valign="top" width="${stage.w + 16}">
        <div id="avStage" class="stage" style="width:${stage.w}px;height:${stage.h}px">
          <table width="${stage.w}" height="${stage.h}" cellpadding="0" cellspacing="0" border="0"><tr>
            <td align="center" valign="middle"><img id="avStill" src="/icq/avatars/${escapeHtml(stageImg.src)}"`
              + ` width="${stageImg.w}" height="${stageImg.h}" alt="${escapeHtml(title)}" border="0"></td>
          </tr></table>
        </div>
      </td>
      <td valign="top">
        <h2 style="margin-top:0">${escapeHtml(title)}</h2>
        <p class="dim">${escapeHtml(avatar.author === 'maker' ? t.tstByMaker
          : avatar.author === 'user' ? t.tstByUser : t.tstByIcq)}
          &middot; ${escapeHtml(avatar.file)}${avatar.size ? `, ${escapeHtml(t.picBytes(avatar.size))}` : ''}
          ${avatar.author === 'maker' ? `<br><a href="${escapeHtml(makerUrl(avatarStem(avatar), lang))}">${escapeHtml(t.tstEditInMaker)}</a>` : ''}</p>
        ${labels.length ? `<div id="avMoods"${playable ? '' : ' style="display:none"'}><b>${escapeHtml(t.tstFaces)}</b>
        <div class="moods">${moods}</div></div>` : ''}
        <div id="avNoPlayer" class="soft" style="display:none">${escapeHtml(t.tstNoPlayer)}<br>
          <a href="${escapeHtml(openHere)}" target="_blank">${escapeHtml(openHere)}</a></div>
        <div id="avFailed" class="soft"${playable ? ' style="display:none"' : ''}>${escapeHtml(t.tstPlayerFailed)}</div>
        <p class="hint">${escapeHtml(t.tstHowToSet)}</p>
      </td>
    </tr></table>
    <h2>${escapeHtml(t.tstPictures)}</h2>
    <table class="pics" cellpadding="0" cellspacing="0" border="0"><tr>
      ${pic(avatar.still, stillSize, t.tstStill, t.tstStillNote)}
      ${pic(avatar.large, largeSize, t.tstLarge, t.tstLargeNote)}
      ${pic(avatar.thumb, thumbSize, t.tstThumb, t.tstThumbNote)}
    </tr></table>
    ${group('icq', `${t.tstAll}: ${t.picAnimIcq}`)}
    ${group('user', `${t.tstAll}: ${t.picAnimUser}`)}
    <p><a href="${escapeHtml(makerUrl('', lang))}">${escapeHtml(t.tstMakeOwn)}</a></p>
    ${playable ? testerScript(movies, labels.length ? emotion : '') : ''}`);
}


// ------------------------------------------------------------ avatar constructor
//
// /icq/avatar/maker: an avatar built from our own parts (maker/avatar.js). The
// avatar is its code, c-<version><one digit per part>, and the page only
// changes the code: the movie and its pictures are made from it on request
// (serveMakerFile), so there is nothing to store or moderate. Inside ICQ 6.5
// (opened from the picture page, with the Xtra's id) "Set as my avatar" hands
// the client the movie's address like the Animated tab does; in a browser
// the page shows the address and how to set it.
//
// Every picker works without scripts too: a colour is a link to the page
// with that colour, the other parts are a form. The script only saves the
// reloads, and plays the movie with Ruffle where it can run; the embedded
// IE shows the server's picture of each face instead.

const makerTemplate = fs.readFileSync(path.join(__dirname, 'pages', 'maker.html'), 'utf8');

function makerUrl(code, lang, extra = '') {
  return `/icq/avatar/maker?${code ? `code=${encodeURIComponent(code)}&` : ''}lang=${encodeURIComponent(lang)}${extra}`;
}

// The parameters a request asks for: ?code= first, then any single part
// (?hair=3) over it; anything out of range is ignored.
function makerParams(url) {
  const params = { ...(maker.parseCode(String(url.searchParams.get('code') || '').toLowerCase()) || maker.DEFAULTS) };
  for (const f of maker.FIELDS) {
    const v = url.searchParams.get(f.key);
    if (v !== null && /^\d{1,2}$/.test(v) && Number(v) < f.count) params[f.key] = Number(v);
  }
  return params;
}

// The rows of pickers: a part and its colour share a row.
const MAKER_ROWS = [['head', 'skin'], ['hair', 'hairColor'], ['eyes', 'eyeColor'], ['mouth', 'cheeks'],
  ['hat', 'hatColor'], ['shirt'], ['bg', 'bgColor']];

// The Xtra's instance id, passed on so the page can reach the client.
const XTRA_ID = /^[A-Za-z0-9{}_.-]{1,80}$/;

function makerPickers(params, lang, idParam, embed = false) {
  const field = (key) => maker.FIELDS.find((f) => f.key === key);
  const name = (f) => f.name[lang] || f.name.en;
  const hidden = [`<input type="hidden" name="lang" value="${escapeHtml(lang)}">`];
  if (idParam) hidden.push(`<input type="hidden" name="id" value="${escapeHtml(idParam)}">`);
  if (embed) hidden.push('<input type="hidden" name="embed" value="1">');
  const extra = (idParam ? `&id=${encodeURIComponent(idParam)}` : '') + (embed ? '&embed=1' : '');
  const rows = MAKER_ROWS.map((keys) => {
    const cells = keys.map((key) => {
      const f = field(key);
      if (f.colors) {
        hidden.push(`<input type="hidden" name="${f.key}" value="${params[f.key]}">`);
        return f.colors.map((c, i) => {
          const href = makerUrl(maker.encode({ ...params, [f.key]: i }), lang, extra);
          return `<a href="${escapeHtml(href)}" id="sw-${f.key}-${i}" class="sw${i === params[f.key] ? ' on' : ''}"`
            + ` style="background:${c}" title="${escapeHtml(name(f))}" onclick="return mkSet('${f.key}', ${i});">&nbsp;</a>`;
        }).join('');
      }
      const options = f.options.map((o, i) => `<option value="${i}"${i === params[f.key] ? ' selected' : ''}>`
        + `${escapeHtml(o[lang] || o.en)}</option>`).join('');
      return `<select name="${f.key}" id="mk-${f.key}" title="${escapeHtml(name(f))}"`
        + ` onchange="mkSet('${f.key}', this.selectedIndex);">${options}</select>`;
    });
    return `<tr><td>${escapeHtml(name(field(keys[0])))}</td><td>${cells.join(' ')}</td></tr>`;
  });
  return `<form id="mkForm" method="get" action="/icq/avatar/maker">${hidden.join('')}
    <table class="pick" cellpadding="0" cellspacing="0" border="0">${rows.join('')}</table>
    <noscript><input type="submit" value="${escapeHtml(dict(lang).mkShow)}"></noscript></form>`;
}

// The constructor in a frame of the picture page, inside the client: no
// frame of its own, no plugin, no address box (see avatar.html).
const MAKER_FRAME_H = 330;
const PLUGIN_OBJECT = `<!-- The Xtraz plugin object, the way back into the client (see avatar.html). -->
<OBJECT CLASSID="clsid:8D18DFF4-0943-4347-8BCA-0C57033F6820" id="plugin" width="0" height="0">
</OBJECT>`;

function makerPage(u, req, url) {
  const t = u.t;
  const lang = u.lang;
  const embed = url.searchParams.get('embed') === '1';
  const params = makerParams(url);
  const code = maker.encode(params);
  const askedMood = url.searchParams.get('emotion') || '';
  const emotion = maker.EMOTIONS.includes(askedMood) ? askedMood : 'stam';
  const idParam = XTRA_ID.test(url.searchParams.get('id') || '') ? url.searchParams.get('id') : '';
  const extra = (idParam ? `&id=${encodeURIComponent(idParam)}` : '') + (embed ? '&embed=1' : '');
  const strings = {};
  for (const k of Object.keys(t)) if (k.startsWith('mk') && typeof t[k] === 'string') strings[k] = t[k];
  const moodName = (l) => (t.tstMood && t.tstMood[l]) || l;
  const moods = maker.EMOTIONS.map((l) => `<a href="${escapeHtml(makerUrl(code, lang, `${extra}&emotion=${l}`))}"`
    + ` id="mood-${l}" class="mood${l === emotion ? ' on' : ''}" onclick="return mkMood('${l}');">`
    + `${escapeHtml(moodName(l))}</a>`).join('');
  const fields = {
    version: code[2],
    list: maker.FIELDS.map((f) => ({ key: f.key, count: f.count })),
  };
  const largeSrc = `/icq/avatars/${code}-large.png${emotion === 'stam' ? '' : `?emotion=${emotion}`}`;
  return makerTemplate
    .replace('{{STYLE}}', () => SHARED_STYLE)
    .replace('{{HEADER}}', () => (embed ? '' : header(escapeHtml(t.mkTitle), escapeHtml(t.mkSub))))
    .replace('{{FOOTER}}', () => (embed ? '' : footer({ langs: langSwitch(lang, u.selfUrl) })))
    .replace('{{PLUGIN_OBJECT}}', () => (embed ? '' : PLUGIN_OBJECT))
    .replace('{{EMBED}}', () => (embed ? 'true' : 'false'))
    .replace('{{BODY_CLASS}}', () => (embed ? ' embed' : ''))
    .replace('{{BACK_TEXT}}', () => escapeHtml(embed ? t.mkBackShort : t.mkBack))
    .replace('{{PICKERS}}', () => makerPickers(params, lang, idParam, embed))
    .replace('{{MOODS}}', () => `<span id="mkMoodList">${moods}</span>`)
    .replace('{{STRINGS}}', () => scriptJson(strings))
    .replace('{{FIELDS}}', () => scriptJson(fields))
    .replace('{{STATE}}', () => scriptJson(params))
    .replace('{{EMOTION}}', () => scriptJson(emotion))
    .replace('{{AVATAR_BASE}}', () => scriptJson(`${plainBase(req)}/icq/avatars/`))
    .replace('{{RUFFLE_SRC}}', () => scriptJson(ruffleFiles.has('ruffle.js') ? `/icq/ruffle/ruffle.js?v=${ruffleTag}` : ''))
    .replace('{{RUFFLE_CONFIG}}', () => scriptJson(TESTER_RUFFLE_CONFIG))
    .replace(/\{\{LARGE_W\}\}/g, () => String(maker.LARGE.w))
    .replace(/\{\{LARGE_H\}\}/g, () => String(maker.LARGE.h))
    .replace('{{STAGE_TD}}', () => String(maker.LARGE.w + 12))
    .replace('{{LARGE_SRC}}', () => escapeHtml(largeSrc))
    .replace('{{TRY_URL}}', () => escapeHtml(`/icq/avatar/tester?name=${code}&lang=${lang}`))
    .replace('{{ADDRESS}}', () => escapeHtml(`${plainBase(req)}/icq/avatars/${code}.swf`))
    .replace(/\{\{LANG\}\}/g, () => lang)
    .replace(/\{\{(mk[A-Za-z]+)\}\}/g, (m, k) => (typeof t[k] === 'string' ? escapeHtml(t[k]) : m));
}

// Pictures on their way from the page to the client, held in memory for a few
// minutes each. A picture is wanted exactly once - ICQ fetches the address it
// was handed, uploads the image to the server under the user's name, and never
// asks again - so nothing is written to disk.
//
// An upload the server can read is kept as its working copy only (upright,
// at most 800 pixels long; the original is dropped at once), for the editor:
// the page shows it, the user moves and zooms it, and the icon is cut from it
// by the chosen zoom and centre when the page asks for it
// (/icq/avatar/file/<id>?z=&u=&v=). One it cannot read goes through as it
// came, as before, with no editor.
//
// The ids are random, nothing lists them, and the whole store is capped by
// count and bytes, the oldest going first.
const pictures = new Map();
const PICTURE_TTL = 15 * 60 * 1000;
const PICTURE_COUNT_MAX = 64;
const PICTURE_BYTES_MAX = 32 * 1024 * 1024;
// The icons cut from one upload, kept in case the client asks again.
const PICTURE_RENDERS_MAX = 8;
const PICTURE_ID = /^[0-9a-f]{16}$/;
// Generous: a photograph straight from a phone is a normal thing to pick, and
// it is scaled down here anyway. The limit only guards against someone sending
// something absurd.
const PICTURE_MAX = 16 * 1024 * 1024;

function pictureBytes(item) {
  let n = (item.work || item.body).length;
  if (item.renders) for (const b of item.renders.values()) n += b.length;
  return n;
}

// Keeps a picture, dropping the oldest ones over the caps.
function keepPicture(id, item) {
  pictures.set(id, item);
  let total = 0;
  for (const it of pictures.values()) total += pictureBytes(it);
  for (const [old, it] of pictures) {
    if (pictures.size <= PICTURE_COUNT_MAX && total <= PICTURE_BYTES_MAX) break;
    if (old === id) continue;
    pictures.delete(old);
    total -= pictureBytes(it);
  }
  setTimeout(() => { if (pictures.get(id) === item) pictures.delete(id); }, PICTURE_TTL).unref();
}

// The address a request reached us at, for links the client is sent back to
// follow: the Xtraz entries, the uploaded picture. nginx serves these pages
// over HTTPS on 8102 and says so in X-Forwarded-Proto; requests straight to
// 8101 are plain HTTP. The Host header carries the port either way.
function selfBase(req) {
  const proto = req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  return `${proto}://${req.headers.host || ''}`;
}

// The same host on this service's own plain HTTP port, whichever way the
// request arrived.
function plainBase(req) {
  const host = String(req.headers.host || '').replace(/:\d+$/, '');
  return `http://${host}:${PORT}`;
}

function uploadPicture(ctx) {
  const t = ctx.u.t;
  const type = ctx.req.headers['content-type'] || '';
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(type);
  if (!boundary) { send(ctx.res, 400, uploadReply('', t.picErrNotForm, '')); return; }
  const mark = Buffer.from('--' + (boundary[1] || boundary[2]).trim());

  const chunks = [];
  let size = 0;
  let stopped = false;
  ctx.req.on('data', (c) => {
    size += c.length;
    // Keep reading to the end even when it is too much: cutting the connection
    // here leaves the page with no answer at all, waiting forever.
    if (size > PICTURE_MAX) { stopped = true; chunks.length = 0; return; }
    chunks.push(c);
  });
  ctx.req.on('end', () => {
    if (stopped) {
      send(ctx.res, 200, uploadReply('', t.picErrTooLarge, ''));
      return;
    }
    const body = Buffer.concat(chunks);
    // One part is expected. Its headers end at the first blank line, and the
    // data runs up to the next boundary, minus the CRLF that precedes it.
    const start = body.indexOf(mark);
    const headEnd = body.indexOf(String.fromCharCode(13, 10, 13, 10), start);
    const next = body.indexOf(mark, headEnd);
    if (start < 0 || headEnd < 0 || next < 0) {
      send(ctx.res, 200, uploadReply('', t.picErrMalformed, ''));
      return;
    }
    const head = body.slice(start, headEnd).toString('latin1');
    const kind = new RegExp('content-type:\\s*([^\\r\\n]+)', 'i').exec(head);
    const data = body.slice(headEnd + 4, next - 2);
    if (!data.length) { send(ctx.res, 200, uploadReply('', t.picErrEmpty, '')); return; }

    // Which engine the page runs in (the embedded IE's document mode), for
    // the log: the editor is written for the oldest it may be.
    const mode = String(ctx.url.searchParams.get('dm') || '').replace(/[^\w .;:()/-]/g, '').slice(0, 20);
    console.log(`picture upload: ${data.length} bytes, document mode ${mode || '-'}, `
      + `ua=${String(ctx.req.headers['user-agent'] || '-').slice(0, 80)}`);
    const id = crypto.randomBytes(8).toString('hex');
    const self = selfBase(ctx.req);
    const work = workingCopy(data);
    if (work) {
      keepPicture(id, { work: work.body, w: work.w, h: work.h, renders: new Map() });
      const file = `/icq/avatar/file/${id}`;
      send(ctx.res, 200, editReply({
        id, w: work.w, h: work.h,
        work: `${self}/icq/avatar/work/${id}`,
        file: `${self}${file}`,
        clientFile: `${plainBase(ctx.req)}${file}`,
      }));
      return;
    }
    const small = shrink(data);
    keepPicture(id, small.body === data
      ? { body: data, type: (kind ? kind[1].trim() : 'image/jpeg') }
      : { body: small.body, type: pictureType(small.body) });
    // Two addresses for the same picture. The page shows it by the scheme the
    // page itself came in on. The client is handed a plain HTTP one: ICQ 6.5
    // downloads the picture with a loader of its own that does not speak HTTPS
    // at all - it drops an https:// address without even connecting - while
    // everything else it opens, this page included, works over HTTPS.
    const file = `/icq/avatar/file/${id}`;
    const note = small.body === data ? '' : t.picReduced(t.picBytes(data.length), t.picBytes(small.body.length));
    send(ctx.res, 200, uploadReply(`${self}${file}`, '', note, `${plainBase(ctx.req)}${file}`));
  });
}

// Fits the picture to the client's frame and scales it down. A buddy icon travels with
// presence and is downloaded by every contact, so a photograph straight from a
// phone has no business going through as it is. Done by a small Python script
// next to this file, since the only image library here is the one Python has;
// without it the picture goes through untouched.
// The script hands back a JPEG, but a file it could not decode goes through
// as it came, so the type is read off the first bytes rather than assumed.
function pictureType(body) {
  return body.length > 8 && body[0] === 0x89 && body[1] === 0x50
    ? 'image/png' : 'image/jpeg';
}

function shrink(data) {
  try {
    const run = child_process.spawnSync('python3',
      [path.join(__dirname, 'shrink-picture.py')],
      { input: data, maxBuffer: 8 * 1024 * 1024 });
    if (run.status !== 0 || !run.stdout || !run.stdout.length) {
      return { body: data };
    }
    if (run.stdout.length >= data.length) { return { body: data }; }
    return { body: run.stdout };
  } catch (e) {
    return { body: data };
  }
}

// The editor's copy of an upload as { body, w, h }, or null when the
// picture cannot be read (or there is no Python with Pillow here).
function workingCopy(data) {
  try {
    const run = child_process.spawnSync('python3',
      [path.join(__dirname, 'shrink-picture.py'), 'work'],
      { input: data, maxBuffer: 8 * 1024 * 1024 });
    if (run.status !== 0 || !run.stdout || !run.stdout.length) return null;
    const size = imageSize(run.stdout);
    if (!size || !size.w || !size.h) return null;
    return { body: run.stdout, w: size.w, h: size.h };
  } catch {
    return null;
  }
}

// The icon cut from a working copy by the editor's zoom and centre, the same
// box the page previewed (pictureCrop), or null.
function cutPicture(item, params) {
  const key = `${params.z}/${params.u}/${params.v}`;
  let body = item.renders.get(key);
  if (body) return body;
  const box = pictureCrop(item.w, item.h, params.z, params.u, params.v, ICON_W, ICON_H);
  try {
    const run = child_process.spawnSync('python3',
      [path.join(__dirname, 'shrink-picture.py'), 'crop',
        ...[box.left, box.top, box.left + box.width, box.top + box.height].map((v) => v.toFixed(4))],
      { input: item.work, maxBuffer: 8 * 1024 * 1024 });
    if (run.status !== 0 || !run.stdout || !run.stdout.length) return null;
    body = run.stdout;
  } catch {
    return null;
  }
  if (item.renders.size >= PICTURE_RENDERS_MAX) item.renders.delete(item.renders.keys().next().value);
  item.renders.set(key, body);
  return body;
}

// GET /icq/avatar/file/<id>[?z=&u=&v=]: the icon of an upload. For one the
// editor has, the zoom and centre choose the part (all three, in range, or a
// 400); without them it is the middle of the picture at zoom 1, the crop the
// page always made. One that went through as it came is handed out as it is.
function servePictureFile(ctx) {
  const id = ctx.path.split('/').pop();
  const item = PICTURE_ID.test(id) ? pictures.get(id) : null;
  const plain = (status, headers = {}) => { ctx.res.writeHead(status, { 'content-length': 0, ...headers }); ctx.res.end(); };
  if (!item || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) { plain(404); return; }
  let body = item.body;
  let type = item.type;
  if (item.work) {
    const q = ctx.url.searchParams;
    const any = q.has('z') || q.has('u') || q.has('v');
    const params = any ? parseCropParams(q.get('z'), q.get('u'), q.get('v')) : { z: 1, u: 0.5, v: 0.5 };
    if (!params) { plain(400); return; }
    body = cutPicture(item, params);
    type = 'image/jpeg';
    if (!body) { plain(500); return; }
  }
  ctx.res.writeHead(200, { 'content-type': type, 'content-length': body.length, 'cache-control': 'no-store' });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : body);
}

// GET /icq/avatar/work/<id>: the working copy the editor shows.
function serveWorkPicture(ctx) {
  const id = ctx.path.split('/').pop();
  const item = PICTURE_ID.test(id) ? pictures.get(id) : null;
  if (!item || !item.work || (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD')) {
    ctx.res.writeHead(404, { 'content-length': 0 });
    ctx.res.end();
    return;
  }
  ctx.res.writeHead(200, { 'content-type': 'image/jpeg', 'content-length': item.work.length, 'cache-control': 'no-store' });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : item.work);
}

// The reply for an upload the editor takes: the working copy, its size, and
// the icon's address (the page adds the zoom and centre to it).
function editReply(edit) {
  return `<!DOCTYPE html><html><body><script>
    parent.uploaded(${scriptJson({ edit, error: '', note: '' })});
  </script></body></html>`;
}

// The reply lands in a hidden frame; it tells the page the address to hand to
// the client, or what went wrong.
function uploadReply(url, error, note, clientUrl) {
  const payload = JSON.stringify({ url, error, note: note || '', clientUrl: clientUrl || url });
  return `<!DOCTYPE html><html><body><script>
    parent.uploaded(${payload});
  </script></body></html>`;
}

const ACTIONS = {
  avatarpage: (ctx) => send(ctx.res, 200, avatarPage(ctx.u, ctx.req)),

  // Any gallery avatar playing in the browser, with its faces and pictures.
  avatartester: (ctx) => send(ctx.res, 200, testerPage(ctx.u, ctx.req, ctx.url)),

  // The avatar constructor.
  avatarmaker: (ctx) => send(ctx.res, 200, makerPage(ctx.u, ctx.req, ctx.url)),

  // Receives a picture from the page and keeps it just long enough for the
  // client to fetch it. The client does not take image data: SetBartItem is
  // given an address, and ICQ downloads it and uploads it to the server itself.
  avatarupload: (ctx) => uploadPicture(ctx),

  // Hands one back out, cut as the editor chose. Short-lived, so nothing
  // accumulates anywhere.
  avatarfile: (ctx) => servePictureFile(ctx),

  // The working copy the picture editor shows.
  avatarwork: (ctx) => serveWorkPicture(ctx),

  drop: (ctx) => { ctx.res.writeHead(404, { 'content-length': 0 }); ctx.res.end(); },

  search: (ctx) => {
    const q = (ctx.url.searchParams.get('q') || '').replace(/^=/, '');
    redirect(ctx.res, expand(ctx.route.target, { ...ctx.vars, q: encodeURIComponent(q) }));
  },

  redirect: (ctx) => {
    if (!config.registerBase && /registerBase/.test(ctx.route.target || '')) {
      send(ctx.res, 200, stubPage(ctx.path, ctx.u));
      return;
    }
    redirect(ctx.res, expand(ctx.route.target, ctx.vars));
  },

  today: async (ctx) => send(ctx.res, 200, await todayPage(ctx.u)),

  // The information pages. /icq/terms arrives from ICQ 6.5 with ?lspid= and a
  // lang= of its own; neither matters here, and a lang= we do not know simply
  // falls back to Accept-Language.
  help: (ctx) => send(ctx.res, 200, helpPage(ctx.u)),
  about: (ctx) => send(ctx.res, 200, aboutPage(ctx.u)),
  legal: (ctx) => send(ctx.res, 200, legalPage(ctx.u)),
  terms: (ctx) => send(ctx.res, 200, termsPage(ctx.u)),
  download: (ctx) => send(ctx.res, 200, downloadPage(ctx.u)),

  center: async (ctx) => send(
    ctx.res, 200,
    await centerPage((ctx.url.searchParams.get('uin')
      || ctx.url.searchParams.get('Uin') || '').trim(), ctx.path, ctx.u),
  ),

  howto: async (ctx) => send(
    ctx.res, 200,
    await howtoPage((ctx.url.searchParams.get('uin') || '').trim(), ctx.path, ctx.u),
  ),

  welcome: async (ctx) => send(
    ctx.res, 200,
    await welcomePage((ctx.url.searchParams.get('uin') || '').trim(), ctx.path, ctx.u),
  ),

  map: async (ctx) => redirect(ctx.res, mapUrl(ctx.req.url)),

  // A user's static picture for the card: /icq/whitepages/icon?icq=<uin>.
  whitepagesicon: (ctx) => serveCardIcon(ctx),

  whitepages: async (ctx) => send(
    ctx.res, 200,
    await whitepagesPage((ctx.url.searchParams.get('icq') || '').trim(), ctx.path, ctx.u),
  ),

  pager: async (ctx) => {
    if (ctx.req.method === 'POST') {
      send(ctx.res, 200, await pagerSend(await readBody(ctx.req), ctx.ip, ctx.path, ctx.u));
      return;
    }
    const uin = (ctx.url.searchParams.get('Uin') || ctx.url.searchParams.get('uin') || '').trim();
    // Show who the message goes to: writing blindly to a number is awkward.
    let card = null;
    if (/^\d{4,10}$/.test(uin)) {
      const c = await userCard(uin, ctx.u.t, ctx.u.lang);
      card = c.exists ? c.html
        : `<p style="${FONT}"><font color="#a06000">`
          + ctx.u.t.notRegistered(escapeHtml(uin)) + '</font></p>';
    }
    send(ctx.res, 200, pagerForm(uin, '', '', ctx.path, card, ctx.u));
  },

  hostsfile: (ctx) => sendText(ctx.res, hostsFileText(ctx.url.searchParams.get('ip') || '')),

  // The Xtraz gallery is fed by a list, not by a page: ICQ 6 reads XtrazListUrl
  // from XtraConfig.xml and fills its own window from it. Without the list the
  // window only reports "a problem opening Xtra", so a stub page cannot help
  // there. We serve a list of one item that opens our own page inside the
  // client - the schema is the original one (xtrazList / groups / xtraz).
  // Before parsing the list, ICQ 6 fetches a DTD next to the localized strings
  // (XtrazStringsUrl + /<lang>/xtraz_list.dtd). It declares the entities the
  // original list used for translated names; ours needs none, but the fetch has
  // to succeed - on a 404 the parse fails and the window only reports "a problem
  // opening Xtra".
  xtrazdtd: (ctx) => {
    const body = Buffer.from('<!-- no entities needed for this list -->', 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'application/xml-dtd',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  // An .xtra is not a package but an HTML document: it embeds the Xtraz plugin
  // object (ISBDhtmlXtraWrapper from MISB.dll), declares a VBScript
  // plugin_OnInitData handler and puts the visible part in a frame. A plain page
  // is fetched but rejected, which is why the gallery window kept reporting a
  // problem. This is the same wrapper with our page inside.
  xtrapage: (ctx) => {
    const self = selfBase(ctx.req);
    const html = `<html>
<head>
<title>Xtraz</title>
<OBJECT CLASSID="clsid:8D18DFF4-0943-4347-8BCA-0C57033F6820" id="plugin">OBJECT NOT SET</OBJECT>
<script language="VBScript">
	Sub plugin_OnInitData ( owner, sequence, buddies, initialData )
	End Sub
</script>
</head>
<frameset rows="*" cols="*" frameborder="0" border="0">
	<frame name="win" id="win" scrolling="auto" src="${self}/icq/stub/xtraz.html?compact=1">
</frameset>
</html>`;
    const body = Buffer.from(html, 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  xtrazlist: (ctx) => {
    // A short list: the welcome window, and the two picture entries. The client
    // draws its Xtraz buttons from this list, so an empty one is what removes
    // them - but some of the interface opens entries from it by id and breaks
    // without them. "Welcome to ICQ" in the main menu is one; clicking one's own
    // picture in the profile is another, and with no "avatar" entry it sends the
    // browser to an error page on icq.com. Those keep an entry each. The client draws its Xtraz
    // buttons from this list, so an empty one is what removes them - but the
    // "Welcome to ICQ" item of the main menu opens an entry from it too, and
    // went dead with the rest. That entry is given back, pointed at our own
    // welcome page.
    //
    // To offer the old entries again, serve `xtrazList` here: it is the
    // archived list, kept next to this file.
    const self = selfBase(ctx.req);
    const body = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<xtrazList majorVer="1" minorVer="0" date="06-10-09">
  <groups/>
  <xtraz>
    <xtra id="icq_welcome" version="1" type="dhtml" resizable="true"
          width="700" minWidth="520" height="430" minHeight="320"
          name="Welcome" desc="Welcome" url="${self}/icq/welcome"/>
    <xtra id="avatar" version="1" type="dhtml" resizable="true"
          width="540" height="480" name="Picture" desc="Picture"
          url="${self}/icq/avatar"/>
    <xtra id="photo_cropper" version="1" type="dhtml" resizable="true"
          width="420" height="300" name="Xtraz" desc="Xtraz"
          url="${self}/icq/stub/xtraz.html?compact=1"/>
  </xtraz>
</xtrazList>
`, 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'text/xml; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  // A tZer movie or thumbnail, by its exact file name: /icq/tzers/kisses.swf.
  // Anything else under /icq/tzers/ is a 404, as the dead ICQ.com one was.
  tzer: (ctx) => serveFolderFile(ctx, /^\/icq\/tzers\//i, tzerFiles),

  // A download of /icq/download by its exact name: /icq/files/icq-65-patch.zip.
  files: (ctx) => serveFolderFile(ctx, /^\/icq\/files\//i, downloadFiles),

  // An animated avatar or its thumbnail, the same way: /icq/avatars/pirate.swf.
  // With ?emotion=stam (or another of its labels) the movie comes with its
  // face on that mood already, for the user card's player (see moodMovie).
  avatarfiles: (ctx) => {
    if (/^\/icq\/avatars\/list\.json$/i.test(ctx.path)) return serveAvatarListJson(ctx);
    const name = ctx.path.replace(/^\/icq\/avatars\//i, '').toLowerCase();
    if (maker.isName(name) && !ctx.url.searchParams.has('emotion')) return serveMakerFile(ctx, name);
    return ctx.url.searchParams.has('emotion')
      ? serveMoodMovie(ctx)
      : serveFolderFile(ctx, /^\/icq\/avatars\//i, avatarFiles);
  },

  // Ruffle's web build, for the user card: /icq/ruffle/ruffle.js and the
  // files it loads itself.
  ruffle: (ctx) => serveRuffle(ctx),

  // Miranda NG's PluginUpdater: /miranda/stable/x32/hashes.zip and the
  // packages it lists, ours and the relayed upstream ones
  // (miranda-updates.js).
  miranda: (ctx) => mirandaMirror.handle(ctx.req, ctx.res, ctx.path.replace(/^\/miranda\/stable/i, '')),

  // The list the original avatar gallery loaded first
  // (xtraz.icq.com/xtraz2/products/avatar/xml/avatarsGalery.php), in its 2007
  // form, with our movies in the Animated_Devils category it kept empty. In
  // case the client or an old Xtra still asks for it.
  avatargallery: (ctx) => {
    const base = `${plainBase(ctx.req)}/icq/avatars/`;
    const esc = (s) => escapeHtml(s);
    const sub = (author, name) => {
      const imgs = avatarList.filter((a) => a.author === author).map((a) => `
      <img>
        <url>${esc(base + a.file)}</url>
        <thumb_url>${esc(base + a.thumb)}</thumb_url>
      </img>`).join('');
      return `
    <sub name="${name}">${imgs}
    </sub>`;
    };
    const body = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<avatar>
  <category name="Animated_Devils" web="0" id="">
    <img_sizes>
      <width>52</width>
      <height>64</height>
    </img_sizes>${sub('icq', 'ICQ_Devils')}${sub('user', 'User_Created')}
  </category>
</avatar>
`, 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'text/xml; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  // The ICQ 6 banner strip: the client expects an image, not a page. Serving a
  // transparent dot leaves the strip empty instead of showing a broken image.
  blank: (ctx) => {
    const gif = Buffer.from(
      'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    ctx.res.writeHead(200, {
      'content-type': 'image/gif',
      'content-length': gif.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(gif);
  },

  stub: (ctx) => send(
    ctx.res, 200,
    // compact=1 comes from the pages the client draws in its own small window,
    // such as the Xtraz gallery: there the roomy layout does not fit.
    stubPage(ctx.path.split('/').filter(Boolean).pop() || ctx.host, ctx.u,
      ctx.url.searchParams.get('compact') === '1'),
  ),
};

// ---------------------------------------------------------------------- routing

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 64 * 1024) { reject(new Error('request too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function route(req, res) {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  const url = new URL(req.url, 'http://placeholder');
  const chosen = pickRoute(host, url.pathname + url.search);

  // Language: an explicit ?lang= wins, otherwise Accept-Language decides.
  const asked = (url.searchParams.get('lang') || '').toLowerCase();
  const lang = LANGS.includes(asked)
    ? asked
    : pickLang(req.headers['accept-language']);
  // The address of this page for the switcher links, with the old lang removed.
  const selfParams = new URLSearchParams(url.search);
  selfParams.delete('lang');
  const selfQuery = selfParams.toString();
  const u = {
    lang,
    t: dict(lang),
    selfUrl: url.pathname + (selfQuery ? `?${selfQuery}` : ''),
  };

  if (!chosen) {
    // A config without a catch-all at the end: say so instead of a silent 404.
    send(res, 200, stubPage(host, u));
    return;
  }

  const ctx = {
    req, res, url, host, u,
    path: url.pathname,
    route: chosen,
    ip: req.socket.remoteAddress || '?',
    vars: { registerBase: config.registerBase, host, path: url.pathname },
  };
  await ACTIONS[chosen.action](ctx);
}

// The upstream is the stable channel of Miranda NG; our packages are made by
// tools/miranda-icq/make-update-packages.py and mounted into MIRANDA_PACKAGES.
const mirandaMirror = createMirror({
  upstream: process.env.MIRANDA_UPSTREAM || 'https://miranda-ng.org/distr/stable',
  dir: process.env.MIRANDA_PACKAGES || path.join(__dirname, 'miranda'),
});

config = loadConfig();
loadTopics();
loadTzers();
loadDownloads();
loadAvatars();
loadRuffle();

// SIGHUP reloads the config: a host can be added without restarting the service.
// If the new file is broken we keep the old one instead of dying.
process.on('SIGHUP', () => {
  try {
    config = loadConfig();
    loadTopics();
    loadTzers();
    loadDownloads();
    loadAvatars();
    loadRuffle();
    mirandaMirror.load();
    console.log(`config reloaded: ${config.routes.length} routes, ${tzerFiles.size} tZer files, ${downloadFiles.size} downloads, `
      + `${avatarList.length} animated avatars`);
  } catch (err) {
    console.error(`config not reloaded, keeping the old one: ${err.message}`);
  }
});

// Request log. Clients ask for things no documentation lists, and the only way
// to learn what a particular window needs is to watch what it fetches.
const LOG_REQUESTS = process.env.LOG_REQUESTS !== '0';

const server = http.createServer((req, res) => {
  if (LOG_REQUESTS) {
    console.log(`${req.method} ${req.headers.host || '-'}${req.url} `
      + `ua=${(req.headers['user-agent'] || '-').slice(0, 40)}`);
  }
  if (serveAsset(req, res)) return;
  route(req, res).catch((err) => {
    const t = dict(pickLang(req.headers['accept-language']));
    send(res, 500, page(t.errorTitle, `<p>${escapeHtml(err.message)}</p>`));
  });
});

server.listen(PORT, BIND, () => {
  console.log(`oscar-legacy-web listening on ${BIND}:${PORT}`);
  if (process.env.MIRANDA_WARM !== '0') mirandaMirror.warm();
  console.log(`config ${CONFIG_PATH}: ${config.routes.length} routes, `
    + `management API ${config.mgmtApi}`);
});
