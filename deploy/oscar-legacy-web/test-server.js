// The legacy web as the tests run it (not a test itself).
//
// server.js is a service, not a module, so it is run as one: a copy of this
// folder with the shared look next to it (as the image has it), on a free
// port, with the management API pointed nowhere.
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const HERE = __dirname;
const SHARED = path.join(HERE, '..', 'shared');

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

// A copy of the service in a temporary folder: its code, data and pages.
// withRuffle=false leaves out the player, as a machine without it would be.
function stage(withRuffle) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'legacy-web-'));
  for (const f of fs.readdirSync(HERE)) {
    if (/\.test\.js$/.test(f) || !/\.(js|json|py|xml)$/.test(f)) continue;
    fs.copyFileSync(path.join(HERE, f), path.join(dir, f));
  }
  for (const d of ['pages', 'avatars', 'maker']) {
    fs.cpSync(path.join(HERE, d), path.join(dir, d), { recursive: true });
  }
  for (const f of ['ui.js', 'flower.png']) fs.copyFileSync(path.join(SHARED, f), path.join(dir, f));
  if (withRuffle) {
    // Only the loader: the pages decide by it whether a player is there.
    fs.mkdirSync(path.join(dir, 'ruffle'));
    fs.copyFileSync(path.join(HERE, 'ruffle', 'ruffle.js'), path.join(dir, 'ruffle', 'ruffle.js'));
  }
  return dir;
}

async function start(withRuffle = true) {
  const dir = stage(withRuffle);
  const port = await freePort();
  const child = spawn(process.execPath, ['server.js'], {
    cwd: dir,
    env: {
      ...process.env, PORT: String(port), BIND: '127.0.0.1', MIRANDA_WARM: '0', LOG_REQUESTS: '0',
      MGMT_API: 'http://127.0.0.1:1', MIRANDA_PACKAGES: path.join(dir, 'miranda'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const log = [];
  await new Promise((resolve, reject) => {
    child.stdout.on('data', (c) => { log.push(String(c)); if (log.join('').includes('listening')) resolve(); });
    child.stderr.on('data', (c) => log.push(String(c)));
    child.on('exit', (code) => reject(new Error(`server exited with ${code}: ${log.join('')}`)));
  });
  return {
    base: `http://127.0.0.1:${port}`,
    log: () => log.join(''),
    stop: () => new Promise((resolve) => {
      child.on('exit', () => { fs.rmSync(dir, { recursive: true, force: true }); resolve(); });
      child.kill();
    }),
  };
}

const get = async (base, p) => {
  const res = await fetch(base + p);
  return { status: res.status, type: res.headers.get('content-type'), text: await res.text() };
};

// The inline scripts of a page, which the client's embedded IE runs too.
const scripts = (html) => [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
const ids = (html, re) => [...html.matchAll(re)].map((m) => m[1]);

// What the embedded IE (IE 7 standards mode, ES3) cannot parse: arrows,
// let/const, template strings, spread, and trailing commas in literals.
// (Texts may contain "...": a spread is followed by a name.)
const MODERN_JS = /=>|\blet\s|\bconst\s|`|\.\.\.[A-Za-z_$([{]|,\s*[}\]]/;

module.exports = { start, get, scripts, ids, MODERN_JS };
