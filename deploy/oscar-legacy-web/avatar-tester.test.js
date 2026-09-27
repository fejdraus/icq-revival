// Tests for the avatar tester, /icq/avatar/tester: node --test "deploy/oscar-legacy-web/*.test.js"
//
// server.js is a service, not a module, so it is run as one: a copy of this
// folder with the shared look next to it (as the image has it), on a free
// port, with the management API pointed nowhere.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');

const HERE = __dirname;
const SHARED = path.join(HERE, '..', 'shared');
const AVATARS = JSON.parse(fs.readFileSync(path.join(HERE, 'avatars', 'avatars.json'), 'utf8')).avatars;

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

// A copy of the service in a temporary folder. withRuffle=false leaves out
// the player, as a machine without it would be.
function stage(withRuffle) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'legacy-web-'));
  for (const f of ['server.js', 'miranda-updates.js', 'services.json', 'topics.json', 'xtrazlist.xml']) {
    fs.copyFileSync(path.join(HERE, f), path.join(dir, f));
  }
  fs.cpSync(path.join(HERE, 'pages'), path.join(dir, 'pages'), { recursive: true });
  fs.cpSync(path.join(HERE, 'avatars'), path.join(dir, 'avatars'), { recursive: true });
  for (const f of ['ui.js', 'flower.png']) fs.copyFileSync(path.join(SHARED, f), path.join(dir, f));
  if (withRuffle) {
    // Only the loader: the page decides by it whether a player is there.
    fs.mkdirSync(path.join(dir, 'ruffle'));
    fs.copyFileSync(path.join(HERE, 'ruffle', 'ruffle.js'), path.join(dir, 'ruffle', 'ruffle.js'));
  }
  return dir;
}

async function start(withRuffle) {
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
  await new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (c) => { out += c; if (out.includes('listening')) resolve(); });
    child.on('exit', (code) => reject(new Error(`server exited with ${code}`)));
  });
  return {
    base: `http://127.0.0.1:${port}`,
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

test('avatar tester with the player', async (t) => {
  const srv = await start(true);
  t.after(srv.stop);
  const pirate = AVATARS.find((a) => a.file === 'pirate.swf');

  await t.test('one face button per label, idle first, each a link that works without scripts', async () => {
    const { status, text } = await get(srv.base, '/icq/avatar/tester?name=pirate&lang=en');
    assert.equal(status, 200);
    assert.deepEqual(ids(text, /id="mood-([a-z0-9_]+)"/g), pirate.labels);
    assert.deepEqual(ids(text, /id="mood-([a-z0-9_]+)" class="mood on"/g), ['stam']);
    assert.match(text, /href="\/icq\/avatar\/tester\?name=pirate&amp;emotion=smile&amp;lang=en"/);
    assert.match(text, /onclick="return avMood\(&quot;smile&quot;\);"/);
    assert.match(text, /\/icq\/ruffle\/ruffle\.js\?v=/);
  });

  await t.test('the still, large and thumbnail pictures are shown and served', async () => {
    const { text } = await get(srv.base, '/icq/avatar/tester?name=pirate');
    for (const f of [pirate.still, pirate.large, pirate.thumb]) {
      assert.ok(text.includes(`/icq/avatars/${f}`), f);
      assert.equal((await get(srv.base, `/icq/avatars/${f}`)).status, 200, f);
    }
    // The stage starts with the large still, until the movie plays over it.
    assert.match(text, new RegExp(`id="avStill" src="/icq/avatars/${pirate.large}"`));
  });

  await t.test('every face the script loads is a movie the server has', async () => {
    const { text } = await get(srv.base, '/icq/avatar/tester?name=pirate');
    const movies = JSON.parse(/var MOVIES = (\{[^\n]*\});/.exec(text)[1]);
    assert.deepEqual(Object.keys(movies), pirate.labels);
    for (const url of Object.values(movies)) {
      const res = await fetch(srv.base + url);
      assert.equal(res.status, 200, url);
      assert.equal(res.headers.get('content-type'), 'application/x-shockwave-flash');
      await res.arrayBuffer();
    }
  });

  await t.test('?emotion= picks the face; an unknown one falls back to idle', async () => {
    let { text } = await get(srv.base, '/icq/avatar/tester?name=pirate&emotion=love');
    assert.deepEqual(ids(text, /id="mood-([a-z0-9_]+)" class="mood on"/g), ['love']);
    ({ text } = await get(srv.base, '/icq/avatar/tester?name=pirate&emotion=%3Cscript%3E'));
    assert.deepEqual(ids(text, /id="mood-([a-z0-9_]+)" class="mood on"/g), ['stam']);
    assert.ok(!text.includes('<script>'));
  });

  await t.test('an unknown or odd name shows the first avatar with a note', async () => {
    for (const name of ['nope', '..%2Fserver', 'pirate.swf%00', '%3Cb%3E']) {
      const { status, text } = await get(srv.base, `/icq/avatar/tester?name=${name}&lang=en`);
      assert.equal(status, 200, name);
      assert.match(text, /There is no such avatar here/, name);
      assert.match(text, new RegExp(`<h2 style="margin-top:0">${AVATARS[0].title.en}</h2>`), name);
    }
    // .swf on the name is fine, and so is no name at all.
    assert.doesNotMatch((await get(srv.base, '/icq/avatar/tester?name=Pirate.swf')).text, /no such avatar/);
    assert.doesNotMatch((await get(srv.base, '/icq/avatar/tester')).text, /no such avatar/);
  });

  await t.test('every avatar of the gallery is listed and opens', async () => {
    const { text } = await get(srv.base, '/icq/avatar/tester?lang=uk');
    for (const a of AVATARS) {
      const stem = a.file.replace(/\.swf$/, '');
      assert.ok(text.includes(`href="/icq/avatar/tester?name=${stem}&amp;lang=uk"`), stem);
      assert.equal((await get(srv.base, `/icq/avatar/tester?name=${stem}`)).status, 200, stem);
    }
    assert.match(text, /Перегляд аватарів/);
  });

  await t.test('the scripts stay plain enough for the embedded IE', async () => {
    const { text } = await get(srv.base, '/icq/avatar/tester?name=pirate');
    const code = scripts(text).join('\n');
    assert.ok(code.length > 0);
    // No ES2015 syntax: arrow functions, let/const, template strings, spread.
    assert.doesNotMatch(code, /=>|\blet\s|\bconst\s|`|\.\.\./);
    // Where there is no WebAssembly the note is shown and nothing is loaded.
    assert.match(code, /typeof WebAssembly != 'object'[\s\S]*?note\('avNoPlayer'\)/);
    assert.match(text, /id="avNoPlayer" class="soft" style="display:none"/);
  });

  await t.test('the picture page links each chosen avatar and the whole tester', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    assert.match(text, /id="animTry" href="\/icq\/avatar\/tester\?lang=en"/);
    assert.match(text, /href="\/icq\/avatar\/tester\?lang=en" target="_blank">Try every avatar in the tester/);
    assert.match(text, /'\/icq\/avatar\/tester\?name='/);
  });

  await t.test('the paths next to the tester are unchanged', async () => {
    assert.equal((await get(srv.base, '/icq/avatars/pirate.swf')).type, 'application/x-shockwave-flash');
    assert.match((await get(srv.base, '/icq/avatar?lang=en')).text, /Your picture/);
  });
});

test('avatar tester without the player', async (t) => {
  const srv = await start(false);
  t.after(srv.stop);
  const { status, text } = await get(srv.base, '/icq/avatar/tester?name=kitty&lang=en');
  assert.equal(status, 200);
  // The still stays, the note says why, and the buttons are neither shown nor
  // wired to a script that is not there.
  assert.match(text, /id="avFailed" class="soft">The player could not start here/);
  assert.match(text, /id="avMoods" style="display:none"/);
  assert.doesNotMatch(text, /onclick="return avMood/);
  assert.equal(scripts(text).length, 0);
});
