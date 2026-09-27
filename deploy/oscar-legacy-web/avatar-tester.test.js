// Tests for the avatar tester, /icq/avatar/tester, and the constructor's
// page: node --test "deploy/oscar-legacy-web/*.test.js"
// (The service is run as the image runs it; see test-server.js.)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { start, get, scripts, ids, MODERN_JS } = require('./test-server.js');

const AVATARS = JSON.parse(fs.readFileSync(path.join(__dirname, 'avatars', 'avatars.json'), 'utf8')).avatars;

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
    // No ES2015 syntax, no trailing commas.
    assert.doesNotMatch(code, MODERN_JS);
    // Where there is no WebAssembly the note is shown and nothing is loaded.
    assert.match(code, /typeof WebAssembly != 'object'[\s\S]*?note\('avNoPlayer'\)/);
    assert.match(text, /id="avNoPlayer" class="soft" style="display:none"/);
  });

  await t.test('the picture page links each chosen avatar and the whole tester', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    assert.match(text, /id="animTry" class="outside" href="\/icq\/avatar\/tester\?lang=en"/);
    assert.match(text, /class="outside" href="\/icq\/avatar\/tester\?lang=en" target="_blank">Try every avatar in the tester/);
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

test('avatar constructor', async (t) => {
  const srv = await start(true);
  t.after(srv.stop);
  const maker = require('./maker');
  const code = maker.encode({ ...maker.DEFAULTS, hat: 3, bg: 4 });

  await t.test('the page: a picker for every part, the preview, the faces, the address', async () => {
    const { status, text } = await get(srv.base, `/icq/avatar/maker?code=${code}&lang=en`);
    assert.equal(status, 200);
    for (const f of maker.FIELDS) {
      if (f.colors) assert.equal(ids(text, new RegExp(`id="sw-${f.key}-(\\d+)"`, 'g')).length, f.count, f.key);
      else assert.match(text, new RegExp(`<select name="${f.key}" id="mk-${f.key}"`), f.key);
    }
    assert.match(text, new RegExp(`id="mkStill" src="/icq/avatars/${code}-large.png"`));
    assert.deepEqual(ids(text, /id="mood-([a-z]+)" class="mood/g), maker.EMOTIONS);
    assert.match(text, new RegExp(`value="http://127\\.0\\.0\\.1:\\d+/icq/avatars/${code}\\.swf"`));
    assert.ok(text.includes(`href="/icq/avatar/tester?name=${code}&amp;lang=en"`));
    // A swatch is a link to the same page with that colour: no script needed.
    const other = maker.encode({ ...maker.DEFAULTS, hat: 3, bg: 4, skin: 0 });
    assert.ok(text.includes(`href="/icq/avatar/maker?code=${other}&amp;lang=en"`));
    assert.match(text, /Avatar constructor/);
    assert.match((await get(srv.base, `/icq/avatar/maker?code=${code}&lang=uk`)).text, /Конструктор аватарів/);
  });

  await t.test('the page: its scripts stay plain enough for the embedded IE', async () => {
    const { text } = await get(srv.base, '/icq/avatar/maker');
    const code2 = scripts(text).join('\n');
    // (Its texts have "..." in them; a spread would be followed by a name.)
    assert.doesNotMatch(code2, MODERN_JS);
    assert.match(code2, /typeof WebAssembly != 'object'/);
  });

  await t.test('the page: parts from the query, bad values ignored', async () => {
    const want = maker.encode({ ...maker.DEFAULTS, hair: 4 });
    let { text } = await get(srv.base, '/icq/avatar/maker?hair=4&eyes=99&head=x');
    assert.ok(text.includes(`/icq/avatars/${want}.swf`));
    ({ text } = await get(srv.base, '/icq/avatar/maker?code=c-1zzzzzzzzzzzzz'));
    assert.ok(text.includes(`/icq/avatars/${maker.encode(maker.DEFAULTS)}.swf`));
    ({ text } = await get(srv.base, '/icq/avatar/maker?id=%22%3E%3Cb%3E'));
    assert.doesNotMatch(text, /name="id"/);
    ({ text } = await get(srv.base, '/icq/avatar/maker?id=abc123'));
    assert.match(text, /<input type="hidden" name="id" value="abc123">/);
  });

  await t.test('the files of a code, made on request; anything else is a 404', async () => {
    const want = [
      [`${code}.swf`, 'application/x-shockwave-flash'],
      [`${code}-still.jpg`, 'image/jpeg'],
      [`${code}-large.png`, 'image/png'],
      [`${code}.png`, 'image/png'],
      [`${code}-large.png?emotion=love`, 'image/png'],
      [`${code}.swf?emotion=smile`, 'application/x-shockwave-flash'],
    ];
    for (const [name, type] of want) {
      const res = await fetch(`${srv.base}/icq/avatars/${name}`);
      assert.equal(res.status, 200, name);
      assert.equal(res.headers.get('content-type'), type, name);
      await res.arrayBuffer();
    }
    // The same bytes every time.
    const a = Buffer.from(await (await fetch(`${srv.base}/icq/avatars/${code}.swf`)).arrayBuffer());
    assert.ok(a.equals(maker.file(`${code}.swf`).body));
    for (const name of ['c-19999999999999.swf', `${code}.gif`, `${code}-still.jpg?emotion=love`,
      `${code}-large.png?emotion=nope`, `${code}.swf?emotion=nope`, 'c-1.swf']) {
      const res = await fetch(`${srv.base}/icq/avatars/${name}`);
      assert.equal(res.status, 404, name);
      await res.arrayBuffer();
    }
  });

  await t.test('the tester shows a constructed avatar and links back', async () => {
    const { status, text } = await get(srv.base, `/icq/avatar/tester?name=${code}&lang=en`);
    assert.equal(status, 200);
    assert.doesNotMatch(text, /no such avatar/);
    assert.match(text, /made in the avatar constructor/);
    assert.ok(text.includes(`href="/icq/avatar/maker?code=${code}&amp;lang=en"`));
    assert.deepEqual(ids(text, /id="mood-([a-z0-9_]+)"/g), maker.EMOTIONS);
    for (const f of [`${code}-still.jpg`, `${code}-large.png`, `${code}.png`]) assert.ok(text.includes(`/icq/avatars/${f}`), f);
  });

  await t.test('the picture page links the constructor; Miranda\'s list does not get created ones', async () => {
    assert.match((await get(srv.base, '/icq/avatar?lang=en')).text, /<button type="button" id="animMake"/);
    await get(srv.base, `/icq/avatars/${code}.swf`);
    const list = JSON.parse((await get(srv.base, '/icq/avatars/list.json')).text);
    assert.ok(list.avatars.every((a) => !a.file.startsWith('c-')));
  });
});
