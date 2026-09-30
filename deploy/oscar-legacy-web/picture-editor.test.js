// Tests for the picture editor of the picture page: the geometry
// (picture-crop.js), the server's cut and its checks, and the page.
// node --test "deploy/oscar-legacy-web/*.test.js"
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { pictureCrop, parseCropParams, ICON_W, ICON_H, ZOOM_MAX } = require('./picture-crop.js');
const { png } = require('./maker/raster.js');
const { start, get, scripts, MODERN_JS } = require('./test-server.js');

// ------------------------------------------------------------------- geometry

const near = (a, b, eps = 1e-9) => Math.abs(a - b) <= eps;

test('geometry: zoom 1 in the middle is the old centre crop', () => {
  // shrink-picture.py without the editor: the largest 52:64 part from the middle.
  const old = (w, h) => {
    const wanted = ICON_W / ICON_H;
    if (w / h > wanted) { const keep = Math.round(h * wanted); return { left: Math.floor((w - keep) / 2), top: 0, width: keep, height: h }; }
    const keep = Math.round(w / wanted);
    return { left: 0, top: Math.floor((h - keep) / 2), width: w, height: keep };
  };
  for (const [w, h] of [[800, 500], [500, 800], [52, 64], [640, 640], [123, 457], [800, 3]]) {
    const b = pictureCrop(w, h, 1, 0.5, 0.5, ICON_W, ICON_H);
    const o = old(w, h);
    for (const k of ['left', 'top', 'width', 'height']) assert.ok(Math.abs(b[k] - o[k]) <= 1, `${w}x${h} ${k}: ${b[k]} vs ${o[k]}`);
    assert.ok(near(b.u, 0.5) && near(b.v, 0.5));
  }
});

test('geometry: the cut has the icon shape, shrinks with the zoom and stays inside the picture', () => {
  let seed = 7;
  const rnd = () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };
  for (let i = 0; i < 2000; i++) {
    const w = 20 + Math.floor(rnd() * 800);
    const h = 20 + Math.floor(rnd() * 800);
    const z = 1 + rnd() * (ZOOM_MAX - 1);
    const b = pictureCrop(w, h, z, rnd(), rnd(), ICON_W, ICON_H);
    const b1 = pictureCrop(w, h, 1, 0.5, 0.5, ICON_W, ICON_H);
    assert.ok(near(b.width / b.height, ICON_W / ICON_H, 1e-9));
    assert.ok(near(b.width, b1.width / z, 1e-9));
    assert.ok(near(b.width * b.scale, ICON_W, 1e-9) && near(b.height * b.scale, ICON_H, 1e-9));
    assert.ok(b.left >= -1e-9 && b.top >= -1e-9, `inside ${JSON.stringify(b)}`);
    assert.ok(b.left + b.width <= w + 1e-9 && b.top + b.height <= h + 1e-9, `inside ${JSON.stringify(b)}`);
    // The centre it reports is where the cut really is, and taking it again
    // changes nothing (the page keeps the moved centre).
    const again = pictureCrop(w, h, z, b.u, b.v, ICON_W, ICON_H);
    for (const k of ['left', 'top', 'width', 'height']) assert.ok(near(again[k], b[k], 1e-6));
  }
});

test('geometry: a centre near the edge is moved just enough', () => {
  const b = pictureCrop(800, 500, 2, 0, 1, ICON_W, ICON_H);
  assert.ok(near(b.left, 0));
  assert.ok(near(b.top + b.height, 500));
});

test('ranges: zoom 1 to the maximum, centre 0 to 1, plain decimals only', () => {
  assert.deepEqual(parseCropParams('1', '0.5', '0.5'), { z: 1, u: 0.5, v: 0.5 });
  assert.deepEqual(parseCropParams(String(ZOOM_MAX), '0', '1'), { z: ZOOM_MAX, u: 0, v: 1 });
  assert.deepEqual(parseCropParams('2.123456', '0.333333', '0.66666'), { z: 2.1235, u: 0.3333, v: 0.6667 });
  const bad = [
    ['0.99', '0.5', '0.5'], [String(ZOOM_MAX + 0.01), '0.5', '0.5'], ['1', '-0.1', '0.5'], ['1', '0.5', '1.01'],
    ['1e0', '0.5', '0.5'], ['1', '.5', '0.5'], ['Infinity', '0.5', '0.5'], ['NaN', '0.5', '0.5'], ['', '0.5', '0.5'],
    [null, '0.5', '0.5'], ['1', '0.5', undefined], ['0x1', '0.5', '0.5'], ['1 ', '0.5', '0.5'], ['1', '0,5', '0.5'],
    ['100', '0.5', '0.5'], ['1.123456789', '0.5', '0.5'],
  ];
  for (const b of bad) assert.equal(parseCropParams(...b), null, JSON.stringify(b));
});

test('geometry: the function is plain enough for the embedded IE', () => {
  assert.doesNotMatch(pictureCrop.toString(), MODERN_JS);
});

// ------------------------------------------------------------------- the server's cut

const havePillow = spawnSync('python3', ['-c', 'import PIL'], { stdio: 'ignore' }).status === 0;

// A picture of four coloured quarters, split at (sx, sy).
const QUARTERS = [[220, 40, 40], [40, 170, 60], [40, 80, 220], [240, 200, 40]];
function quarters(w, h, sx, sy) {
  const rgb = Buffer.alloc(w * h * 3);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const c = QUARTERS[(y < sy ? 0 : 2) + (x < sx ? 0 : 1)];
      rgb.set(c, (y * w + x) * 3);
    }
  }
  return png(w, h, rgb);
}

// The pixels of a JPEG, decoded by Pillow (the library that made it).
function decode(jpegBytes) {
  const run = spawnSync('python3', ['-c', `
import sys, io, json
from PIL import Image
im = Image.open(io.BytesIO(sys.stdin.buffer.read())).convert('RGB')
print(json.dumps({'size': im.size, 'px': list(im.getdata())}))`], { input: jpegBytes, maxBuffer: 1 << 24 });
  assert.equal(run.status, 0, String(run.stderr));
  return JSON.parse(run.stdout);
}

async function upload(base, body, type = 'image/png') {
  const form = new FormData();
  form.append('picture', new Blob([body], { type }), 'picture.png');
  const res = await fetch(`${base}/icq/avatar/upload?lang=en&dm=7`, { method: 'POST', body: form });
  const text = await res.text();
  const m = /parent\.uploaded\((.*)\);/.exec(text);
  assert.ok(m, text);
  return JSON.parse(m[1]);
}

test('the server cut', { skip: !havePillow && 'no python3 with Pillow here' }, async (t) => {
  const srv = await start(false);
  t.after(srv.stop);
  // 600x400: kept at that size (under 800), split off-centre.
  const W = 600; const H = 400; const SX = 380; const SY = 150;
  const reply = await upload(srv.base, quarters(W, H, SX, SY));

  await t.test('an upload it can read opens the editor: the working copy and its size', async () => {
    assert.equal(reply.error, '');
    assert.equal(reply.edit.w, W);
    assert.equal(reply.edit.h, H);
    assert.match(reply.edit.id, /^[0-9a-f]{16}$/);
    const work = await fetch(reply.edit.work);
    assert.equal(work.status, 200);
    assert.equal(work.headers.get('content-type'), 'image/jpeg');
    await work.arrayBuffer();
    assert.match(srv.log(), /picture upload: \d+ bytes, document mode 7/);
  });

  await t.test('the icon is the part the preview shows, pixel for pixel of the geometry', async () => {
    for (const [z, u, v] of [[1, 0.5, 0.5], [2.5, 0.6, 0.4], [4, 0.63, 0.37], [1.7, 0.1, 0.9], [ZOOM_MAX, 0.95, 0.05]]) {
      const params = parseCropParams(String(z), String(u), String(v));
      const res = await fetch(`${reply.edit.file}?z=${params.z}&u=${params.u}&v=${params.v}`);
      assert.equal(res.status, 200);
      const img = decode(Buffer.from(await res.arrayBuffer()));
      assert.deepEqual(img.size, [ICON_W, ICON_H]);
      const box = pictureCrop(W, H, params.z, params.u, params.v, ICON_W, ICON_H);
      let checked = 0;
      for (let y = 0; y < ICON_H; y++) {
        for (let x = 0; x < ICON_W; x++) {
          // Where the page draws this icon pixel from.
          const px = box.left + (x + 0.5) / box.scale;
          const py = box.top + (y + 0.5) / box.scale;
          // Away from the split (resampling and JPEG blur it a little).
          const margin = 3 / box.scale + 2;
          if (Math.abs(px - SX) < margin || Math.abs(py - SY) < margin) continue;
          const want = QUARTERS[(py < SY ? 0 : 2) + (px < SX ? 0 : 1)];
          const got = img.px[y * ICON_W + x];
          const d = Math.max(...got.map((c, i) => Math.abs(c - want[i])));
          assert.ok(d < 40, `z=${z} u=${u} v=${v} at ${x},${y}: ${got} vs ${want}`);
          checked++;
        }
      }
      assert.ok(checked > 200, `${checked} pixels checked`);
    }
  });

  await t.test('untouched, it is the centre crop, the same as zoom 1 in the middle', async () => {
    const a = Buffer.from(await (await fetch(reply.edit.file)).arrayBuffer());
    const b = Buffer.from(await (await fetch(`${reply.edit.file}?z=1&u=0.5&v=0.5`)).arrayBuffer());
    assert.ok(a.equals(b));
  });

  await t.test('out of range or malformed: a 400; an unknown id: a 404', async () => {
    for (const q of ['?z=0.5&u=0.5&v=0.5', `?z=${ZOOM_MAX + 1}&u=0.5&v=0.5`, '?z=1&u=2&v=0.5', '?z=1&u=0.5',
      '?z=abc&u=0.5&v=0.5', '?z=1e1&u=0.5&v=0.5', '?u=0.5']) {
      const res = await fetch(`${reply.edit.file}${q}`);
      assert.equal(res.status, 400, q);
      await res.arrayBuffer();
    }
    for (const p of ['/icq/avatar/file/0123456789abcdef', '/icq/avatar/work/0123456789abcdef', '/icq/avatar/work/..%2Fserver.js',
      '/icq/avatar/file/zz', '/icq/avatar/work/']) {
      const res = await fetch(`${srv.base}${p}`);
      assert.equal(res.status, 404, p);
      await res.arrayBuffer();
    }
  });

  await t.test('a file it cannot read goes through as it came, with no editor', async () => {
    const odd = await upload(srv.base, Buffer.from('not a picture at all'), 'application/octet-stream');
    assert.equal(odd.edit, undefined);
    assert.match(odd.clientUrl, /\/icq\/avatar\/file\/[0-9a-f]{16}$/);
  });

  await t.test('uploads are capped by count, the oldest going first', async () => {
    const tiny = quarters(40, 40, 20, 20);
    const first = await upload(srv.base, tiny);
    for (let i = 0; i < 64; i++) await upload(srv.base, tiny);
    const res = await fetch(first.edit.work);
    assert.equal(res.status, 404);
    await res.arrayBuffer();
  });
});

// ------------------------------------------------------------------- the page

test('the picture page', async (t) => {
  const srv = await start(false);
  t.after(srv.stop);

  await t.test('the editor: frame, previews at both sizes, zoom, nudges, centre, set', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    for (const id of ['editRow', 'edFrame', 'edImg', 'edBig', 'edSmall', 'edTrack', 'edKnob']) {
      assert.match(text, new RegExp(`id="${id}"`), id);
    }
    assert.match(text, /width:85px;height:106px/);
    assert.match(text, /width:52px;height:64px/);
    for (const f of ['zoomBy(1.25)', 'zoomBy(1 / 1.25)', 'nudge(-1, 0)', 'nudge(0, -1)', 'nudge(0, 1)', 'nudge(1, 0)', 'resetEdit()']) {
      assert.ok(text.includes(`onclick="${f}"`), f);
    }
    assert.match(text, /Set as my picture/);
    assert.match((await get(srv.base, '/icq/avatar?lang=uk')).text, /Встановити як мою картинку/);
  });

  await t.test('the page cuts with the server\'s own function', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    assert.ok(text.includes(pictureCrop.toString()));
    assert.match(text, new RegExp(`ZOOM_MAX = ${ZOOM_MAX};`));
  });

  await t.test('its scripts stay plain enough for the embedded IE', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    const code = scripts(text).join('\n');
    assert.doesNotMatch(code, MODERN_JS);
    // The mouse the old way too: window.event and capture.
    assert.match(code, /window\.event/);
    assert.match(code, /setCapture/);
  });

  await t.test('inside the client nothing leaves the Xtra window', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    // The tester links are plain links for a browser, hidden once the page
    // has reached the client; nothing calls OpenUrl or opens a window.
    const blank = [...text.matchAll(/<a [^>]*target="_blank"[^>]*>/g)].map((m) => m[0]);
    assert.ok(blank.length >= 2);
    for (const a of blank) assert.match(a, /class="outside"/, a);
    assert.match(text, /CONNECTED = true;\s+if \(revivalIcqLang\(LANG\)\) \{ return; \}\s+hideOutsideLinks\(\);/);
    assert.doesNotMatch(text, /OpenUrl|window\.open\(/);
    // The constructor comes in a frame of this page, and the page is never
    // navigated away inside the client.
    assert.match(text, /<iframe id="makerFrame" name="makerFrame"/);
    assert.match(text, /makerFrame\.location\.replace\('\/icq\/avatar\/maker\?embed=1&lang=' \+ LANG\)/);
  });

  await t.test('the constructor in the frame: no plugin of its own, sets through the page', async () => {
    const { text } = await get(srv.base, '/icq/avatar/maker?embed=1&lang=en');
    assert.doesNotMatch(text, /<OBJECT/i);
    assert.match(text, /var EMBED = true;/);
    assert.match(text, /<body class="compact embed">/);
    assert.match(text, /host\.setAnimatedUrl\(/);
    // Back is a button on the left of the action row; no tester in the client.
    assert.match(text, /<table class="bar"[^>]*><tr>\s*<td valign="middle">\s*<button type="button" id="mkBack"/);
    assert.match(text, /el\('mkTry'\)\.style\.display = 'none';/);
    assert.doesNotMatch(text, /OpenUrl|window\.open\(/);
    assert.doesNotMatch(text, /class="titlebar"/);
    assert.match(text, /<input type="hidden" name="embed" value="1">/);
    assert.doesNotMatch(scripts(text).join('\n'), MODERN_JS);
    const full = (await get(srv.base, '/icq/avatar/maker?lang=en')).text;
    assert.match(full, /<OBJECT CLASSID="clsid:8D18DFF4/);
    assert.match(full, /var EMBED = false;/);
  });

  await t.test('with an animated avatar set, the current picture is its still, with a note', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    assert.match(text, /id="currentAnimNote" style="display:none[^"]*">While an animated avatar is set, contacts see this still of it\./);
    assert.match(text, /animStill = a && a\.large \? '\/icq\/avatars\/' \+ a\.large : '';/);
    // The gallery hands the page each movie's large still.
    const avatars = JSON.parse(/var AVATARS = (\[[^\n]*\]);/.exec(text)[1]);
    assert.ok(avatars.length > 0 && avatars.every((a) => /-large\.png$/.test(a.large)));
    assert.match((await get(srv.base, '/icq/avatar?lang=uk')).text, /Поки встановлено анімований аватар/);
  });

  await t.test('the constructor is a button in the Animated tab', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    assert.match(text, /<button type="button" id="animMake" class="primary" onclick="makeOwn\(\)">Make your own<\/button>/);
  });

  // The page's plugin calls, run against stand-ins for both clients. ICQ 7.2's
  // SetBartItem and GetBartItem are E_NOTIMPL stubs (JScript error 445); ICQ 6
  // has no SetAvatar or GetAvatar at all (JScript error 438).
  await t.test('ICQ 7.2 gets SetAvatar and GetAvatar, ICQ 6 SetBartItem and GetBartItem', async () => {
    const { text } = await get(srv.base, '/icq/avatar?lang=en');
    const code = /var NO_SUCH_METHOD = 438;[\s\S]*?\nfunction getBart\(kind\) \{[\s\S]*?\n\}\n/.exec(text)[0];
    const jscriptError = (n) => Object.assign(new Error(`JScript ${n}`), { number: (0x800A0000 | n) | 0 });
    const run = (plugin, calls) => new Function('plugin', `
      var BART_PICTURE = 1, BART_ANIMATED = 8, transaction = 5;
      ${code}
      ${calls}`)(plugin);
    const log = [];
    const icq72 = {
      OwnerInfo: { ScreenName: '100001' },
      SetAvatar: (...a) => log.push(['SetAvatar', ...a]),
      GetAvatar: (...a) => log.push(['GetAvatar', ...a]),
      SetBartItem: () => { throw jscriptError(445); },
      GetBartItem: () => { throw jscriptError(445); },
    };
    const icq6 = {
      OwnerInfo: { ScreenName: '100002' },
      SetAvatar: () => { throw jscriptError(438); },
      GetAvatar: () => { throw jscriptError(438); },
      SetBartItem: (...a) => log.push(['SetBartItem', ...a]),
      GetBartItem: (...a) => log.push(['GetBartItem', ...a]),
    };
    const movie = 'http://icq.example/icq/avatars/2308koshak.swf';
    const picture = 'http://icq.example/icq/avatar/file/0123456789abcdef';
    const calls = `setBart(BART_ANIMATED, ${JSON.stringify(movie)});
      setBart(BART_PICTURE, ${JSON.stringify(picture)});
      getBart(BART_ANIMATED);`;

    run(icq72, calls);
    assert.deepEqual(log.splice(0), [
      // The movie goes with its still, which ICQ 7.2 insists on.
      ['SetAvatar', 5, 8, movie, 'http://icq.example/icq/avatars/2308koshak-still.jpg'],
      ['SetAvatar', 5, 1, picture],
      ['GetAvatar', 5, 8, '100001'],
    ]);
    run(icq6, calls);
    assert.deepEqual(log.splice(0), [
      ['SetBartItem', 5, 8, movie],
      ['SetBartItem', 5, 1, picture],
      ['GetBartItem', 5, 8, '100002'],
    ]);

    // Any other refusal of SetAvatar is the client's answer, not a sign of
    // ICQ 6: it reaches the page as it is.
    const refusing = { ...icq72, SetAvatar: () => { throw jscriptError(5); } };
    assert.throws(() => run(refusing, `setBart(BART_ANIMATED, ${JSON.stringify(movie)});`), /JScript 5/);
    assert.deepEqual(log, []);

    // ICQ 7.2 answers in OnAvatarResult, with an HRESULT, through the same
    // handling as ICQ 6's OnBartOp events.
    assert.match(text, /<script for="plugin" event="OnAvatarResult\(transeID, result, bcsData\)" language="JavaScript">\s*\/\/[^\n]*\n\s*if \(result < 0\) \{ bartFailed\(transeID\); \}\s*else \{ bartSucceeded\(transeID, bcsData\); \}/);
    assert.match(text, /event="OnBartOpSucceeded\(transID, bcstrData\)" language="JavaScript">\s*bartSucceeded\(transID, bcstrData\);/);
    assert.match(text, /event="OnBartOpFailed\(transID\)" language="JavaScript">\s*bartFailed\(transID\);/);
    // Nothing calls the old methods directly any more.
    assert.equal(text.match(/plugin\.(SetBartItem|GetBartItem)\(/g).length, 2);
  });
});
