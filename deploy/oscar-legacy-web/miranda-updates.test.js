// Tests for miranda-updates.js: node --test deploy/oscar-legacy-web/
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const {
  createMirror, readZip, writeZip, filterRules, withIncludes, packagePath, wildMatch,
} = require('./miranda-updates.js');

const crcHex = (b) => zlib.crc32(b).toString(16).padStart(8, '0');
const md5 = (b) => crypto.createHash('md5').update(b).digest('hex');

// A fake upstream: path -> Buffer, and a log of what was asked.
function upstreamServer(files) {
  const asked = [];
  const server = http.createServer((req, res) => {
    asked.push(req.url);
    const body = files.get(req.url);
    if (!body) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'content-length': body.length });
    res.end(req.method === 'HEAD' ? undefined : body);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    server, asked, url: `http://127.0.0.1:${server.address().port}`,
  })));
}

function mirrorServer(mirror) {
  const server = http.createServer((req, res) => {
    mirror.handle(req, res, new URL(req.url, 'http://x').pathname.replace(/^\/miranda\/stable/, ''))
      .catch((err) => { res.writeHead(500); res.end(String(err)); });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    server, url: `http://127.0.0.1:${server.address().port}/miranda/stable`,
  })));
}

async function get(url) {
  const res = await fetch(url);
  return { status: res.status, body: Buffer.from(await res.arrayBuffer()) };
}

const LANGPACK = Buffer.from('Miranda Language Pack Version 1\r\n[Hello]\r\nПривет\r\n', 'utf8');
const STOCK_ICQ = writeZip([['Plugins/IcqOscarJ.dll', Buffer.from('stock')]]);
const DUMMY = writeZip([['Plugins/Dummy.dll', Buffer.from('dummy v2')]]);
const LANGPACK_ZIP = writeZip([['Languages/langpack_russian.txt', LANGPACK]]);

function upstreamFiles() {
  const hashes = [
    '; upstream',
    `Plugins\\Dummy.dll 11111111111111111111111111111111 ${crcHex(DUMMY)}`,
    `Plugins\\IcqOscarJ.dll 22222222222222222222222222222222 ${crcHex(STOCK_ICQ)}`,
    `Languages\\langpack_russian.txt 33333333333333333333333333333333 ${crcHex(LANGPACK_ZIP)}`,
    'Core\\StdMsg.dll 44444444444444444444444444444444 00000000',
  ].join('\r\n') + '\r\n';
  const rules = {
    rules: { 'IcqOscarJ.dll': null, 'Flash*.dll': null, 'ICQ.dll': 'Plugins\\IcqOscarJ.dll', 'Obsolete.dll': null },
    packets: [{ module: 'Plugins\\IcqOscarJ.dll', depends: ['Libs\\x.mir'] }, { module: 'Plugins\\Dummy.dll', depends: [] }],
  };
  const hz = writeZip([['hashes.txt', Buffer.from(hashes, 'latin1')], ['rules.txt', Buffer.from(JSON.stringify(rules))]]);
  return new Map([
    ['/x32/hashes.zip', hz],
    ['/x32/Plugins/dummy.zip', DUMMY],
    ['/x32/Plugins/icqoscarj.zip', STOCK_ICQ],
    ['/x32/Languages/langpack_russian.zip', LANGPACK_ZIP],
  ]);
}

// Our packages as make-update-packages.py lays them out.
function ourPackages() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mirpkg-'));
  const files = [];
  for (const [name, data] of [['Plugins\\IcqOscarJ.dll', 'our icq'], ['Plugins\\FlashAvatars.dll', 'our flash']]) {
    const rel = `${name.replace(/\.[^.]+$/, '').replace(/\\/g, '/')}.zip`;
    const body = writeZip([[name.replace(/\\/g, '/'), Buffer.from(data)]]);
    fs.mkdirSync(path.join(dir, 'x32', path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, 'x32', rel), body);
    files.push({ name, hash: md5(Buffer.from(data)), crc: crcHex(body), package: rel });
  }
  fs.writeFileSync(path.join(dir, 'x32', 'manifest.json'), JSON.stringify({
    files,
    langpackIncludes: { 'Languages\\langpack_russian.txt': ['#include langpack_russian_icq.txt'] },
  }));
  return { dir, files };
}

test('packagePath follows PluginUpdater: no extension, slashes, lower-case file name', () => {
  assert.equal(packagePath('Plugins\\IcqOscarJ.dll'), 'Plugins/icqoscarj.zip');
  assert.equal(packagePath('Languages\\langpack_russian.txt'), 'Languages/langpack_russian.zip');
  assert.equal(packagePath('Miranda32.exe'), 'miranda32.zip');
});

test('wildMatch is case-insensitive over the whole name', () => {
  assert.ok(wildMatch('Flash*.dll', 'flashavatars.dll'));
  assert.ok(wildMatch('icq?scarj.dll', 'IcqOscarJ.dll'));
  assert.ok(!wildMatch('Flash*.dll', 'noflash.dll'));
});

test('filterRules drops what touches our files and keeps the rest', () => {
  const out = filterRules({
    rules: { 'IcqOscarJ.dll': null, 'ICQ.dll': 'Plugins\\IcqOscarJ.dll', 'Obsolete.dll': null },
    packets: [{ module: 'Plugins\\IcqOscarJ.dll' }, { module: 'Plugins\\Dummy.dll' }],
  }, ['Plugins\\IcqOscarJ.dll']);
  assert.deepEqual(out.rules, { 'Obsolete.dll': null });
  assert.deepEqual(out.packets, [{ module: 'Plugins\\Dummy.dll' }]);
});

test('withIncludes appends only the missing lines, in the file\'s line endings', () => {
  assert.equal(withIncludes('a\r\nb', ['#include x.txt']), 'a\r\nb\r\n#include x.txt\r\n');
  assert.equal(withIncludes('a\n#include X.txt\n', ['#include x.txt']), 'a\n#include X.txt\n');
});

test('zip round trip', () => {
  const z = writeZip([['a/b.txt', Buffer.from('hello')], ['c', Buffer.alloc(0)]]);
  const back = readZip(z);
  assert.equal(back.get('a/b.txt').toString(), 'hello');
  assert.equal(back.get('c').length, 0);
});

test('the list: our lines in, stock ones out, rules cleaned, translation patched', async (t) => {
  const up = await upstreamServer(upstreamFiles());
  const { dir, files } = ourPackages();
  const mirror = createMirror({ upstream: up.url, dir, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });

  const res = await get(`${srv.url}/x32/hashes.zip`);
  assert.equal(res.status, 200);
  const entries = readZip(res.body);
  const lines = entries.get('hashes.txt').toString('latin1').split('\r\n');
  assert.ok(lines.includes('; upstream'));
  assert.ok(lines.includes(`Plugins\\IcqOscarJ.dll ${files[0].hash} ${files[0].crc}`));
  assert.ok(lines.includes(`Plugins\\FlashAvatars.dll ${files[1].hash} ${files[1].crc}`));
  assert.ok(!lines.some((l) => l.includes('22222222')), 'the stock line is gone');
  assert.ok(lines.some((l) => l.startsWith('Plugins\\Dummy.dll 1111')));

  const rules = JSON.parse(entries.get('rules.txt').toString());
  assert.deepEqual(rules.rules, { 'Obsolete.dll': null });
  assert.deepEqual(rules.packets.map((p) => p.module), ['Plugins\\Dummy.dll']);

  // The translation: upstream's plus our include, hash and crc of what is served.
  const lp = lines.find((l) => l.startsWith('Languages\\langpack_russian.txt '));
  const [, hash, crc] = lp.split(' ');
  const pkg = await get(`${srv.url}/x32/Languages/langpack_russian.zip`);
  assert.equal(pkg.status, 200);
  assert.equal(crcHex(pkg.body), crc);
  const text = readZip(pkg.body).get('Languages/langpack_russian.txt');
  assert.equal(md5(text), hash);
  assert.ok(text.toString('utf8').endsWith('Привет\r\n#include langpack_russian_icq.txt\r\n'));

  // Our package, whatever the case of the file name.
  const ours = await get(`${srv.url}/x32/Plugins/icqoscarj.zip`);
  assert.equal(crcHex(ours.body), files[0].crc);
  assert.ok(!up.asked.includes('/x32/Plugins/icqoscarj.zip'), 'the stock package is never fetched');
});

test('relay: listed files only, cached, nothing that walks out', async (t) => {
  const up = await upstreamServer(upstreamFiles());
  const mirror = createMirror({ upstream: up.url, dir: null, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });

  const a = await get(`${srv.url}/x32/Plugins/dummy.zip`);
  const b = await get(`${srv.url}/x32/Plugins/dummy.zip`);
  assert.equal(a.status, 200);
  assert.deepEqual(a.body, DUMMY);
  assert.deepEqual(b.body, DUMMY);
  assert.equal(up.asked.filter((u) => u === '/x32/Plugins/dummy.zip').length, 1, 'second from the cache');

  // Listed but missing upstream, and not listed at all.
  assert.equal((await get(`${srv.url}/x32/Core/stdmsg.zip`)).status, 404);
  const before = up.asked.length;
  assert.equal((await get(`${srv.url}/x32/Plugins/other.zip`)).status, 404);
  assert.equal((await get(`${srv.url}/x32/Plugins/..%2Fhashes.zip`)).status, 404);
  assert.equal((await get(`${srv.url}/x86/hashes.zip`)).status, 404);
  assert.equal(up.asked.length, before, 'no upstream request for names not in the list');

  // Without our packages the stock line of ours still does not go out, nor
  // do the rules that would delete our files.
  const list = readZip((await get(`${srv.url}/x32/hashes.zip`)).body);
  const lines = list.get('hashes.txt').toString('latin1');
  assert.ok(!lines.includes('IcqOscarJ'));
  assert.ok(lines.includes('Plugins\\Dummy.dll'));
  assert.deepEqual(JSON.parse(list.get('rules.txt').toString()).rules, { 'Obsolete.dll': null });
});

test('a stale list is served while upstream is down; none at all is a 503', async (t) => {
  const files = upstreamFiles();
  const up = await upstreamServer(files);
  const mirror = createMirror({ upstream: up.url, dir: null, ttlMs: 0, retryMs: 0, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });

  const first = await get(`${srv.url}/x32/hashes.zip`);
  assert.equal(first.status, 200);
  files.delete('/x32/hashes.zip');
  const second = await get(`${srv.url}/x32/hashes.zip`);
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, first.body);

  const empty = createMirror({ upstream: up.url, dir: null, log: () => {} });
  const srv2 = await mirrorServer(empty);
  t.after(() => srv2.server.close());
  assert.equal((await get(`${srv2.url}/x32/hashes.zip`)).status, 503);
});

test('a translation package that cannot be fetched leaves its line out', async (t) => {
  const files = upstreamFiles();
  files.delete('/x32/Languages/langpack_russian.zip');
  const up = await upstreamServer(files);
  const { dir } = ourPackages();
  const mirror = createMirror({ upstream: up.url, dir, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });
  const lines = readZip((await get(`${srv.url}/x32/hashes.zip`)).body).get('hashes.txt').toString('latin1');
  assert.ok(!lines.includes('langpack_russian.txt'));
});

test('a relayed file over the cap is refused', async (t) => {
  const files = upstreamFiles();
  files.set('/x32/Plugins/dummy.zip', Buffer.alloc(4096));
  const up = await upstreamServer(files);
  const mirror = createMirror({ upstream: up.url, dir: null, maxFileBytes: 1024, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });
  assert.equal((await get(`${srv.url}/x32/Plugins/dummy.zip`)).status, 502);
});
