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
  createMirror, readZip, writeZip, parseHashes, filterRules, mergeTranslations, translationName,
  mainPackLanguage, translationMasks, packagePath, wildMatch, MERGE_BEGIN, MERGE_END,
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

const LANGPACK = Buffer.from('Miranda Language Pack Version 1\r\n[Hello]\r\nПривіт\r\n#include langpack_russian_flashavatars.txt\r\n', 'utf8');
const STOCK_ICQ = writeZip([['Plugins/IcqOscarJ.dll', Buffer.from('stock')]]);
const DUMMY = writeZip([['Plugins/Dummy.dll', Buffer.from('dummy v2')]]);
const LANGPACK_ZIP = writeZip([['Languages/langpack_russian.txt', LANGPACK]]);
const LANGPACK_UK = Buffer.from('Miranda Language Pack Version 1\r\n[Hello]\r\nПривіт\r\n', 'utf8');
const LANGPACK_UK_ZIP = writeZip([['Languages/langpack_ukrainian.txt', LANGPACK_UK]]);
const LANGPACK_DE = Buffer.from('\uFEFFMiranda Language Pack Version 1\r\n[Hello]\r\nHallo\r\n', 'utf8');
const LANGPACK_DE_ZIP = writeZip([['Languages/langpack_german.txt', LANGPACK_DE]]);

function upstreamFiles() {
  const hashes = [
    '; upstream',
    `Plugins\\Dummy.dll 11111111111111111111111111111111 ${crcHex(DUMMY)}`,
    `Plugins\\IcqOscarJ.dll 22222222222222222222222222222222 ${crcHex(STOCK_ICQ)}`,
    `Languages\\langpack_russian.txt 33333333333333333333333333333333 ${crcHex(LANGPACK_ZIP)}`,
    `Languages\\langpack_ukrainian.txt 55555555555555555555555555555555 ${crcHex(LANGPACK_UK_ZIP)}`,
    // a pack of a language we have no translation for goes out as it is
    `Languages\\langpack_german.txt 77777777777777777777777777777777 ${crcHex(LANGPACK_DE_ZIP)}`,
    // a stock line under the name of a separate translation of ours never goes out
    'Languages\\langpack_ukrainian_icq.txt 66666666666666666666666666666666 00000000',
    'Core\\StdMsg.dll 44444444444444444444444444444444 00000000',
  ].join('\r\n') + '\r\n';
  const rules = {
    // Miranda NG's real rules delete "flashavatars.dll", the old name of ours
    rules: { 'IcqOscarJ.dll': null, 'flashavatars.dll': null, 'ICQ.dll': 'Plugins\\IcqOscarJ.dll', 'Obsolete.dll': null },
    packets: [{ module: 'Plugins\\IcqOscarJ.dll', depends: ['Libs\\x.mir'] }, { module: 'Plugins\\Dummy.dll', depends: [] }],
  };
  const hz = writeZip([['hashes.txt', Buffer.from(hashes, 'latin1')], ['rules.txt', Buffer.from(JSON.stringify(rules))]]);
  return new Map([
    ['/x32/hashes.zip', hz],
    ['/x32/Plugins/dummy.zip', DUMMY],
    ['/x32/Plugins/icqoscarj.zip', STOCK_ICQ],
    ['/x32/Languages/langpack_russian.zip', LANGPACK_ZIP],
    ['/x32/Languages/langpack_ukrainian.zip', LANGPACK_UK_ZIP],
    ['/x32/Languages/langpack_german.zip', LANGPACK_DE_ZIP],
  ]);
}

// Our translation files, as make-update-packages.py copies them: a header of
// their own (with a BOM on one of them), then the #muuid section.
const header = (lang) => `Miranda Language Pack Version 1\r\nLanguage: ${lang}\r\nLocale: 0000\r\n\r\n`;
const TRANSLATIONS = {
  'langpack_russian_icq.txt': `${header('ru')};== IcqOscarJ\r\n#muuid {aaaa}\r\n[Status]\r\nСтатус\r\n`,
  'langpack_russian_icqrevivalflash.txt': `\uFEFF${header('ru')};== IcqRevivalFlash\r\n#muuid {bbbb}\r\n[tZers]\r\nтZers\r\n\r\n`,
  'langpack_ukrainian_icq.txt': `${header('uk')};== IcqOscarJ\r\n#muuid {aaaa}\r\n[Status]\r\nСтатус\r\n`,
  'langpack_ukrainian_icqrevivalflash.txt': `${header('uk')};== IcqRevivalFlash\r\n#muuid {bbbb}\r\n[tZers]\r\nтZери\r\n`,
};

// Our packages as make-update-packages.py lays them out.
function ourPackages({ translations = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mirpkg-'));
  const files = [];
  for (const [name, data] of [['Plugins\\IcqOscarJ.dll', 'our icq'], ['Plugins\\IcqRevivalFlash.dll', 'our flash']]) {
    const rel = `${name.replace(/\.[^.]+$/, '').replace(/\\/g, '/')}.zip`;
    const body = writeZip([[name.replace(/\\/g, '/'), Buffer.from(data)]]);
    fs.mkdirSync(path.join(dir, 'x32', path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, 'x32', rel), body);
    files.push({ name, hash: md5(Buffer.from(data)), crc: crcHex(body), package: rel });
  }
  fs.writeFileSync(path.join(dir, 'x32', 'manifest.json'), JSON.stringify({ files }));
  if (translations) {
    fs.mkdirSync(path.join(dir, 'translations'));
    for (const [name, text] of Object.entries(TRANSLATIONS)) {
      fs.writeFileSync(path.join(dir, 'translations', name), Buffer.from(text, 'utf8'));
    }
  }
  return { dir, files };
}

// What a merged Russian pack must end with: the sections, headers and BOMs gone.
const RU_SECTIONS = `${MERGE_BEGIN}\r\n;== IcqOscarJ\r\n#muuid {aaaa}\r\n[Status]\r\nСтатус\r\n\r\n`
  + `;== IcqRevivalFlash\r\n#muuid {bbbb}\r\n[tZers]\r\nтZers\r\n${MERGE_END}\r\n`;

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

test('filterRules keeps a rule that leaves our file where it is', () => {
  const out = filterRules({
    rules: { 'langpack_*.txt': 'Languages\\*', 'langpack_russian_icq.txt': 'Other\\x.txt', 'flashavatars.dll': null },
  }, ['Languages\\langpack_russian_icq.txt', 'Plugins\\FlashAvatars.dll'], { 'FlashAvatars.dll': 'Plugins\\IcqRevivalFlash.dll' });
  assert.deepEqual(out.rules, { 'FlashAvatars.dll': 'Plugins\\IcqRevivalFlash.dll', 'langpack_*.txt': 'Languages\\*' });
});

test('parseHashes reads upstream\'s own spacing', () => {
  const { lines } = parseHashes('Miranda32.exe F3353902E3F6CEA6934826FD84D0B6C5  7F3D2D33 \r\n; c\r\n');
  assert.equal(lines[0].name, 'Miranda32.exe');
  assert.equal(lines[0].hash, 'f3353902e3f6cea6934826fd84d0b6c5');
  assert.equal(lines[0].crc, '7F3D2D33');
  assert.equal(lines[1].name, undefined);
});

test('translationName and mainPackLanguage read the names, not a list of languages', () => {
  assert.deepEqual(translationName('langpack_russian_icq.txt'), { language: 'russian', plugin: 'icq' });
  assert.deepEqual(translationName('Langpack_Chinese_Traditional_IcqRevivalFlash.txt'),
    { language: 'chinese_traditional', plugin: 'icqrevivalflash' });
  assert.equal(translationName('langpack_russian.txt'), null);
  assert.equal(translationName('langpack-extra-ru.txt'), null);
  assert.equal(mainPackLanguage('Languages\\langpack_ukrainian.txt'), 'ukrainian');
  assert.equal(mainPackLanguage('Languages\\Langpack_Russian.txt'), 'russian');
  assert.equal(mainPackLanguage('Plugins\\langpack_russian.txt'), null);
  assert.deepEqual(translationMasks(new Map([['xx', [{ plugin: 'icq' }, { plugin: 'icqrevivalflash' }]]])),
    ['langpack_*_flashavatars.txt', 'langpack_*_icq.txt', 'langpack_*_icqrevivalflash.txt']);
});

test('mergeTranslations: sections at the end, old includes out, twice is once', () => {
  const sections = [{ body: Buffer.from(TRANSLATIONS['langpack_russian_icq.txt']) },
    { body: Buffer.from(TRANSLATIONS['langpack_russian_icqrevivalflash.txt']) }];
  const masks = ['langpack_*_icq.txt', 'langpack_*_icqrevivalflash.txt', 'langpack_*_flashavatars.txt'];
  const pack = Buffer.from('\uFEFFMiranda Language Pack Version 1\r\n[Hello]\r\nПривіт\r\n'
    + '#include langpack_russian_flashavatars.txt\r\n#include LANGPACK_RUSSIAN_ICQ.txt\r\n#include other.txt\r\n\r\n', 'utf8')
    .toString('latin1');
  const once = mergeTranslations(pack, sections, masks);
  const text = Buffer.from(once, 'latin1').toString('utf8');
  assert.equal(text, '\uFEFFMiranda Language Pack Version 1\r\n[Hello]\r\nПривіт\r\n#include other.txt\r\n\r\n' + RU_SECTIONS);
  assert.equal(mergeTranslations(once, sections, masks), once, 'merging again changes nothing');
  // new sections replace the old ones instead of adding to them
  const again = Buffer.from(mergeTranslations(once, sections.slice(0, 1), masks), 'latin1').toString('utf8');
  assert.equal(again.split(MERGE_BEGIN).length, 2);
  assert.ok(!again.includes('IcqRevivalFlash'));
  // an LF pack gets LF
  assert.equal(mergeTranslations('a\n[k]\nv', [{ body: Buffer.from('#muuid {x}\r\n[k]\r\nw\r\n') }]),
    `a\n[k]\nv\n\n${MERGE_BEGIN}\n#muuid {x}\n[k]\nw\n${MERGE_END}\n`);
});

test('zip round trip', () => {
  const z = writeZip([['a/b.txt', Buffer.from('hello')], ['c', Buffer.alloc(0)]]);
  const back = readZip(z);
  assert.equal(back.get('a/b.txt').toString(), 'hello');
  assert.equal(back.get('c').length, 0);
});

// A served pack: its list line, its package, and the text inside, checked
// against the hash and crc the list gives.
async function servedPack(srvUrl, lines, name) {
  const line = lines.find((l) => l.startsWith(`Languages\\${name}.txt `));
  const [, hash, crc] = line.split(' ');
  const pkg = await get(`${srvUrl}/x32/Languages/${name}.zip`);
  assert.equal(pkg.status, 200);
  assert.equal(crcHex(pkg.body), crc, `${name}: crc of what is served`);
  const text = readZip(pkg.body).get(`Languages/${name}.txt`);
  assert.equal(md5(text), hash, `${name}: hash of what is served`);
  return text;
}

test('the list: our lines in, stock ones out, rules cleaned, translations merged', async (t) => {
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
  assert.ok(lines.includes(`Plugins\\IcqRevivalFlash.dll ${files[1].hash} ${files[1].crc}`));
  assert.ok(!lines.some((l) => /flashavatars/i.test(l)), 'nothing under the old name');
  assert.ok(!lines.some((l) => l.includes('22222222')), 'the stock line is gone');
  assert.ok(!lines.some((l) => /_icq/i.test(l)), 'no line for a separate translation');
  assert.ok(lines.some((l) => l.startsWith('Plugins\\Dummy.dll 1111')));

  const rules = JSON.parse(entries.get('rules.txt').toString());
  // The old name moves to the new one instead of being deleted, and the
  // separate translations go; ours first, since PluginUpdater takes the first
  // rule that matches.
  assert.deepEqual(rules.rules, {
    'FlashAvatars.dll': 'Plugins\\IcqRevivalFlash.dll',
    'langpack_*_flashavatars.txt': null,
    'langpack_*_icq.txt': null,
    'langpack_*_icqrevivalflash.txt': null,
    'Obsolete.dll': null,
  });
  assert.deepEqual(Object.keys(rules.rules)[0], 'FlashAvatars.dll');
  assert.deepEqual(rules.packets.map((p) => p.module), ['Plugins\\Dummy.dll']);

  // Russian: upstream's, its #include of the old name out, our sections in.
  const ru = (await servedPack(srv.url, lines, 'langpack_russian')).toString('utf8');
  assert.equal(ru, 'Miranda Language Pack Version 1\r\n[Hello]\r\nПривіт\r\n\r\n' + RU_SECTIONS);

  // Ukrainian the same way, from its own files.
  const uk = (await servedPack(srv.url, lines, 'langpack_ukrainian')).toString('utf8');
  assert.equal(uk.split(MERGE_BEGIN).length, 2, 'our sections once');
  assert.ok(uk.startsWith(`Miranda Language Pack Version 1\r\n[Hello]\r\nПривіт\r\n\r\n${MERGE_BEGIN}`));
  assert.ok(uk.includes('тZери') && !uk.includes('тZers') && !uk.includes('Language: uk'));
  assert.ok(!lines.some((l) => l.includes('66666666')), 'no stock line under our name');

  // German: no translation of ours, upstream's line and bytes as they are.
  assert.ok(lines.includes(`Languages\\langpack_german.txt 77777777777777777777777777777777 ${crcHex(LANGPACK_DE_ZIP)}`));
  assert.deepEqual((await get(`${srv.url}/x32/Languages/langpack_german.zip`)).body, LANGPACK_DE_ZIP);

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

test('without translations of ours every pack goes out as it is, and nothing is deleted', async (t) => {
  const up = await upstreamServer(upstreamFiles());
  const { dir } = ourPackages({ translations: false });
  const mirror = createMirror({ upstream: up.url, dir, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });
  const list = readZip((await get(`${srv.url}/x32/hashes.zip`)).body);
  const lines = list.get('hashes.txt').toString('latin1');
  assert.ok(lines.includes(`Languages\\langpack_russian.txt 33333333333333333333333333333333 ${crcHex(LANGPACK_ZIP)}`));
  assert.deepEqual((await get(`${srv.url}/x32/Languages/langpack_russian.zip`)).body, LANGPACK_ZIP);
  assert.ok(!Object.keys(JSON.parse(list.get('rules.txt').toString()).rules).some((k) => k.startsWith('langpack')));
});

test('a pack that cannot be fetched leaves its line out, and our separate files in place', async (t) => {
  const files = upstreamFiles();
  files.delete('/x32/Languages/langpack_russian.zip');
  const up = await upstreamServer(files);
  const { dir } = ourPackages();
  const mirror = createMirror({ upstream: up.url, dir, log: () => {} });
  const srv = await mirrorServer(mirror);
  t.after(() => { up.server.close(); srv.server.close(); });
  const list = readZip((await get(`${srv.url}/x32/hashes.zip`)).body);
  const lines = list.get('hashes.txt').toString('latin1');
  assert.ok(!lines.includes('langpack_russian.txt'));
  assert.ok(lines.includes('langpack_ukrainian.txt'));
  assert.deepEqual(JSON.parse(list.get('rules.txt').toString()).rules,
    { 'FlashAvatars.dll': 'Plugins\\IcqRevivalFlash.dll', 'Obsolete.dll': null });
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
