// The /icq/download page: the clients' original installers on the Internet
// Archive, with the SHA-256 the patches were tested with (downloadPage in
// server.js).

const test = require('node:test');
const assert = require('node:assert/strict');
const { start, get } = require('./test-server.js');

const ARCHIVE = 'https://archive.org/download/example/icq-6-5-2024-install_icq65.exe';
const ICQ65_SHA256 = '20195f60f61e2f19882487f93372b56c89f2be0da39b5d51a1ed30dbbd3495fe';

test('download page, an installer with an address', async (t) => {
  const srv = await start(false, {
    downloads: { icq2003bInstaller: 'TODO', icq65Installer: ARCHIVE, icq72Installer: '' },
  });
  t.after(() => srv.stop());

  await t.test('links the installer and shows its SHA-256', async () => {
    const { status, text } = await get(srv.base, '/icq/download');
    assert.equal(status, 200);
    assert.ok(text.includes(`<a href="${ARCHIVE}">original installer (Internet Archive)</a>`));
    assert.ok(text.includes(`SHA-256: <code>${ICQ65_SHA256}</code>`));
    assert.match(text, /The original installers are copies on the Internet Archive, unchanged\./);
    // Only that one: the others have no address (TODO or empty).
    assert.equal(text.match(/original installer \(Internet Archive\)/g).length, 1);
  });

  await t.test('in the page language too', async () => {
    const { text } = await get(srv.base, '/icq/download?lang=uk');
    assert.ok(text.includes(`<a href="${ARCHIVE}">оригінальний інсталятор (Internet Archive)</a>`));
    assert.ok(text.includes(ICQ65_SHA256));
  });
});

test('download page, no installer addresses yet', async (t) => {
  const srv = await start(false, {
    downloads: { icq2003bInstaller: 'TODO', icq65Installer: '', icq72Installer: 'TODO' },
  });
  t.after(() => srv.stop());

  await t.test('no installer link, hash or note', async () => {
    const { status, text } = await get(srv.base, '/icq/download');
    assert.equal(status, 200);
    assert.doesNotMatch(text, /Internet Archive/);
    assert.doesNotMatch(text, /SHA-256/);
    // The patches are still there.
    assert.ok(text.includes('/icq/files/icq-65-patch.zip'));
  });
});
