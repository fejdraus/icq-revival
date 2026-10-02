// The Xtraz list ICQ 6.5 reads every ReloadTimeout: a 304 while it has not
// changed (the client drops its loaded entries on a 200 of an unchanged list,
// see the xtrazlist route), and the date of its last change kept in step with
// its entries.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { start } = require('./test-server.js');

const LIST = '/xtraz2/global/10/6/30007/xtrazlist.xml';

// The entries as of XTRAZ_LIST_CHANGED in server.js, with the server's own
// address taken out. When this fails, the entries changed: move
// XTRAZ_LIST_CHANGED forward, then put the new value here.
const ENTRIES_SHA1 = 'd0575d754153392a8d3f4f6c31e8401fff4e65f8';

test('Xtraz list: 304 while unchanged, 200 when the copy is older', async (t) => {
  const srv = await start(false);
  t.after(() => srv.stop());

  const first = await fetch(srv.base + LIST);
  const body = await first.text();
  assert.equal(first.status, 200);
  const modified = first.headers.get('last-modified');
  const etag = first.headers.get('etag');
  assert.ok(modified && etag);

  await t.test('the entries match the date of their last change', () => {
    const host = new URL(srv.base).host;
    const neutral = body.split(host).join('HOST');
    const sha1 = crypto.createHash('sha1').update(neutral).digest('hex');
    assert.equal(sha1, ENTRIES_SHA1,
      'the Xtraz list changed: move XTRAZ_LIST_CHANGED forward and update ENTRIES_SHA1');
  });

  await t.test('a copy saved after the change gets a 304', async () => {
    const saved = new Date(Date.parse(modified) + 3600e3).toUTCString();
    const res = await fetch(srv.base + LIST, { headers: { 'if-modified-since': saved } });
    assert.equal(res.status, 304);
    assert.equal(await res.text(), '');
  });

  await t.test('the same ETag gets a 304', async () => {
    const res = await fetch(srv.base + LIST, { headers: { 'if-none-match': etag } });
    assert.equal(res.status, 304);
  });

  await t.test('a copy older than the change gets the list', async () => {
    const saved = new Date(Date.parse(modified) - 3600e3).toUTCString();
    const res = await fetch(srv.base + LIST, { headers: { 'if-modified-since': saved } });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), body);
  });
});

// ICQ 7.2's Zlango add-on has a list of its own under the same path: it gets
// an empty one, so the client stops fetching the Zlango files from c.icq.com.
test('Xtraz list of the Zlango add-on: empty, with its own date', async (t) => {
  const srv = await start(false);
  t.after(() => srv.stop());

  const res = await fetch(srv.base + '/xtraz2/global/10/7/zlango7/xtrazlist.xml');
  const body = await res.text();
  assert.equal(res.status, 200);
  assert.match(body, /<xtraz\/>/);
  assert.doesNotMatch(body, /<xtra\s/);
  const modified = res.headers.get('last-modified');
  assert.ok(modified);

  const saved = new Date(Date.parse(modified) + 3600e3).toUTCString();
  const again = await fetch(srv.base + '/xtraz2/global/10/7/zlango7/xtrazlist.xml', { headers: { 'if-modified-since': saved } });
  assert.equal(again.status, 304);

  const older = new Date(Date.UTC(2011, 2, 20)).toUTCString();
  const fresh = await fetch(srv.base + '/xtraz2/global/10/7/zlango7/xtrazlist.xml', { headers: { 'if-modified-since': older } });
  assert.equal(fresh.status, 200);
});
