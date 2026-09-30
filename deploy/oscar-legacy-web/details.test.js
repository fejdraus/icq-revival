// ICQ 7.2's details window: the icq_profile Xtra from the Xtraz list, for
// one's own details and a contact's (detailsPage in server.js).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { start, get, scripts, MODERN_JS } = require('./test-server.js');

// The address ICQ 7.2 opens: the list's url plus bld, dst, id and mode.
const OPENED = '/icq/details?bld=3143&dst=60007&id=1005812876&mode=0';

test('ICQ 7.2 details window', async (t) => {
  const srv = await start(false);
  t.after(() => srv.stop());

  await t.test('the Xtraz list has the icq_profile entry', async () => {
    const { text } = await get(srv.base, '/xtraz2/global/10/6/30007/xtrazlist.xml');
    assert.match(text, /<xtra id="icq_profile" [^>]*url="[^"]*\/icq\/details"\/>/);
    assert.match(text, /<xtra id="icq_profile" [^>]*width="540"[^>]*height="480"/);
  });

  await t.test('the connector binds the plugin and waits for OnInitData', async () => {
    const { status, text } = await get(srv.base, OPENED);
    assert.equal(status, 200);
    assert.match(text, /<OBJECT CLASSID="clsid:8D18DFF4-0943-4347-8BCA-0C57033F6820" id="plugin"/);
    assert.match(text, /var DT_ID = "1005812876";/);
    assert.match(text, /<script for="plugin" event="OnInitData\(owner, launchMode, buddies, initialData\)"/);
    // The handler comes before the call that may fire it.
    assert.ok(text.indexOf('event="OnInitData') < text.indexOf('setTimeout(dtConnect, 0)'));
    assert.match(text, /plugin\.Initialize\(DT_ID\)/);
    assert.match(text, /GetIMClientData\('LANG_ID'\)/);
    assert.match(text, /<body class="compact">/);
    for (const s of scripts(text)) assert.doesNotMatch(s, MODERN_JS);
  });

  await t.test('the connector reads the initial data MUICore gives', async () => {
    // The connector's script, run with a stand-in plugin and window.
    const { text } = await get(srv.base, OPENED);
    const code = scripts(text).find((s) => /function dtShow/.test(s));
    const run = (initialData, screenName = '100001', search = '?id=1005812876') => {
      let replaced = null;
      const plugin = { OwnerInfo: { ScreenName: screenName }, GetIMClientData: () => 'ua-ua' };
      const window = { location: { search, pathname: '/icq/details', replace: (u) => { replaced = u; } } };
      // eslint-disable-next-line no-new-func
      new Function('plugin', 'window', 'document', `${code}; dtShow(${JSON.stringify(initialData)});`)(plugin, window, {});
      return replaced;
    };
    assert.equal(run('var owner="100001",target="0";'),
      '/icq/details?id=1005812876&icq=100001&own=1&lang=uk');
    assert.equal(run('var owner="100001",target="100002";'),
      '/icq/details?id=1005812876&icq=100002&lang=uk');
    assert.equal(run('var owner="100001",target="100001";'),
      '/icq/details?id=1005812876&icq=100001&own=1&lang=uk', 'one\'s own number is one\'s own details');
    assert.equal(run('var owner="100001",target="Some Buddy";', '100001', '?id=1005812876&lang=en'),
      '/icq/details?id=1005812876&icq=Some%20Buddy&lang=en', 'an explicit language wins');
    assert.equal(run('', '100001'), '/icq/details?id=1005812876&icq=100001&own=1&lang=uk');
    assert.equal(run('', ''), null, 'nothing known: it waits and then says so');
  });

  await t.test('in a browser the connector offers the search', async () => {
    const { text } = await get(srv.base, '/icq/details?lang=en');
    assert.doesNotMatch(text, /<OBJECT/i);
    assert.match(text, /action="\/icq\/whitepages"/);
  });

  await t.test('one\'s own details: the card, a Picture tab and the address to edit', async () => {
    const { status, text } = await get(srv.base, '/icq/details?id=1005812876&icq=100001&own=1&lang=en');
    assert.equal(status, 200);
    assert.match(text, /<title>My details/);
    assert.match(text, /<a href="#" class="on" onclick="return false;">My details<\/a><a href="\/icq\/avatar\?id=1005812876&amp;lang=en&amp;from=details&amp;icq=100001">Picture<\/a>/);
    // Inside ICQ the account page is an address to copy, not a link.
    assert.match(text, /<input type="text" id="editAddress" readonly [^>]*value="https:\/\/[^"]*\/profile\?lang=en"/);
    assert.doesNotMatch(text, /OpenUrl|window\.open\(|target="_blank"/);
    assert.match(text, /plugin\.Initialize\("1005812876"\)/);
    for (const s of scripts(text)) assert.doesNotMatch(s, MODERN_JS);
  });

  await t.test('opened in a browser, the account page is a link', async () => {
    const { text } = await get(srv.base, '/icq/details?icq=100001&own=1&lang=en');
    assert.match(text, /<a href="https:\/\/[^"]*\/profile\?lang=en">Change my details/);
    assert.doesNotMatch(text, /<OBJECT/i);
  });

  await t.test('a contact\'s details: the card only', async () => {
    const { text } = await get(srv.base, '/icq/details?id=1005812876&icq=100002&lang=uk');
    assert.match(text, /<title>Анкета 100002/);
    assert.doesNotMatch(text, /class="tabs"|editAddress/);
    for (const s of scripts(text)) assert.doesNotMatch(s, MODERN_JS);
  });

  await t.test('a number that is no number is not taken', async () => {
    const { text } = await get(srv.base, '/icq/details?id=1&icq=%3Cscript%3E&lang=en');
    assert.doesNotMatch(text, /<script>/);
    assert.match(text, /id="dtState"/);
  });

  await t.test('the picture page has a tab back to the details', async () => {
    const { text } = await get(srv.base, '/icq/avatar?id=1005812876&lang=en&from=details&icq=100001');
    assert.match(text, /<div class="tabs" style=""><a href="\/icq\/details\?id=1005812876&amp;icq=100001&amp;own=1&amp;lang=en">My details<\/a><a href="#" id="tabPicture"/);
    const plain = (await get(srv.base, '/icq/avatar?id=1005812876&lang=en')).text;
    assert.doesNotMatch(plain, /\/icq\/details/);
  });

  await t.test('the details route comes before the catch-all', () => {
    const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, 'services.json'), 'utf8'));
    const i = cfg.routes.findIndex((r) => r.action === 'details');
    const stub = cfg.routes.findIndex((r) => r.path === '^/icq/stub');
    assert.ok(i >= 0 && i < stub);
  });
});
