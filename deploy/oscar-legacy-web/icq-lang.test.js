// Pages ICQ 6.5 opens in its Xtra windows follow ICQ's own interface
// language (revivalIcqLang, via plugin.GetIMClientData("LANG_ID")); opened
// in a browser they keep going by Accept-Language.

const test = require('node:test');
const assert = require('node:assert/strict');
const { start, get, scripts, MODERN_JS } = require('./test-server.js');

test('ICQ interface language on the pages of its Xtra windows', async (t) => {
  const srv = await start(false);
  t.after(() => srv.stop());

  await t.test('the welcome window asks ICQ for its language', async () => {
    const { status, text } = await get(srv.base, '/icq/welcome?bld=2024&dst=60007&id=1005812876&mode=0');
    assert.equal(status, 200);
    assert.match(text, /GetIMClientData\('LANG_ID'\)/);
    assert.match(text, /plugin\.Initialize\("1005812876"\)/);
    for (const s of scripts(text)) assert.doesNotMatch(s, MODERN_JS);
  });

  await t.test('the welcome page in a browser does not', async () => {
    const { text } = await get(srv.base, '/icq/welcome');
    assert.doesNotMatch(text, /GetIMClientData/);
  });

  await t.test('the picture page asks after connecting', async () => {
    const { status, text } = await get(srv.base, '/icq/avatar?id=1005812876');
    assert.equal(status, 200);
    assert.match(text, /function revivalIcqLang/);
    assert.match(text, /if \(revivalIcqLang\(LANG\)\) \{ return; \}/);
    for (const s of scripts(text)) assert.doesNotMatch(s, MODERN_JS);
  });

  await t.test('the language is chosen by the ICQ locale', () => {
    // The mapping inside revivalIcqLang, run the way the page runs it.
    const { text } = { text: require('node:fs').readFileSync(require('node:path').join(__dirname, 'server.js'), 'utf8') };
    const body = /const ICQ_LANG_SCRIPT = `([\s\S]*?)`;/.exec(text)[1];
    const run = (locale, search) => {
      let replaced = null;
      const plugin = { GetIMClientData: () => locale };
      const window = { location: { search, pathname: '/icq/avatar', replace: (u) => { replaced = u; } } };
      // eslint-disable-next-line no-new-func
      new Function('plugin', 'window', `${body}; return revivalIcqLang('en');`)(plugin, window);
      return replaced;
    };
    assert.equal(run('ua-ua', '?id=1'), '/icq/avatar?id=1&lang=uk');
    assert.equal(run('ru-ru', '?id=1'), null);
    assert.equal(run('en-us', '?id=1'), null);
    assert.equal(run('ua-ua', '?id=1&lang=en'), null, 'an explicit choice wins');
  });
});
