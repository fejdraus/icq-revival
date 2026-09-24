// Stand-in for the dead ICQ web services.
//
// Clients from 98 to 5.1 talk HTTP to cf.icq.com, web.icq.com, wwp.icq.com and
// other AOL hosts. None of them answer any more, yet DNS still resolves them, so
// the client hangs until the TCP timeout instead of failing fast. This service
// answers for them: some pages are genuinely restored, the rest return a clear
// stub instead of a hang.
//
// It runs in two modes, both described in services.json; no address is hard
// coded here:
//
//   by path  - the client points at an arbitrary server address (/icq/today and
//              so on). The Host header can be anything; the address is chosen by
//              whoever runs the client. This is the main mode.
//   by name  - the original ICQ.com names are intercepted through DNS or hosts.
//              Needed when the address is baked into the client and no config
//              can change it.
//
// The route is the first matching rule: paths first, then names.
//
// No dependencies, the standard library only.

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const child_process = require('node:child_process');
// The shared look of the project, the same as registration and the admin page.
const { STYLE: SHARED_STYLE, LANGS, FALLBACK_LANG, pickLang,
  langLabel, header, footer, serveAsset } = require('./ui.js');

const PORT = Number(process.env.PORT || 8101);
// Clients connect to the address written in their own config, so the service has
// to be reachable on the network. The default is still the loopback: opening it
// up should be a deliberate act.
const BIND = process.env.BIND || '127.0.0.1';
const CONFIG_PATH = process.env.CONFIG || path.join(__dirname, 'services.json');

// The ICQ code books (countries, interests), the same ones the profile page
// uses. Without the file a card simply shows no decoded names instead of
// failing.
// The Xtraz list ICQ 6 fills its own windows from. It is the original list with
// one entry of ours added: serving a shorter one replaces the client's own
// categories, and the strip at the top loses everything it had.
let xtrazList = '<xtrazList majorVer="1" minorVer="0"><groups/><xtraz/></xtrazList>';
try {
  xtrazList = fs.readFileSync(path.join(__dirname, 'xtrazlist.xml'), 'utf8');
} catch {
  // Without the file the gallery stays as it was: the client reports a problem.
}

let CODES = {};
try {
  CODES = JSON.parse(fs.readFileSync(path.join(__dirname, 'icq-codes.json'), 'utf8'));
} catch {
  CODES = {};
}

// ------------------------------------------------------------------- config

function loadConfig() {
  const cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  if (!Array.isArray(cfg.routes) || cfg.routes.length === 0) {
    throw new Error(`${CONFIG_PATH}: routes is empty`);
  }
  for (const [i, r] of cfg.routes.entries()) {
    if (!r.action) throw new Error(`${CONFIG_PATH}: route #${i} has no action`);
    if (!ACTIONS[r.action]) {
      throw new Error(`${CONFIG_PATH}: route #${i}: unknown action "${r.action}"`);
    }
    // Compile the regular expressions once; this also catches typos at startup.
    r._path = r.path ? new RegExp(r.path, 'i') : null;
  }
  // Environment variables override the file, which is handy under systemd.
  cfg.mgmtApi = process.env.MGMT_API || cfg.mgmtApi || 'http://127.0.0.1:8090';
  cfg.registerBase = process.env.REGISTER_BASE || cfg.registerBase || '';
  cfg.serverName = process.env.SERVER_NAME || cfg.serverName || 'ICQ Revival';
  cfg.oscarHost = process.env.OSCAR_HOST || cfg.oscarHost || '';
  return cfg;
}

// Filled in at the end of the file: loadConfig validates actions against the
// ACTIONS table, which is a const and, unlike a function, is not hoisted.
let config;

// The ICQ.com help topics: what each one was and what replaces it. Lives next to
// the config and is reloaded together with it.
let topics = {};

function loadTopics() {
  const file = path.join(path.dirname(CONFIG_PATH), 'topics.json');
  try {
    topics = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    console.error(`topics not loaded (${err.message}), falling back to the generic stub`);
    topics = {};
  }
}

function hostMatches(pattern, host) {
  if (!pattern || pattern === '*') return true;
  if (pattern.startsWith('*.')) return host === pattern.slice(2) || host.endsWith(pattern.slice(1));
  return host === pattern.toLowerCase();
}

// Match the path together with the query string: several services name the
// topic in the parameters, e.g. /cgi-bin/support.pl5?topic=Registration_2001b.
function pickRoute(host, pathAndQuery) {
  return config.routes.find(
    (r) => hostMatches(r.host, host) && (!r._path || r._path.test(pathAndQuery)),
  );
}

function expand(target, vars) {
  return String(target || '').replace(/\{(\w+)\}/g, (all, key) => (
    key in vars ? vars[key] : all
  ));
}

// ---------------------------------------------------------------- management

async function mgmt(apiPath, options = {}) {
  const res = await fetch(config.mgmtApi + apiPath, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) {
    throw new Error(`${options.method || 'GET'} ${apiPath}: HTTP ${res.status}`);
  }
  // Some routes answer with plain text ("Message sent") rather than JSON.
  const type = res.headers.get('content-type') || '';
  if (res.status === 204 || !type.includes('json')) {
    await res.arrayBuffer();
    return null;
  }
  return res.json();
}

// ---------------------------------------------------------------- translations
//
// The languages are the ones registration and the admin page use, taken from the
// shared module. Chosen by the ?lang= parameter, otherwise by Accept-Language.

const I18N = {
  en: {
    poweredBy: 'powered by ICQ Revival',
    welcomeTitle: 'Welcome',
    welcomeSub: 'the old ICQ, back on the air',
    signedInAs: (u) => `Signed in as <b>${u}</b>`,
    signedIn: 'Signed in',
    dirDown: 'the server directory is not answering',
    nobodyElse: 'nobody else is online',
    othersOnline: (n) => `<b>${n}</b> other${n === 1 ? '' : 's'} online`,
    intro: 'A private ICQ server: the same protocol and the same clients you '
      + 'remember, talking to something that answers again. Contact list, offline '
      + 'messages, statuses, search and file transfer all work. ICQ.com itself is '
      + 'long gone, so the menu items that pointed there now point here.',
    lnkToday: 'Who is online right now',
    lnkFind: 'Look up a user by number',
    lnkPager: 'Send a message from the web pager',
    lnkPwd: 'Change or recover your password',
    lnkProfile: 'Your profile: details, password, email',
    lnkAccount: 'Change your number, or close your account',
    lnkSendSomeone: 'Send a message to someone',

    todayTitle: 'Who Is Online',
    colNumber: 'Number',
    colStatus: 'Status',
    colOnlineFor: 'Online for',
    nobodyOnline: 'Nobody is online right now.',
    onlineNow: (n) => `Online now: ${n}`,
    loadFailed: (e) => `Could not load the list: ${e}`,

    findTitle: 'Find a User',
    icqNumber: 'ICQ number:',
    searchBtn: 'Search',
    notRegistered: (u) => `Number <b>${u}</b> is not registered on this server.`,
    serverSilent: (e) => `The server did not respond: ${e}`,
    sendViaPager: 'Send a message with the Web Pager',

    pagerTitle: 'Web Pager',
    toNumber: 'To (number):',
    fromLabel: 'From:',
    sendBtn: 'Send',
    sendAMessage: 'Send a message',
    offlineNote: 'If the recipient is offline, the message arrives at their next sign-in.',
    badNumber: 'That number is not valid.',
    emptyMessage: 'The message is empty.',
    tooOften: 'Too many messages. Please wait a minute.',
    notSent: (e) => `Not sent: ${e}`,
    accepted: (u) => `Message for <b>${u}</b> accepted.`,
    writeAnother: 'Write another',

    cSignedInFor: 'Signed in for',
    cAbout: 'About',
    cAccount: 'Account',
    cSuspended: 'suspended',
    cNick: 'Nickname',
    cName: 'Name',
    cGender: 'Gender',
    cMale: 'male',
    cFemale: 'female',
    cAge: 'Age',
    cYears: (n) => `${n}`,
    cCity: 'City',
    cCountry: 'Country',
    cFrom: 'Originally from',
    cHomepage: 'Homepage',
    cInterests: 'Interests',
    cEmail: 'E-mail',
    sOnline: 'online',
    sOffline: 'offline',
    sAway: 'away',
    sIdleFor: (d) => `idle for ${d}`,

    centreTitle: 'Messaging Centre',
    centreSub: 'your account on this server',
    centreAbout: 'About this page',
    centreText: 'The original messaging centre gathered what people sent you through '
      + 'the ICQ.com web page, by e-mail and by SMS. Those gateways are gone. Messages '
      + 'sent from a client arrive in the client itself, including the ones sent while '
      + 'you were offline.',

    howtoTitle: 'How to start',
    howtoSub: 'the short version',
    howtoYou: (u) => `Your number is <b>${u}</b> — that is what people need to add you.`,
    howtoSteps: 'Getting going',
    howtoAdd: 'Add a friend with the <b>Add</b> button in the contact list: type their '
      + 'number and wait for them to accept. The number is the address here, there is '
      + 'no search by e-mail.',
    howtoInvite: 'Your friend has no number yet? Send them the registration page — it '
      + 'takes a minute.',
    howtoOffline: 'Write to people who are not online. The message waits on the server '
      + 'and arrives the moment they sign in.',
    howtoFiles: 'File transfer, statuses and away messages work as they always did.',
    howtoSettings: 'Server settings, should you ever need them again',
    howtoPorts: 'Clients of that era knew no encryption and need the plain port with SSL '
      + 'switched off. If your client does support SSL, turn it on and use the SSL port.',
    howtoPlain: 'plain port',
    howtoSsl: 'port with SSL',
    howtoServer: 'Server',
    lnkRegister: 'Get a number for a friend',
    stubTitle: 'Service Unavailable',
    stubWorks: 'What does work here',
    topicUse: 'How to use it',
    topicSub: 'what this was',
    topicSubNow: 'how it works here',
    stubP1: (n) => `The <b>${n}</b> section was hosted on ICQ.com servers and no longer exists.`,
    stubP2: 'This client runs against its own server, which does not provide that '
      + 'service. The contact list, messages and statuses are unaffected.',
    errorTitle: 'Error',
    unit: { h: 'h', m: 'm', s: 's' },
  },

  uk: {
    poweredBy: 'працює на ICQ Revival',
    welcomeTitle: 'Ласкаво просимо',
    welcomeSub: 'стара ICQ знову в ефірі',
    signedInAs: (u) => `Ви увійшли як <b>${u}</b>`,
    signedIn: 'Ви увійшли',
    dirDown: 'каталог сервера не відповідає',
    nobodyElse: 'більше нікого немає в мережі',
    othersOnline: (n) => `<b>${n}</b> ${n === 1 ? 'інший' : 'інших'} у мережі`,
    intro: 'Приватний сервер ICQ: той самий протокол і ті самі клієнти, що ви '
      + 'пам’ятаєте, знову мають із ким розмовляти. Список контактів, повідомлення '
      + 'офлайн, статуси, пошук і передавання файлів працюють. Самої ICQ.com давно '
      + 'немає, тож пункти меню, які вели туди, тепер ведуть сюди.',
    lnkToday: 'Хто зараз у мережі',
    lnkFind: 'Знайти користувача за номером',
    lnkPager: 'Надіслати повідомлення з веб-пейджера',
    lnkPwd: 'Змінити або відновити пароль',
    lnkProfile: 'Ваш профіль: анкета, пароль, пошта',
    lnkAccount: 'Змінити номер або видалити обліковий запис',
    lnkSendSomeone: 'Надіслати комусь повідомлення',

    todayTitle: 'Хто в мережі',
    colNumber: 'Номер',
    colStatus: 'Статус',
    colOnlineFor: 'У мережі',
    nobodyOnline: 'Зараз нікого немає в мережі.',
    onlineNow: (n) => `У мережі: ${n}`,
    loadFailed: (e) => `Не вдалося отримати список: ${e}`,

    findTitle: 'Пошук користувача',
    icqNumber: 'Номер ICQ:',
    searchBtn: 'Знайти',
    notRegistered: (u) => `Номер <b>${u}</b> не зареєстрований на цьому сервері.`,
    serverSilent: (e) => `Сервер не відповів: ${e}`,
    sendViaPager: 'Надіслати повідомлення через веб-пейджер',

    pagerTitle: 'Веб-пейджер',
    toNumber: 'Кому (номер):',
    fromLabel: 'Від кого:',
    sendBtn: 'Надіслати',
    sendAMessage: 'Надіслати повідомлення',
    offlineNote: 'Якщо одержувач не в мережі, повідомлення надійде під час наступного входу.',
    badNumber: 'Номер вказано неправильно.',
    emptyMessage: 'Повідомлення порожнє.',
    tooOften: 'Занадто часто. Зачекайте хвилину.',
    notSent: (e) => `Не надіслано: ${e}`,
    accepted: (u) => `Повідомлення для <b>${u}</b> прийнято.`,
    writeAnother: 'Написати ще',

    cSignedInFor: 'У мережі вже',
    cAbout: 'Про себе',
    cAccount: 'Обліковий запис',
    cSuspended: 'заблоковано',
    cNick: 'Нік',
    cName: "Ім'я",
    cGender: 'Стать',
    cMale: 'чоловіча',
    cFemale: 'жіноча',
    cAge: 'Вік',
    cYears: (n) => `${n}`,
    cCity: 'Місто',
    cCountry: 'Країна',
    cFrom: 'Родом з',
    cHomepage: 'Домашня сторінка',
    cInterests: 'Інтереси',
    cEmail: 'Пошта',
    sOnline: 'у мережі',
    sOffline: 'не в мережі',
    sAway: 'відійшов',
    sIdleFor: (d) => `неактивний ${d}`,

    centreTitle: 'Центр повідомлень',
    centreSub: 'ваш обліковий запис на цьому сервері',
    centreAbout: 'Про цю сторінку',
    centreText: 'Первісний центр повідомлень збирав те, що вам надсилали через '
      + 'вебсторінку ICQ.com, електронною поштою та в SMS. Тих шлюзів більше немає. '
      + 'Повідомлення з клієнта надходять просто в клієнт, зокрема й надіслані, '
      + 'поки вас не було в мережі.',

    howtoTitle: 'Як почати',
    howtoSub: 'коротко',
    howtoYou: (u) => `Ваш номер — <b>${u}</b>, саме його потрібно знати тим, хто вас додає.`,
    howtoSteps: 'З чого почати',
    howtoAdd: 'Додайте друга кнопкою <b>Add</b> у списку контактів: введіть '
      + 'його номер і зачекайте підтвердження. Адресою тут є номер, пошуку '
      + 'за поштою немає.',
    howtoInvite: 'У друга ще немає номера? Надішліть йому сторінку '
      + 'реєстрації — це справа однієї хвилини.',
    howtoOffline: 'Пишіть тим, кого немає в мережі: повідомлення '
      + 'зачекає на сервері й надійде, тільки вони увійдуть.',
    howtoFiles: 'Передавання файлів, статуси та повідомлення про відсутність '
      + 'працюють як і раніше.',
    howtoSettings: 'Налаштування сервера, якщо знадобляться знову',
    howtoPorts: 'Клієнти тих років шифрування не знали: їм потрібен '
      + 'звичайний порт із вимкненим SSL. Якщо клієнт уміє SSL, увімкніть '
      + 'його та вкажіть порт із SSL.',
    howtoPlain: 'звичайний порт',
    howtoSsl: 'порт із SSL',
    howtoServer: 'Сервер',
    lnkRegister: 'Отримати номер для друга',
    stubTitle: 'Служба недоступна',
    stubWorks: 'Що тут працює',
    topicUse: 'Як користуватися',
    topicSub: 'що це було',
    topicSubNow: 'як це працює',
    stubP1: (n) => `Розділ <b>${n}</b> розміщувався на серверах ICQ.com і більше не існує.`,
    stubP2: 'Клієнт працює через власний сервер, у якого цієї служби немає. '
      + 'На список контактів, повідомлення та статуси це не впливає.',
    errorTitle: 'Помилка',
    unit: { h: 'год', m: 'хв', s: 'с' },
  },
};

function dict(lang) {
  return I18N[lang] || I18N[FALLBACK_LANG];
}

// The switcher links: pages are served without scripts, so we simply reload the
// same page with a different ?lang=.
function langSwitch(lang, selfUrl) {
  const parts = LANGS.map((code) => {
    const url = new URL(selfUrl || '/', 'http://x');
    url.searchParams.set('lang', code);
    const href = escapeHtml(url.pathname + url.search);
    return code === lang
      ? `<b>${langLabel(code)}</b>`
      : `<a href="${href}">${langLabel(code)}</a>`;
  });
  return parts.join(' ');
}

// ----------------------------------------------------------------------- layout

// The pages are rendered by an embedded Internet Explorer 5-6. No flexbox, no
// custom properties, no external files: tables and inline styles, or it breaks.
const FONT = 'font-family:Tahoma,Arial,sans-serif;font-size:13px';

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

// The shell shared by every page: the same green header with the flower as the
// welcome screen. The styling lives in a style sheet rather than inline: even
// IE 5 understands classes and borders, and simply skips rounded corners and
// shadows. The layout is still built on tables, because the Today panel is drawn
// by the embedded engine.

// compact is for the pages the client draws itself in its small fixed-size
// window (the welcome screen, the Today panel). Everything else opens in an
// external browser, which needs no cramping.
// Two shells for two consumers.
//
// roomy   - the page is opened by an ordinary browser. The markup and style
//           sheet are the ones registration and the admin page use: one look
//           across the services.
// compact - the page is drawn by the client's own embedded engine in a small
//           window: tables instead of blocks, a pixel flower instead of SVG.
// One shell for everybody, the same as registration and the admin page. The only
// difference is density: inside the client the window is small, so body gets the
// compact class and the shared style sheet tightens the spacing.
function page(title, bodyHtml, subtitle, compact, u) {
  const langs = u ? langSwitch(u.lang, u.selfUrl) : '';
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${SHARED_STYLE}</style>
</head>
<body${compact ? ' class="compact"' : ''}>
<main class="window">
  ${header(escapeHtml(title), subtitle)}
  <div class="body">${bodyHtml}</div>
  ${footer({ langs })}
</main>
</body>
</html>`;
}

function send(res, status, html) {
  const body = Buffer.from(html, 'utf8');
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'content-length': body.length,
    // IE caches aggressively, and Today has to be fresh.
    'cache-control': 'no-cache, no-store',
    'pragma': 'no-cache',
  });
  res.end(body);
}

function sendText(res, text) {
  const body = Buffer.from(text, 'utf8');
  res.writeHead(200, {
    'content-type': 'text/plain; charset=utf-8',
    'content-length': body.length,
  });
  res.end(body);
}

function redirect(res, url) {
  res.writeHead(302, { location: url, 'content-length': 0 });
  res.end();
}

function formatDuration(seconds, t) {
  const unit = (t || dict(FALLBACK_LANG)).unit;
  const s = Number(seconds) || 0;
  if (s < 60) return `${s}${unit.s}`;
  if (s < 3600) return `${Math.floor(s / 60)}${unit.m}`;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return m ? `${h}${unit.h} ${m}${unit.m}` : `${h}${unit.h}`;
}

// ------------------------------------------------------------------- actions

// The simplest rate limit: the web pager is open to everyone on the tailnet.
const pagerHits = new Map();

function pagerAllowed(ip) {
  const now = Date.now();
  const hits = (pagerHits.get(ip) || []).filter((t) => now - t < 60_000);
  hits.push(now);
  pagerHits.set(ip, hits);
  if (pagerHits.size > 500) pagerHits.clear();
  return hits.length <= 5;
}

// selfPath is the address this very page was opened at. Forms post back to it so
// the service works both under the ICQ.com names and at whatever server address
// the client's config points to.
function pagerForm(uin, message, note, selfPath, cardHtml, u) {
  const t = u.t;
  return page(t.pagerTitle, `
    ${note || ''}
    ${cardHtml || ''}
    ${cardHtml ? '<p style="' + FONT + ';margin:10px 0 4px 0"><b>' + t.sendAMessage + '</b></p>' : ''}
    <form method="post" action="${escapeHtml(selfPath || '')}">
      <table cellpadding="0" cellspacing="0" border="0">
        <tr><td style="${FONT};padding:0 6px 4px 0">${t.toNumber}</td>
            <td style="padding:0 0 4px 0"><input type="text" name="uin" size="14"
                value="${escapeHtml(uin || '')}" style="${FONT}"></td></tr>
        <tr><td style="${FONT};padding:0 6px 4px 0">${t.fromLabel}</td>
            <td style="padding:0 0 4px 0"><input type="text" name="from" size="14"
                value="WebPager" style="${FONT}"></td></tr>
      </table>
      <p><textarea name="text" rows="5" cols="46" style="${FONT}">${escapeHtml(message || '')}</textarea></p>
      <p><input type="submit" value="${t.sendBtn}" style="${FONT}"></p>
    </form>
    <p><font color="#808080">${t.offlineNote}</font></p>`, '', false, u);
}

async function pagerSend(body, ip, selfPath, u) {
  const t = u.t;
  const params = new URLSearchParams(body);
  const uin = (params.get('uin') || '').trim();
  const from = (params.get('from') || 'WebPager').trim().slice(0, 32) || 'WebPager';
  const text = (params.get('text') || '').trim();

  if (!/^\d{4,10}$/.test(uin)) {
    return pagerForm(uin, text, `<p><font color="#c00000">${t.badNumber}</font></p>`, selfPath, null, u);
  }
  if (!text) {
    return pagerForm(uin, text, `<p><font color="#c00000">${t.emptyMessage}</font></p>`, selfPath, null, u);
  }
  if (!pagerAllowed(ip)) {
    return pagerForm(uin, text,
      `<p><font color="#c00000">${t.tooOften}</font></p>`, selfPath, null, u);
  }

  try {
    await mgmt('/instant-message', {
      method: 'POST',
      body: JSON.stringify({ from, to: uin, text: text.slice(0, 2000) }),
    });
  } catch (err) {
    return pagerForm(uin, text,
      `<p><font color="#c00000">${t.notSent(escapeHtml(err.message))}</font></p>`, selfPath, null, u);
  }

  return page(t.pagerTitle, `
    <p>${t.accepted(escapeHtml(uin))}</p>
    <p><a href="${escapeHtml(selfPath || '')}" style="${FONT}">${t.writeAnother}</a></p>`,
    '', false, u);
}

async function todayPage(u) {
  const t = u.t;
  let sessions;
  try {
    const data = await mgmt('/session');
    sessions = (data.sessions || []).filter((s) => !s.is_invisible);
  } catch (err) {
    return page(t.todayTitle, `<p>${t.loadFailed(escapeHtml(err.message))}</p>`,
      '', true, u);
  }

  if (sessions.length === 0) {
    return page(t.todayTitle, `<p>${t.nobodyOnline}</p>`, '', true, u);
  }

  const rows = sessions.map((s) => {
    const status = s.is_away ? t.sAway : s.idle_seconds > 0 ? t.sIdleFor('').trim() : t.sOnline;
    const cls = s.is_away || s.idle_seconds > 0 ? 'warn' : 'ok';
    return `<tr>
      <td style="padding:3px 8px 3px 0;${FONT}"><b>${escapeHtml(s.screen_name)}</b></td>
      <td style="padding:3px 8px 3px 0;${FONT}"><span class="${cls}">${status}</span></td>
      <td style="padding:3px 0"><span class="dim">${formatDuration(s.online_seconds, t)}</span></td>
    </tr>`;
  }).join('');

  return page(t.todayTitle, `
    <table cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding:0 8px 4px 0;${FONT}"><span class="dim">${t.colNumber}</span></td>
        <td style="padding:0 8px 4px 0;${FONT}"><span class="dim">${t.colStatus}</span></td>
        <td style="padding:0 0 4px 0;${FONT}"><span class="dim">${t.colOnlineFor}</span></td>
      </tr>
      ${rows}
    </table>
    <p><span class="dim">${t.onlineNow(sessions.length)}</span></p>`, '', true, u);
}

// A user card: number, state, profile. Shown both in the white pages and above
// the pager form - writing blindly to a number is awkward.
// Returns { exists, html } or { error }.
// Country codes 0 and 0xFFFF mean "unspecified" in an ICQ profile.
function countryName(code) {
  if (!code || code === 65535) return '';
  const table = CODES.countries || {};
  return table[String(code)] || String(code);
}

function ageFrom(y, m, d) {
  if (!y) return 0;
  const now = new Date();
  let age = now.getFullYear() - y;
  const month = (m || 1) - 1;
  const day = d || 1;
  if (now.getMonth() < month || (now.getMonth() === month && now.getDate() < day)) age--;
  return age > 0 && age < 130 ? age : 0;
}

function interestNames(interests) {
  if (!interests) return [];
  const table = CODES.interests || {};
  const out = [];
  for (let i = 1; i <= 4; i++) {
    const code = interests[`code${i}`];
    const word = (interests[`keyword${i}`] || '').trim();
    const name = code ? (table[String(code)] || '') : '';
    if (name && word) out.push(`${name}: ${word}`);
    else if (name) out.push(name);
    else if (word) out.push(word);
  }
  return out;
}

// The profile rows of a card. Empty values are left out: in the ICQ white pages
// an empty field looked exactly like a missing one.
function profileRows(icq, t, row) {
  if (!icq) return [];

  const basic = icq.basic_info || {};
  const more = icq.more_info || {};
  const out = [];

  const add = (label, value) => { if (value) out.push(row(label, escapeHtml(value))); };

  add(t.cNick, (basic.nickname || '').trim());
  add(t.cName, [basic.first_name, basic.last_name].map((v) => (v || '').trim()).filter(Boolean).join(' '));

  if (more.gender === 1 || more.gender === 2) {
    out.push(row(t.cGender, more.gender === 2 ? t.cMale : t.cFemale));
  }

  const age = ageFrom(more.birth_year, more.birth_month, more.birth_day);
  if (age) out.push(row(t.cAge, t.cYears(age)));

  add(t.cCity, (basic.city || '').trim());
  add(t.cCountry, countryName(basic.country_code));

  const from = [(basic.origin_city || '').trim(), countryName(basic.origin_country_code)]
    .filter(Boolean).join(', ');
  add(t.cFrom, from);

  // The address is shown only if the owner allowed it: that is their own profile
  // setting, not ours.
  if (basic.publish_email) add(t.cEmail, (basic.email || '').trim());

  const home = (more.homepage || '').trim();
  if (home && /^https?:\/\//i.test(home)) {
    out.push(row(t.cHomepage,
      `<a href="${escapeHtml(home)}" style="${FONT}">${escapeHtml(home.slice(0, 80))}</a>`));
  } else {
    add(t.cHomepage, home);
  }

  add(t.cInterests, interestNames(icq.interests).join(', '));

  return out;
}

async function userCard(uin, t) {
  let account;
  try {
    account = await mgmt(`/user/${encodeURIComponent(uin)}/account`);
  } catch (err) {
    // A 404 on a number that does not exist is an answer, not a failure.
    if (/HTTP 404/.test(err.message)) return { exists: false };
    return { error: err.message };
  }
  if (!account) return { exists: false };

  let session = null;
  try {
    const data = await mgmt(`/session/${encodeURIComponent(uin)}`);
    session = (data.sessions || []).find((s) => !s.is_invisible) || null;
  } catch {
    // The card still makes sense without the presence state.
  }

  let state;
  if (!session) {
    state = `<span class="dim">${t.sOffline}</span>`;
  } else if (session.is_away) {
    state = `<span class="warn">${t.sAway}</span>`
      + (session.away_message
        ? ` &#8212; ${escapeHtml(session.away_message.replace(/<[^>]*>/g, '').slice(0, 120))}`
        : '');
  } else if (session.idle_seconds > 0) {
    state = `<span class="warn">${t.sIdleFor(formatDuration(session.idle_seconds, t))}</span>`;
  } else {
    state = `<span class="ok">${t.sOnline}</span>`;
  }

  // The profile is stored apart from the account: `/account` knows only the
  // number, the e-mail and the state, while the nickname, name and city live in
  // `/icq`. Without the second request the card showed a number and a status.
  let icq = null;
  if (account.is_icq) {
    try {
      icq = await mgmt(`/user/${encodeURIComponent(uin)}/icq`);
    } catch {
      // There may be no profile at all; the card then lacks these rows.
    }
  }

  const row = (label, value) => `<tr>
    <td valign="top" style="padding:1px 10px 1px 0"><span class="dim">${label}</span></td>
    <td valign="top" style="padding:1px 0">${value}</td></tr>`;

  const about = (account.profile || '').trim() || ((icq && icq.notes) || '').trim();

  const rows = [
    row(t.colNumber, `<b>${escapeHtml(uin)}</b>`),
    row(t.colStatus, state),
    session ? row(t.cSignedInFor, formatDuration(session.online_seconds, t)) : '',
    ...profileRows(icq, t, row),
    // "About" lives in the profile for AIM and in the profile notes for ICQ.
    about ? row(t.cAbout, escapeHtml(about.replace(/<[^>]*>/g, '').slice(0, 400))) : '',
    account.suspended_status ? row(t.cAccount, `<span class="bad">${t.cSuspended}</span>`) : '',
  ].join('');

  return {
    exists: true,
    html: `<div class="card">
      <table cellpadding="0" cellspacing="0" border="0">${rows}</table>
    </div>`,
  };
}

async function whitepagesPage(uin, selfPath, u) {
  const t = u.t;
  if (!uin) {
    return page(t.findTitle, `
      <form method="get" action="${escapeHtml(selfPath || '')}">
        <p>${t.icqNumber}
        <input type="text" name="icq" size="14" style="${FONT}">
        <input type="submit" value="${t.searchBtn}" style="${FONT}"></p>
      </form>`, '', false, u);
  }

  const card = await userCard(uin, t);
  if (card.error) {
    return page(t.findTitle, `<p>${t.serverSilent(escapeHtml(card.error))}</p>`, '', false, u);
  }
  if (!card.exists) {
    return page(t.findTitle, `<p>${t.notRegistered(escapeHtml(uin))}</p>`, '', false, u);
  }

  return page(t.findTitle, `
    ${card.html}
    <p style="margin:10px 0 0 0"><a href="${escapeHtml(pagerLink(uin))}"
       style="${FONT}">${t.sendViaPager}</a></p>`, '', false, u);
}

// The link from a user card to the web pager. The address comes from the config:
// http://wwp.icq.com/wwp/ when the ICQ.com names are intercepted, a plain path
// when the server has an address of its own.
function pagerLink(uin) {
  const base = (config.links && config.links.pager) || '/icq/wwp';
  return base + (base.includes('?') ? '&' : '?') + 'Uin=' + encodeURIComponent(uin);
}

// The "ICQ Welcome" window opens after sign-in. It used to carry ICQ.com
// advertising; now it greets the user and reports the state of their server.
async function welcomePage(uin, selfPath, u) {
  const t = u.t;
  let online = null;
  try {
    const data = await mgmt('/session');
    // There is no point listing yourself among "who else is online".
    online = (data.sessions || [])
      .filter((s) => !s.is_invisible && s.screen_name !== uin);
  } catch {
    // The management server is unreachable; greet the user anyway.
  }

  const base = selfPath.replace(/\/welcome.*$/, '');
  const item = (href, text) => `<tr>
    <td valign="top" width="13" style="padding:3px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:1px 0 2px 0">
      <a href="${escapeHtml(base + href)}">${text}</a>
    </td></tr>`;

  const who = uin ? t.signedInAs(escapeHtml(uin)) : t.signedIn;

  let status;
  if (online === null) {
    status = `<span class="warn">${t.dirDown}</span>`;
  } else if (online.length === 0) {
    status = `<span class="dim">${t.nobodyElse}</span>`;
  } else {
    // Only the count: the numbers themselves are on the "who is online" page,
    // linked right here, so repeating them in the status line adds nothing.
    status = t.othersOnline(online.length);
  }

  return page(t.welcomeTitle, `
    <div class="panel">${who} &#183; ${status}</div>

    <p>${t.intro}</p>

    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">
        ${item('/today', t.lnkToday)}
        ${item('/whitepages', t.lnkFind)}
        ${item('/wwp', t.lnkPager)}
        ${item('/password', t.lnkPwd)}
        ${item('/account', t.lnkAccount)}
      </table>
    </div>`, t.welcomeSub, true, u);
}

// "User's Unified Messaging Center" is a button in the message window. It used
// to collect the messages that reached the number's owner over the web, e-mail
// and SMS. Those services are gone, so we show the state of the account.
async function centerPage(uin, selfPath, u) {
  const t = u.t;
  const base = selfPath.replace(/\/center.*$/, '');
  const item = (href, text) => `<tr>
    <td valign="top" width="13" style="padding:3px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:1px 0 2px 0"><a href="${escapeHtml(base + href)}">${text}</a></td>
  </tr>`;

  const card = /^\d{4,10}$/.test(uin) ? await userCard(uin, t) : { exists: false };
  const head = card.exists
    ? card.html
    : `<div class="card">${t.colNumber} <b>${escapeHtml(uin || '&#8212;')}</b></div>`;

  return page(t.centreTitle, `
    ${head}

    <h2>${t.centreAbout}</h2>
    <p>${t.centreText}</p>

    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">
        ${item('/wwp', t.lnkSendSomeone)}
        ${item('/today', t.lnkToday)}
        ${item('/whitepages', t.lnkFind)}
        ${item('/password', t.lnkPwd)}
        ${item('/account', t.lnkAccount)}
      </table>
    </div>`, t.centreSub, false, u);
}

// "How to Start" from the contact list. It used to lead to a stub; now it is a
// short guide: the owner's number, how to add a buddy, how to invite a new one.
function howtoPage(uin, selfPath, u) {
  const t = u.t;
  const base = selfPath.replace(/\/howto.*$/, '');
  const item = (text) => `<tr>
    <td valign="top" width="14" style="padding:4px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:1px 0 6px 0">${text}</td></tr>`;

  const reg = config.registerBase
    ? `<p><a href="${escapeHtml(config.registerBase)}">${t.lnkRegister}</a></p>`
    : '';

  const host = config.oscarHost || '';
  const ports = host
    ? `<div class="card">
        <table cellpadding="0" cellspacing="0" border="0">
          <tr><td style="padding:1px 10px 1px 0"><span class="dim">${t.howtoServer}</span></td>
              <td><code>${escapeHtml(host)}</code></td></tr>
          <tr><td style="padding:1px 10px 1px 0"><span class="dim">${t.howtoPlain}</span></td>
              <td><code>5190</code></td></tr>
          <tr><td style="padding:1px 10px 1px 0"><span class="dim">${t.howtoSsl}</span></td>
              <td><code>5193</code></td></tr>
        </table>
      </div>
      <p><span class="dim">${t.howtoPorts}</span></p>`
    : '';

  return page(t.howtoTitle, `
    <div class="panel">${uin ? t.howtoYou(escapeHtml(uin)) : ''}</div>

    <h2>${t.howtoSteps}</h2>
    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">
        ${item(t.howtoAdd)}
        ${item(t.howtoInvite)}
        ${item(t.howtoOffline)}
        ${item(t.howtoFiles)}
      </table>
    </div>
    ${reg}

    ${host ? `<h2>${t.howtoSettings}</h2>` : ''}
    ${ports}`, t.howtoSub, false, u);
}

function stubPage(topic, u, compact = false) {
  const t = u.t;
  const slug = topic.replace(/\.html?$/i, '').trim().toLowerCase();

  // Aliases: several ICQ.com addresses led to one and the same topic.
  let entry = topics[slug];
  if (entry && entry.alias_topic) entry = topics[entry.alias_topic];

  const item = (href, text) => `<tr>
    <td valign="top" width="14" style="padding:5px 0 0 0">
      <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
    </td>
    <td style="padding:2px 0 4px 0"><a href="${escapeHtml('/icq' + href)}">${text}</a></td>
  </tr>`;

  const LABEL = {
    '/howto': t.howtoTitle,
    '/today': t.lnkToday,
    '/whitepages': t.lnkFind,
    '/wwp': t.lnkPager,
    '/password': t.lnkPwd,
    '/profile': t.lnkProfile,
    '/account': t.lnkAccount,
  };

  if (entry && entry[u.lang]) {
    const e = entry[u.lang];
    const links = (entry.links || []).map((h) => item(h, LABEL[h] || h)).join('');
    // If the service works, describe it and how to use it. If not, say what it
    // was and what replaces it. The "on this server" caveats fit only the
    // latter case.
    const steps = (e.use || [])
      .map((line) => `<tr>
        <td valign="top" width="14" style="padding:5px 0 0 0">
          <table cellpadding="0" cellspacing="0" border="0"><tr><td class="bul"></td></tr></table>
        </td>
        <td style="padding:2px 0 4px 0">${line}</td></tr>`).join('');
    const body = steps
      ? `<h2>${t.topicUse}</h2>
         <div class="soft">
           <table cellpadding="0" cellspacing="0" border="0">${steps}</table>
         </div>
         ${e.note ? `<p><span class="dim">${e.note}</span></p>` : ''}`
      : `<p>${e.here}</p>`;
    return page(e.title, `
      <p>${e.text}</p>
      ${body}
      ${links ? `<h2>${t.stubWorks}</h2>
      <div class="soft">
        <table cellpadding="0" cellspacing="0" border="0">${links}</table>
      </div>` : ''}`, entry.now ? t.topicSubNow : t.topicSub, compact, u);
  }

  // The topic is missing from the dictionary: a generic page, still with links.
  let nice = topic.replace(/\.html?$/i, '').replace(/[_\-]+/g, ' ').trim();
  if (!/[a-zа-яё]{3}/i.test(nice)) nice = '';
  const all = ['/howto', '/today', '/whitepages', '/wwp', '/profile', '/password', '/account']
    .map((h) => item(h, LABEL[h])).join('');
  return page(t.stubTitle, `
    <p>${t.stubP1(escapeHtml(nice || 'ICQ.com'))}</p>
    <p>${t.stubP2}</p>

    <h2>${t.stubWorks}</h2>
    <div class="soft">
      <table cellpadding="0" cellspacing="0" border="0">${all}</table>
    </div>`, '', false, u);
}

function hostsFileText(serviceAddress) {
  const names = (config.hostsFile && config.hostsFile.names) || [];
  const lines = names.map((n) => `${serviceAddress}\t${n}`);
  return [
    '# Dead ICQ web services, intercepted by a local server.',
    '# Add to %SystemRoot%\System32\drivers\etc\hosts as administrator.',
    '# To undo, delete this whole block.',
    '',
    ...lines,
    '',
  ].join('\r\n');
}

// The table of known actions. loadConfig checks against it so that a typo in the
// config surfaces at startup rather than on the first request.
// The page that sets the user's own picture, served to the client as an Xtra.
// Read once at startup like the other data files next to this one.
const avatarPage = fs.readFileSync(path.join(__dirname, 'pages', 'avatar.html'), 'utf8');


// Pictures on their way from the page to the client, held in memory for a few
// minutes each. A picture is wanted exactly once - ICQ fetches the address it
// was handed, uploads the image to the server under the user's name, and never
// asks again - so nothing is written to disk.
const pictures = new Map();
const PICTURE_TTL = 5 * 60 * 1000;
// Generous: a photograph straight from a phone is a normal thing to pick, and
// it is scaled down here anyway. The limit only guards against someone sending
// something absurd.
const PICTURE_MAX = 16 * 1024 * 1024;

// The address a request reached us at, for links the client is sent back to
// follow: the Xtraz entries, the uploaded picture. nginx serves these pages
// over HTTPS on 8102 and says so in X-Forwarded-Proto; requests straight to
// 8101 are plain HTTP. The Host header carries the port either way.
function selfBase(req) {
  const proto = req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  return `${proto}://${req.headers.host || ''}`;
}

// The same host on this service's own plain HTTP port, whichever way the
// request arrived.
function plainBase(req) {
  const host = String(req.headers.host || '').replace(/:\d+$/, '');
  return `http://${host}:${PORT}`;
}

function uploadPicture(ctx) {
  const type = ctx.req.headers['content-type'] || '';
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(type);
  if (!boundary) { send(ctx.res, 400, uploadReply('', 'not a form upload', '')); return; }
  const mark = Buffer.from('--' + (boundary[1] || boundary[2]).trim());

  const chunks = [];
  let size = 0;
  let stopped = false;
  ctx.req.on('data', (c) => {
    size += c.length;
    // Keep reading to the end even when it is too much: cutting the connection
    // here leaves the page with no answer at all, waiting forever.
    if (size > PICTURE_MAX) { stopped = true; chunks.length = 0; return; }
    chunks.push(c);
  });
  ctx.req.on('end', () => {
    if (stopped) {
      send(ctx.res, 200, uploadReply('', 'the file is larger than 16 MB', ''));
      return;
    }
    const body = Buffer.concat(chunks);
    // One part is expected. Its headers end at the first blank line, and the
    // data runs up to the next boundary, minus the CRLF that precedes it.
    const start = body.indexOf(mark);
    const headEnd = body.indexOf(String.fromCharCode(13, 10, 13, 10), start);
    const next = body.indexOf(mark, headEnd);
    if (start < 0 || headEnd < 0 || next < 0) {
      send(ctx.res, 200, uploadReply('', 'the upload is malformed', ''));
      return;
    }
    const head = body.slice(start, headEnd).toString('latin1');
    const kind = new RegExp('content-type:\\s*([^\\r\\n]+)', 'i').exec(head);
    const data = body.slice(headEnd + 4, next - 2);
    if (!data.length) { send(ctx.res, 200, uploadReply('', 'the file is empty', '')); return; }

    const small = shrink(data);
    const id = crypto.randomBytes(8).toString('hex');
    pictures.set(id, small.body === data
      ? { body: data, type: (kind ? kind[1].trim() : 'image/jpeg') }
      : { body: small.body, type: pictureType(small.body) });
    setTimeout(() => pictures.delete(id), PICTURE_TTL).unref();
    const self = selfBase(ctx.req);
    // Two addresses for the same picture. The page shows it by the scheme the
    // page itself came in on. The client is handed a plain HTTP one: ICQ 6.5
    // downloads the picture with a loader of its own that does not speak HTTPS
    // at all - it drops an https:// address without even connecting - while
    // everything else it opens, this page included, works over HTTPS.
    const file = `/icq/avatar/file/${id}`;
    send(ctx.res, 200, uploadReply(`${self}${file}`, '', small.note, `${plainBase(ctx.req)}${file}`));
  });
}

// Squares off and scales down anything large. A buddy icon travels with
// presence and is downloaded by every contact, so a photograph straight from a
// phone has no business going through as it is. Done by a small Python script
// next to this file, since the only image library here is the one Python has;
// without it the picture goes through untouched.
// The script hands back a PNG where it can and a JPEG where the PNG would be
// too large, so the type is read off the first bytes rather than assumed.
function pictureType(body) {
  return body.length > 8 && body[0] === 0x89 && body[1] === 0x50
    ? 'image/png' : 'image/jpeg';
}

function size(bytes) {
  return bytes < 1024 ? `${bytes} bytes` : `${Math.round(bytes / 1024)} KB`;
}

function shrink(data) {
  try {
    const run = child_process.spawnSync('python3',
      [path.join(__dirname, 'shrink-picture.py')],
      { input: data, maxBuffer: 8 * 1024 * 1024 });
    if (run.status !== 0 || !run.stdout || !run.stdout.length) {
      return { body: data, note: '' };
    }
    if (run.stdout.length >= data.length) { return { body: data, note: '' }; }
    return { body: run.stdout, note: `${size(data.length)} reduced to ${size(run.stdout.length)}` };
  } catch (e) {
    return { body: data, note: '' };
  }
}

// The reply lands in a hidden frame; it tells the page the address to hand to
// the client, or what went wrong.
function uploadReply(url, error, note, clientUrl) {
  const payload = JSON.stringify({ url, error, note: note || '', clientUrl: clientUrl || url });
  return `<!DOCTYPE html><html><body><script>
    parent.uploaded(${payload});
  </script></body></html>`;
}

const ACTIONS = {
  avatarpage: (ctx) => send(ctx.res, 200, avatarPage),

  // Receives a picture from the page and keeps it just long enough for the
  // client to fetch it. The client does not take image data: SetBartItem is
  // given an address, and ICQ downloads it and uploads it to the server itself.
  avatarupload: (ctx) => uploadPicture(ctx),

  // Hands one back out. Short-lived, so nothing accumulates anywhere.
  avatarfile: (ctx) => {
    const item = pictures.get(ctx.path.split('/').pop());
    if (!item) { ctx.res.writeHead(404, { 'content-length': 0 }); ctx.res.end(); return; }
    ctx.res.writeHead(200, { 'content-type': item.type, 'content-length': item.body.length });
    ctx.res.end(item.body);
  },

  drop: (ctx) => { ctx.res.writeHead(404, { 'content-length': 0 }); ctx.res.end(); },

  search: (ctx) => {
    const q = (ctx.url.searchParams.get('q') || '').replace(/^=/, '');
    redirect(ctx.res, expand(ctx.route.target, { ...ctx.vars, q: encodeURIComponent(q) }));
  },

  redirect: (ctx) => {
    if (!config.registerBase && /registerBase/.test(ctx.route.target || '')) {
      send(ctx.res, 200, stubPage(ctx.path, ctx.u));
      return;
    }
    redirect(ctx.res, expand(ctx.route.target, ctx.vars));
  },

  today: async (ctx) => send(ctx.res, 200, await todayPage(ctx.u)),

  center: async (ctx) => send(
    ctx.res, 200,
    await centerPage((ctx.url.searchParams.get('uin')
      || ctx.url.searchParams.get('Uin') || '').trim(), ctx.path, ctx.u),
  ),

  howto: async (ctx) => send(
    ctx.res, 200,
    await howtoPage((ctx.url.searchParams.get('uin') || '').trim(), ctx.path, ctx.u),
  ),

  welcome: async (ctx) => send(
    ctx.res, 200,
    await welcomePage((ctx.url.searchParams.get('uin') || '').trim(), ctx.path, ctx.u),
  ),

  whitepages: async (ctx) => send(
    ctx.res, 200,
    await whitepagesPage((ctx.url.searchParams.get('icq') || '').trim(), ctx.path, ctx.u),
  ),

  pager: async (ctx) => {
    if (ctx.req.method === 'POST') {
      send(ctx.res, 200, await pagerSend(await readBody(ctx.req), ctx.ip, ctx.path, ctx.u));
      return;
    }
    const uin = (ctx.url.searchParams.get('Uin') || ctx.url.searchParams.get('uin') || '').trim();
    // Show who the message goes to: writing blindly to a number is awkward.
    let card = null;
    if (/^\d{4,10}$/.test(uin)) {
      const c = await userCard(uin, ctx.u.t);
      card = c.exists ? c.html
        : `<p style="${FONT}"><font color="#a06000">`
          + ctx.u.t.notRegistered(escapeHtml(uin)) + '</font></p>';
    }
    send(ctx.res, 200, pagerForm(uin, '', '', ctx.path, card, ctx.u));
  },

  hostsfile: (ctx) => sendText(ctx.res, hostsFileText(ctx.url.searchParams.get('ip') || '')),

  // The Xtraz gallery is fed by a list, not by a page: ICQ 6 reads XtrazListUrl
  // from XtraConfig.xml and fills its own window from it. Without the list the
  // window only reports "a problem opening Xtra", so a stub page cannot help
  // there. We serve a list of one item that opens our own page inside the
  // client - the schema is the original one (xtrazList / groups / xtraz).
  // Before parsing the list, ICQ 6 fetches a DTD next to the localized strings
  // (XtrazStringsUrl + /<lang>/xtraz_list.dtd). It declares the entities the
  // original list used for translated names; ours needs none, but the fetch has
  // to succeed - on a 404 the parse fails and the window only reports "a problem
  // opening Xtra".
  xtrazdtd: (ctx) => {
    const body = Buffer.from('<!-- no entities needed for this list -->', 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'application/xml-dtd',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  // An .xtra is not a package but an HTML document: it embeds the Xtraz plugin
  // object (ISBDhtmlXtraWrapper from MISB.dll), declares a VBScript
  // plugin_OnInitData handler and puts the visible part in a frame. A plain page
  // is fetched but rejected, which is why the gallery window kept reporting a
  // problem. This is the same wrapper with our page inside.
  xtrapage: (ctx) => {
    const self = selfBase(ctx.req);
    const html = `<html>
<head>
<title>Xtraz</title>
<OBJECT CLASSID="clsid:8D18DFF4-0943-4347-8BCA-0C57033F6820" id="plugin">OBJECT NOT SET</OBJECT>
<script language="VBScript">
	Sub plugin_OnInitData ( owner, sequence, buddies, initialData )
	End Sub
</script>
</head>
<frameset rows="*" cols="*" frameborder="0" border="0">
	<frame name="win" id="win" scrolling="auto" src="${self}/icq/stub/xtraz.html?compact=1">
</frameset>
</html>`;
    const body = Buffer.from(html, 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  xtrazlist: (ctx) => {
    // A short list: the welcome window, and the two picture entries. The client
    // draws its Xtraz buttons from this list, so an empty one is what removes
    // them - but some of the interface opens entries from it by id and breaks
    // without them. "Welcome to ICQ" in the main menu is one; clicking one's own
    // picture in the profile is another, and with no "avatar" entry it sends the
    // browser to an error page on icq.com. Those keep an entry each. The client draws its Xtraz
    // buttons from this list, so an empty one is what removes them - but the
    // "Welcome to ICQ" item of the main menu opens an entry from it too, and
    // went dead with the rest. That entry is given back, pointed at our own
    // welcome page.
    //
    // To offer the old entries again, serve `xtrazList` here: it is the
    // archived list, kept next to this file.
    const self = selfBase(ctx.req);
    const body = Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>
<xtrazList majorVer="1" minorVer="0" date="06-10-09">
  <groups/>
  <xtraz>
    <xtra id="icq_welcome" version="1" type="dhtml" resizable="true"
          width="700" minWidth="520" height="430" minHeight="320"
          name="Welcome" desc="Welcome" url="${self}/icq/welcome"/>
    <xtra id="avatar" version="1" type="dhtml" resizable="true"
          width="540" height="480" name="Picture" desc="Picture"
          url="${self}/icq/avatar"/>
    <xtra id="photo_cropper" version="1" type="dhtml" resizable="true"
          width="420" height="300" name="Xtraz" desc="Xtraz"
          url="${self}/icq/stub/xtraz.html?compact=1"/>
  </xtraz>
</xtrazList>
`, 'utf8');
    ctx.res.writeHead(200, {
      'content-type': 'text/xml; charset=utf-8',
      'content-length': body.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(body);
  },

  // The ICQ 6 banner strip: the client expects an image, not a page. Serving a
  // transparent dot leaves the strip empty instead of showing a broken image.
  blank: (ctx) => {
    const gif = Buffer.from(
      'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    ctx.res.writeHead(200, {
      'content-type': 'image/gif',
      'content-length': gif.length,
      'cache-control': 'no-store',
    });
    ctx.res.end(gif);
  },

  stub: (ctx) => send(
    ctx.res, 200,
    // compact=1 comes from the pages the client draws in its own small window,
    // such as the Xtraz gallery: there the roomy layout does not fit.
    stubPage(ctx.path.split('/').filter(Boolean).pop() || ctx.host, ctx.u,
      ctx.url.searchParams.get('compact') === '1'),
  ),
};

// ---------------------------------------------------------------------- routing

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 64 * 1024) { reject(new Error('request too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function route(req, res) {
  const host = String(req.headers.host || '').split(':')[0].toLowerCase();
  const url = new URL(req.url, 'http://placeholder');
  const chosen = pickRoute(host, url.pathname + url.search);

  // Language: an explicit ?lang= wins, otherwise Accept-Language decides.
  const asked = (url.searchParams.get('lang') || '').toLowerCase();
  const lang = LANGS.includes(asked)
    ? asked
    : pickLang(req.headers['accept-language']);
  // The address of this page for the switcher links, with the old lang removed.
  const selfParams = new URLSearchParams(url.search);
  selfParams.delete('lang');
  const selfQuery = selfParams.toString();
  const u = {
    lang,
    t: dict(lang),
    selfUrl: url.pathname + (selfQuery ? `?${selfQuery}` : ''),
  };

  if (!chosen) {
    // A config without a catch-all at the end: say so instead of a silent 404.
    send(res, 200, stubPage(host, u));
    return;
  }

  const ctx = {
    req, res, url, host, u,
    path: url.pathname,
    route: chosen,
    ip: req.socket.remoteAddress || '?',
    vars: { registerBase: config.registerBase, host, path: url.pathname },
  };
  await ACTIONS[chosen.action](ctx);
}

config = loadConfig();
loadTopics();

// SIGHUP reloads the config: a host can be added without restarting the service.
// If the new file is broken we keep the old one instead of dying.
process.on('SIGHUP', () => {
  try {
    config = loadConfig();
    loadTopics();
    console.log(`config reloaded: ${config.routes.length} routes`);
  } catch (err) {
    console.error(`config not reloaded, keeping the old one: ${err.message}`);
  }
});

// Request log. Clients ask for things no documentation lists, and the only way
// to learn what a particular window needs is to watch what it fetches.
const LOG_REQUESTS = process.env.LOG_REQUESTS !== '0';

const server = http.createServer((req, res) => {
  if (LOG_REQUESTS) {
    console.log(`${req.method} ${req.headers.host || '-'}${req.url} `
      + `ua=${(req.headers['user-agent'] || '-').slice(0, 40)}`);
  }
  if (serveAsset(req, res)) return;
  route(req, res).catch((err) => {
    const t = dict(pickLang(req.headers['accept-language']));
    send(res, 500, page(t.errorTitle, `<p>${escapeHtml(err.message)}</p>`));
  });
});

server.listen(PORT, BIND, () => {
  console.log(`oscar-legacy-web listening on ${BIND}:${PORT}`);
  console.log(`config ${CONFIG_PATH}: ${config.routes.length} routes, `
    + `management API ${config.mgmtApi}`);
});
