#!/usr/bin/env node
'use strict';

// Open OSCAR Server admin panel: users, passwords, blocks, sessions.
// A wrapper over the management API, guarded by a sign-in page (session in a
// cookie). The UI language comes from Accept-Language and can be switched.

const http = require('http');
const crypto = require('crypto');
// The look is shared by all the project's services, see ui.js.
const { STYLE, flowerImg, header, footer, serveAsset, FAVICON } = require('./ui.js');

const API = process.env.API_BASE || 'http://127.0.0.1:8090';
const PORT = Number(process.env.PORT || 8100);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_SECRET = process.env.ADMIN_PASSWORD || '';
// The session after sign-in: a random token in a cookie, valid for
// SESSION_HOURS hours. It is kept in memory - restarting the service just
// asks you to sign in again.
const SESSION_COOKIE = 'icq_admin';
const SESSION_HOURS = 12;
// Password guessing: this many failed attempts from one address and sign-in
// is closed for LOCK_MINUTES minutes. nginx rate-limits on top of that.
const MAX_FAILURES = 5;
const LOCK_MINUTES = 15;

if (!ADMIN_SECRET) {
  console.error('ADMIN_PASSWORD is not set - refusing to start without a password.');
  process.exit(1);
}

// The server's own limits (state/user.go).
const PASS_ICQ = [6, 8];
const PASS_AIM = [4, 16];
const SUSPEND_STATES = ['suspended', 'expired', 'suspended_age', 'deleted'];

const LANGS = ['uk', 'en'];
const FALLBACK_LANG = 'en';

const I18N = {
  en: {
    name: 'English',
    docTitle: 'Server administration — ICQ Revival',
    loginTitle: 'Sign in to ICQ Revival administration',
    loginUser: 'Login',
    loginPass: 'Password',
    loginBtn: 'Sign in',
    loginBad: 'Wrong login or password.',
    loginLocked: (m) => `Too many failed attempts. Try again in ${m} min.`,
    btnLogout: 'Sign out',
    winTitle: 'Server administration — accounts',
    filterPlaceholder: 'Search by number or name',
    btnRefresh: 'Refresh',
    btnCreate: 'Create',
    thAccount: 'Account',
    thType: 'Type',
    thState: 'State',
    thSession: 'Session',
    empty: 'No accounts yet',
    online: 'online',
    offline: 'offline',
    btnPwd: 'Password',
    btnPwdHint: 'Reset the password',
    btnBlock: 'Block',
    btnUnblock: 'Unblock',
    btnKick: 'Disconnect',
    btnKickHint: 'Drop the active session',
    btnDelete: 'Delete',
    btnCancel: 'Cancel',
    counts: (total, online, blocked) =>
      `Total: ${total} · Online: ${online} · Blocked: ${blocked}`,
    statusReady: '',
    statusLoading: 'Loading…',
    statusChangingPwd: 'Changing the password…',
    statusBlocking: 'Blocking…',
    statusUnblocking: 'Removing the block…',
    statusKicking: 'Disconnecting…',
    statusDeleting: 'Deleting…',
    statusCreating: 'Creating…',
    statusError: (m) => `Error: ${m}`,
    msgPwdChanged: (n) => `Password for ${n} changed`,
    msgCreated: (n) => `Account ${n} created`,
    msgDeleted: (n) => `Account ${n} deleted`,
    msgDeleteCancelled: 'Deletion cancelled: the number did not match',
    dlgResetTitle: 'Reset the password',
    dlgResetText: (n) => `New password for <b>${n}</b>.`,
    dlgNewPwdLabel: 'New password',
    dlgLenNote: (l) => `Length: ${l} characters.`,
    dlgResetOk: 'Change',
    dlgBlockTitle: 'Block account',
    dlgBlockText: (n) =>
      `Block <b>${n}</b>? The active session will be dropped and sign-in refused.`,
    dlgBlockOk: 'Block',
    dlgDeleteTitle: 'Delete account',
    dlgDeleteText: (n) =>
      `Delete <b>${n}</b> along with its profile and buddy list? This cannot be undone.<br><br>Type the number to confirm:`,
    dlgDeleteNote: (n) => `Type ${n}`,
    dlgDeleteOk: 'Delete',
    dlgCreateTitle: 'New account',
    dlgCreateNameText: 'ICQ number (UIN) or AIM screen name:',
    dlgCreateNameNote: 'For ICQ — a number from 10000 up.',
    dlgCreateNext: 'Next',
    dlgCreatePwdText: (n) => `Password for <b>${n}</b>:`,
    dlgCreateOk: 'Create',
    err: {
      empty_name: 'The account name is empty.',
      pass_length: (min, max, kind) =>
        `The password must be ${min} to ${max} characters (${kind}).`,
      invalid_status: (s) => `Invalid status: ${s}`,
      upstream: (d) => `The server rejected the operation: ${d}`,
      internal: 'Internal error in the admin panel.',
    },
  },
  uk: {
    name: 'Українська',
    docTitle: 'Керування сервером — ICQ Revival',
    loginTitle: 'Вхід до керування ICQ Revival',
    loginUser: 'Логін',
    loginPass: 'Пароль',
    loginBtn: 'Увійти',
    loginBad: 'Неправильний логін або пароль.',
    loginLocked: (m) => `Забагато невдалих спроб. Спробуйте за ${m} хв.`,
    btnLogout: 'Вийти',
    winTitle: 'Керування сервером — користувачі',
    filterPlaceholder: 'Пошук за номером або іменем',
    btnRefresh: 'Оновити',
    btnCreate: 'Створити',
    thAccount: 'Обліковий запис',
    thType: 'Тип',
    thState: 'Стан',
    thSession: 'Сесія',
    empty: 'Користувачів немає',
    online: 'у мережі',
    offline: 'не в мережі',
    btnPwd: 'Пароль',
    btnPwdHint: 'Скинути пароль',
    btnBlock: 'Заблокувати',
    btnUnblock: 'Розблокувати',
    btnKick: 'Відключити',
    btnKickHint: 'Розірвати активну сесію',
    btnDelete: 'Видалити',
    btnCancel: 'Скасувати',
    counts: (total, online, blocked) =>
      `Усього: ${total} · У мережі: ${online} · Блокувань: ${blocked}`,
    statusReady: '',
    statusLoading: 'Завантажую…',
    statusChangingPwd: 'Змінюю пароль…',
    statusBlocking: 'Блокую…',
    statusUnblocking: 'Знімаю блокування…',
    statusKicking: 'Відключаю…',
    statusDeleting: 'Видаляю…',
    statusCreating: 'Створюю…',
    statusError: (m) => `Помилка: ${m}`,
    msgPwdChanged: (n) => `Пароль для ${n} змінено`,
    msgCreated: (n) => `Обліковий запис ${n} створено`,
    msgDeleted: (n) => `Обліковий запис ${n} видалено`,
    msgDeleteCancelled: 'Видалення скасовано: номер не збігся',
    dlgResetTitle: 'Скидання пароля',
    dlgResetText: (n) => `Новий пароль для <b>${n}</b>.`,
    dlgNewPwdLabel: 'Новий пароль',
    dlgLenNote: (l) => `Довжина: ${l} символів.`,
    dlgResetOk: 'Змінити',
    dlgBlockTitle: 'Блокування',
    dlgBlockText: (n) =>
      `Заблокувати <b>${n}</b>? Активну сесію буде розірвано, вхід стане неможливим.`,
    dlgBlockOk: 'Заблокувати',
    dlgDeleteTitle: 'Видалення облікового запису',
    dlgDeleteText: (n) =>
      `Видалити <b>${n}</b> разом із профілем і контакт-листом? Скасувати це неможливо.<br><br>Для підтвердження введіть номер:`,
    dlgDeleteNote: (n) => `Введіть ${n}`,
    dlgDeleteOk: 'Видалити',
    dlgCreateTitle: 'Новий обліковий запис',
    dlgCreateNameText: 'Номер ICQ (UIN) або ім’я AIM:',
    dlgCreateNameNote: 'Для ICQ — число від 10000.',
    dlgCreateNext: 'Далі',
    dlgCreatePwdText: (n) => `Пароль для <b>${n}</b>:`,
    dlgCreateOk: 'Створити',
    err: {
      empty_name: 'Порожнє ім’я облікового запису.',
      pass_length: (min, max, kind) =>
        `Пароль має містити від ${min} до ${max} символів (${kind}).`,
      invalid_status: (s) => `Неприпустимий статус: ${s}`,
      upstream: (d) => `Сервер відхилив операцію: ${d}`,
      internal: 'Внутрішня помилка адмінки.',
    },
  },
};

function pickLang(header) {
  if (!header) return FALLBACK_LANG;
  const ranked = String(header)
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params
        .map((p) => p.trim())
        .filter((p) => p.startsWith('q='))
        .map((p) => Number(p.slice(2)))[0];
      return { tag: tag.trim().toLowerCase(), q: Number.isFinite(q) ? q : 1 };
    })
    .filter((x) => x.tag)
    .sort((a, b) => b.q - a.q);

  for (const { tag } of ranked) {
    const base = tag.split('-')[0];
    if (LANGS.includes(base)) return base;
  }
  return FALLBACK_LANG;
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) {
    // Compare anyway so the response time does not give away the length.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

const sessions = new Map(); // token -> expiry (ms)
const failures = new Map(); // client address -> { count, until }

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// The address failed sign-ins are counted against: the one nginx saw, or
// the socket's when the panel is opened through an SSH tunnel.
function clientAddr(req) {
  return String(req.headers['x-real-ip'] || req.socket.remoteAddress || '');
}

function viaHttps(req) {
  return req.headers['x-forwarded-proto'] === 'https';
}

function authorized(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return false;
  const expires = sessions.get(token);
  if (!expires) return false;
  if (expires < Date.now()) {
    sessions.delete(token);
    return false;
  }
  return true;
}

// Minutes left of a lockout for this address, or 0.
function lockedFor(addr) {
  const f = failures.get(addr);
  if (!f || !f.until) return 0;
  const left = f.until - Date.now();
  if (left <= 0) {
    failures.delete(addr);
    return 0;
  }
  return Math.ceil(left / 60000);
}

function checkCredentials(user, secret) {
  // Both comparisons always run - no short-circuit.
  const okUser = safeEqual(user, ADMIN_USER);
  const okSecret = safeEqual(secret, ADMIN_SECRET);
  return okUser && okSecret;
}

function cookieAttrs(req, maxAge) {
  const attrs = ['HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${maxAge}`];
  if (viaHttps(req)) attrs.push('Secure');
  return attrs.join('; ');
}

function newSession(req) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, Date.now() + SESSION_HOURS * 3600 * 1000);
  // Expired sessions go when a new one starts, so the map stays small.
  for (const [k, exp] of sessions) if (exp < Date.now()) sessions.delete(k);
  return `${SESSION_COOKIE}=${token}; ${cookieAttrs(req, SESSION_HOURS * 3600)}`;
}

function endSession(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (token) sessions.delete(token);
  return `${SESSION_COOKIE}=; ${cookieAttrs(req, 0)}`;
}

// A request that changes something must come from our own page: the cookie
// is SameSite=Strict already, and a browser that says the request is
// cross-site, or names another origin, is refused as well.
function sameOrigin(req) {
  if (req.headers['sec-fetch-site'] === 'cross-site') return false;
  const origin = req.headers.origin;
  if (!origin || origin === 'null') return !origin;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function readForm(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 4096) req.destroy();
    });
    req.on('end', () => resolve(new URLSearchParams(body)));
    req.on('error', () => resolve(new URLSearchParams()));
  });
}

function renderLoginPage(lang, error) {
  const t = I18N[lang];
  const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  return `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(t.loginTitle)}</title>
${FAVICON}
<style>${STYLE}
  /* The sign-in box in the middle of the window, both ways. */
  body { min-height: 100vh; box-sizing: border-box; display: flex; align-items: center; justify-content: center; }
  .login { max-width: 360px; margin: 0 auto; padding: 16px; }
  .login label { display: block; margin: 10px 0 4px; }
  .login input { width: 100%; box-sizing: border-box; }
  .login .actions { margin-top: 16px; text-align: right; }
  .login .err { color: #b00020; margin: 8px 0 0; }
</style>
</head>
<body>
<main class="window" style="max-width:420px">
  ${header(t.loginTitle, '', '')}
  <form class="login" method="post" action="login?lang=${lang}">
    <label for="user">${esc(t.loginUser)}</label>
    <input type="text" id="user" name="user" autocomplete="username" autofocus required>
    <label for="pass">${esc(t.loginPass)}</label>
    <input type="password" id="pass" name="pass" autocomplete="current-password" required>
    ${error ? `<p class="err">${esc(error)}</p>` : ''}
    <div class="actions"><button type="submit" class="primary">${esc(t.loginBtn)}</button></div>
  </form>
</main>
</body>
</html>`;
}

async function apiCall(path, opts = {}) {
  const res = await fetch(`${API}${path}`, opts);
  const text = (await res.text()).trim();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  return { ok: res.ok, status: res.status, body };
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res, code, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

// Errors go out as a code with arguments: the browser builds the text in the
// current language.
function validateSecret(value, isICQ) {
  const [min, max] = isICQ ? PASS_ICQ : PASS_AIM;
  const len = String(value || '').length;
  if (len < min || len > max) {
    return { code: 'pass_length', args: [min, max, isICQ ? 'ICQ' : 'AIM'] };
  }
  return null;
}

function serializeI18N() {
  return JSON.stringify(I18N, (key, value) =>
    typeof value === 'function' ? { __fn: value.toString() } : value,
  );
}

function renderPage(lang) {
  const t = I18N[lang];
  return /* html */ `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.docTitle}</title>
${FAVICON}
<style>${STYLE}
  /* A table of every account wants the whole browser window, not the
     narrow ICQ window the forms of the other pages use. */
  main.window { max-width: none; width: calc(100% - 32px); margin: 16px auto; }
  .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px;
    margin: 0; padding: 14px 16px; border-bottom: 1px solid rgba(0,0,0,.08); }
  .toolbar > * { margin: 0; }
  .toolbar .grow { flex: 0 1 420px; min-width: 220px; }
  .toolbar .grow input { width: 100%; box-sizing: border-box; }
  .toolbar .signout { margin-left: auto; }
  /* Password, block, disconnect (online only), delete: always in the same
     four columns, so the buttons line up from row to row. */
  .rowactions { display: grid; grid-template-columns: 8.5em 6.5em 9.5em 7em;
    gap: 6px; justify-content: end; align-items: center; }
  .rowactions button { margin: 0; white-space: nowrap; width: 100%; }
  /* Disconnect comes first, so rows without it keep the gap at the left. */
  .rowactions .slot-kick { order: -1; }
  .dot { margin-right: 6px; vertical-align: 1px; }
  @media (max-width: 900px) {
    .rowactions { grid-template-columns: repeat(2, max-content); }
    .rowactions span.slot-kick { display: none; }
    .toolbar .signout { margin-left: 0; }
  }
  table.data th:last-child, table.data td:last-child { width: auto !important; }
  @media (max-width: 700px) { main.window { width: 100%; margin: 0; } }
</style>
</head>
<body>
<main class="window">
  ${header(t.winTitle, '', 'data-i18n="winTitle"')}

  <div class="toolbar">
    <div class="grow"><input type="text" id="filter" data-i18n-placeholder="filterPlaceholder" placeholder="${t.filterPlaceholder}" autocomplete="off"></div>
    <button type="button" id="refresh" data-i18n="btnRefresh">${t.btnRefresh}</button>
    <button type="button" id="create" class="primary" data-i18n="btnCreate">${t.btnCreate}</button>
    <form method="post" action="logout" class="signout"><button type="submit" data-i18n="btnLogout">${t.btnLogout}</button></form>
  </div>

  <div class="body">
    <div class="scroll">
      <table class="data">
        <thead>
          <tr>
            <th style="width:20%" data-i18n="thAccount">${t.thAccount}</th>
            <th style="width:8%" data-i18n="thType">${t.thType}</th>
            <th style="width:16%" data-i18n="thState">${t.thState}</th>
            <th class="hide-sm" style="width:22%" data-i18n="thSession">${t.thSession}</th>
            <th style="width:20%"></th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
      <div class="empty" id="empty" data-i18n="empty" hidden>${t.empty}</div>
    </div>
  </div>

  ${footer({ statusId: 'status', langsId: 'langs',
    extra: '<span id="counts">\u2014</span>' })}
</main>

<dialog id="dlg">
  <div class="titlebar">${flowerImg(18)}<span class="label" id="dlg-title"></span></div>
  <div class="content">
    <p id="dlg-text"></p>
    <div id="dlg-field" hidden>
      <label for="dlg-input" id="dlg-label"></label>
      <input type="text" id="dlg-input" autocomplete="off">
      <p class="note" id="dlg-note"></p>
    </div>
  </div>
  <div class="foot">
    <button type="button" id="dlg-cancel"></button>
    <button type="button" id="dlg-ok" class="primary"></button>
  </div>
</dialog>

<script>
const LANGS = ${JSON.stringify(LANGS)};
const LANG_LABEL = (c) => String(c).toUpperCase();

const I18N = JSON.parse(${JSON.stringify(serializeI18N())}, (key, value) => {
  if (value && typeof value === 'object' && typeof value.__fn === 'string') {
    return new Function('return (' + value.__fn + ')')();
  }
  return value;
});

let lang = ${JSON.stringify(lang)};
try {
  const saved = localStorage.getItem('lang');
  if (saved && LANGS.includes(saved)) lang = saved;
} catch {}

let t = I18N[lang];
let users = [];
let sessions = {};
let lastStatus = { key: 'statusReady', args: [] };

const rowsEl = document.getElementById('rows');
const emptyEl = document.getElementById('empty');
const statusEl = document.getElementById('status');
const countsEl = document.getElementById('counts');
const filterEl = document.getElementById('filter');
const langsEl = document.getElementById('langs');
const dlg = document.getElementById('dlg');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

const UNITS = {
  en: { h: ' h ', m: ' min', s: ' s' },
  uk: { h: ' год ', m: ' хв', s: ' с' },
};

function fmtDuration(sec) {
  if (sec == null) return '';
  const u = UNITS[lang] || UNITS.en;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h) return h + u.h + m + u.m;
  if (m) return m + u.m;
  return sec + u.s;
}

function setStatus(key, ...args) {
  lastStatus = { key, args };
  const v = t[key];
  statusEl.textContent = typeof v === 'function' ? v(...args) : v;
}

// An error arrives as {code, args} - we build the text in the current language.
function errText(payload) {
  if (payload && payload.code) {
    const entry = t.err[payload.code];
    if (entry) return typeof entry === 'function' ? entry(...(payload.args || [])) : entry;
  }
  return t.err.internal;
}

async function call(path, opts) {
  const r = await fetch(path, opts);
  // The session ended (expired, signed out elsewhere, service restarted).
  if (r.status === 401) { location.href = 'login'; throw new Error(''); }
  const d = await r.json().catch(() => ({}));
  if (!r.ok || d.ok === false) throw new Error(errText(d));
  return d;
}

function ask({ title, text, field, label, note, okLabel }) {
  return new Promise((resolve) => {
    document.getElementById('dlg-title').textContent = title;
    document.getElementById('dlg-text').innerHTML = text;
    const wrap = document.getElementById('dlg-field');
    const input = document.getElementById('dlg-input');
    const okBtn = document.getElementById('dlg-ok');
    const cancelBtn = document.getElementById('dlg-cancel');

    wrap.hidden = !field;
    document.getElementById('dlg-label').textContent = label || '';
    document.getElementById('dlg-note').textContent = note || '';
    input.value = '';
    okBtn.textContent = okLabel;
    cancelBtn.textContent = t.btnCancel;

    function cleanup(result) {
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      dlg.removeEventListener('cancel', onCancel);
      dlg.close();
      resolve(result);
    }
    function onOk() { cleanup(field ? { value: input.value } : { value: true }); }
    function onCancel(e) { if (e) e.preventDefault(); cleanup(null); }

    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    dlg.addEventListener('cancel', onCancel);
    dlg.showModal();
    if (field) input.focus();
  });
}

function updateCounts() {
  const online = Object.keys(sessions).length;
  const blocked = users.filter((u) => u.suspended_status).length;
  countsEl.textContent = t.counts(users.length, online, blocked);
}

async function load() {
  setStatus('statusLoading');
  try {
    const d = await call('api/state');
    users = d.users;
    sessions = d.sessions;
    render();
    updateCounts();
    setStatus('statusReady');
  } catch (e) {
    setStatus('statusError', e.message);
  }
}

function render() {
  const q = filterEl.value.trim().toLowerCase();
  const list = users.filter((u) => !q || u.screen_name.toLowerCase().includes(q));
  rowsEl.innerHTML = '';
  emptyEl.hidden = list.length > 0;

  for (const u of list) {
    const s = sessions[u.screen_name];
    const blocked = Boolean(u.suspended_status);
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td><span class="uin">' + esc(u.screen_name) + '</span></td>' +
      '<td>' + (u.is_icq ? 'ICQ' : 'AIM') + '</td>' +
      '<td>' +
        '<span class="dot ' + (s ? 'on' : 'off') + '"></span>' +
        (s ? t.online : t.offline) +
        (blocked ? ' <span class="tag blocked">' + esc(u.suspended_status) + '</span>' : '') +
      '</td>' +
      '<td class="hide-sm">' + (s
        ? esc(s.ip) + '<br><span style="font-size:11px;color:#555">' + fmtDuration(s.online_seconds) + '</span>'
        : '—') + '</td>' +
      '<td><div class="rowactions"></div></td>';

    const actions = tr.querySelector('.rowactions');

    const pwdBtn = document.createElement('button');
    pwdBtn.textContent = t.btnPwd;
    pwdBtn.title = t.btnPwdHint;
    pwdBtn.addEventListener('click', () => resetSecret(u));
    actions.appendChild(pwdBtn);

    const blockBtn = document.createElement('button');
    blockBtn.textContent = blocked ? t.btnUnblock : t.btnBlock;
    blockBtn.addEventListener('click', () => toggleBlock(u, blocked));
    actions.appendChild(blockBtn);

    if (s) {
      const kickBtn = document.createElement('button');
      kickBtn.textContent = t.btnKick;
      kickBtn.title = t.btnKickHint;
      kickBtn.addEventListener('click', () => kick(u));
      kickBtn.className = 'slot-kick';
      actions.appendChild(kickBtn);
    } else {
      // An empty slot, so every row's buttons stand in the same columns.
      const gap = document.createElement('span');
      gap.className = 'slot-kick';
      actions.appendChild(gap);
    }

    const delBtn = document.createElement('button');
    delBtn.textContent = t.btnDelete;
    delBtn.className = 'danger';
    delBtn.addEventListener('click', () => removeUser(u));
    actions.appendChild(delBtn);

    rowsEl.appendChild(tr);
  }
}

function applyLang(next) {
  lang = next;
  t = I18N[lang];
  document.documentElement.lang = lang;
  document.title = t.docTitle;

  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t[el.dataset.i18n];
  }
  for (const el of document.querySelectorAll('[data-i18n-placeholder]')) {
    el.placeholder = t[el.dataset.i18nPlaceholder];
  }

  setStatus(lastStatus.key, ...lastStatus.args);
  render();
  updateCounts();
  renderLangs();

  try { localStorage.setItem('lang', lang); } catch {}
}

function renderLangs() {
  langsEl.innerHTML = '';
  for (const code of LANGS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = LANG_LABEL(code);
    b.title = I18N[code].name;
    b.setAttribute('aria-current', String(code === lang));
    if (code !== lang) b.addEventListener('click', () => applyLang(code));
    langsEl.appendChild(b);
  }
}

async function resetSecret(u) {
  const limits = u.is_icq ? '6–8' : '4–16';
  const r = await ask({
    title: t.dlgResetTitle,
    text: t.dlgResetText(esc(u.screen_name)),
    field: true,
    label: t.dlgNewPwdLabel,
    note: t.dlgLenNote(limits),
    okLabel: t.dlgResetOk,
  });
  if (!r) return;
  setStatus('statusChangingPwd');
  try {
    await call('api/users/' + encodeURIComponent(u.screen_name) + '/password', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: r.value }),
    });
    setStatus('msgPwdChanged', u.screen_name);
  } catch (e) {
    setStatus('statusError', e.message);
  }
}

async function toggleBlock(u, blocked) {
  if (!blocked) {
    const r = await ask({
      title: t.dlgBlockTitle,
      text: t.dlgBlockText(esc(u.screen_name)),
      okLabel: t.dlgBlockOk,
    });
    if (!r) return;
  }
  setStatus(blocked ? 'statusUnblocking' : 'statusBlocking');
  try {
    await call('api/users/' + encodeURIComponent(u.screen_name) + '/suspend', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: blocked ? null : 'suspended' }),
    });
    await load();
  } catch (e) {
    setStatus('statusError', e.message);
  }
}

async function kick(u) {
  setStatus('statusKicking');
  try {
    await call('api/sessions/' + encodeURIComponent(u.screen_name), { method: 'DELETE' });
    await load();
  } catch (e) {
    setStatus('statusError', e.message);
  }
}

async function removeUser(u) {
  const r = await ask({
    title: t.dlgDeleteTitle,
    text: t.dlgDeleteText(esc(u.screen_name)),
    field: true,
    label: t.thAccount,
    note: t.dlgDeleteNote(u.screen_name),
    okLabel: t.dlgDeleteOk,
  });
  if (!r) return;
  if (String(r.value).trim() !== u.screen_name) {
    setStatus('msgDeleteCancelled');
    return;
  }
  setStatus('statusDeleting');
  try {
    await call('api/users/' + encodeURIComponent(u.screen_name), { method: 'DELETE' });
    await load();
    setStatus('msgDeleted', u.screen_name);
  } catch (e) {
    setStatus('statusError', e.message);
  }
}

document.getElementById('create').addEventListener('click', async () => {
  const nameAnswer = await ask({
    title: t.dlgCreateTitle,
    text: t.dlgCreateNameText,
    field: true,
    label: t.thAccount,
    note: t.dlgCreateNameNote,
    okLabel: t.dlgCreateNext,
  });
  if (!nameAnswer || !String(nameAnswer.value).trim()) return;
  const name = String(nameAnswer.value).trim();
  const isICQ = /^\\d+$/.test(name);
  const secretAnswer = await ask({
    title: t.dlgCreateTitle,
    text: t.dlgCreatePwdText(esc(name)),
    field: true,
    label: t.dlgNewPwdLabel,
    note: t.dlgLenNote(isICQ ? '6–8' : '4–16'),
    okLabel: t.dlgCreateOk,
  });
  if (!secretAnswer) return;
  setStatus('statusCreating');
  try {
    await call('api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ screen_name: name, password: secretAnswer.value }),
    });
    await load();
    setStatus('msgCreated', name);
  } catch (e) {
    setStatus('statusError', e.message);
  }
});

document.getElementById('refresh').addEventListener('click', load);
filterEl.addEventListener('input', render);

applyLang(lang);
load();
setInterval(load, 20000);
</script>
</body>
</html>`;
}

const server = http.createServer(async (req, res) => {
  // The image is served without a password: otherwise no browser would show it.
  if (serveAsset(req, res)) return;
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pageLang = () => {
    const forced = String(url.searchParams.get('lang') || '').toLowerCase();
    return LANGS.includes(forced) ? forced : pickLang(req.headers['accept-language']);
  };
  const html = (status, body) => {
    res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(body);
  };
  const redirect = (to, cookie) => {
    const h = { Location: to, 'Cache-Control': 'no-store' };
    if (cookie) h['Set-Cookie'] = cookie;
    res.writeHead(303, h);
    res.end();
  };

  // The redirects are relative on purpose: behind nginx the panel lives
  // under /admin/, through an SSH tunnel at the root.
  if (url.pathname === '/login') {
    const lang = pageLang();
    if (req.method === 'GET') {
      if (authorized(req)) return redirect('./');
      html(200, renderLoginPage(lang, ''));
      return;
    }
    if (req.method === 'POST') {
      const addr = clientAddr(req);
      const locked = lockedFor(addr);
      if (locked) {
        html(429, renderLoginPage(lang, I18N[lang].loginLocked(locked)));
        return;
      }
      const form = await readForm(req);
      if (!sameOrigin(req) || !checkCredentials(form.get('user') || '', form.get('pass') || '')) {
        const f = failures.get(addr) || { count: 0, until: 0 };
        f.count += 1;
        if (f.count >= MAX_FAILURES) {
          f.until = Date.now() + LOCK_MINUTES * 60000;
          f.count = 0;
          console.log(`admin: sign-in locked for ${LOCK_MINUTES} min after ${MAX_FAILURES} failures`);
        }
        failures.set(addr, f);
        html(401, renderLoginPage(lang, I18N[lang].loginBad));
        return;
      }
      failures.delete(addr);
      redirect('./', newSession(req));
      return;
    }
  }

  if (url.pathname === '/logout' && req.method === 'POST') {
    redirect('login', endSession(req));
    return;
  }

  if (!authorized(req)) {
    if (url.pathname.startsWith('/api/')) {
      res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ ok: false, code: 'auth' }));
      return;
    }
    redirect('login');
    return;
  }

  if (req.method !== 'GET' && url.pathname.startsWith('/api/') && !sameOrigin(req)) {
    res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ ok: false, code: 'origin' }));
    return;
  }

  const parts = url.pathname.split('/').filter(Boolean);

  try {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const forced = String(url.searchParams.get('lang') || '').toLowerCase();
      const lang = LANGS.includes(forced) ? forced : pickLang(req.headers['accept-language']);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Language': lang,
        'Cache-Control': 'no-store',
        Vary: 'Accept-Language',
      });
      res.end(renderPage(lang));
      return;
    }

    // The user list plus active sessions in one request.
    if (req.method === 'GET' && url.pathname === '/api/state') {
      const [users, sess] = await Promise.all([apiCall('/user'), apiCall('/session')]);
      if (!users.ok) {
        json(res, 502, { ok: false, code: 'upstream', args: [`/user: ${users.status}`] });
        return;
      }

      const sessions = {};
      const list = (sess.ok && sess.body && sess.body.sessions) || [];
      for (const s of list) {
        const inst = (s.instances && s.instances[0]) || {};
        sessions[s.screen_name] = {
          ip: inst.remote_addr ? `${inst.remote_addr}:${inst.remote_port}` : '—',
          online_seconds: s.online_seconds,
          is_away: s.is_away,
        };
      }
      json(res, 200, { users: users.body || [], sessions });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/users') {
      const payload = JSON.parse(await readBody(req));
      const name = String(payload.screen_name || '').trim();
      if (!name) {
        json(res, 400, { ok: false, code: 'empty_name' });
        return;
      }
      const problem = validateSecret(payload.password, /^\d+$/.test(name));
      if (problem) {
        json(res, 400, { ok: false, ...problem });
        return;
      }
      const r = await apiCall('/user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ screen_name: name, password: payload.password }),
      });
      if (!r.ok) {
        json(res, 502, { ok: false, code: 'upstream', args: [String(r.body || r.status)] });
        return;
      }
      console.log(`created ${name}`);
      json(res, 200, { ok: true });
      return;
    }

    // /api/users/:name/password
    if (req.method === 'PUT' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'users' && parts[3] === 'password') {
      const name = decodeURIComponent(parts[2]);
      const payload = JSON.parse(await readBody(req));
      const problem = validateSecret(payload.password, /^\d+$/.test(name));
      if (problem) {
        json(res, 400, { ok: false, ...problem });
        return;
      }
      const r = await apiCall('/user/password', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ screen_name: name, password: payload.password }),
      });
      if (!r.ok) {
        json(res, 502, { ok: false, code: 'upstream', args: [String(r.body || r.status)] });
        return;
      }
      console.log(`password reset for ${name}`);
      json(res, 200, { ok: true });
      return;
    }

    // /api/users/:name/suspend
    if (req.method === 'PATCH' && parts.length === 4 && parts[0] === 'api' && parts[1] === 'users' && parts[3] === 'suspend') {
      const name = decodeURIComponent(parts[2]);
      const payload = JSON.parse(await readBody(req));
      // Lifting a block is an empty string: the server answers null with 304
      // because it treats it as "field not sent".
      const status = payload.status == null ? '' : String(payload.status);
      if (status !== '' && !SUSPEND_STATES.includes(status)) {
        json(res, 400, { ok: false, code: 'invalid_status', args: [status] });
        return;
      }
      const r = await apiCall(`/user/${encodeURIComponent(name)}/account`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ suspended_status: status }),
      });
      if (!r.ok) {
        json(res, 502, { ok: false, code: 'upstream', args: [String(r.body || r.status)] });
        return;
      }
      // Blocking does not kick a user who is already connected - we do it ourselves.
      if (status !== '') {
        await apiCall(`/session/${encodeURIComponent(name)}`, { method: 'DELETE' });
      }
      console.log(`suspend ${name} -> ${status || '(none)'}`);
      json(res, 200, { ok: true });
      return;
    }

    // /api/users/:name
    if (req.method === 'DELETE' && parts.length === 3 && parts[0] === 'api' && parts[1] === 'users') {
      const name = decodeURIComponent(parts[2]);
      const r = await apiCall('/user', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ screen_name: name }),
      });
      if (!r.ok) {
        json(res, 502, { ok: false, code: 'upstream', args: [String(r.body || r.status)] });
        return;
      }
      console.log(`deleted ${name}`);
      json(res, 200, { ok: true });
      return;
    }

    // /api/sessions/:name
    if (req.method === 'DELETE' && parts.length === 3 && parts[0] === 'api' && parts[1] === 'sessions') {
      const name = decodeURIComponent(parts[2]);
      const r = await apiCall(`/session/${encodeURIComponent(name)}`, { method: 'DELETE' });
      if (!r.ok && r.status !== 404) {
        json(res, 502, { ok: false, code: 'upstream', args: [String(r.body || r.status)] });
        return;
      }
      console.log(`kicked ${name}`);
      json(res, 200, { ok: true });
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  } catch (err) {
    console.error('request failed', err);
    json(res, 500, { ok: false, code: 'internal' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`admin panel on http://${HOST}:${PORT} (management API: ${API}, user: ${ADMIN_USER})`);
});
