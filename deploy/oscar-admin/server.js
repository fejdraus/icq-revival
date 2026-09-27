#!/usr/bin/env node
'use strict';

// Админка Open OSCAR Server: пользователи, пароли, блокировки, сессии.
// Обёртка над management API, закрытая HTTP Basic-авторизацией.
// Язык интерфейса определяется по Accept-Language, переключается вручную.

const http = require('http');
const crypto = require('crypto');
// Оформление — общее для всех сервисов проекта, см. ui.js.
const { STYLE, flowerImg, header, footer, serveAsset } = require('./ui.js');

const API = process.env.API_BASE || 'http://127.0.0.1:8090';
const PORT = Number(process.env.PORT || 8100);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_SECRET = process.env.ADMIN_PASSWORD || '';
const REALM = 'ICQ Revival admin';

if (!ADMIN_SECRET) {
  console.error('ADMIN_PASSWORD не задан — отказываюсь запускаться без пароля.');
  process.exit(1);
}

// Ограничения самого сервера (state/user.go).
const PASS_ICQ = [6, 8];
const PASS_AIM = [4, 16];
const SUSPEND_STATES = ['suspended', 'expired', 'suspended_age', 'deleted'];

const LANGS = ['uk', 'en'];
const FALLBACK_LANG = 'en';

const I18N = {
  en: {
    name: 'English',
    docTitle: 'Server administration',
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
    docTitle: 'Керування сервером',
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
    // Сравниваем всё равно, чтобы время ответа не выдавало длину.
    crypto.timingSafeEqual(ba, ba);
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

function authorized(req) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Basic ')) return false;
  let decoded;
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  } catch {
    return false;
  }
  const idx = decoded.indexOf(':');
  if (idx < 0) return false;
  const user = decoded.slice(0, idx);
  const secret = decoded.slice(idx + 1);
  // Оба сравнения выполняются всегда — без short-circuit.
  const okUser = safeEqual(user, ADMIN_USER);
  const okSecret = safeEqual(secret, ADMIN_SECRET);
  return okUser && okSecret;
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

// Ошибки уезжают кодом с аргументами: текст собирает браузер на текущем языке.
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
<style>${STYLE}</style>
</head>
<body>
<main class="window">
  ${header(t.winTitle, '', 'data-i18n="winTitle"')}

  <div class="toolbar">
    <div class="grow"><input type="text" id="filter" data-i18n-placeholder="filterPlaceholder" placeholder="${t.filterPlaceholder}" autocomplete="off"></div>
    <button type="button" id="refresh" data-i18n="btnRefresh">${t.btnRefresh}</button>
    <button type="button" id="create" class="primary" data-i18n="btnCreate">${t.btnCreate}</button>
  </div>

  <div class="body">
    <div class="scroll">
      <table class="data">
        <thead>
          <tr>
            <th style="width:30%" data-i18n="thAccount">${t.thAccount}</th>
            <th style="width:14%" data-i18n="thType">${t.thType}</th>
            <th style="width:20%" data-i18n="thState">${t.thState}</th>
            <th class="hide-sm" style="width:16%" data-i18n="thSession">${t.thSession}</th>
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

// Ошибка приходит как {code, args} — текст собираем на текущем языке.
function errText(payload) {
  if (payload && payload.code) {
    const entry = t.err[payload.code];
    if (entry) return typeof entry === 'function' ? entry(...(payload.args || [])) : entry;
  }
  return t.err.internal;
}

async function call(path, opts) {
  const r = await fetch(path, opts);
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
      actions.appendChild(kickBtn);
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
  // Картинка отдаётся без пароля: иначе её не покажет ни один браузер.
  if (serveAsset(req, res)) return;
  if (!authorized(req)) {
    res.writeHead(401, {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Content-Type': 'text/plain; charset=utf-8',
    });
    res.end('Authorization required');
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
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

    // Список пользователей + активные сессии одним запросом.
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
      // Снятие блокировки — это пустая строка: на null сервер отвечает 304,
      // потому что трактует его как "поле не передано".
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
      // Блокировка не выкидывает уже подключённого — делаем это сами.
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
