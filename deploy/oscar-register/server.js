#!/usr/bin/env node
'use strict';

// ICQ account registration for Open OSCAR Server.
// A thin wrapper over the management API: form -> POST /user.
// The page language is picked from Accept-Language and can be switched by hand.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { sendMail, mailConfigured } = require('./mail');

const API = process.env.API_BASE || 'http://127.0.0.1:8090';
const PORT = Number(process.env.PORT || 8099);
const HOST = process.env.HOST || '0.0.0.0';
const OSCAR_HOST = process.env.OSCAR_HOST || '192.168.1.43';
const OSCAR_PORT = process.env.OSCAR_PORT || '5190';
// Port of the TLS front with the Tailscale certificate, for clients that can do SSL.
const OSCAR_PORT_SSL = process.env.OSCAR_PORT_SSL || '5193';
const DB_PATH = process.env.DB_PATH || '/var/lib/open-oscar-server/oscar.sqlite';

// A database of our own, for recovery addresses and one-time links.
// They must not go into the server's database: the mail field of the ICQ
// profile is searchable through the directory, so the address would become public.
const RECOVERY_DB = process.env.RECOVERY_DB || '/var/lib/oscar-register/recovery.sqlite';
// The admin panel, linked at the foot of every page when set: /admin/ of the
// same host, which nginx passes to it (deploy/nginx/conf.d/register.conf).
// Empty: no link.
const ADMIN_URL = (process.env.ADMIN_URL || '').trim();
// The admin panel's entry in a row of page links, with its separator.
function adminLink(t) {
  if (!ADMIN_URL) return '';
  return `
      &nbsp;·&nbsp;
      <a href="${ADMIN_URL.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)}" data-i18n="linkToAdmin">${t.linkToAdmin}</a>`;
}

const PUBLIC_BASE = (process.env.PUBLIC_BASE_URL || `http://${OSCAR_HOST}:${PORT}`).replace(/\/+$/, '');
const TOKEN_TTL_MS = 30 * 60 * 1000;
// Mail is sent sparingly: no more than once a minute and three times an hour per number.
const MAIL_COOLDOWN_MS = 60 * 1000;
const MAIL_PER_HOUR = 3;
const EMAIL_MAX = 320;

// Changing the password requires checking the current one, which the management
// API cannot do, so we compare the hash ourselves, opening the server's database read-only.
const HASH_SUFFIX = 'AOL Instant Messenger (SM)';
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const attempts = new Map();

// Limits of Open OSCAR Server itself (state/user.go).
const UIN_MIN = 10000;
const UIN_MAX = 2147483646;
const PASS_MIN = 6;
const PASS_MAX = 8;

const LANGS = ['uk', 'en'];
const FALLBACK_LANG = 'en';

// Translations live both on the server (for <html lang> and <title>) and in the
// browser, so switching the language does not reload the page.
const I18N = {
  en: {
    name: 'English',
    docTitle: 'Registration — ICQ Revival',
    winTitle: 'Register a new number',
    heroTitle: 'Get an ICQ Revival number',
    heroText: 'Pick a free number and a password — then you are on the air.',
    legendAccount: 'Account',
    labelUin: 'Desired number (UIN)',
    hintUin: `From ${UIN_MIN} to ${UIN_MAX}. We will check whether it is free.`,
    labelPass: 'Password',
    hintPass: `From ${PASS_MIN} to ${PASS_MAX} characters — that is how the ICQ protocol works.`,
    labelPass2: 'Repeat password',
    btnSuggest: 'Suggest a number',
    btnSubmit: 'Register',
    legendSetup: 'Client settings',
    setupServer: 'Server',
    setupPort: 'Port',
    setupPortSsl: 'SSL port',
    setupNote:
      'Clients of that era knew no encryption — ICQ 2000b–5.1, QIP 2005/2010/2012, Pidgin need the plain port with SSL switched off. If your client does support SSL (Miranda NG, for one), turn it on and use the SSL port.',
    setupDownload: 'The patches for ICQ 2003b and ICQ 6.5 and our ICQ plugin for Miranda NG:',
    linkToDownload: 'Clients and patches',
    statusReady: '',
    statusSuggesting: 'Looking for a free number…',
    statusSuggested: (u) => `Number ${u} is free`,
    statusSuggestFailed: 'Could not suggest a number',
    statusChecking: 'Checking the number…',
    statusFree: (u) => `Number ${u} is free`,
    statusTaken: (u) => `Number ${u} is already taken`,
    statusCheckFailed: 'Could not check',
    statusRegistering: 'Registering…',
    statusError: 'Error',
    statusOffline: 'Connection error',
    count: (n) => `Numbers: ${n}`,
    okTitle: 'Account created',
    okYourNumber: 'Your number:',
    okHowTo: (host, port) =>
      `Enter it with your password in the client settings — server <code>${host}</code>, port <code>${port}</code>.`,
    errTitle: 'Something went wrong',
    errOffline: 'The registration service is unavailable.',
    linkToChange: 'Change password',
    linkToProfile: 'My profile',
    linkToAdmin: 'Admin panel',
    linkToRegister: 'Get a number',
    chDocTitle: 'Change password — ICQ Revival',
    chWinTitle: 'Change password',
    chHeroTitle: 'Change your password',
    chHeroText: 'You will need your number and current password.',
    chLabelUin: 'Number (UIN)',
    chLabelCurrent: 'Current password',
    chLabelNew: 'New password',
    chLabelNew2: 'Repeat new password',
    chBtnSubmit: 'Change password',
    chStatusWorking: 'Changing the password…',
    chOkTitle: 'Password changed',
    chOkText: (u) => `The password for ${u} has been updated. Enter the new one in your client.`,
    chNote: 'ICQ clients change passwords over a protocol request this server does not implement — hence this page.',
    labelMail: 'Recovery email',
    hintMail: 'Optional. Without it a forgotten password can only be reset by the administrator, and you can only sign in with your number. With it, the client takes the address in its "ICQ#/Email" field as well. One address belongs to one account; other users cannot see it.',
    legendRecovery: 'Account recovery',
    rcBindText: 'Enter your number, current password and address — we will send a confirmation letter.',
    rcBtnBind: 'Attach address',
    rcBoundTitle: 'Letter sent',
    rcBoundText: (mail) => `A letter went to ${mail}. Open the link inside it to confirm the address.`,
    rcDocTitle: 'Password recovery — ICQ Revival',
    rcWinTitle: 'Password recovery',
    rcHeroTitle: 'Forgot your password?',
    rcHeroText: 'We will send a link to the address attached to your number.',
    rcLabelUin: 'Number (UIN)',
    rcBtnSend: 'Send the link',
    rcSentTitle: 'Check your mail',
    rcSentText: 'If a confirmed address is attached to this number, a letter with the link has been sent. The link is valid for 30 minutes.',
    rcSetTitle: 'New password',
    rcSetText: (u) => `Choose a new password for number ${u}.`,
    rcBtnSet: 'Set the password',
    rcOkTitle: 'Password set',
    rcOkText: (u) => `The password for ${u} has been updated. Enter the new one in your client.`,
    vfOkTitle: 'Address confirmed',
    vfOkText: (u) => `The password for number ${u} can now be recovered by email.`,
    vfErrTitle: 'The link did not work',
    vfErrText: 'The link has expired or has already been used. Request a new one.',
    linkToRecover: 'Forgot your password?',
    statusSending: 'Sending the letter…',
    statusSent: 'Letter sent',
    mailVerifySubject: 'Confirm the address for your ICQ Revival number',
    mailVerifyBody: (u, url) =>
      `Hello!\n\nThis address was given for recovering the password of ICQ Revival number ${u}.\nTo confirm it, open the link:\n\n${url}\n\nThe link is valid for 30 minutes.\nIf you did not attach anything, simply delete this letter.\n`,
    mailResetSubject: 'ICQ Revival password recovery',
    mailResetBody: (u, url) =>
      `Hello!\n\nA password reset was requested for ICQ Revival number ${u}.\nTo set a new password, open the link:\n\n${url}\n\nThe link is valid for 30 minutes and works once.\nIf it was not you, do nothing — the password stays as it is.\n`,
    acDocTitle: 'Number and account — ICQ Revival',
    acWinTitle: 'Manage your number',
    acHeroTitle: 'Number and account',
    acHeroText: 'You can take a different number or delete the account entirely.',
    acLegendMove: 'Change the number',
    acMoveText:
      'The server cannot rename a number, so we create the new one and delete the old. Your password, contact list, profile details and recovery email move across.',
    acMoveWarn:
      'Your friends will still have the old number in their lists — they will have to add you again. Messages waiting for the old number are lost, and the number itself becomes free for others.',
    acLabelNewUin: 'New number',
    acBtnMove: 'Change the number',
    acMovedTitle: 'Number changed',
    acMovedText: (from, to) => `Number ${from} has been replaced by ${to}. Enter the new number and your old password in the client.`,
    acMovedPartial: 'The old number could not be deleted and is still taken. Please tell the administrator.',
    acLegendDelete: 'Delete the account',
    acDeleteText: 'The account, the contact list and the profile will be gone for good. The number becomes free again.',
    acLabelConfirm: 'Type the number once more to confirm',
    acBtnDelete: 'Delete the account',
    acDeletedTitle: 'Account deleted',
    acDeletedText: (u) => `Number ${u} is gone. If you change your mind, it can be registered again.`,
    linkToAccount: 'Change or delete the number',
    statusMoving: 'Moving the number…',
    statusDeleting: 'Deleting the account…',
    err: {
      uin_not_number: 'The number must contain digits only.',
      uin_range: `The number must be between ${UIN_MIN} and ${UIN_MAX}.`,
      pass_length: `The password must be ${PASS_MIN} to ${PASS_MAX} characters — an ICQ protocol limit.`,
      pass_mismatch: 'The passwords do not match.',
      uin_taken: (u) => `Number ${u} is already taken — pick another one.`,
      bad_request: 'Malformed request.',
      upstream: 'The server rejected the registration.',
      internal: 'Internal error in the registration service.',
      no_user: (u) => `There is no number ${u} on this server.`,
      wrong_current: 'The current password is incorrect.',
      same_secret: 'The new password is the same as the old one.',
      too_many: (m) => `Too many failed attempts. Try again in ${m} min.`,
      suspended: 'This account is blocked — contact the administrator.',
      mail_invalid: 'That email address does not look right.',
      mail_failed: 'The letter could not be sent. Try later or contact the administrator.',
      mail_off: 'Sending mail is not configured on this server — contact the administrator.',
      mail_cooldown: 'A letter has already been sent. Wait a minute and check your spam folder.',
      mail_taken: 'That address is already confirmed for another number. One address belongs to one account.',
      token_bad: 'The link is not valid — it may have been used already.',
      token_expired: 'The link has expired. Request a new one.',
      uin_same: 'The new number is the same as the current one.',
      confirm_mismatch: 'To confirm, type the same number.',
      delete_failed: 'The account could not be deleted. Please tell the administrator.',
    },
  },
  uk: {
    name: 'Українська',
    docTitle: 'Реєстрація — ICQ Revival',
    winTitle: 'Реєстрація нового номера',
    heroTitle: 'Отримати номер ICQ Revival',
    heroText: 'Оберіть вільний номер і пароль — і можна виходити на зв’язок.',
    legendAccount: 'Обліковий запис',
    labelUin: 'Бажаний номер (UIN)',
    hintUin: `Від ${UIN_MIN} до ${UIN_MAX}. Перевіримо, чи вільний.`,
    labelPass: 'Пароль',
    hintPass: `Від ${PASS_MIN} до ${PASS_MAX} символів — так влаштовано протокол ICQ.`,
    labelPass2: 'Пароль ще раз',
    btnSuggest: 'Підібрати номер',
    btnSubmit: 'Зареєструвати',
    legendSetup: 'Налаштування клієнта',
    setupServer: 'Сервер',
    setupPort: 'Порт',
    setupPortSsl: 'Порт із SSL',
    setupNote:
      'Клієнти тих років шифрування не знали — ICQ 2000b–5.1, QIP 2005/2010/2012, Pidgin: їм потрібен звичайний порт і вимкнений SSL. Якщо клієнт уміє SSL (наприклад, Miranda NG), увімкніть його та вкажіть порт із SSL.',
    setupDownload: 'Патчі для ICQ 2003b та ICQ 6.5 і наш плагін ICQ для Miranda NG:',
    linkToDownload: 'Клієнти та патчі',
    statusReady: '',
    statusSuggesting: 'Підбираю вільний номер…',
    statusSuggested: (u) => `Номер ${u} вільний`,
    statusSuggestFailed: 'Не вдалося підібрати номер',
    statusChecking: 'Перевіряю номер…',
    statusFree: (u) => `Номер ${u} вільний`,
    statusTaken: (u) => `Номер ${u} вже зайнято`,
    statusCheckFailed: 'Перевірити не вдалося',
    statusRegistering: 'Реєструю…',
    statusError: 'Помилка',
    statusOffline: 'Помилка зв’язку',
    count: (n) => `Номерів: ${n}`,
    okTitle: 'Номер зареєстровано',
    okYourNumber: 'Ваш номер:',
    okHowTo: (host, port) =>
      `Вкажіть його та пароль у налаштуваннях клієнта — сервер <code>${host}</code>, порт <code>${port}</code>.`,
    errTitle: 'Не вийшло',
    errOffline: 'Сервіс реєстрації недоступний.',
    linkToChange: 'Змінити пароль',
    linkToProfile: 'Мій профіль',
    linkToAdmin: 'Адмінка',
    linkToRegister: 'Отримати номер',
    chDocTitle: 'Зміна пароля — ICQ Revival',
    chWinTitle: 'Зміна пароля',
    chHeroTitle: 'Змінити пароль',
    chHeroText: 'Знадобиться номер і поточний пароль.',
    chLabelUin: 'Номер (UIN)',
    chLabelCurrent: 'Поточний пароль',
    chLabelNew: 'Новий пароль',
    chLabelNew2: 'Новий пароль ще раз',
    chBtnSubmit: 'Змінити пароль',
    chStatusWorking: 'Змінюю пароль…',
    chOkTitle: 'Пароль змінено',
    chOkText: (u) => `Пароль для номера ${u} оновлено. Вкажіть новий пароль у налаштуваннях клієнта.`,
    chNote: 'Клієнти ICQ змінюють пароль через запит, який сервер не підтримує, — тому ця сторінка.',
    labelMail: 'Пошта для відновлення',
    hintMail: 'Не обов’язково. Без неї забутий пароль скине лише адміністратор, а входити можна буде тільки за номером. З нею клієнт приймає адресу й у полі «ICQ#/Email». Одна адреса — один обліковий запис; іншим користувачам вона не видна.',
    legendRecovery: 'Відновлення доступу',
    rcBindText: 'Вкажіть номер, поточний пароль і адресу — надішлемо лист для підтвердження.',
    rcBtnBind: 'Прив’язати пошту',
    rcBoundTitle: 'Лист надіслано',
    rcBoundText: (mail) => `Лист пішов на ${mail}. Перейдіть за посиланням із нього, щоб підтвердити адресу.`,
    rcDocTitle: 'Відновлення пароля — ICQ Revival',
    rcWinTitle: 'Відновлення пароля',
    rcHeroTitle: 'Забули пароль?',
    rcHeroText: 'Надішлемо посилання на пошту, прив’язану до номера.',
    rcLabelUin: 'Номер (UIN)',
    rcBtnSend: 'Надіслати посилання',
    rcSentTitle: 'Перевірте пошту',
    rcSentText: 'Якщо до цього номера прив’язано підтверджену адресу, лист із посиланням уже надіслано. Посилання діє 30 хвилин.',
    rcSetTitle: 'Новий пароль',
    rcSetText: (u) => `Придумайте новий пароль для номера ${u}.`,
    rcBtnSet: 'Встановити пароль',
    rcOkTitle: 'Пароль встановлено',
    rcOkText: (u) => `Пароль для номера ${u} оновлено. Вкажіть новий пароль у налаштуваннях клієнта.`,
    vfOkTitle: 'Адресу підтверджено',
    vfOkText: (u) => `Тепер пароль для номера ${u} можна відновити поштою.`,
    vfErrTitle: 'Посилання не підійшло',
    vfErrText: 'Посилання застаріло або вже використане. Запросіть нове.',
    linkToRecover: 'Забули пароль?',
    statusSending: 'Надсилаю лист…',
    statusSent: 'Лист надіслано',
    mailVerifySubject: 'Підтвердження адреси для номера ICQ Revival',
    mailVerifyBody: (u, url) =>
      `Вітаємо!\n\nЦю адресу вказано для відновлення пароля номера ICQ Revival ${u}.\nЩоб підтвердити її, відкрийте посилання:\n\n${url}\n\nПосилання діє 30 хвилин.\nЯкщо ви нічого не прив’язували, просто видаліть цей лист.\n`,
    mailResetSubject: 'Відновлення пароля ICQ Revival',
    mailResetBody: (u, url) =>
      `Вітаємо!\n\nДля номера ICQ Revival ${u} запитано скидання пароля.\nЩоб задати новий пароль, відкрийте посилання:\n\n${url}\n\nПосилання діє 30 хвилин і спрацює один раз.\nЯкщо скидання запитували не ви, нічого робити не потрібно — пароль залишиться попереднім.\n`,
    acDocTitle: 'Номер і обліковий запис — ICQ Revival',
    acWinTitle: 'Керування номером',
    acHeroTitle: 'Номер і обліковий запис',
    acHeroText: 'Можна зайняти інший номер або видалити обліковий запис зовсім.',
    acLegendMove: 'Зміна номера',
    acMoveText:
      'Перейменувати номер сервер не вміє, тому ми заведемо новий і видалимо старий. Пароль, контакт-лист, дані профілю та пошта для відновлення переїдуть.',
    acMoveWarn:
      'У друзів у контакт-листах залишиться старий номер — їх доведеться додати заново. Непрочитані повідомлення, що чекають на старий номер, зникнуть, а сам він звільниться для інших.',
    acLabelNewUin: 'Новий номер',
    acBtnMove: 'Змінити номер',
    acMovedTitle: 'Номер змінено',
    acMovedText: (from, to) => `Номер ${from} замінено на ${to}. Вкажіть новий номер і колишній пароль у налаштуваннях клієнта.`,
    acMovedPartial: 'Старий номер видалити не вдалося — він досі зайнятий. Повідомте адміністратора.',
    acLegendDelete: 'Видалення облікового запису',
    acDeleteText: 'Обліковий запис, контакт-лист і профіль буде видалено безповоротно. Номер знову стане вільним.',
    acLabelConfirm: 'Для підтвердження введіть номер ще раз',
    acBtnDelete: 'Видалити обліковий запис',
    acDeletedTitle: 'Обліковий запис видалено',
    acDeletedText: (u) => `Номера ${u} більше немає. Якщо передумаєте — його можна зареєструвати заново.`,
    linkToAccount: 'Змінити або видалити номер',
    statusMoving: 'Переношу номер…',
    statusDeleting: 'Видаляю обліковий запис…',
    err: {
      uin_not_number: 'Номер має складатися лише з цифр.',
      uin_range: `Номер має бути в діапазоні від ${UIN_MIN} до ${UIN_MAX}.`,
      pass_length: `Пароль має містити від ${PASS_MIN} до ${PASS_MAX} символів — це обмеження протоколу ICQ.`,
      pass_mismatch: 'Паролі не збігаються.',
      uin_taken: (u) => `Номер ${u} вже зайнято — оберіть інший.`,
      bad_request: 'Некоректний запит.',
      upstream: 'Сервер відхилив реєстрацію.',
      internal: 'Внутрішня помилка сервісу реєстрації.',
      no_user: (u) => `Номера ${u} на сервері немає.`,
      wrong_current: 'Поточний пароль неправильний.',
      same_secret: 'Новий пароль збігається зі старим.',
      too_many: (m) => `Забагато невдалих спроб. Повторіть через ${m} хв.`,
      suspended: 'Обліковий запис заблоковано — зверніться до адміністратора.',
      mail_invalid: 'Адреса пошти виглядає неправильно.',
      mail_failed: 'Не вдалося надіслати лист. Спробуйте пізніше або зверніться до адміністратора.',
      mail_off: 'Надсилання листів на цьому сервері не налаштовано — зверніться до адміністратора.',
      mail_cooldown: 'Лист уже надіслано. Зачекайте хвилину та перевірте теку зі спамом.',
      mail_taken: 'Цю адресу вже підтверджено для іншого номера. Одна адреса — один обліковий запис.',
      token_bad: 'Посилання недійсне — можливо, ним уже скористалися.',
      token_expired: 'Термін дії посилання минув. Запросіть нове.',
      uin_same: 'Новий номер збігається з поточним.',
      confirm_mismatch: 'Для підтвердження потрібно ввести той самий номер.',
      delete_failed: 'Видалити обліковий запис не вдалося. Повідомте адміністратора.',
    },
  },
};

// Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8 -> 'ru'
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

// Errors are returned as codes, not text: the browser translates them,
// so switching the language does not need another request.
function validate({ uin, password, password2 }) {
  if (!/^\d+$/.test(String(uin || '').trim())) {
    return { code: 'uin_not_number' };
  }
  const n = Number(uin);
  if (n < UIN_MIN || n > UIN_MAX) {
    return { code: 'uin_range' };
  }
  const p = String(password || '');
  if (p.length < PASS_MIN || p.length > PASS_MAX) {
    return { code: 'pass_length' };
  }
  if (p !== password2) {
    return { code: 'pass_mismatch' };
  }
  return null;
}

// The ICQ profile goes only through the management API: that way edits from the
// page pass the same checks as edits from the client.
async function fetchProfile(uin) {
  const res = await fetch(`${API}/user/${encodeURIComponent(uin)}/icq`);
  if (!res.ok) throw new Error(`management API returned ${res.status}`);
  return res.json();
}

async function saveProfile(uin, profile) {
  const res = await fetch(`${API}/user/${encodeURIComponent(uin)}/icq`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
  });
  return { ok: res.ok, status: res.status, text: await res.text() };
}

async function listUsers() {
  const res = await fetch(`${API}/user`);
  if (!res.ok) throw new Error(`management API returned ${res.status}`);
  return res.json();
}

function md5(buf) {
  return crypto.createHash('md5').update(buf).digest();
}

// Mirrors wire/user.go: weak = MD5(authKey + pass + suffix),
// strong = MD5(authKey + MD5(pass) + suffix).
function weakHash(pass, authKey) {
  return md5(Buffer.concat([Buffer.from(authKey), Buffer.from(pass), Buffer.from(HASH_SUFFIX)]));
}

function strongHash(pass, authKey) {
  return md5(Buffer.concat([Buffer.from(authKey), md5(Buffer.from(pass)), Buffer.from(HASH_SUFFIX)]));
}

function hexEqual(hex, digest) {
  if (!hex) return false;
  const a = Buffer.from(hex, 'hex');
  if (a.length !== digest.length) return false;
  return crypto.timingSafeEqual(a, digest);
}

// Returns null if there is no such user, false if the password does not match.
function verifyCurrentSecret(uin, value) {
  let db;
  try {
    db = new DatabaseSync(DB_PATH, { readOnly: true });
    const row = db
      .prepare(
        'SELECT authKey, hex(strongMD5Pass) AS s, hex(weakMD5Pass) AS w FROM users WHERE identScreenName = ?',
      )
      .get(String(uin));
    if (!row) return null;
    const authKey = row.authKey || '';
    return (
      hexEqual(row.s, strongHash(value, authKey)) || hexEqual(row.w, weakHash(value, authKey))
    );
  } finally {
    try {
      if (db) db.close();
    } catch {}
  }
}

function rateKey(ip, uin) {
  return `${ip}|${uin}`;
}

function lockedFor(key) {
  const rec = attempts.get(key);
  if (!rec) return 0;
  if (rec.count < MAX_ATTEMPTS) return 0;
  const left = rec.until - Date.now();
  if (left <= 0) {
    attempts.delete(key);
    return 0;
  }
  return Math.ceil(left / 60000);
}

function noteFailure(key) {
  const rec = attempts.get(key) || { count: 0, until: 0 };
  rec.count += 1;
  rec.until = Date.now() + LOCKOUT_MS;
  attempts.set(key, rec);
}

async function setSecret(uin, value) {
  const res = await fetch(`${API}/user/password`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ screen_name: String(uin), password: value }),
  });
  const text = (await res.text()).trim();
  return { ok: res.ok, status: res.status, text };
}

async function createUser(uin, password) {
  const res = await fetch(`${API}/user`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ screen_name: String(uin), password }),
  });
  const text = (await res.text()).trim();
  return { ok: res.ok, status: res.status, text };
}

// After a reset the active session is kicked: if someone has taken over the number,
// they must lose the connection at once rather than stay on until evening.
async function dropSessions(uin) {
  try {
    await fetch(`${API}/session/${encodeURIComponent(uin)}`, { method: 'DELETE' });
  } catch (err) {
    console.error('session drop failed', err);
  }
}

async function deleteUser(uin) {
  const res = await fetch(`${API}/user`, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ screen_name: String(uin) }),
  });
  const text = (await res.text()).trim();
  return { ok: res.ok, status: res.status, text };
}

// ---------------------------------------------------------------------------
// Moving to another number and deleting the account
// ---------------------------------------------------------------------------

// The ICQ profile is carried over as is: GET and PUT take the same structure,
// only the uin field changes.
async function copyProfile(from, to) {
  const res = await fetch(`${API}/user/${encodeURIComponent(from)}/icq`);
  if (!res.ok) return false;
  const profile = await res.json();
  profile.uin = Number(to);
  const put = await fetch(`${API}/user/${encodeURIComponent(to)}/icq`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(profile),
  });
  return put.ok;
}

// The contact list is moved group by group: first the group is created under the
// new number (the server assigns its ID itself), then the contacts are added to it.
async function copyContacts(from, to) {
  const res = await fetch(`${API}/feedbag/${encodeURIComponent(from)}/group`);
  if (!res.ok) return 0;
  const groups = await res.json();
  let moved = 0;
  for (const group of Array.isArray(groups) ? groups : []) {
    const made = await fetch(
      `${API}/feedbag/${encodeURIComponent(to)}/group/${encodeURIComponent(group.group_name)}`,
      { method: 'PUT' },
    );
    if (!made.ok) continue;
    const handle = await made.json().catch(() => null);
    if (!handle || !handle.group_id) continue;
    for (const buddy of group.buddies || []) {
      const added = await fetch(
        `${API}/feedbag/${encodeURIComponent(to)}/group/${handle.group_id}/buddy/${encodeURIComponent(buddy.name)}`,
        { method: 'PUT' },
      );
      if (added.ok) moved += 1;
    }
  }
  return moved;
}

// DELETE /user removes only the row in users. The contact list, profile and
// visibility settings are left orphaned (these tables have no foreign keys), and the
// next owner of the freed number would get someone else's contact list. So we
// clean up ourselves; the rows no longer belong to anyone, so writing is safe.
function purgeLeftovers(uin) {
  let db;
  try {
    db = new DatabaseSync(DB_PATH, { timeout: 5000 });
    let removed = 0;
    for (const [table, column] of [
      ['feedbag', 'screenName'],
      ['profile', 'screenName'],
      ['buddyListMode', 'screenName'],
      ['clientSideBuddyList', 'me'],
    ]) {
      removed += db.prepare(`DELETE FROM ${table} WHERE ${column} = ?`).run(String(uin)).changes;
    }
    return removed;
  } finally {
    try {
      if (db) db.close();
    } catch {}
  }
}

// ---------------------------------------------------------------------------
// Recovery by mail
// ---------------------------------------------------------------------------

fs.mkdirSync(path.dirname(RECOVERY_DB), { recursive: true });
const store = new DatabaseSync(RECOVERY_DB);
store.exec(`
  CREATE TABLE IF NOT EXISTS recoveryEmail (
    uin       TEXT PRIMARY KEY,
    email     TEXT    NOT NULL,
    verified  INTEGER NOT NULL DEFAULT 0,
    updatedAt INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS recoveryToken (
    hash      TEXT PRIMARY KEY,
    uin       TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    email     TEXT    NOT NULL,
    expiresAt INTEGER NOT NULL,
    usedAt    INTEGER
  );
  CREATE TABLE IF NOT EXISTS mailLog (
    uin  TEXT    NOT NULL,
    sent INTEGER NOT NULL
  );
`);

// Migration at startup: on a server where addresses were confirmed before the login
// table appeared, it would otherwise stay empty until the first address edit.
process.nextTick(syncLoginEmail);

// The address is checked conservatively: one "@", a dot in the domain, no spaces.
function normalizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  if (!email || email.length > EMAIL_MAX) return null;
  if (!/^[^\s@,;<>"']+@[^\s@,;<>"'.]+(\.[^\s@,;<>"'.]+)+$/.test(email)) return null;
  return email;
}

function getRecovery(uin) {
  return store.prepare('SELECT email, verified FROM recoveryEmail WHERE uin = ?').get(String(uin)) || null;
}

// The number the address already belongs to, or null. The address lives in three
// places (the ICQ profile, the AIM account and here), and each of them lets its
// owner into the client, so all three are checked: one address, one account.
function emailOwner(email, exceptUin) {
  const addr = String(email).trim().toLowerCase();
  const except = String(exceptUin || '');

  const row = store
    .prepare('SELECT uin FROM recoveryEmail WHERE email = ? AND uin <> ?')
    .get(addr, except);
  if (row) return row.uin;

  let db;
  try {
    db = new DatabaseSync(DB_PATH, { readOnly: true });
    const hit = db
      .prepare(
        `SELECT identScreenName AS uin FROM users
          WHERE identScreenName <> ?
            AND (LOWER(TRIM(icq_basicInfo_emailAddress)) = ? OR LOWER(TRIM(emailAddress)) = ?)`,
      )
      .get(except, addr, addr);
    return hit ? hit.uin : null;
  } catch (err) {
    // The main database is unavailable; refusing is safer than handing out the address twice.
    console.error(`could not check the address against the main database: ${err.message}`);
    return 'unknown';
  } finally {
    try {
      if (db) db.close();
    } catch {}
  }
}

function saveRecovery(uin, email) {
  store
    .prepare(
      `INSERT INTO recoveryEmail (uin, email, verified, updatedAt) VALUES (?, ?, 0, ?)
       ON CONFLICT(uin) DO UPDATE SET email = excluded.email, verified = 0, updatedAt = excluded.updatedAt`,
    )
    .run(String(uin), email, Date.now());
  syncLoginEmail();
}

// Returns false if another number has taken the address in the meantime: between
// the mail and the click on the link it may have been attached elsewhere.
function markVerified(uin, email) {
  if (emailOwner(email, uin)) return false;
  store
    .prepare('UPDATE recoveryEmail SET verified = 1, updatedAt = ? WHERE uin = ? AND email = ?')
    .run(Date.now(), String(uin), email);
  syncLoginEmail();
  return true;
}

// Login by mail address is done by the OSCAR server, while the recovery address is
// kept by this service in its own database. So it is mirrored into the main database,
// where login reads it. The set is tiny, so it is rewritten in full: after any edit
// no discrepancies remain.
//
// Confirmation by mail plays no part here: an address can only be attached by
// someone who knows the account's current password, so an unconfirmed address does
// not let anyone in anyway. Confirmation is needed only for password recovery itself,
// so that the mail with the link goes to a mailbox the person really reads.
//
// The table may not exist yet if the server with the needed migration has not run;
// then we just log it and try again next time.
function syncLoginEmail() {
  const rows = store
    .prepare('SELECT uin, email, updatedAt FROM recoveryEmail')
    .all();
  let db;
  try {
    db = new DatabaseSync(DB_PATH, { timeout: 5000 });
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('DELETE FROM loginEmail').run();
      const insert = db.prepare(
        'INSERT INTO loginEmail (identScreenName, email, boundAt) VALUES (?, ?, ?)',
      );
      for (const row of rows) {
        insert.run(
          String(row.uin),
          String(row.email).trim().toLowerCase(),
          Math.floor(row.updatedAt / 1000),
        );
      }
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw err;
    }
  } catch (err) {
    console.error(`recovery addresses were not copied to the main database: ${err.message}`);
  } finally {
    try {
      if (db) db.close();
    } catch {}
  }
}

function tokenHash(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Only the hash is stored: a leaked file does not yield working links.
function issueToken(uin, kind, email) {
  store.prepare('DELETE FROM recoveryToken WHERE expiresAt < ?').run(Date.now());
  const raw = crypto.randomBytes(32).toString('base64url');
  store
    .prepare('INSERT INTO recoveryToken (hash, uin, kind, email, expiresAt, usedAt) VALUES (?, ?, ?, ?, ?, NULL)')
    .run(tokenHash(raw), String(uin), kind, email, Date.now() + TOKEN_TTL_MS);
  return raw;
}

// Returns {code} on refusal, or the token string.
function takeToken(raw, kind) {
  if (!raw || !/^[A-Za-z0-9_-]{16,128}$/.test(raw)) return { code: 'token_bad' };
  const row = store.prepare('SELECT * FROM recoveryToken WHERE hash = ?').get(tokenHash(raw));
  if (!row || row.kind !== kind || row.usedAt) return { code: 'token_bad' };
  if (row.expiresAt < Date.now()) return { code: 'token_expired' };
  store.prepare('UPDATE recoveryToken SET usedAt = ? WHERE hash = ?').run(Date.now(), row.hash);
  return { row };
}

// Any password change invalidates the links already issued.
function dropTokens(uin) {
  store.prepare('DELETE FROM recoveryToken WHERE uin = ?').run(String(uin));
}

// The account is gone, so its address must be erased.
function forgetRecovery(uin) {
  for (const table of ['recoveryEmail', 'recoveryToken', 'mailLog']) {
    store.prepare(`DELETE FROM ${table} WHERE uin = ?`).run(String(uin));
  }
  syncLoginEmail();
}

// On a move the address goes to the new number together with its confirmation mark:
// the person has already proved the mailbox is theirs.
function moveRecovery(from, to) {
  const rec = getRecovery(from);
  forgetRecovery(to);
  if (rec) {
    store
      .prepare('INSERT INTO recoveryEmail (uin, email, verified, updatedAt) VALUES (?, ?, ?, ?)')
      .run(String(to), rec.email, rec.verified, Date.now());
  }
  forgetRecovery(from);
  syncLoginEmail();
}

function mailAllowed(uin) {
  const now = Date.now();
  store.prepare('DELETE FROM mailLog WHERE sent < ?').run(now - 60 * 60 * 1000);
  const rows = store.prepare('SELECT sent FROM mailLog WHERE uin = ? ORDER BY sent DESC').all(String(uin));
  if (rows.length >= MAIL_PER_HOUR) return false;
  if (rows.length && now - rows[0].sent < MAIL_COOLDOWN_MS) return false;
  return true;
}

function noteMail(uin) {
  store.prepare('INSERT INTO mailLog (uin, sent) VALUES (?, ?)').run(String(uin), Date.now());
}

// The mail is sent in the language the person was viewing the page in.
async function sendRecoveryMail(uin, email, kind, lang) {
  const t = I18N[LANGS.includes(lang) ? lang : FALLBACK_LANG];
  const raw = issueToken(uin, kind, email);
  const url =
    kind === 'verify'
      ? `${PUBLIC_BASE}/verify?token=${raw}&lang=${lang}`
      : `${PUBLIC_BASE}/recover?token=${raw}&lang=${lang}`;
  await sendMail({
    to: email,
    subject: kind === 'verify' ? t.mailVerifySubject : t.mailResetSubject,
    text: kind === 'verify' ? t.mailVerifyBody(uin, url) : t.mailResetBody(uin, url),
  });
  noteMail(uin);
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

// The browser needs the dictionary functions as strings, so they are serialized as is.
function serializeI18N() {
  return JSON.stringify(I18N, (key, value) =>
    typeof value === 'function' ? { __fn: value.toString() } : value,
  );
}

// The styling is shared by all of the project's services, see ui.js.
const { STYLE, flowerImg, header, footer, langLabel, serveAsset, FAVICON } = require('./ui.js');

// The profile page lives in a separate file: its markup is large. Its strings
// are merged into the shared dictionary, otherwise the language switch would not work on it.
const { STRINGS: PROFILE_STRINGS, renderProfilePage } = require('./profile.js');
for (const code of Object.keys(PROFILE_STRINGS)) {
  Object.assign(I18N[code], PROFILE_STRINGS[code]);
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
<style>${STYLE}</style>
</head>
<body>
<main class="window">
  ${header(t.winTitle, '', 'data-i18n="winTitle"')}

  <div class="body">
    <div class="hero">
      <div>
        <h1 data-i18n="heroTitle">${t.heroTitle}</h1>
        <p data-i18n="heroText">${t.heroText}</p>
      </div>
    </div>

    <div id="message" hidden></div>

    <form id="form" autocomplete="off" novalidate>
      <fieldset>
        <legend data-i18n="legendAccount">${t.legendAccount}</legend>
        <div class="row">
          <label for="uin" data-i18n="labelUin">${t.labelUin}</label>
          <input type="text" id="uin" name="uin" inputmode="numeric" maxlength="10" required>
          <p class="hint" data-i18n="hintUin">${t.hintUin}</p>
        </div>
        <div class="row">
          <label for="password" data-i18n="labelPass">${t.labelPass}</label>
          <input type="password" id="password" name="password" minlength="${PASS_MIN}" maxlength="${PASS_MAX}" required>
          <p class="hint" data-i18n="hintPass">${t.hintPass}</p>
        </div>
        <div class="row">
          <label for="password2" data-i18n="labelPass2">${t.labelPass2}</label>
          <input type="password" id="password2" name="password2" maxlength="${PASS_MAX}" required>
        </div>
        <div class="row">
          <label for="mail" data-i18n="labelMail">${t.labelMail}</label>
          <input type="email" id="mail" name="mail" maxlength="${EMAIL_MAX}" autocomplete="email">
          <p class="hint" data-i18n="hintMail">${t.hintMail}</p>
        </div>
      </fieldset>

      <div class="actions">
        <button type="button" id="suggest" data-i18n="btnSuggest">${t.btnSuggest}</button>
        <button type="submit" id="submit" data-i18n="btnSubmit">${t.btnSubmit}</button>
      </div>
    </form>

    <fieldset style="margin-top:14px">
      <legend data-i18n="legendSetup">${t.legendSetup}</legend>
      <div class="setup">
        <span data-i18n="setupServer">${t.setupServer}</span>: <code>${OSCAR_HOST}</code><br>
        <span data-i18n="setupPort">${t.setupPort}</span>: <code>${OSCAR_PORT}</code> &nbsp;
        <span data-i18n="setupPortSsl">${t.setupPortSsl}</span>: <code>${OSCAR_PORT_SSL}</code><br>
        <span data-i18n="setupNote">${t.setupNote}</span><br>
        <span data-i18n="setupDownload">${t.setupDownload}</span>
        <a href="/icq/download" data-i18n="linkToDownload">${t.linkToDownload}</a>
      </div>
    </fieldset>

    <div class="nav">
      <a href="/icq/download" data-i18n="linkToDownload">${t.linkToDownload}</a>
      &nbsp;·&nbsp;
      <a href="/profile" id="nav-link" data-i18n="linkToProfile">${t.linkToProfile}</a>
      &nbsp;·&nbsp;
      <a href="/recover" data-i18n="linkToRecover">${t.linkToRecover}</a>
      &nbsp;·&nbsp;
      <a href="/account" data-i18n="linkToAccount">${t.linkToAccount}</a>${adminLink(t)}
    </div>
  </div>

  ${footer({ statusId: 'status', langsId: 'langs',
    extra: '<span id="count">\u2014</span>' })}
</main>

<script>
const OSCAR_HOST = ${JSON.stringify(OSCAR_HOST)};
const OSCAR_PORT = ${JSON.stringify(OSCAR_PORT)};
const LANGS = ${JSON.stringify(LANGS)};
const LANG_LABEL = (c) => String(c).toUpperCase();

// Dictionary functions arrive as strings, so they are made callable again.
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
let lastStatus = { key: 'statusReady', arg: null };

const form = document.getElementById('form');
const uinEl = document.getElementById('uin');
const passEl = document.getElementById('password');
const pass2El = document.getElementById('password2');
const mailEl = document.getElementById('mail');
const msgEl = document.getElementById('message');
const statusEl = document.getElementById('status');
const countEl = document.getElementById('count');
const submitEl = document.getElementById('submit');
const suggestEl = document.getElementById('suggest');
const langsEl = document.getElementById('langs');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function setStatus(key, arg) {
  lastStatus = { key, arg };
  const v = t[key];
  statusEl.textContent = typeof v === 'function' ? v(arg) : v;
}

function translateError(payload) {
  const entry = t.err[payload.code] || t.err.internal;
  return typeof entry === 'function' ? entry(payload.uin) : entry;
}

// The last message is kept as data so it can be redrawn in another language.
let lastMessage = null;

function renderMessage() {
  if (!lastMessage) return;
  if (lastMessage.kind === 'ok') {
    msgEl.className = 'msg ok';
    let extra = '';
    if (lastMessage.mail === 'sent') {
      extra = '<p>' + esc(t.rcBoundText(lastMessage.email)) + '</p>';
    } else if (lastMessage.mail === 'failed') {
      extra = '<p>' + esc(t.err.mail_failed) + '</p>';
    }
    msgEl.innerHTML =
      '<h2>' + t.okTitle + '</h2>' +
      '<p>' + t.okYourNumber + ' <span class="uin">' + esc(lastMessage.uin) + '</span></p>' +
      '<p>' + t.okHowTo(OSCAR_HOST, OSCAR_PORT) + '</p>' + extra;
  } else {
    msgEl.className = 'msg err';
    const text = lastMessage.offline ? t.errOffline : translateError(lastMessage.payload);
    msgEl.innerHTML = '<h2>' + t.errTitle + '</h2><p>' + esc(text) + '</p>';
  }
  msgEl.hidden = false;
}

function applyLang(next) {
  lang = next;
  t = I18N[lang];
  document.documentElement.lang = lang;
  document.title = t.docTitle;

  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t[el.dataset.i18n];
  }

  setStatus(lastStatus.key, lastStatus.arg);
  renderMessage();
  renderLangs();
  refreshCount();

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

async function refreshCount() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    countEl.textContent = t.count(d.count);
  } catch {
    countEl.textContent = '—';
  }
}

suggestEl.addEventListener('click', async () => {
  setStatus('statusSuggesting');
  try {
    const r = await fetch('/api/suggest');
    const d = await r.json();
    uinEl.value = d.uin;
    setStatus('statusSuggested', d.uin);
  } catch {
    setStatus('statusSuggestFailed');
  }
});

uinEl.addEventListener('blur', async () => {
  const v = uinEl.value.trim();
  if (!/^\\d+$/.test(v)) return;
  setStatus('statusChecking');
  try {
    const r = await fetch('/api/check?uin=' + encodeURIComponent(v));
    const d = await r.json();
    setStatus(d.taken ? 'statusTaken' : 'statusFree', v);
  } catch {
    setStatus('statusCheckFailed');
  }
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  submitEl.disabled = true;
  setStatus('statusRegistering');
  try {
    const r = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        uin: uinEl.value.trim(),
        password: passEl.value,
        password2: pass2El.value,
        mail: mailEl.value.trim(),
        lang: lang,
      }),
    });
    const d = await r.json();
    if (d.ok) {
      lastMessage = { kind: 'ok', uin: d.uin, mail: d.mail, email: d.email };
      renderMessage();
      form.reset();
      setStatus('statusReady');
      refreshCount();
    } else {
      lastMessage = { kind: 'err', payload: d };
      renderMessage();
      setStatus('statusError');
    }
    msgEl.scrollIntoView({ block: 'nearest' });
  } catch {
    lastMessage = { kind: 'err', offline: true };
    renderMessage();
    setStatus('statusOffline');
  } finally {
    submitEl.disabled = false;
  }
});

applyLang(lang);
</script>
</body>
</html>`;
}

function renderRecoverPage(lang, token) {
  const t = I18N[lang];
  return /* html */ `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.rcDocTitle}</title>
${FAVICON}
<style>${STYLE}</style>
</head>
<body>
<main class="window">
  ${header(t.rcWinTitle, '', 'data-i18n="rcWinTitle"')}

  <div class="body">
    <div class="hero">
      <div>
        <h1 data-i18n="${token ? 'rcSetTitle' : 'rcHeroTitle'}">${token ? t.rcSetTitle : t.rcHeroTitle}</h1>
        <p data-i18n="${token ? 'rcHeroText' : 'rcHeroText'}">${t.rcHeroText}</p>
      </div>
    </div>

    <div id="message" hidden></div>

    <form id="form" autocomplete="off" novalidate${token ? ' hidden' : ''}>
      <fieldset>
        <legend data-i18n="legendRecovery">${t.legendRecovery}</legend>
        <div class="row">
          <label for="uin" data-i18n="rcLabelUin">${t.rcLabelUin}</label>
          <input type="text" id="uin" name="uin" inputmode="numeric" maxlength="10" required>
        </div>
      </fieldset>
      <div class="actions">
        <button type="submit" id="submit" data-i18n="rcBtnSend">${t.rcBtnSend}</button>
      </div>
    </form>

    <form id="setform" autocomplete="off" novalidate${token ? '' : ' hidden'}>
      <fieldset>
        <legend data-i18n="rcSetTitle">${t.rcSetTitle}</legend>
        <div class="row">
          <label for="next" data-i18n="chLabelNew">${t.chLabelNew}</label>
          <input type="password" id="next" name="next" minlength="${PASS_MIN}" maxlength="${PASS_MAX}" required>
          <p class="hint" data-i18n="hintPass">${t.hintPass}</p>
        </div>
        <div class="row">
          <label for="next2" data-i18n="chLabelNew2">${t.chLabelNew2}</label>
          <input type="password" id="next2" name="next2" maxlength="${PASS_MAX}" required>
        </div>
      </fieldset>
      <div class="actions">
        <button type="submit" id="setsubmit" data-i18n="rcBtnSet">${t.rcBtnSet}</button>
      </div>
    </form>

    <div class="nav">
      <a href="/" data-i18n="linkToRegister">${t.linkToRegister}</a>
      &nbsp;·&nbsp;
      <a href="/profile" data-i18n="linkToProfile">${t.linkToProfile}</a>
      &nbsp;·&nbsp;
      <a href="/account" data-i18n="linkToAccount">${t.linkToAccount}</a>${adminLink(t)}
    </div>
  </div>

  ${footer({ statusId: 'status', langsId: 'langs' })}
</main>

<script>
const LANGS = ${JSON.stringify(LANGS)};
const LANG_LABEL = (c) => String(c).toUpperCase();
const TOKEN = ${JSON.stringify(token || '')};

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
let lastStatus = { key: 'statusReady', arg: null };
let lastMessage = null;

const form = document.getElementById('form');
const setForm = document.getElementById('setform');
const uinEl = document.getElementById('uin');
const nextEl = document.getElementById('next');
const next2El = document.getElementById('next2');
const msgEl = document.getElementById('message');
const statusEl = document.getElementById('status');
const submitEl = document.getElementById('submit');
const setSubmitEl = document.getElementById('setsubmit');
const langsEl = document.getElementById('langs');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function setStatus(key, arg) {
  lastStatus = { key, arg };
  const v = t[key];
  statusEl.textContent = typeof v === 'function' ? v(arg) : v;
}

function translateError(payload) {
  const entry = t.err[(payload && payload.code) || 'internal'] || t.err.internal;
  return typeof entry === 'function' ? entry(payload && payload.arg) : entry;
}

function renderMessage() {
  if (!lastMessage) return;
  if (lastMessage.kind === 'sent') {
    msgEl.className = 'msg ok';
    msgEl.innerHTML = '<h2>' + t.rcSentTitle + '</h2><p>' + esc(t.rcSentText) + '</p>';
  } else if (lastMessage.kind === 'ok') {
    msgEl.className = 'msg ok';
    msgEl.innerHTML = '<h2>' + t.rcOkTitle + '</h2><p>' + esc(t.rcOkText(lastMessage.uin)) + '</p>';
  } else {
    msgEl.className = 'msg err';
    const text = lastMessage.offline ? t.errOffline : translateError(lastMessage.payload);
    msgEl.innerHTML = '<h2>' + t.errTitle + '</h2><p>' + esc(text) + '</p>';
  }
  msgEl.hidden = false;
}

function applyLang(next) {
  lang = next;
  t = I18N[lang];
  document.documentElement.lang = lang;
  document.title = t.rcDocTitle;

  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t[el.dataset.i18n];
  }

  setStatus(lastStatus.key, lastStatus.arg);
  renderMessage();
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

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  submitEl.disabled = true;
  setStatus('statusSending');
  try {
    const r = await fetch('/api/recover-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uin: uinEl.value.trim(), lang: lang }),
    });
    const d = await r.json();
    lastMessage = d.ok ? { kind: 'sent' } : { kind: 'err', payload: d };
    setStatus(d.ok ? 'statusSent' : 'statusError');
    renderMessage();
  } catch {
    lastMessage = { kind: 'err', offline: true };
    renderMessage();
    setStatus('statusOffline');
  } finally {
    submitEl.disabled = false;
  }
});

setForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  setSubmitEl.disabled = true;
  setStatus('chStatusWorking');
  try {
    const r = await fetch('/api/recover-confirm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: TOKEN, next: nextEl.value, next2: next2El.value }),
    });
    const d = await r.json();
    if (d.ok) {
      lastMessage = { kind: 'ok', uin: d.uin };
      setForm.hidden = true;
      setStatus('statusReady');
    } else {
      lastMessage = { kind: 'err', payload: d };
      setStatus('statusError');
    }
    renderMessage();
  } catch {
    lastMessage = { kind: 'err', offline: true };
    renderMessage();
    setStatus('statusOffline');
  } finally {
    setSubmitEl.disabled = false;
  }
});

applyLang(lang);
</script>
</body>
</html>`;
}

// Address confirmation: a short page with the result, no forms.
function renderVerifyPage(lang, uin, failText) {
  const t = I18N[lang];
  const ok = Boolean(uin);
  return /* html */ `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.rcDocTitle}</title>
${FAVICON}
<style>${STYLE}</style>
</head>
<body>
<main class="window">
  <div class="titlebar">
    <span class="label">${t.rcWinTitle}</span>
  </div>

  <div class="body">
    <div class="msg ${ok ? 'ok' : 'err'}">
      <h2>${ok ? t.vfOkTitle : t.vfErrTitle}</h2>
      <p>${ok ? t.vfOkText(uin) : failText || t.vfErrText}</p>
    </div>
    <div class="nav">
      <a href="/">${t.linkToRegister}</a>
      &nbsp;·&nbsp;
      <a href="/profile">${t.linkToProfile}</a>
      &nbsp;·&nbsp;
      <a href="/recover">${t.linkToRecover}</a>${adminLink(t)}
    </div>
  </div>

  <div class="statusbar">
    <span class="grow">${t.statusReady}</span>
  </div>
</main>
</body>
</html>`;
}

// Changing the number and deleting the account are both irreversible and both are
// proved with the current password, so they share one page with common sign-in fields.
function renderAccountPage(lang) {
  const t = I18N[lang];
  return /* html */ `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${t.acDocTitle}</title>
${FAVICON}
<style>${STYLE}</style>
</head>
<body>
<main class="window">
  ${header(t.acWinTitle, '', 'data-i18n="acWinTitle"')}

  <div class="body">
    <div class="hero">
      <div>
        <h1 data-i18n="acHeroTitle">${t.acHeroTitle}</h1>
        <p data-i18n="acHeroText">${t.acHeroText}</p>
      </div>
    </div>

    <div id="message" hidden></div>

    <form id="form" autocomplete="off" novalidate>
      <fieldset>
        <legend data-i18n="legendAccount">${t.legendAccount}</legend>
        <div class="row">
          <label for="uin" data-i18n="chLabelUin">${t.chLabelUin}</label>
          <input type="text" id="uin" name="uin" inputmode="numeric" maxlength="10" required>
        </div>
        <div class="row">
          <label for="current" data-i18n="chLabelCurrent">${t.chLabelCurrent}</label>
          <input type="password" id="current" name="current" maxlength="${PASS_MAX}" required>
        </div>
      </fieldset>

      <fieldset>
        <legend data-i18n="acLegendMove">${t.acLegendMove}</legend>
        <p class="hint" data-i18n="acMoveText" style="margin:0 0 6px">${t.acMoveText}</p>
        <p class="hint" data-i18n="acMoveWarn" style="margin:0 0 10px">${t.acMoveWarn}</p>
        <div class="row">
          <label for="newuin" data-i18n="acLabelNewUin">${t.acLabelNewUin}</label>
          <input type="text" id="newuin" name="newuin" inputmode="numeric" maxlength="10">
        </div>
        <div class="actions" style="margin-top:10px">
          <button type="button" id="suggest" data-i18n="btnSuggest">${t.btnSuggest}</button>
          <button type="button" id="move" data-i18n="acBtnMove">${t.acBtnMove}</button>
        </div>
      </fieldset>

      <fieldset>
        <legend data-i18n="acLegendDelete">${t.acLegendDelete}</legend>
        <p class="hint" data-i18n="acDeleteText" style="margin:0 0 10px">${t.acDeleteText}</p>
        <div class="row">
          <label for="confirm" data-i18n="acLabelConfirm">${t.acLabelConfirm}</label>
          <input type="text" id="confirm" name="confirm" inputmode="numeric" maxlength="10">
        </div>
        <div class="actions" style="margin-top:10px">
          <button type="button" id="drop" data-i18n="acBtnDelete">${t.acBtnDelete}</button>
        </div>
      </fieldset>
    </form>

    <div class="nav">
      <a href="/" data-i18n="linkToRegister">${t.linkToRegister}</a>
      &nbsp;·&nbsp;
      <a href="/profile" data-i18n="linkToProfile">${t.linkToProfile}</a>
      &nbsp;·&nbsp;
      <a href="/recover" data-i18n="linkToRecover">${t.linkToRecover}</a>${adminLink(t)}
    </div>
  </div>

  ${footer({ statusId: 'status', langsId: 'langs' })}
</main>

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
let lastStatus = { key: 'statusReady', arg: null };
let lastMessage = null;

const uinEl = document.getElementById('uin');
const currentEl = document.getElementById('current');
const newUinEl = document.getElementById('newuin');
const confirmEl = document.getElementById('confirm');
const msgEl = document.getElementById('message');
const statusEl = document.getElementById('status');
const suggestEl = document.getElementById('suggest');
const moveEl = document.getElementById('move');
const dropEl = document.getElementById('drop');
const langsEl = document.getElementById('langs');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function setStatus(key, arg) {
  lastStatus = { key, arg };
  const v = t[key];
  statusEl.textContent = typeof v === 'function' ? v(arg) : v;
}

function translateError(payload) {
  const entry = t.err[(payload && payload.code) || 'internal'] || t.err.internal;
  return typeof entry === 'function' ? entry(payload && payload.arg) : entry;
}

function renderMessage() {
  if (!lastMessage) return;
  if (lastMessage.kind === 'moved') {
    msgEl.className = 'msg ok';
    msgEl.innerHTML =
      '<h2>' + t.acMovedTitle + '</h2>' +
      '<p>' + esc(t.acMovedText(lastMessage.from, lastMessage.to)) + '</p>' +
      '<p>' + t.okYourNumber + ' <span class="uin">' + esc(lastMessage.to) + '</span></p>' +
      (lastMessage.partial ? '<p>' + esc(t.acMovedPartial) + '</p>' : '');
  } else if (lastMessage.kind === 'deleted') {
    msgEl.className = 'msg ok';
    msgEl.innerHTML = '<h2>' + t.acDeletedTitle + '</h2><p>' + esc(t.acDeletedText(lastMessage.uin)) + '</p>';
  } else {
    msgEl.className = 'msg err';
    const text = lastMessage.offline ? t.errOffline : translateError(lastMessage.payload);
    msgEl.innerHTML = '<h2>' + t.errTitle + '</h2><p>' + esc(text) + '</p>';
  }
  msgEl.hidden = false;
}

function applyLang(next) {
  lang = next;
  t = I18N[lang];
  document.documentElement.lang = lang;
  document.title = t.acDocTitle;

  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t[el.dataset.i18n];
  }

  setStatus(lastStatus.key, lastStatus.arg);
  renderMessage();
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

suggestEl.addEventListener('click', async () => {
  setStatus('statusSuggesting');
  try {
    const r = await fetch('/api/suggest');
    const d = await r.json();
    newUinEl.value = d.uin;
    setStatus('statusSuggested', d.uin);
  } catch {
    setStatus('statusSuggestFailed');
  }
});

async function run(button, statusKey, path, body, onOk) {
  button.disabled = true;
  setStatus(statusKey);
  try {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();
    if (d.ok) {
      onOk(d);
      setStatus('statusReady');
    } else {
      lastMessage = { kind: 'err', payload: d };
      setStatus('statusError');
    }
    renderMessage();
    msgEl.scrollIntoView({ block: 'nearest' });
  } catch {
    lastMessage = { kind: 'err', offline: true };
    renderMessage();
    setStatus('statusOffline');
  } finally {
    button.disabled = false;
  }
}

moveEl.addEventListener('click', () => {
  run(
    moveEl,
    'statusMoving',
    '/api/change-uin',
    { uin: uinEl.value.trim(), current: currentEl.value, next_uin: newUinEl.value.trim() },
    (d) => {
      lastMessage = { kind: 'moved', from: d.from, to: d.uin, partial: d.partial };
      uinEl.value = d.uin;
      newUinEl.value = '';
    },
  );
});

dropEl.addEventListener('click', () => {
  // Entering the number a second time is the confirmation; no separate dialog is needed.
  run(
    dropEl,
    'statusDeleting',
    '/api/delete-account',
    { uin: uinEl.value.trim(), current: currentEl.value, confirm: confirmEl.value.trim() },
    (d) => {
      lastMessage = { kind: 'deleted', uin: d.uin };
      uinEl.value = '';
      currentEl.value = '';
      confirmEl.value = '';
    },
  );
});

applyLang(lang);
</script>
</body>
</html>`;
}

const server = http.createServer(async (req, res) => {
  if (serveAsset(req, res)) return;
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

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

    // Password change lives on the profile page, next to the address and the rest of
    // the account data. The old URL still works: bookmarks and the client itself
    // point to it.
    if (req.method === 'GET' && (url.pathname === '/password' || url.pathname === '/password.html')) {
      res.writeHead(302, { Location: '/profile', 'Cache-Control': 'no-store' });
      res.end();
      return;
    }

    if (req.method === 'GET' && url.pathname === '/recover') {
      const forced = String(url.searchParams.get('lang') || '').toLowerCase();
      const lang = LANGS.includes(forced) ? forced : pickLang(req.headers['accept-language']);
      const token = String(url.searchParams.get('token') || '');
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Language': lang,
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        Vary: 'Accept-Language',
      });
      res.end(renderRecoverPage(lang, token));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/profile') {
      const forced = String(url.searchParams.get('lang') || '').toLowerCase();
      const lang = LANGS.includes(forced) ? forced : pickLang(req.headers['accept-language']);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Language': lang,
        'Cache-Control': 'no-store',
        Vary: 'Accept-Language',
      });
      res.end(renderProfilePage(lang, {
        STYLE, FAVICON, header, footer, I18N, LANGS, PASS_MAX, EMAIL_MAX, serializeI18N, adminLink,
      }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/account') {
      const forced = String(url.searchParams.get('lang') || '').toLowerCase();
      const lang = LANGS.includes(forced) ? forced : pickLang(req.headers['accept-language']);
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Language': lang,
        'Cache-Control': 'no-store',
        Vary: 'Accept-Language',
      });
      res.end(renderAccountPage(lang));
      return;
    }

    if (
      req.method === 'POST' &&
      (url.pathname === '/api/change-uin' || url.pathname === '/api/delete-account')
    ) {
      const dropping = url.pathname === '/api/delete-account';
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const uin = String(payload.uin || '').trim();
      const ip = req.socket.remoteAddress || 'unknown';
      const key = rateKey(ip, uin);

      const waitMinutes = lockedFor(key);
      if (waitMinutes) {
        json(res, 429, { ok: false, code: 'too_many', arg: waitMinutes });
        return;
      }
      if (!/^\d+$/.test(uin)) {
        json(res, 400, { ok: false, code: 'uin_not_number' });
        return;
      }

      let target = '';
      if (dropping) {
        if (String(payload.confirm || '').trim() !== uin) {
          json(res, 400, { ok: false, code: 'confirm_mismatch' });
          return;
        }
      } else {
        target = String(payload.next_uin || '').trim();
        if (!/^\d+$/.test(target)) {
          json(res, 400, { ok: false, code: 'uin_not_number' });
          return;
        }
        const n = Number(target);
        if (n < UIN_MIN || n > UIN_MAX) {
          json(res, 400, { ok: false, code: 'uin_range' });
          return;
        }
        if (target === uin) {
          json(res, 400, { ok: false, code: 'uin_same' });
          return;
        }
      }

      let verdict;
      try {
        verdict = verifyCurrentSecret(uin, String(payload.current || ''));
      } catch (err) {
        console.error('secret check failed', err);
        json(res, 500, { ok: false, code: 'internal' });
        return;
      }
      if (verdict === null) {
        noteFailure(key);
        json(res, 404, { ok: false, code: 'no_user', arg: uin });
        return;
      }
      if (!verdict) {
        noteFailure(key);
        console.log(`failed secret check for ${uin} from ${ip}`);
        json(res, 403, { ok: false, code: 'wrong_current' });
        return;
      }

      // A locked-out account can neither escape to a new number nor delete itself.
      const account = await fetch(`${API}/user/${encodeURIComponent(uin)}/account`);
      if (account.ok) {
        const info = await account.json().catch(() => null);
        if (info && info.suspended_status) {
          json(res, 403, { ok: false, code: 'suspended' });
          return;
        }
      }
      attempts.delete(key);

      if (dropping) {
        await dropSessions(uin);
        const gone = await deleteUser(uin);
        if (!gone.ok) {
          console.error('account delete failed', gone.status, gone.text);
          json(res, 502, { ok: false, code: 'delete_failed' });
          return;
        }
        forgetRecovery(uin);
        try {
          console.log(`account ${uin} deleted, leftover rows removed: ${purgeLeftovers(uin)}`);
        } catch (err) {
          console.error('leftover cleanup failed', err);
        }
        json(res, 200, { ok: true, uin });
        return;
      }

      const users = await listUsers();
      if (users.some((u) => u.screen_name === target)) {
        json(res, 409, { ok: false, code: 'uin_taken', arg: target });
        return;
      }

      // Create the new number first: if that fails, the old one is intact.
      const created = await createUser(target, String(payload.current || ''));
      if (!created.ok) {
        console.error('new uin create failed', created.status, created.text);
        json(res, 502, { ok: false, code: 'upstream' });
        return;
      }

      let carried = { profile: false, contacts: 0 };
      try {
        carried.profile = await copyProfile(uin, target);
        carried.contacts = await copyContacts(uin, target);
      } catch (err) {
        console.error('carrying data over failed', err);
      }
      moveRecovery(uin, target);

      await dropSessions(uin);
      const gone = await deleteUser(uin);
      if (!gone.ok) console.error('old uin delete failed', gone.status, gone.text);
      if (gone.ok) {
        try {
          purgeLeftovers(uin);
        } catch (err) {
          console.error('leftover cleanup failed', err);
        }
      }

      console.log(
        `uin ${uin} -> ${target} (profile=${carried.profile}, contacts=${carried.contacts}, old removed=${gone.ok})`,
      );
      json(res, 200, { ok: true, uin: target, from: uin, partial: !gone.ok });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/verify') {
      const forced = String(url.searchParams.get('lang') || '').toLowerCase();
      const lang = LANGS.includes(forced) ? forced : pickLang(req.headers['accept-language']);
      const taken = takeToken(String(url.searchParams.get('token') || ''), 'verify');
      let confirmed = null;
      let failText = null;
      if (taken.row) {
        if (markVerified(taken.row.uin, taken.row.email)) {
          confirmed = taken.row.uin;
          console.log(`recovery mail confirmed for ${taken.row.uin}`);
        } else {
          failText = I18N[lang].err.mail_taken;
          console.log(`recovery mail already belongs to another number, refused for ${taken.row.uin}`);
        }
      }
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Language': lang,
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
      });
      res.end(renderVerifyPage(lang, confirmed, failText));
      return;
    }

    // Attaching an address: the current password serves as proof of ownership.
    if (req.method === 'POST' && url.pathname === '/api/recovery-email') {
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const uin = String(payload.uin || '').trim();
      const ip = req.socket.remoteAddress || 'unknown';
      const key = rateKey(ip, uin);

      const waitMinutes = lockedFor(key);
      if (waitMinutes) {
        json(res, 429, { ok: false, code: 'too_many', arg: waitMinutes });
        return;
      }
      if (!/^\d+$/.test(uin)) {
        json(res, 400, { ok: false, code: 'uin_not_number' });
        return;
      }
      if (!mailConfigured()) {
        json(res, 503, { ok: false, code: 'mail_off' });
        return;
      }
      const email = normalizeEmail(payload.mail);
      if (!email) {
        json(res, 400, { ok: false, code: 'mail_invalid' });
        return;
      }

      let verdict;
      try {
        verdict = verifyCurrentSecret(uin, String(payload.current || ''));
      } catch (err) {
        console.error('secret check failed', err);
        json(res, 500, { ok: false, code: 'internal' });
        return;
      }
      if (verdict === null) {
        noteFailure(key);
        json(res, 404, { ok: false, code: 'no_user', arg: uin });
        return;
      }
      if (!verdict) {
        noteFailure(key);
        json(res, 403, { ok: false, code: 'wrong_current' });
        return;
      }
      if (!mailAllowed(uin)) {
        json(res, 429, { ok: false, code: 'mail_cooldown' });
        return;
      }

      if (emailOwner(email, uin)) {
        json(res, 409, { ok: false, code: 'mail_taken' });
        return;
      }

      attempts.delete(key);
      saveRecovery(uin, email);
      try {
        await sendRecoveryMail(uin, email, 'verify', String(payload.lang || FALLBACK_LANG));
      } catch (err) {
        console.error('verify mail failed', err);
        json(res, 502, { ok: false, code: 'mail_failed' });
        return;
      }
      console.log(`recovery mail attached to ${uin}`);
      json(res, 200, { ok: true, email });
      return;
    }

    // Link request: the reply is always the same so that the page does not reveal
    // which numbers have mail.
    if (req.method === 'POST' && url.pathname === '/api/recover-request') {
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const uin = String(payload.uin || '').trim();
      if (!/^\d+$/.test(uin)) {
        json(res, 400, { ok: false, code: 'uin_not_number' });
        return;
      }
      if (!mailConfigured()) {
        json(res, 503, { ok: false, code: 'mail_off' });
        return;
      }

      const rec = getRecovery(uin);
      if (rec && rec.verified && mailAllowed(uin)) {
        try {
          await sendRecoveryMail(uin, rec.email, 'reset', String(payload.lang || FALLBACK_LANG));
          console.log(`reset link sent for ${uin}`);
        } catch (err) {
          console.error('reset mail failed', err);
        }
      }
      json(res, 200, { ok: true });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/recover-confirm') {
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const next = String(payload.next || '');
      if (next.length < PASS_MIN || next.length > PASS_MAX) {
        json(res, 400, { ok: false, code: 'pass_length' });
        return;
      }
      if (next !== payload.next2) {
        json(res, 400, { ok: false, code: 'pass_mismatch' });
        return;
      }

      // The token is spent only after the form is validated, otherwise a typo in the
      // password would burn the link.
      const taken = takeToken(String(payload.token || ''), 'reset');
      if (!taken.row) {
        json(res, 400, { ok: false, code: taken.code });
        return;
      }
      const uin = taken.row.uin;

      const account = await fetch(`${API}/user/${encodeURIComponent(uin)}/account`);
      if (account.ok) {
        const info = await account.json().catch(() => null);
        if (info && info.suspended_status) {
          json(res, 403, { ok: false, code: 'suspended' });
          return;
        }
      }

      const changed = await setSecret(uin, next);
      if (!changed.ok) {
        console.error('recovery reset failed', changed.status, changed.text);
        json(res, 502, { ok: false, code: 'upstream' });
        return;
      }

      dropTokens(uin);
      await dropSessions(uin);
      console.log(`password recovered for ${uin}`);
      json(res, 200, { ok: true, uin });
      return;
    }

    // There is no separate cookie-based sign-in: every request is signed with the number
    // and current password, like the rest of this service's actions.
    if (
      req.method === 'POST' &&
      (url.pathname === '/api/profile' || url.pathname === '/api/profile-save')
    ) {
      const saving = url.pathname === '/api/profile-save';
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const uin = String(payload.uin || '').trim();
      const ip = req.socket.remoteAddress || 'unknown';
      const key = rateKey(ip, uin);

      const waitMinutes = lockedFor(key);
      if (waitMinutes) {
        json(res, 429, { ok: false, code: 'too_many', arg: waitMinutes });
        return;
      }
      if (!/^\d+$/.test(uin)) {
        json(res, 400, { ok: false, code: 'uin_not_number' });
        return;
      }

      let verdict;
      try {
        verdict = verifyCurrentSecret(uin, String(payload.current || ''));
      } catch (err) {
        console.error('secret check failed', err);
        json(res, 500, { ok: false, code: 'internal' });
        return;
      }
      if (verdict === null) {
        noteFailure(key);
        json(res, 404, { ok: false, code: 'no_user', arg: uin });
        return;
      }
      if (!verdict) {
        noteFailure(key);
        json(res, 403, { ok: false, code: 'wrong_current' });
        return;
      }
      attempts.delete(key);

      if (!saving) {
        try {
          const profile = await fetchProfile(uin);
          const rec = getRecovery(uin);
          json(res, 200, {
            ok: true,
            profile,
            mail: rec ? { email: rec.email, verified: Boolean(rec.verified) } : null,
          });
        } catch (err) {
          console.error('profile read failed', err);
          json(res, 502, { ok: false, code: 'upstream' });
        }
        return;
      }

      const profile = payload.profile;
      if (!profile || typeof profile !== 'object') {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      let saved;
      try {
        saved = await saveProfile(uin, profile);
      } catch (err) {
        console.error('profile save failed', err);
        json(res, 502, { ok: false, code: 'upstream' });
        return;
      }
      if (saved.status === 409) {
        json(res, 409, { ok: false, code: 'mail_taken' });
        return;
      }
      if (!saved.ok) {
        console.error('profile save rejected', saved.status, saved.text);
        json(res, 502, { ok: false, code: 'upstream', detail: saved.text });
        return;
      }

      console.log(`profile updated for ${uin}`);
      json(res, 200, { ok: true });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/change-password') {
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const uin = String(payload.uin || '').trim();
      const ip = req.socket.remoteAddress || 'unknown';
      const key = rateKey(ip, uin);

      const waitMinutes = lockedFor(key);
      if (waitMinutes) {
        json(res, 429, { ok: false, code: 'too_many', arg: waitMinutes });
        return;
      }

      if (!/^\d+$/.test(uin)) {
        json(res, 400, { ok: false, code: 'uin_not_number' });
        return;
      }
      const next = String(payload.next || '');
      if (next.length < PASS_MIN || next.length > PASS_MAX) {
        json(res, 400, { ok: false, code: 'pass_length' });
        return;
      }
      if (next !== payload.next2) {
        json(res, 400, { ok: false, code: 'pass_mismatch' });
        return;
      }
      if (next === String(payload.current || '')) {
        json(res, 400, { ok: false, code: 'same_secret' });
        return;
      }

      let verdict;
      try {
        verdict = verifyCurrentSecret(uin, String(payload.current || ''));
      } catch (err) {
        console.error('secret check failed', err);
        json(res, 500, { ok: false, code: 'internal' });
        return;
      }

      if (verdict === null) {
        // A nonexistent number also counts as a failed attempt, otherwise
        // the page turns into a handy way to enumerate existing UINs.
        noteFailure(key);
        json(res, 404, { ok: false, code: 'no_user', arg: uin });
        return;
      }
      if (!verdict) {
        noteFailure(key);
        console.log(`failed secret check for ${uin} from ${ip}`);
        json(res, 403, { ok: false, code: 'wrong_current' });
        return;
      }

      // Locked-out accounts are not allowed to change the password.
      const account = await fetch(`${API}/user/${encodeURIComponent(uin)}/account`);
      if (account.ok) {
        const info = await account.json().catch(() => null);
        if (info && info.suspended_status) {
          json(res, 403, { ok: false, code: 'suspended' });
          return;
        }
      }

      const changed = await setSecret(uin, next);
      if (!changed.ok) {
        console.error('password change failed', changed.status, changed.text);
        json(res, 502, { ok: false, code: 'upstream' });
        return;
      }

      attempts.delete(key);
      dropTokens(uin);
      console.log(`password changed for ${uin} from ${ip}`);
      json(res, 200, { ok: true, uin });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/stats') {
      const users = await listUsers();
      json(res, 200, { count: users.length });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/check') {
      const uin = String(url.searchParams.get('uin') || '').trim();
      const users = await listUsers();
      json(res, 200, { uin, taken: users.some((u) => u.screen_name === uin) });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/suggest') {
      const users = await listUsers();
      const taken = new Set(users.map((u) => u.screen_name));
      let n = 100001;
      while (taken.has(String(n))) n++;
      json(res, 200, { uin: String(n) });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/register') {
      let payload;
      try {
        payload = JSON.parse(await readBody(req));
      } catch {
        json(res, 400, { ok: false, code: 'bad_request' });
        return;
      }

      const problem = validate(payload);
      if (problem) {
        json(res, 400, { ok: false, ...problem });
        return;
      }

      // The address is optional, but if given it is checked before the number is created,
      // so that a typo does not leave an account without recovery.
      const wantedMail = String(payload.mail || '').trim();
      let email = null;
      if (wantedMail) {
        email = normalizeEmail(wantedMail);
        if (!email) {
          json(res, 400, { ok: false, code: 'mail_invalid' });
          return;
        }
      }

      const uin = String(payload.uin).trim();
      const users = await listUsers();
      if (users.some((u) => u.screen_name === uin)) {
        json(res, 409, { ok: false, code: 'uin_taken', uin });
        return;
      }

      const created = await createUser(uin, payload.password);
      if (!created.ok) {
        console.error('create failed', created.status, created.text);
        json(res, 502, { ok: false, code: 'upstream', detail: created.text });
        return;
      }

      // The number is already created, so a mail failure does not undo the registration;
      // the address can always be attached later on the password change page.
      let mailState = 'none';
      if (email) {
        mailState = 'failed';
        if (mailConfigured()) {
          if (emailOwner(email, uin)) {
            json(res, 409, { ok: false, code: 'mail_taken', uin });
            return;
          }
          saveRecovery(uin, email);
          try {
            await sendRecoveryMail(uin, email, 'verify', String(payload.lang || FALLBACK_LANG));
            mailState = 'sent';
          } catch (err) {
            console.error('verify mail failed', err);
          }
        }
      }

      console.log(`registered uin=${uin} mail=${mailState}`);
      json(res, 200, { ok: true, uin, mail: mailState, email });
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
  console.log(`registration page on http://${HOST}:${PORT} (management API: ${API})`);
  console.log(
    mailConfigured()
      ? `recovery by mail is on, links point to ${PUBLIC_BASE}`
      : 'recovery by mail is off: SMTP_HOST/SMTP_FROM are not set',
  );
});
