'use strict';

// Страница профиля: показывает и правит анкету ICQ, пароль и адрес почты.
//
// Отдельным файлом, потому что разметка большая, а server.js и без неё не
// маленький. Строки словаря отдаются наружу и подмешиваются в общий I18N —
// иначе переключение языка на странице работать не будет.
//
// Анкета читается и пишется через управляющий API (`/user/{uin}/icq`), а не
// прямо в базу: тогда правки с этой страницы проходят те же проверки, что и
// правки из клиента, включая «один адрес — одна учётная запись».
//
// Часового пояса в форме нет намеренно: в каком виде ICQ хранит GMTOffset, по
// коду сервера не видно, а записать наугад — испортить анкету. Его по-прежнему
// ставит клиент.

const fs = require('node:fs');
const path = require('node:path');

// Справочники кодов взяты из файлов самого клиента (DataFiles/*.fld, *.txt).
const CODES = JSON.parse(fs.readFileSync(path.join(__dirname, 'icq-codes.json'), 'utf8'));

const STRINGS = {
  en: {
    pfDocTitle: 'ICQ profile',
    pfWinTitle: 'Profile',
    pfHeroTitle: 'Your profile',
    pfHeroText: 'Sign in with your number and password to see and change what this account holds.',
    pfSignedText: (u) => `Signed in as ${u}.`,
    pfBtnOpen: 'Open profile',
    pfBtnSignOut: 'Sign out',
    pfBtnSave: 'Save profile',
    pfSavedTitle: 'Profile saved',
    pfSavedText: 'The changes are in place. Clients show them after the next profile request.',

    pfLegendMain: 'Basic',
    pfLegendMore: 'Details',
    pfLegendWork: 'Work',
    pfLegendInterests: 'Interests',
    pfLegendPast: 'Background',
    pfLegendNotes: 'Notes',
    pfLegendPrivacy: 'Privacy',
    pfLegendSecret: 'Password',
    pfLegendMail: 'Email',

    pfNickname: 'Nickname',
    pfFirstName: 'First name',
    pfLastName: 'Last name',
    pfEmail: 'Email in the profile',
    pfCity: 'City',
    pfState: 'State or region',
    pfCountry: 'Country',
    pfZip: 'Postal code',
    pfAddress: 'Address',
    pfPhone: 'Phone',
    pfCell: 'Mobile',
    pfFax: 'Fax',

    pfGender: 'Gender',
    pfGenderNone: 'not specified',
    pfGenderFemale: 'female',
    pfGenderMale: 'male',
    pfBirth: 'Date of birth',
    pfBirthDay: 'day',
    pfBirthMonth: 'month',
    pfBirthYear: 'year',
    pfHomepage: 'Homepage',
    pfLang: (n) => `Language ${n}`,

    pfCompany: 'Company',
    pfDepartment: 'Department',
    pfPosition: 'Position',
    pfOccupation: 'Occupation',
    pfWebPage: 'Company website',

    pfInterest: (n) => `Interest ${n}`,
    pfKeyword: 'in their own words',
    pfPastKind: (n) => `Past ${n}`,
    pfGroupKind: (n) => `Organisation ${n}`,
    pfNotesText: 'Anything else you want others to read about you.',

    pfPublishEmail: 'Show my email address to others',
    pfPublishEmailHint: 'Off means the address still signs you in and recovers your password, but nobody sees it in your details or finds you by it.',
    pfAuthRequired: 'Ask me before anyone adds me to their list',
    pfWebAware: 'Let my status be seen on the web',
    pfAllowSpam: 'Accept mailings from the server',

    pfSecretText: 'Changing the password signs this account out of every client.',
    pfBtnSecret: 'Change password',
    pfMailText: 'This address recovers a forgotten password and can be typed instead of the number in the "ICQ#/Email" field of a client. It is optional, and it belongs to one account only.',
    pfMailNone: 'No address attached.',
    pfMailAttached: (m) => `Attached: ${m}`,
    pfMailUnconfirmed: 'The letter has not been opened yet — recovery by mail will start working once it is.',
    pfBtnMail: 'Attach address',

    pfNone: '— not chosen —',
  },
  uk: {
    pfDocTitle: 'Профіль ICQ',
    pfWinTitle: 'Профіль',
    pfHeroTitle: 'Ваш профіль',
    pfHeroText: 'Увійдіть за номером і паролем, щоб побачити та змінити те, що зберігає обліковий запис.',
    pfSignedText: (u) => `Ви увійшли як ${u}.`,
    pfBtnOpen: 'Відкрити профіль',
    pfBtnSignOut: 'Вийти',
    pfBtnSave: 'Зберегти анкету',
    pfSavedTitle: 'Анкету збережено',
    pfSavedText: 'Зміни на місці. Клієнти покажуть їх після наступного запиту анкети.',

    pfLegendMain: 'Основне',
    pfLegendMore: 'Подробиці',
    pfLegendWork: 'Робота',
    pfLegendInterests: 'Інтереси',
    pfLegendPast: 'Минуле',
    pfLegendNotes: 'Нотатки',
    pfLegendPrivacy: 'Приватність',
    pfLegendSecret: 'Пароль',
    pfLegendMail: 'Пошта',

    pfNickname: 'Прізвисько',
    pfFirstName: "Ім'я",
    pfLastName: 'Прізвище',
    pfEmail: 'Пошта в анкеті',
    pfCity: 'Місто',
    pfState: 'Область або регіон',
    pfCountry: 'Країна',
    pfZip: 'Поштовий індекс',
    pfAddress: 'Адреса',
    pfPhone: 'Телефон',
    pfCell: 'Мобільний',
    pfFax: 'Факс',

    pfGender: 'Стать',
    pfGenderNone: 'не вказано',
    pfGenderFemale: 'жіноча',
    pfGenderMale: 'чоловіча',
    pfBirth: 'Дата народження',
    pfBirthDay: 'день',
    pfBirthMonth: 'місяць',
    pfBirthYear: 'рік',
    pfHomepage: 'Домашня сторінка',
    pfLang: (n) => `Мова ${n}`,

    pfCompany: 'Компанія',
    pfDepartment: 'Відділ',
    pfPosition: 'Посада',
    pfOccupation: 'Рід занять',
    pfWebPage: 'Сайт компанії',

    pfInterest: (n) => `Інтерес ${n}`,
    pfKeyword: 'своїми словами',
    pfPastKind: (n) => `Минуле ${n}`,
    pfGroupKind: (n) => `Організація ${n}`,
    pfNotesText: 'Усе інше, що хочете розповісти про себе.',

    pfPublishEmail: 'Показувати мою адресу іншим',
    pfPublishEmailHint: 'Якщо вимкнено, адреса так само впускає вас і відновлює пароль, але ніхто не бачить її у ваших даних і не знайде вас за нею.',
    pfAuthRequired: 'Питати мене, перш ніж додати до списку',
    pfWebAware: 'Показувати мій статус у вебі',
    pfAllowSpam: 'Приймати розсилки від сервера',

    pfSecretText: 'Зміна пароля виводить цей запис з усіх клієнтів.',
    pfBtnSecret: 'Змінити пароль',
    pfMailText: 'Ця адреса відновлює забутий пароль і її можна вводити замість номера в полі «ICQ#/Email» у клієнті. Вона не обов’язкова і належить лише одному обліковому запису.',
    pfMailNone: 'Адресу не прив’язано.',
    pfMailAttached: (m) => `Прив’язано: ${m}`,
    pfMailUnconfirmed: 'Лист ще не відкрито — відновлення поштою запрацює після цього.',
    pfBtnMail: 'Прив’язати адресу',

    pfNone: '— не обрано —',
  },
};

// Поля, которые страница показывает как обычный текстовый ввод: ключ в JSON
// управляющего API, ключ подписи, максимальная длина (та же, что проверяет
// сервер, — чтобы отказ не приходил после отправки).
const BASIC_TEXT = [
  ['nickname', 'pfNickname', 20],
  ['first_name', 'pfFirstName', 64],
  ['last_name', 'pfLastName', 64],
  ['email', 'pfEmail', 64],
  ['city', 'pfCity', 64],
  ['state', 'pfState', 64],
  ['zip', 'pfZip', 12],
  ['address', 'pfAddress', 64],
  ['phone', 'pfPhone', 30],
  ['cell_phone', 'pfCell', 30],
  ['fax', 'pfFax', 30],
];

const WORK_TEXT = [
  ['company', 'pfCompany', 64],
  ['department', 'pfDepartment', 64],
  ['position', 'pfPosition', 64],
  ['address', 'pfAddress', 64],
  ['city', 'pfCity', 64],
  ['state', 'pfState', 64],
  ['zip', 'pfZip', 12],
  ['phone', 'pfPhone', 30],
  ['fax', 'pfFax', 30],
  ['web_page', 'pfWebPage', 127],
];

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));
}

function textRow(prefix, key, labelKey, max, t) {
  const id = `${prefix}_${key}`;
  return `<div class="row">
      <label for="${id}" data-i18n="${labelKey}">${esc(t[labelKey])}</label>
      <input type="text" id="${id}" maxlength="${max}">
    </div>`;
}

function selectRow(id, labelKey, labelText, t) {
  return `<div class="row">
      <label for="${id}">${esc(labelText)}</label>
      <select id="${id}"></select>
    </div>`;
}

function checkRow(id, labelKey, t, hintKey) {
  return `<div class="row">
      <label for="${id}"><input type="checkbox" id="${id}"> <span data-i18n="${labelKey}">${esc(t[labelKey])}</span></label>
      ${hintKey ? `<p class="hint" data-i18n="${hintKey}">${esc(t[hintKey])}</p>` : ''}
    </div>`;
}

// deps: всё, что страница берёт у сервиса, — оформление, словарь, языки.
function renderProfilePage(lang, deps) {
  const { STYLE, FAVICON, header, footer, I18N, LANGS, PASS_MAX, EMAIL_MAX, serializeI18N, adminLink } = deps;
  const t = I18N[lang];

  const basic = BASIC_TEXT.map(([k, l, m]) => textRow('b', k, l, m, t)).join('\n');
  const work = WORK_TEXT.map(([k, l, m]) => textRow('w', k, l, m, t)).join('\n');

  const interests = [1, 2, 3, 4]
    .map(
      (n) => `<div class="row">
      <label for="i_code${n}">${esc(t.pfInterest(n))}</label>
      <select id="i_code${n}"></select>
      <input type="text" id="i_word${n}" maxlength="64" placeholder="${esc(t.pfKeyword)}" style="margin-top:5px">
    </div>`,
    )
    .join('\n');

  const past = [1, 2, 3]
    .map(
      (n) => `<div class="row">
      <label for="p_code${n}">${esc(t.pfPastKind(n))}</label>
      <select id="p_code${n}"></select>
      <input type="text" id="p_word${n}" maxlength="64" placeholder="${esc(t.pfKeyword)}" style="margin-top:5px">
    </div>`,
    )
    .join('\n');

  const groups = [1, 2, 3]
    .map(
      (n) => `<div class="row">
      <label for="g_code${n}">${esc(t.pfGroupKind(n))}</label>
      <select id="g_code${n}"></select>
      <input type="text" id="g_word${n}" maxlength="64" placeholder="${esc(t.pfKeyword)}" style="margin-top:5px">
    </div>`,
    )
    .join('\n');

  const langs = [1, 2, 3]
    .map((n) => selectRow(`m_lang${n}`, 'pfLang', t.pfLang(n), t))
    .join('\n');

  return /* html */ `<!DOCTYPE html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(t.pfDocTitle)}</title>
${FAVICON}
<style>${STYLE}</style>
</head>
<body>
<main class="window">
  ${header(t.pfWinTitle, '', 'data-i18n="pfWinTitle"')}

  <div class="body">
    <div class="hero">
      <div>
        <h1 data-i18n="pfHeroTitle">${esc(t.pfHeroTitle)}</h1>
        <p id="lead" data-i18n="pfHeroText">${esc(t.pfHeroText)}</p>
      </div>
    </div>

    <div id="message" hidden></div>

    <form id="signin" autocomplete="off" novalidate>
      <fieldset>
        <legend data-i18n="legendAccount">${esc(t.legendAccount)}</legend>
        <div class="row">
          <label for="uin" data-i18n="chLabelUin">${esc(t.chLabelUin)}</label>
          <input type="text" id="uin" inputmode="numeric" maxlength="10" required>
        </div>
        <div class="row">
          <label for="current" data-i18n="chLabelCurrent">${esc(t.chLabelCurrent)}</label>
          <input type="password" id="current" maxlength="${PASS_MAX}" required>
        </div>
        <div class="actions">
          <button type="submit" class="primary" id="open" data-i18n="pfBtnOpen">${esc(t.pfBtnOpen)}</button>
        </div>
      </fieldset>
    </form>

    <form id="editor" autocomplete="off" novalidate hidden>
      <fieldset>
        <legend data-i18n="pfLegendMain">${esc(t.pfLegendMain)}</legend>
        ${basic}
        ${selectRow('b_country_code', 'pfCountry', t.pfCountry, t)}
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendMore">${esc(t.pfLegendMore)}</legend>
        ${selectRow('m_gender', 'pfGender', t.pfGender, t)}
        <div class="row">
          <label for="m_birth_day">${esc(t.pfBirth)}</label>
          <input type="text" id="m_birth_day" inputmode="numeric" maxlength="2" placeholder="${esc(t.pfBirthDay)}" style="width:5em">
          <input type="text" id="m_birth_month" inputmode="numeric" maxlength="2" placeholder="${esc(t.pfBirthMonth)}" style="width:5em">
          <input type="text" id="m_birth_year" inputmode="numeric" maxlength="4" placeholder="${esc(t.pfBirthYear)}" style="width:7em">
        </div>
        <div class="row">
          <label for="m_homepage" data-i18n="pfHomepage">${esc(t.pfHomepage)}</label>
          <input type="text" id="m_homepage" maxlength="127">
        </div>
        ${langs}
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendWork">${esc(t.pfLegendWork)}</legend>
        ${work}
        ${selectRow('w_country_code', 'pfCountry', t.pfCountry, t)}
        ${selectRow('w_occupation_code', 'pfOccupation', t.pfOccupation, t)}
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendInterests">${esc(t.pfLegendInterests)}</legend>
        ${interests}
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendPast">${esc(t.pfLegendPast)}</legend>
        ${past}
        ${groups}
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendNotes">${esc(t.pfLegendNotes)}</legend>
        <p class="hint" data-i18n="pfNotesText" style="margin:0 0 6px">${esc(t.pfNotesText)}</p>
        <textarea id="notes" rows="5" maxlength="450"></textarea>
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendPrivacy">${esc(t.pfLegendPrivacy)}</legend>
        ${checkRow('x_publish_email', 'pfPublishEmail', t, 'pfPublishEmailHint')}
        ${checkRow('x_auth_required', 'pfAuthRequired', t)}
        ${checkRow('x_web_aware', 'pfWebAware', t)}
        ${checkRow('x_allow_spam', 'pfAllowSpam', t)}
      </fieldset>

      <div class="actions">
        <button type="submit" class="primary" id="save" data-i18n="pfBtnSave">${esc(t.pfBtnSave)}</button>
        <button type="button" id="signout" data-i18n="pfBtnSignOut">${esc(t.pfBtnSignOut)}</button>
      </div>
    </form>

    <form id="extras" autocomplete="off" novalidate hidden>
      <fieldset>
        <legend data-i18n="pfLegendSecret">${esc(t.pfLegendSecret)}</legend>
        <p class="hint" data-i18n="pfSecretText" style="margin:0 0 8px">${esc(t.pfSecretText)}</p>
        <div class="row">
          <label for="next" data-i18n="chLabelNew">${esc(t.chLabelNew)}</label>
          <input type="password" id="next" maxlength="${PASS_MAX}">
        </div>
        <div class="row">
          <label for="next2" data-i18n="chLabelNew2">${esc(t.chLabelNew2)}</label>
          <input type="password" id="next2" maxlength="${PASS_MAX}">
        </div>
        <div class="actions">
          <button type="button" id="secret" data-i18n="pfBtnSecret">${esc(t.pfBtnSecret)}</button>
        </div>
      </fieldset>

      <fieldset>
        <legend data-i18n="pfLegendMail">${esc(t.pfLegendMail)}</legend>
        <p class="hint" data-i18n="pfMailText" style="margin:0 0 8px">${esc(t.pfMailText)}</p>
        <p class="hint" id="mailstate" style="margin:0 0 8px"></p>
        <div class="row">
          <label for="mail" data-i18n="labelMail">${esc(t.labelMail)}</label>
          <input type="email" id="mail" maxlength="${EMAIL_MAX}">
        </div>
        <div class="actions">
          <button type="button" id="bind" data-i18n="pfBtnMail">${esc(t.pfBtnMail)}</button>
        </div>
      </fieldset>

    </form>

    <div class="nav">
      <a href="/" data-i18n="linkToRegister">${esc(t.linkToRegister)}</a>
      &nbsp;·&nbsp;
      <a href="/recover" data-i18n="linkToRecover">${esc(t.linkToRecover)}</a>
      &nbsp;·&nbsp;
      <a href="/account" data-i18n="linkToAccount">${esc(t.linkToAccount)}</a>${adminLink ? adminLink(t) : ''}
    </div>

    ${footer({ statusId: 'status', langsId: 'langs' })}
  </div>
</main>

<script>
const LANGS = ${JSON.stringify(LANGS)};
const LANG_LABEL = (c) => String(c).toUpperCase();
const CODES = ${JSON.stringify(CODES)};

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

// Пароль живёт только в памяти вкладки: каждый запрос к серверу подписывается
// им заново, хранить его негде и незачем.
let session = null;
let lastMessage = null;

const $ = (id) => document.getElementById(id);
const signinEl = $('signin');
const editorEl = $('editor');
const extrasEl = $('extras');
const msgEl = $('message');
const leadEl = $('lead');
const langsEl = $('langs');

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function translateError(payload) {
  const entry = t.err[(payload && payload.code) || 'internal'] || t.err.internal;
  return typeof entry === 'function' ? entry(payload && payload.arg) : entry;
}

function renderMessage() {
  if (!lastMessage) { msgEl.hidden = true; return; }
  if (lastMessage.kind === 'err') {
    msgEl.className = 'msg err';
    const text = lastMessage.offline ? t.errOffline : translateError(lastMessage.payload);
    msgEl.innerHTML = '<h2>' + esc(t.errTitle) + '</h2><p>' + esc(text) + '</p>';
  } else {
    msgEl.className = 'msg ok';
    msgEl.innerHTML = '<h2>' + esc(t[lastMessage.title]) + '</h2><p>' +
      esc(typeof t[lastMessage.text] === 'function' ? t[lastMessage.text](lastMessage.arg) : t[lastMessage.text]) + '</p>';
  }
  msgEl.hidden = false;
}

// Страница длинная: без этого ответ остался бы за верхним краем экрана.
// Только на новый ответ — при смене языка дёргать прокрутку незачем.
function reveal() {
  try { msgEl.scrollIntoView({ block: 'center', behavior: 'smooth' }); } catch {}
}

function ok(title, text, arg) { lastMessage = { kind: 'ok', title, text, arg }; renderMessage(); reveal(); }
function fail(payload, offline) { lastMessage = { kind: 'err', payload, offline }; renderMessage(); reveal(); }

// Выпадающие списки заполняются справочниками клиента; 0 значит «не выбрано».
function fillSelect(el, table, extra) {
  el.innerHTML = '';
  const none = document.createElement('option');
  none.value = '0';
  none.textContent = t.pfNone;
  el.appendChild(none);
  for (const [code, name] of extra || []) {
    const o = document.createElement('option');
    o.value = String(code);
    o.textContent = name;
    el.appendChild(o);
  }
  const entries = Object.entries(table || {})
    .filter(([code, name]) => Number(code) > 0 && name)
    .sort((a, b) => a[1].localeCompare(b[1]));
  for (const [code, name] of entries) {
    const o = document.createElement('option');
    o.value = code;
    o.textContent = name;
    el.appendChild(o);
  }
}

function fillAllSelects() {
  fillSelect($('b_country_code'), CODES.countries);
  fillSelect($('w_country_code'), CODES.countries);
  fillSelect($('w_occupation_code'), CODES.occupations);
  fillSelect($('m_gender'), null, [[1, t.pfGenderFemale], [2, t.pfGenderMale]]);
  for (const n of [1, 2, 3]) fillSelect($('m_lang' + n), CODES.languages);
  for (const n of [1, 2, 3, 4]) fillSelect($('i_code' + n), CODES.interests);
  for (const n of [1, 2, 3]) fillSelect($('p_code' + n), CODES.past);
  for (const n of [1, 2, 3]) fillSelect($('g_code' + n), CODES.groups);
}

const BASIC_TEXT = ${JSON.stringify(BASIC_TEXT.map((f) => f[0]))};
const WORK_TEXT = ${JSON.stringify(WORK_TEXT.map((f) => f[0]))};

function setValue(id, value) { const el = $(id); if (el) el.value = value == null ? '' : String(value); }
function getValue(id) { const el = $(id); return el ? el.value.trim() : ''; }
function getNumber(id) { const n = parseInt(getValue(id), 10); return Number.isFinite(n) ? n : 0; }

function showProfile(p) {
  for (const key of BASIC_TEXT) setValue('b_' + key, p.basic_info[key]);
  setValue('b_country_code', p.basic_info.country_code || 0);

  setValue('m_gender', p.more_info.gender || 0);
  setValue('m_birth_day', p.more_info.birth_day || '');
  setValue('m_birth_month', p.more_info.birth_month || '');
  setValue('m_birth_year', p.more_info.birth_year || '');
  setValue('m_homepage', p.more_info.homepage);
  for (const n of [1, 2, 3]) setValue('m_lang' + n, p.more_info['lang' + n] || 0);

  for (const key of WORK_TEXT) setValue('w_' + key, p.work_info[key]);
  setValue('w_country_code', p.work_info.country_code || 0);
  setValue('w_occupation_code', p.work_info.occupation_code || 0);

  for (const n of [1, 2, 3, 4]) {
    setValue('i_code' + n, p.interests['code' + n] || 0);
    setValue('i_word' + n, p.interests['keyword' + n]);
  }
  for (const n of [1, 2, 3]) {
    setValue('p_code' + n, p.affiliations['past_code' + n] || 0);
    setValue('p_word' + n, p.affiliations['past_keyword' + n]);
    setValue('g_code' + n, p.affiliations['current_code' + n] || 0);
    setValue('g_word' + n, p.affiliations['current_keyword' + n]);
  }

  $('notes').value = p.notes || '';
  $('x_publish_email').checked = Boolean(p.basic_info.publish_email);
  $('x_auth_required').checked = Boolean(p.permissions.auth_required);
  $('x_web_aware').checked = Boolean(p.permissions.web_aware);
  $('x_allow_spam').checked = Boolean(p.permissions.allow_spam);
}

// Собираем целиком: управляющий API принимает анкету одним PUT.
function collectProfile(uin) {
  const basic = { country_code: getNumber('b_country_code'), publish_email: $('x_publish_email').checked };
  for (const key of BASIC_TEXT) basic[key] = getValue('b_' + key);

  const work = {
    country_code: getNumber('w_country_code'),
    occupation_code: getNumber('w_occupation_code'),
  };
  for (const key of WORK_TEXT) work[key] = getValue('w_' + key);

  const interests = {};
  for (const n of [1, 2, 3, 4]) {
    interests['code' + n] = getNumber('i_code' + n);
    interests['keyword' + n] = getValue('i_word' + n);
  }

  const affiliations = {};
  for (const n of [1, 2, 3]) {
    affiliations['past_code' + n] = getNumber('p_code' + n);
    affiliations['past_keyword' + n] = getValue('p_word' + n);
    affiliations['current_code' + n] = getNumber('g_code' + n);
    affiliations['current_keyword' + n] = getValue('g_word' + n);
  }

  return {
    uin: Number(uin),
    basic_info: basic,
    more_info: {
      gender: getNumber('m_gender'),
      homepage: getValue('m_homepage'),
      birth_year: getNumber('m_birth_year'),
      birth_month: getNumber('m_birth_month'),
      birth_day: getNumber('m_birth_day'),
      lang1: getNumber('m_lang1'),
      lang2: getNumber('m_lang2'),
      lang3: getNumber('m_lang3'),
    },
    work_info: work,
    notes: $('notes').value.trim(),
    interests: interests,
    affiliations: affiliations,
    permissions: {
      auth_required: $('x_auth_required').checked,
      web_aware: $('x_web_aware').checked,
      allow_spam: $('x_allow_spam').checked,
    },
  };
}

async function call(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  let payload = null;
  try { payload = await res.json(); } catch {}
  return { res, payload };
}

function showMailState(state) {
  const el = $('mailstate');
  if (!state || !state.email) { el.textContent = t.pfMailNone; return; }
  el.textContent = t.pfMailAttached(state.email) + (state.verified ? '' : ' ' + t.pfMailUnconfirmed);
  $('mail').value = state.email;
}

function enterProfile(data) {
  session = { uin: data.uin, current: data.current };
  signinEl.hidden = true;
  editorEl.hidden = false;
  extrasEl.hidden = false;
  leadEl.textContent = t.pfSignedText(data.uin);
  fillAllSelects();
  showProfile(data.profile);
  showMailState(data.mail);
}

function leaveProfile() {
  session = null;
  signinEl.hidden = false;
  editorEl.hidden = true;
  extrasEl.hidden = true;
  leadEl.textContent = t.pfHeroText;
  $('current').value = '';
}

signinEl.addEventListener('submit', async (e) => {
  e.preventDefault();
  lastMessage = null;
  renderMessage();
  const uin = getValue('uin');
  const current = $('current').value;
  try {
    const { res, payload } = await call('/api/profile', { uin, current });
    if (!res.ok) { fail(payload); return; }
    enterProfile({ uin, current, profile: payload.profile, mail: payload.mail });
  } catch {
    fail(null, true);
  }
});

editorEl.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!session) return;
  try {
    const { res, payload } = await call('/api/profile-save', {
      uin: session.uin,
      current: session.current,
      profile: collectProfile(session.uin),
    });
    if (!res.ok) { fail(payload); return; }
    ok('pfSavedTitle', 'pfSavedText');
  } catch {
    fail(null, true);
  }
});

$('signout').addEventListener('click', leaveProfile);

$('secret').addEventListener('click', async () => {
  if (!session) return;
  const next = $('next').value;
  try {
    const { res, payload } = await call('/api/change-password', {
      uin: session.uin, current: session.current,
      next: next, next2: $('next2').value, lang: lang,
    });
    if (!res.ok) { fail(payload); return; }
    // Пароль сменился — прежний больше не подпишет запросы.
    session.current = next;
    $('next').value = '';
    $('next2').value = '';
    ok('chOkTitle', 'chOkText', session.uin);
  } catch {
    fail(null, true);
  }
});

$('bind').addEventListener('click', async () => {
  if (!session) return;
  try {
    const { res, payload } = await call('/api/recovery-email', {
      uin: session.uin, current: session.current, email: getValue('mail'), lang: lang,
    });
    if (!res.ok) { fail(payload); return; }
    ok('rcBoundTitle', 'rcBoundText', payload.email);
    showMailState({ email: payload.email, verified: false });
  } catch {
    fail(null, true);
  }
});

function applyLang(next) {
  lang = next;
  t = I18N[lang];
  document.documentElement.lang = lang;
  document.title = t.pfDocTitle;
  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t[el.dataset.i18n];
  }
  if (session) {
    const snapshot = collectProfile(session.uin);
    fillAllSelects();
    showProfile(snapshot);
  }
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

applyLang(lang);
</script>
</body>
</html>`;
}

module.exports = { STRINGS, renderProfilePage, CODES };
