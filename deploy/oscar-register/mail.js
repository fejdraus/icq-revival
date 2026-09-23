'use strict';

// Отправка писем без внешних зависимостей — короткий SMTP-клиент.
// Сценарий ровно один: письмо со ссылкой, поэтому из протокола реализованы
// только EHLO, STARTTLS, AUTH LOGIN, MAIL/RCPT/DATA и QUIT.
//
// Настройки берутся из окружения; пароль ящика держим в отдельном
// EnvironmentFile с правами 600, чтобы он не лежал в юните.

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const HOST = process.env.SMTP_HOST || '';
const PORT = Number(process.env.SMTP_PORT || 465);
// implicit — TLS с первого байта (порт 465), starttls — апгрейд после EHLO (587).
const MODE = process.env.SMTP_MODE || (PORT === 465 ? 'implicit' : 'starttls');
const USER = process.env.SMTP_USER || '';
const SECRET = process.env.SMTP_SECRET || '';
const FROM = process.env.SMTP_FROM || USER;
const FROM_NAME = process.env.SMTP_FROM_NAME || 'ICQ';
const TIMEOUT_MS = Number(process.env.SMTP_TIMEOUT_MS || 20000);

function mailConfigured() {
  return Boolean(HOST && FROM);
}

// Ответ SMTP может занимать несколько строк: «250-РАСШИРЕНИЕ», затем «250 OK».
// Считаем ответ завершённым, когда встретили строку с пробелом после кода.
function makeReader(socket) {
  let buffer = '';
  let pending = null;
  let failure = null;

  const settle = () => {
    if (!pending) return;
    if (failure) {
      const { reject } = pending;
      pending = null;
      reject(failure);
      return;
    }
    const match = buffer.match(/^(?:\d{3}-[^\n]*\n)*(\d{3}) [^\n]*\n/);
    if (!match) return;
    const reply = buffer.slice(0, match[0].length);
    buffer = buffer.slice(match[0].length);
    const { resolve } = pending;
    pending = null;
    resolve({ code: Number(match[1]), text: reply.trim() });
  };

  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    settle();
  });
  socket.on('error', (err) => {
    failure = err;
    settle();
  });
  socket.on('close', () => {
    failure = failure || new Error('SMTP: соединение закрыто');
    settle();
  });

  return {
    read() {
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
        settle();
      });
    },
    // Читатель переносим на TLS-сокет после STARTTLS.
    detach() {
      socket.removeAllListeners('data');
    },
  };
}

function withTimeout(promise, what) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`SMTP: таймаут на ${what}`)), TIMEOUT_MS);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

function connect(secure) {
  return new Promise((resolve, reject) => {
    const socket = secure
      ? tls.connect({ host: HOST, port: PORT, servername: HOST })
      : net.connect({ host: HOST, port: PORT });
    const event = secure ? 'secureConnect' : 'connect';
    const onError = (err) => {
      socket.removeListener(event, onReady);
      reject(err);
    };
    const onReady = () => {
      socket.removeListener('error', onError);
      resolve(socket);
    };
    socket.once(event, onReady);
    socket.once('error', onError);
  });
}

function upgrade(socket) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: HOST });
    const onError = (err) => {
      secure.removeListener('secureConnect', onReady);
      reject(err);
    };
    const onReady = () => {
      secure.removeListener('error', onError);
      resolve(secure);
    };
    secure.once('secureConnect', onReady);
    secure.once('error', onError);
  });
}

// Тема письма — UTF-8, поэтому кодируем по RFC 2047.
function encodeHeader(value) {
  if (/^[\x20-\x7e]*$/.test(value)) return value;
  return `=?UTF-8?B?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

// Тело шлём base64: это разом решает и UTF-8, и точку в начале строки.
function encodeBody(text) {
  const b64 = Buffer.from(text.replace(/\r?\n/g, '\r\n'), 'utf8').toString('base64');
  return (b64.match(/.{1,76}/g) || []).join('\r\n');
}

function buildMessage({ to, subject, text }) {
  const domain = FROM.includes('@') ? FROM.split('@')[1] : 'localhost';
  const headers = [
    `From: ${encodeHeader(FROM_NAME)} <${FROM}>`,
    `To: <${to}>`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${crypto.randomUUID()}@${domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    'Auto-Submitted: auto-generated',
  ];
  return `${headers.join('\r\n')}\r\n\r\n${encodeBody(text)}\r\n`;
}

async function sendMail({ to, subject, text }) {
  if (!mailConfigured()) throw new Error('SMTP не настроен');

  let socket = await withTimeout(connect(MODE === 'implicit'), 'подключение');
  let reader = makeReader(socket);

  const expect = async (want, what) => {
    const reply = await withTimeout(reader.read(), what);
    if (!want.includes(reply.code)) {
      throw new Error(`SMTP: на «${what}» пришло ${reply.text.split('\n')[0]}`);
    }
    return reply;
  };
  const say = (line) => socket.write(`${line}\r\n`);
  let finished = false;

  try {
    await expect([220], 'приветствие');
    say(`EHLO ${FROM.includes('@') ? FROM.split('@')[1] : 'localhost'}`);
    let hello = await expect([250], 'EHLO');

    if (MODE === 'starttls') {
      say('STARTTLS');
      await expect([220], 'STARTTLS');
      reader.detach();
      socket = await withTimeout(upgrade(socket), 'TLS-рукопожатие');
      reader = makeReader(socket);
      say(`EHLO ${FROM.includes('@') ? FROM.split('@')[1] : 'localhost'}`);
      hello = await expect([250], 'EHLO после STARTTLS');
    }

    if (USER) {
      // AUTH LOGIN понимают все, с кем этот сервис реально столкнётся.
      if (!/AUTH[ -=].*LOGIN/i.test(hello.text)) {
        throw new Error('SMTP: сервер не предлагает AUTH LOGIN');
      }
      say('AUTH LOGIN');
      await expect([334], 'AUTH LOGIN');
      say(Buffer.from(USER, 'utf8').toString('base64'));
      await expect([334], 'имя пользователя');
      say(Buffer.from(SECRET, 'utf8').toString('base64'));
      await expect([235], 'вход');
    }

    say(`MAIL FROM:<${FROM}>`);
    await expect([250], 'MAIL FROM');
    say(`RCPT TO:<${to}>`);
    await expect([250, 251], 'RCPT TO');
    say('DATA');
    await expect([354], 'DATA');
    socket.write(buildMessage({ to, subject, text }));
    say('.');
    await expect([250], 'приём письма');
    // Прощаемся по-человечески: QUIT и закрытие записи, без обрыва сокета.
    finished = true;
    socket.end('QUIT\r\n');
  } finally {
    if (!finished) socket.destroy();
  }
}

module.exports = { sendMail, mailConfigured };
