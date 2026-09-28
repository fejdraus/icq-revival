'use strict';

// Sends mail without external dependencies: a short SMTP client.
// There is exactly one use case, a message with a link, so only EHLO,
// STARTTLS, AUTH LOGIN, MAIL/RCPT/DATA and QUIT are implemented.
//
// Settings come from the environment; the mailbox password lives in a separate
// EnvironmentFile with mode 600 so that it is not kept in the unit.

const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const HOST = process.env.SMTP_HOST || '';
const PORT = Number(process.env.SMTP_PORT || 465);
// implicit: TLS from the first byte (port 465); starttls: upgrade after EHLO (587).
const MODE = process.env.SMTP_MODE || (PORT === 465 ? 'implicit' : 'starttls');
const USER = process.env.SMTP_USER || '';
const SECRET = process.env.SMTP_SECRET || '';
const FROM = process.env.SMTP_FROM || USER;
const FROM_NAME = process.env.SMTP_FROM_NAME || 'ICQ Revival';
const TIMEOUT_MS = Number(process.env.SMTP_TIMEOUT_MS || 20000);

function mailConfigured() {
  return Boolean(HOST && FROM);
}

// An SMTP reply can span several lines: "250-EXTENSION", then "250 OK".
// The reply is complete once we see a line with a space after the code.
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
    failure = failure || new Error('SMTP: connection closed');
    settle();
  });

  return {
    read() {
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
        settle();
      });
    },
    // The reader moves over to the TLS socket after STARTTLS.
    detach() {
      socket.removeAllListeners('data');
    },
  };
}

function withTimeout(promise, what) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`SMTP: timeout on ${what}`)), TIMEOUT_MS);
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

// The subject is UTF-8, so it is encoded per RFC 2047.
function encodeHeader(value) {
  if (/^[\x20-\x7e]*$/.test(value)) return value;
  return `=?UTF-8?B?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

// The body is sent as base64: that handles both UTF-8 and a leading dot at once.
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
  if (!mailConfigured()) throw new Error('SMTP is not configured');

  let socket = await withTimeout(connect(MODE === 'implicit'), 'connect');
  let reader = makeReader(socket);

  const expect = async (want, what) => {
    const reply = await withTimeout(reader.read(), what);
    if (!want.includes(reply.code)) {
      throw new Error(`SMTP: got ${reply.text.split('\n')[0]} on "${what}"`);
    }
    return reply;
  };
  const say = (line) => socket.write(`${line}\r\n`);
  let finished = false;

  try {
    await expect([220], 'greeting');
    say(`EHLO ${FROM.includes('@') ? FROM.split('@')[1] : 'localhost'}`);
    let hello = await expect([250], 'EHLO');

    if (MODE === 'starttls') {
      say('STARTTLS');
      await expect([220], 'STARTTLS');
      reader.detach();
      socket = await withTimeout(upgrade(socket), 'TLS handshake');
      reader = makeReader(socket);
      say(`EHLO ${FROM.includes('@') ? FROM.split('@')[1] : 'localhost'}`);
      hello = await expect([250], 'EHLO after STARTTLS');
    }

    if (USER) {
      // Every server this service will realistically meet understands AUTH LOGIN.
      if (!/AUTH[ -=].*LOGIN/i.test(hello.text)) {
        throw new Error('SMTP: server does not offer AUTH LOGIN');
      }
      say('AUTH LOGIN');
      await expect([334], 'AUTH LOGIN');
      say(Buffer.from(USER, 'utf8').toString('base64'));
      await expect([334], 'username');
      say(Buffer.from(SECRET, 'utf8').toString('base64'));
      await expect([235], 'login');
    }

    say(`MAIL FROM:<${FROM}>`);
    await expect([250], 'MAIL FROM');
    say(`RCPT TO:<${to}>`);
    await expect([250, 251], 'RCPT TO');
    say('DATA');
    await expect([354], 'DATA');
    socket.write(buildMessage({ to, subject, text }));
    say('.');
    await expect([250], 'message acceptance');
    // Say goodbye properly: QUIT and close the write side, without dropping the socket.
    finished = true;
    socket.end('QUIT\r\n');
  } finally {
    if (!finished) socket.destroy();
  }
}

module.exports = { sendMail, mailConfigured };
