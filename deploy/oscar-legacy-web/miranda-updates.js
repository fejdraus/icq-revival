// Miranda NG's PluginUpdater through this server, with our own plugins in it.
//
// PluginUpdater takes a base address and asks for <base>/hashes.zip: a zip
// with hashes.txt, one "<path> <hash> <crc32 of the package>" line per file of
// the release, and rules.txt, JSON with files to delete or rename. A file whose
// hash differs from the installed one is downloaded from <base>/<path without
// extension>.zip - a zip holding that file under its path from the Miranda
// folder - and checked against the crc32.
//
// /miranda/stable/x32 and /x64 here are such a base. hashes.zip is the
// upstream one (stable channel), cached, with our lines put in:
//
//   - our files (Plugins\IcqOscarJ.dll, Plugins\FlashAvatars.dll,
//     Libs\FlashPlayerControl.dll, their translations) with the hashes of our
//     builds, so PluginUpdater offers our build and never a stock one;
//   - the rules that would delete or rename them are dropped;
//   - the main Russian translation is served with the #include lines of our
//     translations appended, since the stock one does not have them and an
//     update would otherwise cut our plugins' translations off. When its
//     package cannot be fetched, its line is left out and the installed file
//     is kept as it is.
//
// Our packages and their hashes come ready-made from
// tools/miranda-icq/make-update-packages.py (the hash is PluginUpdater's own
// CalculateModuleHash over the PE sections, not a plain MD5, so it is computed
// where the builds are): <dir>/x32 and <dir>/x64, each with manifest.json and
// the zips. Read at start and on SIGHUP. Without the folder there are no
// packages of ours, but upstream's lines and rules for our files are still
// left out (OUR_FILES), so PluginUpdater leaves those files as they are.
//
// Every other package is relayed from upstream byte for byte, streamed, and
// kept in a small memory cache. Only the names in the current upstream list
// are relayed, so this is not an open proxy.
//
// The standard library only: zip is read and written here, the deflate is
// zlib's.

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');

const PLATFORMS = ['x32', 'x64'];

// Our files, as the list names them. Upstream lines and rules for them never
// go out, packages or not: with PluginUpdater pointed here our plugins stop
// keeping it off their files, and a stock line or a delete rule would hit
// them. manifest.json may add names.
const OUR_FILES = [
  'Plugins\\IcqOscarJ.dll',
  'Plugins\\FlashAvatars.dll',
  'Libs\\FlashPlayerControl.dll',
  'Languages\\langpack_russian_icq.txt',
  'Languages\\langpack_russian_flashavatars.txt',
];

// The lines our translations need in the main one (see withIncludes).
const LANGPACK_INCLUDES = {
  'Languages\\langpack_russian.txt': [
    '#include langpack_russian_icq.txt',
    '#include langpack_russian_flashavatars.txt',
  ],
};

// ------------------------------------------------------------------- zip

// The entries of a zip as { name: Buffer }. Only what PluginUpdater's lists
// and packages use: stored or deflated, no zip64, no encryption.
function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out = new Map();
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('broken zip directory');
    const method = buf.readUInt16LE(p + 10);
    const csize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (buf.readUInt32LE(local) !== 0x04034b50) throw new Error('broken zip entry');
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + csize);
    if (method === 0) out.set(name, Buffer.from(raw));
    else if (method === 8) out.set(name, zlib.inflateRawSync(raw));
    else throw new Error(`zip method ${method} in ${name}`);
  }
  return out;
}

// A zip of the given entries, deflated. The attributes are a DOS file's:
// PluginUpdater hands them to CreateFile as they are.
function writeZip(entries) {
  const locals = [];
  const central = [];
  let offset = 0;
  // 2026-01-01 00:00 in DOS form, so the same content gives the same bytes.
  const dosTime = 0;
  const dosDate = ((2026 - 1980) << 9) | (1 << 5) | 1;
  for (const [name, data] of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const packed = zlib.deflateRawSync(data, { level: 9 });
    const crc = zlib.crc32(data);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(0, 6);
    head.writeUInt16LE(8, 8);
    head.writeUInt16LE(dosTime, 10);
    head.writeUInt16LE(dosDate, 12);
    head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(packed.length, 18);
    head.writeUInt32LE(data.length, 22);
    head.writeUInt16LE(nameBuf.length, 26);
    head.writeUInt16LE(0, 28);
    const dir = Buffer.alloc(46);
    dir.writeUInt32LE(0x02014b50, 0);
    dir.writeUInt16LE(20, 4); // made by: MS-DOS
    dir.writeUInt16LE(20, 6);
    dir.writeUInt16LE(0, 8);
    dir.writeUInt16LE(8, 10);
    dir.writeUInt16LE(dosTime, 12);
    dir.writeUInt16LE(dosDate, 14);
    dir.writeUInt32LE(crc, 16);
    dir.writeUInt32LE(packed.length, 20);
    dir.writeUInt32LE(data.length, 24);
    dir.writeUInt16LE(nameBuf.length, 28);
    dir.writeUInt32LE(0x20, 38); // FILE_ATTRIBUTE_ARCHIVE
    dir.writeUInt32LE(offset, 42);
    locals.push(head, nameBuf, packed);
    central.push(dir, nameBuf);
    offset += head.length + nameBuf.length + packed.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}

// ------------------------------------------------------------------- lists

const crcHex = (buf) => zlib.crc32(buf).toString(16).padStart(8, '0');

// The address PluginUpdater builds for a listed file: the path without the
// extension, forward slashes, the file name in lower case.
function packagePath(name) {
  const noExt = name.replace(/\.[^.\\]*$/, '');
  const i = noExt.lastIndexOf('\\');
  const dir = i < 0 ? '' : noExt.slice(0, i + 1);
  return `${dir}${noExt.slice(i + 1).toLowerCase()}.zip`.replace(/\\/g, '/');
}

// hashes.txt as PluginUpdater reads it: "<name> <hash> [crc]"; ';' starts a
// comment. The lines are kept as they are so that the rest goes out unchanged.
function parseHashes(text) {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  return {
    eol,
    lines: lines.map((raw) => {
      const s = raw.trimEnd();
      if (!s || s.startsWith(';') || !s.includes(' ')) return { raw };
      const [name, hash, crc] = s.split(' ');
      return { raw, name, hash: (hash || '').toLowerCase(), crc: crc || '' };
    }),
  };
}

// wildcmpiw: * and ?, case-insensitive, over the whole name.
function wildMatch(mask, name) {
  const re = new RegExp(`^${mask.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
  return re.test(name);
}

const baseName = (name) => name.slice(name.lastIndexOf('\\') + 1);

// rules.txt without what would touch our files. PluginUpdater tests a rule
// against the bare file name; a rename into one of our paths goes too, and
// so does a packet (dependency list) of one of our modules.
function filterRules(json, ourNames) {
  const ourBase = ourNames.map(baseName);
  const ourLower = new Set(ourNames.map((n) => n.toLowerCase()));
  const out = { ...json };
  if (json.rules && typeof json.rules === 'object') {
    out.rules = {};
    for (const [mask, target] of Object.entries(json.rules)) {
      if (ourBase.some((n) => wildMatch(mask, n))) continue;
      if (typeof target === 'string' && ourLower.has(target.toLowerCase())) continue;
      out.rules[mask] = target;
    }
  }
  if (Array.isArray(json.packets)) {
    out.packets = json.packets.filter((p) => !ourLower.has(String(p && p.module).toLowerCase()));
  }
  return out;
}

// The main translation with the lines ours need appended, if missing.
function withIncludes(text, includes) {
  const have = new Set(text.split(/\r?\n/).map((l) => l.trim().toLowerCase()));
  const missing = includes.filter((l) => !have.has(l.trim().toLowerCase()));
  if (!missing.length) return text;
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const sep = text.endsWith('\n') || text === '' ? '' : eol;
  return text + sep + missing.join(eol) + eol;
}

// ------------------------------------------------------------------- mirror

function createMirror(options = {}) {
  const upstream = String(options.upstream || 'https://miranda-ng.org/distr/stable').replace(/\/+$/, '');
  const dir = options.dir;
  const ttl = options.ttlMs ?? 45 * 60 * 1000;
  const retry = options.retryMs ?? 5 * 60 * 1000;
  const timeout = options.timeoutMs ?? 30 * 1000;
  const maxFile = options.maxFileBytes ?? 64 * 1024 * 1024;
  const cacheBudget = options.cacheBytes ?? 96 * 1024 * 1024;
  const cacheEntryMax = options.cacheEntryBytes ?? 16 * 1024 * 1024;
  const log = options.log || ((m) => console.log(`miranda: ${m}`));
  const agent = options.userAgent || 'ICQ-Revival-mirror (PluginUpdater relay)';

  // Our packages per platform: { files: Map(name lower -> entry), includes }.
  let ours = new Map();
  // Per platform: the list we hand out and what it was built from.
  const lists = new Map();
  // Upstream packages, least recently used first: key -> Buffer.
  const cache = new Map();
  let cacheSize = 0;

  function load() {
    const next = new Map();
    for (const platform of PLATFORMS) {
      const folder = dir ? path.join(dir, platform) : null;
      let manifest;
      try {
        manifest = JSON.parse(fs.readFileSync(path.join(folder, 'manifest.json'), 'utf8'));
      } catch {
        continue;
      }
      const files = new Map();
      for (const f of manifest.files || []) {
        try {
          const body = fs.readFileSync(path.join(folder, ...f.package.split('/')));
          if (crcHex(body) !== f.crc) throw new Error('crc differs from manifest.json');
          files.set(f.name.toLowerCase(), { ...f, body });
        } catch (err) {
          log(`${platform} ${f.name} left out: ${err.message}`);
        }
      }
      next.set(platform, { files, includes: manifest.langpackIncludes || LANGPACK_INCLUDES });
    }
    ours = next;
    // A list built from the previous packages is out of date.
    for (const l of lists.values()) l.fetchedAt = 0;
    log(`packages: ${PLATFORMS.map((p) => `${p} ${ours.get(p)?.files.size || 0}`).join(', ')}`);
  }

  async function fetchUpstream(platform, rel) {
    const res = await fetch(`${upstream}/${platform}/${rel}`, {
      headers: { 'user-agent': agent },
      signal: AbortSignal.timeout(timeout),
    });
    if (res.status !== 200) throw new Error(`${rel}: upstream answered ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > maxFile) throw new Error(`${rel}: too large`);
    return buf;
  }

  function cacheGet(key) {
    const hit = cache.get(key);
    if (hit) { cache.delete(key); cache.set(key, hit); }
    return hit;
  }

  function cachePut(key, buf) {
    if (buf.length > cacheEntryMax || cache.has(key)) return;
    cache.set(key, buf);
    cacheSize += buf.length;
    for (const [k, v] of cache) {
      if (cacheSize <= cacheBudget) break;
      cache.delete(k);
      cacheSize -= v.length;
    }
  }

  // An upstream package, from the cache or fetched, checked against its crc.
  async function upstreamPackage(platform, line) {
    const rel = packagePath(line.name);
    const key = `${platform}/${rel.toLowerCase()}/${line.crc}`;
    let buf = cacheGet(key);
    if (!buf) {
      buf = await fetchUpstream(platform, rel);
      if (line.crc && parseInt(line.crc, 16) && crcHex(buf) !== line.crc.toLowerCase().padStart(8, '0')) {
        throw new Error(`${rel}: crc differs from the list`);
      }
      cachePut(key, buf);
    }
    return buf;
  }

  // Builds the list for a platform from a fresh upstream copy.
  async function build(platform) {
    const upstreamZip = await fetchUpstream(platform, 'hashes.zip');
    const entries = readZip(upstreamZip);
    const hashesName = [...entries.keys()].find((n) => n.toLowerCase() === 'hashes.txt');
    if (!hashesName) throw new Error('hashes.zip without hashes.txt');
    const own = ours.get(platform) || { files: new Map(), includes: LANGPACK_INCLUDES };
    const ourNames = new Set([...OUR_FILES, ...[...own.files.values()].map((f) => f.name)]
      .map((n) => n.toLowerCase()));
    const parsed = parseHashes(entries.get(hashesName).toString('latin1'));

    const upstreamNames = new Map(); // package path lower -> line, for the relay
    const patched = new Map();       // package path lower -> our patched zip
    const out = [];
    const written = new Set();
    for (const line of parsed.lines) {
      if (!line.name) { out.push(line.raw); continue; }
      const lower = line.name.toLowerCase();
      const mine = own.files.get(lower);
      if (mine) {
        if (!written.has(lower)) out.push(`${mine.name} ${mine.hash} ${mine.crc}`);
        written.add(lower);
        continue;
      }
      // Ours without a package here: the installed file stays as it is.
      if (ourNames.has(lower)) continue;
      const includeKey = Object.keys(own.includes).find((k) => k.toLowerCase() === lower);
      if (includeKey) {
        try {
          const zip = await upstreamPackage(platform, line);
          const inner = readZip(zip);
          const [entryName, data] = [...inner.entries()][0] || [];
          if (!entryName) throw new Error('empty package');
          const text = withIncludes(data.toString('latin1'), own.includes[includeKey]);
          const body = Buffer.from(text, 'latin1');
          const pkg = writeZip([[entryName, body]]);
          const hash = crypto.createHash('md5').update(body).digest('hex');
          patched.set(packagePath(line.name).toLowerCase(), pkg);
          out.push(`${line.name} ${hash} ${crcHex(pkg)}`);
        } catch (err) {
          // The installed translation stays as it is: better than one
          // without our lines.
          log(`${platform} ${line.name} left out of the list: ${err.message}`);
        }
        continue;
      }
      upstreamNames.set(packagePath(line.name).toLowerCase(), line);
      out.push(line.raw);
    }
    for (const [lower, f] of own.files) {
      if (!written.has(lower)) out.push(`${f.name} ${f.hash} ${f.crc}`);
    }

    const zipEntries = [[hashesName, Buffer.from(out.join(parsed.eol) + parsed.eol, 'latin1')]];
    for (const [name, data] of entries) {
      if (name === hashesName) continue;
      if (name.toLowerCase() === 'rules.txt') {
        try {
          const json = JSON.parse(data.toString('utf8').trimStart());
          const names = [...OUR_FILES, ...[...own.files.values()].map((f) => f.name)];
          zipEntries.push([name, Buffer.from(JSON.stringify(filterRules(json, names), null, 1), 'utf8')]);
        } catch (err) {
          // A rules file we cannot read may delete anything: leave it out.
          log(`${platform} rules.txt left out: ${err.message}`);
        }
        continue;
      }
      zipEntries.push([name, data]);
    }
    return { zip: writeZip(zipEntries), upstreamNames, patched, fetchedAt: Date.now(), failedAt: 0 };
  }

  // The current list, refreshed in the background once it is older than the
  // TTL: PluginUpdater gives hashes.zip five seconds, so nobody waits for
  // upstream except the very first request.
  function refresh(platform) {
    let state = lists.get(platform);
    if (!state) { state = { zip: null, fetchedAt: 0, failedAt: 0 }; lists.set(platform, state); }
    if (state.pending) return state.pending;
    state.pending = build(platform).then((fresh) => {
      Object.assign(state, fresh);
      log(`${platform} list refreshed: ${fresh.upstreamNames.size} upstream files`);
    }, (err) => {
      state.failedAt = Date.now();
      log(`${platform} list not refreshed${state.zip ? ', serving the old one' : ''}: ${err.message}`);
    }).finally(() => { state.pending = null; });
    return state.pending;
  }

  async function currentList(platform) {
    const state = lists.get(platform);
    const now = Date.now();
    const stale = !state || now - state.fetchedAt > ttl;
    const mayRetry = !state || now - state.failedAt > retry;
    if (stale && mayRetry) {
      const p = refresh(platform);
      if (!state || !state.zip) await p;
    }
    return lists.get(platform);
  }

  function reply(res, status, body, head) {
    res.writeHead(status, {
      'content-type': body ? 'application/zip' : 'application/octet-stream',
      'content-length': body ? body.length : 0,
      'cache-control': 'no-cache',
    });
    res.end(head ? undefined : body);
  }

  // GET <prefix>/<x32|x64>/<file>. rest is the part after the prefix.
  async function handle(req, res, rest) {
    const m = /^\/?(x32|x64)\/(.+)$/i.exec(rest);
    if (!m || (req.method !== 'GET' && req.method !== 'HEAD')) { reply(res, 404); return; }
    const platform = m[1].toLowerCase();
    const rel = m[2];
    const head = req.method === 'HEAD';

    if (rel.toLowerCase() === 'hashes.zip') {
      const state = await currentList(platform);
      if (!state || !state.zip) { reply(res, 503); return; }
      reply(res, 200, state.zip, head);
      return;
    }

    // Only a zip named like a listed file, and nothing that walks up.
    if (!/^[A-Za-z0-9_\-. /]+\.zip$/.test(rel) || rel.split('/').some((s) => s === '..' || s === '.' || s === '')) {
      reply(res, 404);
      return;
    }
    const key = rel.toLowerCase();

    const own = ours.get(platform);
    if (own) {
      for (const f of own.files.values()) {
        if (packagePath(f.name).toLowerCase() === key) {
          reply(res, 200, f.body, head);
          return;
        }
      }
    }

    const state = await currentList(platform);
    if (!state || !state.zip) { reply(res, 503); return; }
    const mine = state.patched.get(key);
    if (mine) { reply(res, 200, mine, head); return; }
    const line = state.upstreamNames.get(key);
    if (!line) { reply(res, 404); return; }

    const cacheKey = `${platform}/${key}/${line.crc}`;
    const hit = cacheGet(cacheKey);
    if (hit) { reply(res, 200, hit, head); return; }
    await relay(req, res, platform, packagePath(line.name), cacheKey, head);
  }

  // Streams one upstream file to the client and keeps a copy if it is small.
  async function relay(req, res, platform, rel, cacheKey, head) {
    let up;
    try {
      up = await fetch(`${upstream}/${platform}/${rel}`, {
        method: head ? 'HEAD' : 'GET',
        headers: { 'user-agent': agent },
        signal: AbortSignal.timeout(timeout),
      });
    } catch (err) {
      log(`${platform} ${rel}: ${err.message}`);
      reply(res, 502);
      return;
    }
    const length = Number(up.headers.get('content-length')) || 0;
    if (up.status !== 200 || length > maxFile) {
      if (up.body) up.body.cancel().catch(() => {});
      reply(res, up.status === 404 ? 404 : 502);
      return;
    }
    const headers = { 'content-type': 'application/zip', 'cache-control': 'no-cache' };
    if (length) headers['content-length'] = length;
    res.writeHead(200, headers);
    if (head || !up.body) { res.end(); return; }

    const chunks = [];
    let size = 0;
    const body = Readable.fromWeb(up.body);
    body.on('data', (c) => {
      size += c.length;
      if (size > maxFile) { body.destroy(new Error('too large')); return; }
      if (size <= cacheEntryMax) chunks.push(c);
      if (!res.write(c)) body.pause();
    });
    res.on('drain', () => body.resume());
    res.on('close', () => { if (!body.destroyed && !res.writableFinished) body.destroy(); });
    await new Promise((resolve) => {
      body.on('end', () => {
        res.end();
        if (size <= cacheEntryMax && (!length || size === length)) cachePut(cacheKey, Buffer.concat(chunks));
        resolve();
      });
      body.on('error', (err) => {
        log(`${platform} ${rel}: ${err.message}`);
        res.destroy();
        resolve();
      });
    });
  }

  // The lists are ready before PluginUpdater first asks.
  function warm() {
    for (const p of PLATFORMS) refresh(p).catch(() => {});
  }

  load();
  return { handle, load, warm };
}

module.exports = {
  createMirror, readZip, writeZip, parseHashes, filterRules, withIncludes, packagePath, wildMatch,
};
