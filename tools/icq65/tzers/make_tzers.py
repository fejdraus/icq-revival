# Rebuilds the tZers the server hands out (deploy/oscar-legacy-web/tzers/):
# the movies from the copies the Wayback Machine kept, the thumbnails from
# the ICQ 6.5 client itself.
#
# ICQ 6.5 lists twelve tZers in ConfigFiles\tzer.xml, under
# http://c.icq.com/xtraz2/img/teaser/common. Of that folder only kisses.swf
# was archived. ICQ 5 played the same twelve from
# c.icq.com/xtraz/products/teaser/anims/common/ under other names, and all
# twelve of those survive.
#
# The ICQ 6 kisses.swf is the ICQ 5 one with one addition: the last frame's
# script also sends fscommand("animEnd"), which ICQ 6 waits for to close the
# animation (a small shape differs too). The same addition is made here to the
# other eleven, so they end the way ICQ 6 expects; nothing else in them is
# changed. kisses.swf is the archived ICQ 6 file itself.
#
# The thumbnails come with the client, in
# services\icqApp\ver1\theme\IMAGES\tzer\ - the folder its tZer buttons take
# their pictures from (MUICore.dll builds <theme>\images\tzer\<thumb file>, and
# fetches baseurl + thumb only when that file is missing). They are copied
# byte for byte, for a client whose folder lacks them.
#
#   python make_tzers.py --client <ICQ 6.5 folder> [--cache <dir>] [--out <dir>]
#
# Needs Python 3. Downloads are cached; nothing is fetched twice.

import argparse
import hashlib
import os
import shutil
import struct
import sys
import tempfile
import time
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, '..', '..', '..', 'deploy', 'oscar-legacy-web', 'tzers'))
THUMBS = os.path.join('services', 'icqApp', 'ver1', 'theme', 'IMAGES', 'tzer')

ICQ5 = 'http://c.icq.com:80/xtraz/products/teaser/anims/common/'
ICQ6 = 'http://c.icq.com/xtraz2/img/teaser/common/'

# ICQ 6 name (tzer.xml, and the client's thumbnail) -> the archived movie.
TZERS = [
    ('gangsta',   '20061105234221', ICQ5 + 'gangsterSheep.swf'),
    ('canthearu', '20070205090448', ICQ5 + 'cant_hear.swf'),
    ('skratch',   '20061105233936', ICQ5 + 'scratch.swf'),
    ('boo',       '20060701205152', ICQ5 + 'boo.swf'),
    ('kisses',    '20101231180044', ICQ6 + 'kisses.swf'),
    ('chillout',  '20061214145031', ICQ5 + 'rastamab.swf'),
    ('akitaka',   '20061109213845', ICQ5 + 'sappuko.swf'),
    ('laugh',     '20070109162414', ICQ5 + 'laugh.swf'),
    ('duh',       '20070212084647', ICQ5 + 'dahh.swf'),
    ('beback',    '20070323041920', ICQ5 + 'beBack.swf'),
    ('likeu',     '20070207142857', ICQ5 + 'iLikeU.swf'),
    ('sorry',     '20060822011118', ICQ5 + 'sorry.swf'),
]

ANIM_END = b'\x83\x13\x00FSCommand:animEnd\x00\x00'  # GetURL "FSCommand:animEnd", ""
ENDED_CALL = b'OnAnimEnded\x00\x52\x17'              # ..."OnAnimEnded"; CallMethod; Pop


def fetch(stamp, url, cache):
    name = hashlib.sha1((stamp + url).encode()).hexdigest()[:12] + '-' + url.rsplit('/', 1)[1]
    path = os.path.join(cache, name)
    if os.path.exists(path):
        return open(path, 'rb').read()
    raw = 'http://web.archive.org/web/%sid_/%s' % (stamp, url)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(raw, timeout=120) as r:
                if r.status != 200:
                    raise IOError('HTTP %d' % r.status)
                data = r.read()
            break
        except Exception as e:  # the archive times out now and then
            if attempt == 3:
                raise SystemExit('could not fetch %s: %s' % (raw, e))
            time.sleep(5)
    open(path, 'wb').write(data)
    time.sleep(1)
    return data


def swf_body(data):
    sig = data[:3]
    if sig == b'FWS':
        return data[8:]
    if sig == b'CWS':
        return zlib.decompress(data[8:])
    raise SystemExit('not a SWF (header %r)' % sig)


def check_swf(name, data):
    body = swf_body(data)
    declared = struct.unpack('<I', data[4:8])[0]
    # rastamab.swf carries 88 zero bytes past its End tag, in every capture.
    if len(body) + 8 < declared:
        raise SystemExit('%s: truncated (%d of %d bytes)' % (name, len(body) + 8, declared))
    return body


def tags(body):
    nbits = body[0] >> 3
    p = (5 + 4 * nbits + 7) // 8 + 4
    head, out = body[:p], []
    while p < len(body):
        code_len = struct.unpack('<H', body[p:p + 2])[0]
        code, length = code_len >> 6, code_len & 63
        hl = 2
        if length == 63:
            length = struct.unpack('<I', body[p + 2:p + 6])[0]
            hl = 6
        out.append((code, body[p + hl:p + hl + length]))
        p += hl + length
        if code == 0:
            break
    return head, out, body[p:]


def tag_bytes(code, data):
    if len(data) < 63:
        return struct.pack('<H', (code << 6) | len(data)) + data
    return struct.pack('<HI', (code << 6) | 63, len(data)) + data


# The ICQ 5 movie with fscommand("animEnd") after its _root.prog.OnAnimEnded()
# call - where the ICQ 6 kisses.swf has it.
def add_anim_end(name, data):
    body = check_swf(name, data)
    head, ts, tail = tags(body)
    done = 0
    out = []
    for code, d in ts:
        if code == 12 and ENDED_CALL in d and ANIM_END not in d:
            at = d.index(ENDED_CALL) + len(ENDED_CALL)
            d = d[:at] + ANIM_END + d[at:]
            done += 1
        out.append(tag_bytes(code, d))
    if done != 1:
        raise SystemExit('%s: %d end-of-animation scripts found, expected one' % (name, done))
    new_body = head + b''.join(out) + tail
    return b'CWS' + data[3:4] + struct.pack('<I', len(new_body) + 8) + zlib.compress(new_body, 9)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--client', required=True, help='an ICQ 6.5 (build 2024) folder, for the thumbnails')
    ap.add_argument('--cache', default=os.path.join(tempfile.gettempdir(), 'icq65-tzers-cache'))
    ap.add_argument('--out', default=OUT)
    a = ap.parse_args()
    os.makedirs(a.cache, exist_ok=True)
    os.makedirs(a.out, exist_ok=True)

    for name, stamp, url in TZERS:
        data = fetch(stamp, url, a.cache)
        if url.startswith(ICQ6):
            check_swf(name, data)
            if ANIM_END not in swf_body(data):
                raise SystemExit('%s: the ICQ 6 movie has no animEnd' % name)
            swf = data
        else:
            swf = add_anim_end(name, data)
        check_swf(name, swf)
        open(os.path.join(a.out, name + '.swf'), 'wb').write(swf)

        thumb = os.path.join(a.client, THUMBS, name + '.png')
        if not os.path.exists(thumb):
            raise SystemExit('no thumbnail %s - is this ICQ 6.5 build 2024?' % thumb)
        shutil.copyfile(thumb, os.path.join(a.out, name + '.png'))
        print('%-10s %6d bytes  <- %s (%s)' % (name, len(swf), url.rsplit('/', 1)[1], stamp))


if __name__ == '__main__':
    sys.exit(main())
