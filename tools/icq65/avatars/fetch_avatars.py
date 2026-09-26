# Rebuilds the animated avatars the server hands out
# (deploy/oscar-legacy-web/avatars/): the Flash "devils" ICQ 6 showed in
# place of a buddy picture, from the copies the Wayback Machine kept.
#
# An animated devil is an AVM1 movie with a clip named `face` on its stage.
# The client sets `face.emotion` to the owner's mood or status; the setter
# (the class avatar.MyEmotion, registered for that clip) does gotoAndPlay on
# one of the frame labels stam, smile, sad, laugh, mad, cry, love, busy,
# offline. A movie is picked by handing SetBartItem(trans, 8, url) the
# address of the SWF; the buddies' clients then fetch the movie from that
# address themselves, over plain HTTP.
#
# The list below is every animated avatar the archive answered 200 for, under
# /xtraz/img/avatar/ (c.icq.com, xtraz.icq.com, www.icq.com, icq.com; uc/ is
# the "user created" folder) and c.icq.com/xtraz2/img/avatar/. Each movie is
# checked before it is kept: it has to parse, be AVM1 (the client drives it
# with ActionScript 1/2), and carry the `face` clip, the `emotion` property
# and the frame labels. Movies that fail are left out and said so.
#
# The 2007 gallery list (xtraz2/products/avatar/xml/avatarsGalery.php) names
# no movies in its Animated_Devils category - the gallery page filled it from
# elsewhere - so the thumbnails are:
#   archive  the static GIF ICQ.com kept next to the movie, under the same
#            number (avatar_10526.swf -> avatar_10526.gif)
#   render   the first seconds of the movie, drawn by our Ruffle-based
#            FlashPlayerControl.dll through its example host (--render)
#   placeholder  a plain frame, when neither is available
#
#   python fetch_avatars.py [--render <host.exe> <FlashPlayerControl.dll>]
#                           [--cache <dir>] [--out <dir>] [--cdx]
#
# --cdx asks the archive's CDX index again for the folders above and prints
# any movie it lists that is missing here; it changes nothing by itself.
#
# Needs Python 3 and, for the thumbnails, Pillow. Downloads are cached;
# nothing is fetched twice.

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, '..', '..', '..', 'deploy', 'oscar-legacy-web', 'avatars'))

# The size the client stores a buddy picture in, and the gallery list's
# <img_sizes>: thumbnails are made to it.
THUMB_W, THUMB_H = 52, 64

ICQ = 'icq'    # made by ICQ (/xtraz/img/avatar/, /xtraz2/img/avatar/)
USER = 'user'  # user created (/xtraz/img/avatar/uc/)

# file on our server, capture, original address, author group, title (en, uk).
AVATARS = [
    ('avatar_10522.swf', '20060209030456', 'http://xtraz.icq.com:80/xtraz/img/avatar/avatar_10522.swf', ICQ),
    ('avatar_10526.swf', '20070129083425', 'http://xtraz.icq.com:80/xtraz/img/avatar/avatar_10526.swf', ICQ),
    ('avatar_10529.swf', '20120819175814', 'http://c.icq.com/xtraz/img/avatar/avatar_10529.swf', ICQ),
    ('alian_10529.swf', '20060715130318', 'http://xtraz.icq.com:80/xtraz/img/avatar/alian_10529.swf', ICQ),
    ('avatar_10530.swf', '20060209031449', 'http://c.icq.com:80/xtraz/img/avatar/avatar_10530.swf', ICQ),
    ('avatar_10763.swf', '20120819175806', 'http://c.icq.com/xtraz/img/avatar/avatar_10763.swf', ICQ),
    ('baby_10914.swf', '20050104000120', 'http://xtraz.icq.com:80/xtraz/img/avatar/baby_10914.swf', ICQ),
    ('avatar_11074.swf', '20060209040122', 'http://c.icq.com:80/xtraz/img/avatar/avatar_11074.swf', ICQ),
    ('avatar_11102.swf', '20100930223659', 'http://c.icq.com/xtraz/img/avatar/avatar_11102.swf', ICQ),
    ('shark_11102.swf', '20041111070333', 'http://xtraz.icq.com:80/xtraz/img/avatar/shark_11102.swf', ICQ),
    ('avatar_11151.swf', '20101228151107', 'http://c.icq.com/xtraz/img/avatar/avatar_11151.swf', ICQ),
    ('avatar_boy.swf', '20100603053006', 'http://c.icq.com/xtraz/img/avatar/avatar_boy.swf', ICQ),
    ('avatar_girl.swf', '20101221224508', 'http://c.icq.com/xtraz/img/avatar/avatar_girl.swf', ICQ),
    ('avatar_santa.swf', '20060209040412', 'http://c.icq.com:80/xtraz/img/avatar/avatar_santa.swf', ICQ),
    ('superboy.swf', '20100820035220', 'http://c.icq.com/xtraz/img/avatar/superboy.swf', ICQ),
    # The ICQ 6 folder: newer than the /xtraz/ pirate.swf (2010, 69432 bytes).
    ('pirate.swf', '20120118212050', 'http://c.icq.com/xtraz2/img/avatar/pirate.swf', ICQ),
    ('robot.swf', '20120805184253', 'http://c.icq.com/xtraz2/img/avatar/robot.swf', ICQ),
    ('2308intheend.swf', '20060822011106', 'http://c.icq.com:80/xtraz/img/avatar/uc/2308intheend.swf', USER),
    ('2308koshak.swf', '20070202020823', 'http://c.icq.com:80/xtraz/img/avatar/uc/2308koshak.swf', USER),
    ('bg.swf', '20110904003226', 'http://c.icq.com/xtraz/img/avatar/uc/BG.swf', USER),
    ('bob.swf', '20100820035159', 'http://c.icq.com/xtraz/img/avatar/uc/bob.swf', USER),
    ('face1.swf', '20070220110701', 'http://c.icq.com:80/xtraz/img/avatar/uc/face1.swf', USER),
    ('kitty.swf', '20070319190551', 'http://c.icq.com:80/xtraz/img/avatar/uc/kitty.swf', USER),
    ('klex.swf', '20061031024248', 'http://xtraz.icq.com:80/xtraz/img/avatar/uc/klex.swf', USER),
    ('may18lr01.swf', '20060209040011', 'http://c.icq.com:80/xtraz/img/avatar/uc/may18lr01.swf', USER),
    ('mcshlain.swf', '20101228151122', 'http://c.icq.com/xtraz/img/avatar/uc/mcshlain.swf', USER),
    # uc/neger.swf, archived too, is left out on purpose: a racial caricature.
    ('oran.swf', '20120221233446', 'http://c.icq.com/xtraz/img/avatar/uc/oran.swf', USER),
    ('red.swf', '20120805184244', 'http://c.icq.com/xtraz/img/avatar/uc/red.swf', USER),
    ('sasuke.swf', '20100618032801', 'http://xtraz.icq.com/xtraz/img/avatar/uc/sasuke.swf', USER),
    ('sheep.swf', '20101207052643', 'http://c.icq.com/xtraz/img/avatar/uc/sheep.swf', USER),
    ('silke.swf', '20060715223311', 'http://c.icq.com:80/xtraz/img/avatar/uc/silke.swf', USER),
    ('smile.swf', '20101102061812', 'http://c.icq.com/xtraz/img/avatar/uc/smile.swf', USER),
    ('spongy.swf', '20070319190440', 'http://c.icq.com:80/xtraz/img/avatar/uc/spongy.swf', USER),
    ('wings.swf', '20060210231239', 'http://c.icq.com:80/xtraz/img/avatar/uc/wings.swf', USER),
]

# Two movies are archived twice under different names (alian_10529 and
# avatar_10529, shark_11102 and avatar_11102): the same movie, byte for byte
# once decompressed. The first in the list above is kept, and the other name
# gives it its title.

# Static pictures ICQ.com kept under the movie's number.
THUMBS = {
    '10522': ('20070320130541', 'http://c.icq.com:80/xtraz/img/avatar/avatar_10522.gif'),
    '10526': ('20060212154206', 'http://c.icq.com:80/xtraz/img/avatar/avatar_10526.gif'),
    '10529': ('20050502070233', 'http://icq.com:80/xtraz/img/avatar/avatar_10529.gif'),
    '10763': ('20041126225029', 'http://www.icq.com:80/xtraz/img/avatar/avatar_10763.gif'),
    '10914': ('20040718164957', 'http://www.icq.com:80/xtraz/img/avatar/avatar_10914.gif'),
    '11074': ('20060526185448', 'http://c.icq.com:80/xtraz/img/avatar/avatar_11074.gif'),
    '11102': ('20060525070215', 'http://c.icq.com:80/xtraz/img/avatar/avatar_11102.gif'),
}

# Titles for the gallery. The gallery list names no animated avatar, so a
# title is the file name cleaned up (a duplicate's name where it says more,
# the prefixes and the typos dropped), and translated where it is a word.
TITLES = {
    'avatar_10522': ('Avatar 10522', 'Аватар 10522'),
    'avatar_10526': ('Avatar 10526', 'Аватар 10526'),
    'avatar_10529': ('Alien', 'Прибулець'),      # also archived as alian_10529
    'avatar_10530': ('Avatar 10530', 'Аватар 10530'),
    'avatar_10763': ('Avatar 10763', 'Аватар 10763'),
    'avatar_11074': ('Avatar 11074', 'Аватар 11074'),
    'avatar_11102': ('Shark', 'Акула'),          # also archived as shark_11102
    'avatar_11151': ('Avatar 11151', 'Аватар 11151'),
    'baby_10914': ('Baby', 'Малюк'),
    'avatar_boy': ('Boy', 'Хлопець'),
    'avatar_girl': ('Girl', 'Дівчина'),
    'avatar_santa': ('Santa', 'Санта'),
    'superboy': ('Superboy', 'Супербой'),
    'pirate': ('Pirate', 'Пірат'),
    'robot': ('Robot', 'Робот'),
    '2308intheend': ('In the End', 'In the End'),
    '2308koshak': ('Koshak', 'Кошак'),
    'bg': ('BG', 'BG'),
    'bob': ('Bob', 'Боб'),
    'face1': ('Face 1', 'Обличчя 1'),
    'kitty': ('Kitty', 'Кошеня'),
    'klex': ('Klex', 'Klex'),
    'may18lr01': ('May 18', 'May 18'),
    'mcshlain': ('McShlain', 'McShlain'),
    'oran': ('Oran', 'Oran'),
    'red': ('Red', 'Червоний'),
    'sasuke': ('Sasuke', 'Саске'),
    'sheep': ('Sheep', 'Вівця'),
    'silke': ('Silke', 'Silke'),
    'smile': ('Smile', 'Усмішка'),
    'spongy': ('Spongy', 'Spongy'),
    'wings': ('Wings', 'Крила'),
}

LABELS = ['stam', 'smile', 'sad', 'laugh', 'mad', 'cry', 'love', 'busy', 'offline']

CDX_PREFIXES = [
    'c.icq.com/xtraz/img/avatar/', 'xtraz.icq.com/xtraz/img/avatar/',
    'www.icq.com/xtraz/img/avatar/', 'icq.com/xtraz/img/avatar/',
    'c.icq.com/xtraz2/img/avatar/',
]


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
                print('  could not fetch %s: %s' % (raw, e))
                return None
            time.sleep(5)
    open(path, 'wb').write(data)
    time.sleep(1)
    return data


# ------------------------------------------------------------------ SWF check

class Bits:
    def __init__(self, data, pos):
        self.d, self.p, self.b = data, pos, 0

    def u(self, n):
        v = 0
        for _ in range(n):
            byte = self.d[self.p]
            v = (v << 1) | ((byte >> (7 - self.b)) & 1)
            self.b += 1
            if self.b == 8:
                self.b, self.p = 0, self.p + 1
        return v

    def align(self):
        if self.b:
            self.b, self.p = 0, self.p + 1
        return self.p


def skip_matrix(d, p):
    b = Bits(d, p)
    if b.u(1):
        n = b.u(5); b.u(2 * n)
    if b.u(1):
        n = b.u(5); b.u(2 * n)
    n = b.u(5); b.u(2 * n)
    return b.align()


def skip_cxform(d, p):
    b = Bits(d, p)
    has_add, has_mult = b.u(1), b.u(1)
    n = b.u(4)
    b.u(4 * n * (has_mult + has_add))
    return b.align()


def cstr(d, p):
    e = d.index(b'\0', p)
    return d[p:e].decode('latin1'), e + 1


def tag_list(d, pos, end):
    while pos + 2 <= end:
        h = struct.unpack('<H', d[pos:pos + 2])[0]
        pos += 2
        code, ln = h >> 6, h & 0x3f
        if ln == 0x3f:
            ln = struct.unpack('<I', d[pos:pos + 4])[0]
            pos += 4
        yield code, d[pos:pos + ln]
        pos += ln
        if code == 0:
            break


def action_strings(code):
    """The strings an AVM1 block pushes or keeps in its constant pool."""
    out = set()
    i = 0
    while i < len(code):
        op = code[i]
        i += 1
        if op == 0:
            continue
        if op < 0x80:
            continue
        ln = struct.unpack('<H', code[i:i + 2])[0]
        arg = code[i + 2:i + 2 + ln]
        i += 2 + ln
        if op == 0x88:  # ConstantPool
            n = struct.unpack('<H', arg[:2])[0]
            out.update(x.decode('latin1') for x in arg[2:].split(b'\0')[:n])
        elif op == 0x96:  # Push
            j = 0
            while j < len(arg):
                t = arg[j]
                j += 1
                if t == 0:
                    s = arg[j:].split(b'\0')[0]
                    out.add(s.decode('latin1'))
                    j += len(s) + 1
                else:
                    j += {1: 4, 2: 0, 3: 0, 4: 1, 5: 1, 6: 8, 7: 4, 8: 1, 9: 2}.get(t, 0)
        elif op in (0x8c, 0x8b):  # GotoLabel, SetTarget
            out.add(arg.split(b'\0')[0].decode('latin1'))
        elif op in (0x9b, 0x8e):  # DefineFunction(2): the name and the parameters
            out.update(re.findall(r'[A-Za-z_$][\w$]*', arg.decode('latin1')))
    return out


def scan(d, pos, end, info):
    for code, t in tag_list(d, pos, end):
        if code in (72, 82):
            info['as3'] = True
        elif code == 69 and t and t[0] & 0x08:
            info['as3'] = True
        elif code == 43:
            info['labels'].add(t.split(b'\0')[0].decode('latin1'))
        elif code == 39:
            scan(t, 4, len(t), info)
        elif code == 12:
            info['strings'] |= action_strings(t)
        elif code == 59:
            info['strings'] |= action_strings(t[2:])
        elif code == 56:  # ExportAssets: linkage names
            n = struct.unpack('<H', t[:2])[0]
            p = 2
            for _ in range(n):
                name, p = cstr(t, p + 2)
                info['exports'].add(name)
        elif code in (26, 70):
            try:
                info['names'] |= place_name(code, t)
            except (IndexError, ValueError):
                pass
            if code == 26 and t[0] & 0x80:  # clip actions carry AVM1 too
                info['strings'] |= set(re.findall(r'[A-Za-z_]\w{2,}', t.decode('latin1')))


def place_name(code, t):
    if code == 26:
        f, p, f2 = t[0], 3, 0
    else:
        f, f2, p = t[0], t[1], 4
        if f2 & 0x08 or (f2 & 0x10 and f & 0x02):
            _, p = cstr(t, p)
    if f & 0x02:
        p += 2
    if f & 0x04:
        p = skip_matrix(t, p)
    if f & 0x08:
        p = skip_cxform(t, p)
    if f & 0x10:
        p += 2
    if f & 0x20:
        name, p = cstr(t, p)
        return {name}
    return set()


def swf_body(data):
    return data[8:] if data[:3] == b'FWS' else zlib.decompress(data[8:])


def check_swf(data):
    """(ok, reason, info) for one movie."""
    if not data or data[:3] not in (b'FWS', b'CWS'):
        return False, 'not a SWF', None
    try:
        body = swf_body(data)
    except zlib.error as e:
        return False, 'does not decompress (%s)' % e, None
    declared = struct.unpack('<I', data[4:8])[0]
    if len(body) + 8 < declared:
        return False, 'truncated (%d of %d bytes)' % (len(body) + 8, declared), None
    nbits = body[0] >> 3
    p = (5 + 4 * nbits + 7) // 8
    info = {'version': data[3], 'as3': False, 'labels': set(), 'strings': set(),
            'names': set(), 'exports': set()}
    try:
        scan(body, p + 4, len(body), info)
    except (struct.error, IndexError, ValueError) as e:
        return False, 'does not parse (%s)' % e, info
    if info['as3']:
        return False, 'ActionScript 3, the client drives AVM1 only', info
    missing = []
    # The clip has to be on the stage under that name: robot.swf exports a
    # `face` symbol but places it as `ff`, where the client never looks.
    if 'face' not in info['names']:
        missing.append('the face clip')
    if 'emotion' not in info['strings']:
        missing.append('the emotion property')
    labels = [l for l in LABELS if l in {x.lower() for x in info['labels'] | info['strings']}]
    if 'stam' not in labels or len(labels) < 5:
        missing.append('the labels (has %s)' % (', '.join(labels) or 'none'))
    if missing:
        return False, 'no ' + ', no '.join(missing), info
    info['found_labels'] = labels
    return True, '', info


# ----------------------------------------------------------------- thumbnails

def fit(img):
    """The picture on a white 52x64 frame, scaled to fit, centred."""
    from PIL import Image
    img = img.convert('RGBA')
    box = img.getchannel('A').getbbox()
    if box:
        img = img.crop(box)
    scale = min(THUMB_W / img.width, THUMB_H / img.height)
    size = (max(1, round(img.width * scale)), max(1, round(img.height * scale)))
    img = img.resize(size, Image.LANCZOS)
    frame = Image.new('RGBA', (THUMB_W, THUMB_H), (255, 255, 255, 255))
    frame.alpha_composite(img, ((THUMB_W - size[0]) // 2, (THUMB_H - size[1]) // 2))
    out = io.BytesIO()
    frame.convert('RGB').save(out, 'PNG', optimize=True)
    return out.getvalue()


def render(host, dll, swf_path):
    """Plays the movie through the Ruffle DLL's example host and takes the
    frame it snapshots after GotoFrame(0): the start of the movie, where the
    face stands on its `stam` (idle) loop - what a contact sees most of the
    time. The devils have a one-frame root timeline, so the host counts them
    as finished at once and never reaches its three-second snapshot."""
    from PIL import Image
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run([host, dll, 'play', swf_path, tmp], timeout=90,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass
        shots = [os.path.join(tmp, n) for n in ('snapshot-goto-0.png', 'snapshot-3s.png')]
        shots = [s for s in shots if os.path.exists(s)]
        if not shots:
            return None
        shot = shots[0]
        img = Image.open(shot)
        img.load()
        if not img.convert('RGBA').getchannel('A').getbbox():
            return None  # nothing drawn
        return fit(img)


def placeholder():
    from PIL import Image, ImageDraw
    img = Image.new('RGB', (THUMB_W, THUMB_H), (251, 253, 251))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, THUMB_W - 1, THUMB_H - 1], outline=(207, 227, 213))
    d.ellipse([12, 16, 40, 44], outline=(120, 170, 130), width=2)
    d.arc([19, 24, 33, 38], 20, 160, fill=(120, 170, 130), width=2)
    d.point([(21, 26), (31, 26)], fill=(120, 170, 130))
    out = io.BytesIO()
    img.save(out, 'PNG', optimize=True)
    return out.getvalue()


# ----------------------------------------------------------------------- main

def cdx_check(known):
    for prefix in CDX_PREFIXES:
        q = ('http://web.archive.org/cdx/search/cdx?url=%s&matchType=prefix'
             '&filter=statuscode:200&filter=mimetype:application/x-shockwave-flash'
             '&collapse=urlkey&fl=original,timestamp' % prefix)
        try:
            with urllib.request.urlopen(q, timeout=120) as r:
                rows = r.read().decode('utf8', 'replace').splitlines()
        except Exception as e:
            print('cdx %s: %s' % (prefix, e))
            continue
        for row in rows:
            original = row.split(' ')[0]
            base = original.rsplit('/', 1)[1].split('?')[0].lower()
            if base not in known:
                print('not in the list: %s' % row)
        time.sleep(2)


def title_of(stem):
    if stem in TITLES:
        return TITLES[stem]
    num = re.search(r'(\d{5})$', stem)
    if num:
        return ('Devil %s' % num.group(1), 'Дияволик %s' % num.group(1))
    word = re.sub(r'^\d+', '', stem).replace('_', ' ').strip().capitalize() or stem
    return (word, word)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cache', default=os.path.join(tempfile.gettempdir(), 'icq65-avatars-cache'))
    ap.add_argument('--out', default=OUT)
    ap.add_argument('--render', nargs=2, metavar=('HOST_EXE', 'DLL'),
                    help='draw the missing thumbnails with the Ruffle DLL example host')
    ap.add_argument('--cdx', action='store_true', help='list archived movies missing from this list')
    a = ap.parse_args()
    os.makedirs(a.cache, exist_ok=True)

    if a.cdx:
        cdx_check({u.rsplit('/', 1)[1].lower() for _, _, u, _ in AVATARS})
        return 0

    good, dropped, seen = {}, [], {}
    for name, stamp, url, group in AVATARS:
        data = fetch(stamp, url, a.cache)
        ok, why, info = check_swf(data)
        if ok:
            movie = hashlib.sha1(swf_body(data)).hexdigest()
            if movie in seen:
                ok, why = False, 'the same movie as %s' % seen[movie]
            seen.setdefault(movie, name)
        if not ok:
            dropped.append((name, why))
            print('drop %-18s %s' % (name, why))
            continue
        good[name] = (stamp, url, group, data, info)

    if os.path.isdir(a.out):
        shutil.rmtree(a.out)
    os.makedirs(a.out)

    manifest = []
    for name, (stamp, url, group, data, info) in good.items():
        stem = name[:-4]
        open(os.path.join(a.out, name), 'wb').write(data)

        thumb, source = None, None
        num = re.search(r'(\d{5})$', stem)
        if num and num.group(1) in THUMBS:
            t_stamp, t_url = THUMBS[num.group(1)]
            gif = fetch(t_stamp, t_url, a.cache)
            if gif and gif[:4] == b'GIF8':
                thumb, source, ext = gif, 'archive', '.gif'
        if thumb is None and a.render:
            png = render(a.render[0], a.render[1], os.path.abspath(os.path.join(a.out, name)))
            if png:
                thumb, source, ext = png, 'render', '.png'
        if thumb is None:
            thumb, source, ext = placeholder(), 'placeholder', '.png'
        thumb_name = stem + ext
        open(os.path.join(a.out, thumb_name), 'wb').write(thumb)

        en, uk = title_of(stem)
        manifest.append({
            'file': name,
            'title': {'en': en, 'uk': uk},
            'category': 'Animated_Devils',
            'sub': 'ICQ_Devils' if group == ICQ else 'User_Created',
            'author': group,
            'size': len(data),
            'thumb': thumb_name,
            'thumbSource': source,
            'source': url,
            'captured': stamp,
            'labels': info['found_labels'],
        })
        print('keep %-18s %6d bytes  thumb %-11s <- %s (%s)' % (name, len(data), source, url, stamp))

    manifest.sort(key=lambda m: (m['author'] != ICQ, m['title']['en'].lower()))
    with open(os.path.join(a.out, 'avatars.json'), 'w', encoding='utf8', newline='\n') as f:
        json.dump({
            'note': 'Written by tools/icq65/avatars/fetch_avatars.py; do not edit by hand.',
            'avatars': manifest,
            'dropped': [{'file': n, 'why': w} for n, w in dropped],
        }, f, ensure_ascii=False, indent=1)
        f.write('\n')
    print('%d kept, %d dropped' % (len(manifest), len(dropped)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
