"""Builds the translated resources the ICQ 2003b patch writes into the client.

    python build.py <client folder> [uk-UA.json]

The client folder must hold the untouched files of ICQ Pro 2003b build 3916
(a copy, or the backups the patch keeps). For every menu, dialog and string
table with a translated text it writes the whole resource again, and puts
them all into ../patch/ICQ-2003b-uk-UA.txt: gzip, then base64, so the patch
can carry it inside its exe.

A resource is only written into a client when its English original is the
one this was built from: each carries the SHA-256 of that original.

The "Send By:" words, which the patch blanks, live in a string table of
Icq.exe. The patch writes that table as a whole in both languages, so the
build also gives it blanked in English and in Ukrainian.
"""

import base64
import gzip
import hashlib
import json
import os
import sys
from collections import OrderedDict

import pefile

import icqres

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'patch', 'ICQ-2003b-uk-UA.txt')

# The words the "Send By" job blanks: Icq.exe, string 8727.
SEND_BY = {'file': 'Icq.exe', 'string': 8727, 'text': 'Send By:', 'blank': ' ' * 8}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    root = sys.argv[1]
    source = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, 'uk-UA.json')
    with open(source, encoding='utf-8') as f:
        tr = json.load(f)['texts']

    files = OrderedDict()
    counts = {'resources': 0, 'texts': 0, 'missing': 0}
    missing = set()
    send_by = None
    for name in sorted(os.listdir(root)):
        if not name.lower().endswith(('.exe', '.dll')):
            continue
        path = os.path.join(root, name)
        try:
            res = list(icqres.resources(path))
        except pefile.PEFormatError:
            continue
        items = []
        for rtype, rname, lang, data in res:
            old = icqres.texts(rtype, data)
            new = []
            for t in old:
                if not t:
                    new.append(t)
                    continue
                u = tr.get(t)
                if u is None:
                    missing.add(t)
                    u = t
                new.append(u)
            is_send_by = (name == SEND_BY['file'] and rtype == icqres.RT_STRING
                          and (rname - 1) * 16 <= SEND_BY['string'] < rname * 16)
            if is_send_by:
                i = SEND_BY['string'] - (rname - 1) * 16
                assert old[i] == SEND_BY['text'], old[i]
                blank_en = list(old)
                blank_uk = list(new)
                blank_en[i] = blank_uk[i] = SEND_BY['blank']
                send_by = OrderedDict([
                    ('file', name), ('t', rtype), ('n', rname), ('l', lang), ('from', sha(data)),
                    ('en', base64.b64encode(icqres.with_texts(rtype, data, blank_en)).decode()),
                    ('uk', base64.b64encode(icqres.with_texts(rtype, data, blank_uk)).decode()),
                ])
            if new == old:
                continue
            out = icqres.with_texts(rtype, data, new)
            items.append(OrderedDict([('t', rtype), ('n', rname), ('l', lang), ('from', sha(data)),
                                      ('d', base64.b64encode(out).decode())]))
            counts['resources'] += 1
            counts['texts'] += sum(1 for a, b in zip(old, new) if a != b)
        if items:
            files[name] = OrderedDict([('size', os.path.getsize(path)), ('items', items)])

    payload = OrderedDict([('language', 'uk-UA'), ('files', files), ('sendBy', send_by)])
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    packed = base64.b64encode(gzip.compress(raw, 9, mtime=0)).decode()
    with open(OUT, 'w', newline='\n') as f:
        for i in range(0, len(packed), 100):
            f.write(packed[i:i + 100] + '\n')
    print(f'{len(files)} files, {counts["resources"]} resources, {counts["texts"]} texts; '
          f'{len(missing)} texts not translated yet; {len(packed):,} bytes -> {os.path.normpath(OUT)}')


if __name__ == '__main__':
    main()
