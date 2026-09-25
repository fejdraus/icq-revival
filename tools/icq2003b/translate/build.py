"""Builds the recipe the ICQ 2003b patch follows to translate the client.

    python build.py <client folder> [uk-UA.json]

The client folder must hold the untouched files of ICQ Pro 2003b build 3916
(a copy, or the backups the patch keeps). For every menu, dialog and string
table with a translated text it records WHAT to change - the replaced strings,
menu items and control captions, and the widths a dialog's controls are given
to fit the longer text - and writes it all, as readable UTF-8 text, to
../patch/ICQ-2003b-uk-UA.json. The patch carries that recipe and rebuilds each
translated resource itself, from the client's own English resource, so the exe
holds only text, no packed or binary payload.

A resource is only translated in a client when its English original is the one
this was built from: each record carries the SHA-256 of that original.

A translated dialog is also fitted here, at build time (fit.py measures fonts
with Windows): a control whose text no longer fits is widened where the dialog
has room to its right, and the recipe records the width it ends up with. What
still does not fit is listed in overflow.json, with the pixels there are, for
the translation to be made shorter.

The "Send By:" words, which the patch blanks, live in a string table of
Icq.exe. The recipe names that table and the string in it, and the patch
blanks it in whichever language it writes.
"""

import hashlib
import json
import os
import sys
from collections import OrderedDict

import pefile

import fit
import icqres

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'patch', 'ICQ-2003b-uk-UA.json')

# The words the "Send By" job blanks: Icq.exe, string 8727.
SEND_BY = {'file': 'Icq.exe', 'string': 8727, 'text': 'Send By:', 'blank': ' ' * 8}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def changed_map(old, new):
    """Which texts changed, by index, as a string-keyed ordered dict."""
    out = OrderedDict()
    for i, (a, b) in enumerate(zip(old, new)):
        if a != b:
            out[str(i)] = b
    return out


def main():
    root = sys.argv[1]
    source = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, 'uk-UA.json')
    with open(source, encoding='utf-8') as f:
        doc = json.load(f)
    tr = doc['texts']

    files = OrderedDict()
    counts = {'resources': 0, 'texts': 0}
    missing = set()
    send_by = None
    overflow = []
    widened = 0
    for name in sorted(os.listdir(root)):
        if not name.lower().endswith(('.exe', '.dll', '.ocx')):
            continue
        path = os.path.join(root, name)
        try:
            res = list(icqres.resources(path))
        except pefile.PEFormatError:
            continue
        records = []
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
            if rtype == icqres.RT_DIALOG:
                for i in range(1, len(new)):
                    o = doc.get('overrides', {}).get(f'{name} dialog {rname} control {i - 1}')
                    if o is not None and old[i]:
                        new[i] = o
            is_send_by = (name == SEND_BY['file'] and rtype == icqres.RT_STRING
                          and (rname - 1) * 16 <= SEND_BY['string'] < rname * 16)
            if is_send_by:
                i = SEND_BY['string'] - (rname - 1) * 16
                assert old[i] == SEND_BY['text'], old[i]
                send_by = OrderedDict([
                    ('file', name), ('type', rtype), ('name', rname), ('lang', lang),
                    ('from', sha(data)), ('index', i), ('blank', SEND_BY['blank']),
                ])
            if new == old:
                continue
            record = OrderedDict([('type', rtype), ('name', rname), ('lang', lang), ('from', sha(data))])
            if rtype == icqres.RT_STRING:
                record['strings'] = changed_map(old, new)
            elif rtype == icqres.RT_MENU:
                record['items'] = changed_map(old, new)
            else:
                # A dialog: its caption (index 0), the control captions that
                # changed, and the widths fit.py gives the controls it widens.
                d = icqres.read_dialog(data)
                before = [c['cx'] for c in d['controls']]
                d['text'] = new[0]
                for c, t in zip(d['controls'], new[1:]):
                    if isinstance(c['text'], str):
                        c['text'] = t
                for i, t, have, needed in fit.fit_dialog(d, new):
                    c = d['controls'][i]
                    overflow.append(OrderedDict([('en', old[i + 1]), ('uk', t), ('where', f'{name} dialog {rname} control {i}'),
                                                 ('have', have), ('need', int(needed)),
                                                 ('control', OrderedDict([('cls', list(c['cls']) if isinstance(c['cls'], tuple) else c['cls']),
                                                                          ('style', c['style']), ('cx', c['cx']), ('cy', c['cy'])]))]))
                widths = OrderedDict()
                for j, (a, c) in enumerate(zip(before, d['controls'])):
                    if c['cx'] != a:
                        widths[str(j)] = c['cx']
                        widened += 1
                if new[0] != old[0]:
                    record['caption'] = new[0]
                controls = OrderedDict()
                for j, c in enumerate(d['controls']):
                    if isinstance(c['text'], str) and new[j + 1] != old[j + 1]:
                        controls[str(j)] = new[j + 1]
                if controls:
                    record['controls'] = controls
                if widths:
                    record['widths'] = widths
            records.append(record)
            counts['resources'] += 1
            counts['texts'] += sum(1 for a, b in zip(old, new) if a != b)
        if records:
            files[name] = OrderedDict([('size', os.path.getsize(path)), ('resources', records)])

    # Texts in the data of a program or in the skin: written over the English
    # one, never longer than the room it had - its own bytes, and for ANSI the
    # zeros after it up to where the next text is aligned. The recipe records
    # the text and the room; the patch encodes and pads.
    for e in doc.get('inplace', []):
        path = os.path.join(root, e['file'])
        with open(path, 'rb') as f:
            data = f.read()
        off = int(e['offset'], 16)
        if e['encoding'] == 'ansi':
            en, uk = e['en'].encode('cp1252'), e['uk'].encode('cp1251')
            room = len(en)
            while off + room + 1 < len(data) and data[off + room + 1] == 0 and (off + room + 1) % 4:
                room += 1
            slot = room + 1
        else:
            en, uk = e['en'].encode('utf-16-le'), e['uk'].encode('utf-16-le')
            room = len(en)
            slot = room + 2
        assert data[off:off + len(en)] == en, (e['file'], e['offset'], e['en'])
        assert len(uk) <= room, f"{e['file']} {e['offset']}: '{e['uk']}' needs {len(uk)} bytes, room for {room}"
        entry = files.setdefault(e['file'], OrderedDict([('size', len(data)), ('resources', [])]))
        entry.setdefault('inplace', []).append(OrderedDict([
            ('offset', off), ('encoding', e['encoding']), ('slot', slot),
            ('en', e['en']), ('uk', e['uk'])]))
        counts['texts'] += 1

    # Text files of the client: every field after a tab that is a name the file
    # lists gets its translation, and the file is written whole. The recipe
    # records the translated text; the patch encodes it (Windows-1251).
    for rel, names in doc.get('datafiles', {}).items():
        path = os.path.join(root, rel)
        with open(path, 'rb') as f:
            data = f.read()
        lines = data.decode('cp1252').split('\r\n')
        out = []
        for line in lines:
            parts = line.split('\t')
            if len(parts) > 1 and parts[-1] in names and parts[-1] != 'note':
                parts[-1] = names[parts[-1]]
                counts['texts'] += 1
            out.append('\t'.join(parts))
        text = '\r\n'.join(out)
        entry = files.setdefault(rel, OrderedDict([('size', len(data)), ('resources', [])]))
        entry['whole'] = OrderedDict([('from', sha(data)), ('text', text)])

    payload = OrderedDict([('language', 'uk-UA'), ('sendBy', send_by), ('files', files)])
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
        f.write('\n')
    with open(os.path.join(HERE, 'overflow.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(overflow, f, ensure_ascii=False, indent=1)
    size = os.path.getsize(OUT)
    print(f'{len(files)} files, {counts["resources"]} resources, {counts["texts"]} texts; '
          f'{len(missing)} texts not translated yet; {size:,} bytes -> {os.path.normpath(OUT)}')
    print(f'{widened} controls widened to fit, {len(overflow)} texts still too long (overflow.json)')


if __name__ == '__main__':
    main()
