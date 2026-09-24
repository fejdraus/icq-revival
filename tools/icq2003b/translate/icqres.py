"""Reading and writing the text resources of ICQ Pro 2003b: string tables,
menus and dialogs, the three kinds that carry its interface text.

Only what the translation needs: each resource is parsed into its texts plus
everything else kept as it was, and written back with other texts. The
layout of a dialog - positions, sizes, styles - stays as it is unless a
change asks for another width.
"""

import struct

import pefile

RT_MENU, RT_DIALOG, RT_STRING = 4, 5, 6
KINDS = {RT_MENU: 'menu', RT_DIALOG: 'dialog', RT_STRING: 'string'}
ENGLISH = 9  # primary language id of the resources that are translated


def resources(path):
    """Yields (type, name, lang, data) for every menu, dialog and string
    table in English; name is an int id or a str."""
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if t.struct.Id not in KINDS:
            continue
        for e in t.directory.entries:
            name = str(e.name) if e.name is not None else e.struct.Id
            for l in e.directory.entries:
                if l.data.lang != ENGLISH:
                    continue
                lang = l.data.lang | (l.data.sublang << 10)
                d = l.data.struct
                yield t.struct.Id, name, lang, pe.get_data(d.OffsetToData, d.Size)


# --- string tables ------------------------------------------------------------

def read_strings(data):
    out, i = [], 0
    while len(out) < 16 and i + 2 <= len(data):
        n = struct.unpack_from('<H', data, i)[0]
        i += 2
        out.append(data[i:i + 2 * n].decode('utf-16-le'))
        i += 2 * n
    while len(out) < 16:
        out.append('')
    return out


def write_strings(texts):
    b = bytearray()
    for t in texts:
        u = t.encode('utf-16-le')
        b += struct.pack('<H', len(u) // 2) + u
    return bytes(b)


# --- menus --------------------------------------------------------------------

def _wstr(data, i):
    j = i
    while data[j:j + 2] != b'\0\0':
        j += 2
    return data[i:j].decode('utf-16-le'), j + 2


def _align4(i):
    return (i + 3) & ~3


def read_menu(data):
    """A menu as a list of items; each item a dict with 'text' and whatever
    else it needs to be written back unchanged."""
    version, offset = struct.unpack_from('<HH', data, 0)
    items = []
    if version == 0:
        i = 4
        while i < len(data):
            flags = struct.unpack_from('<H', data, i)[0]
            i += 2
            item = {'flags': flags}
            if not flags & 0x10:  # MF_POPUP
                item['id'] = struct.unpack_from('<H', data, i)[0]
                i += 2
            item['text'], i = _wstr(data, i)
            items.append(item)
        return {'ex': False, 'items': items}
    i = 4 + offset
    while i < len(data):
        typ, state, mid, flags = struct.unpack_from('<IIIH', data, i)
        i += 14
        text, i = _wstr(data, i)
        i = _align4(i)
        item = {'type': typ, 'state': state, 'id': mid, 'flags': flags, 'text': text}
        if flags & 0x01:  # has a submenu: a help id before it
            item['help'] = struct.unpack_from('<I', data, i)[0]
            i += 4
        items.append(item)
    return {'ex': True, 'offset': offset, 'head': data[4:4 + offset], 'items': items}


def write_menu(menu):
    b = bytearray()
    if not menu['ex']:
        b += struct.pack('<HH', 0, 0)
        for it in menu['items']:
            b += struct.pack('<H', it['flags'])
            if 'id' in it:
                b += struct.pack('<H', it['id'])
            b += it['text'].encode('utf-16-le') + b'\0\0'
        return bytes(b)
    b += struct.pack('<HH', 1, menu['offset']) + menu['head']
    for it in menu['items']:
        b += struct.pack('<IIIH', it['type'], it['state'], it['id'], it['flags'])
        b += it['text'].encode('utf-16-le') + b'\0\0'
        while len(b) % 4:
            b += b'\0'
        if 'help' in it:
            b += struct.pack('<I', it['help'])
    return bytes(b)


# --- dialogs ------------------------------------------------------------------

def _sz_or_ord(data, i):
    """A name that is either 0 (none), 0xFFFF + ordinal, or a string."""
    w = struct.unpack_from('<H', data, i)[0]
    if w == 0:
        return None, i + 2
    if w == 0xFFFF:
        return ('ord', struct.unpack_from('<H', data, i + 2)[0]), i + 4
    s, i = _wstr(data, i)
    return s, i


def _put_sz_or_ord(v):
    if v is None:
        return b'\0\0'
    if isinstance(v, tuple):
        return struct.pack('<HH', 0xFFFF, v[1])
    return v.encode('utf-16-le') + b'\0\0'


def read_dialog(data):
    ex = struct.unpack_from('<HH', data, 0) == (1, 0xFFFF)
    d = {'ex': ex}
    if ex:
        d['help'], d['exstyle'], d['style'], n, d['x'], d['y'], d['cx'], d['cy'] = \
            struct.unpack_from('<IIIHhhhh', data, 4)
        i = 26
    else:
        d['style'], d['exstyle'], n, d['x'], d['y'], d['cx'], d['cy'] = struct.unpack_from('<IIHhhhh', data, 0)
        i = 18
    d['menu'], i = _sz_or_ord(data, i)
    d['cls'], i = _sz_or_ord(data, i)
    d['text'], i = _wstr(data, i)
    if d['style'] & 0x40:  # DS_SETFONT, also part of DS_SHELLFONT
        if ex:
            d['size'], d['weight'], d['italic'], d['charset'] = struct.unpack_from('<HHBB', data, i)
            i += 6
        else:
            d['size'] = struct.unpack_from('<H', data, i)[0]
            i += 2
        d['font'], i = _wstr(data, i)
    d['controls'] = []
    for _ in range(n):
        i = _align4(i)
        c = {}
        if ex:
            c['help'], c['exstyle'], c['style'], c['x'], c['y'], c['cx'], c['cy'], c['id'] = \
                struct.unpack_from('<IIIhhhhI', data, i)
            i += 24
        else:
            c['style'], c['exstyle'], c['x'], c['y'], c['cx'], c['cy'], c['id'] = \
                struct.unpack_from('<IIhhhhH', data, i)
            i += 18
        c['cls'], i = _sz_or_ord(data, i)
        c['text'], i = _sz_or_ord(data, i)
        extra = struct.unpack_from('<H', data, i)[0]
        c['extra'] = data[i + 2:i + 2 + extra]
        i += 2 + extra
        d['controls'].append(c)
    return d


def write_dialog(d):
    b = bytearray()
    n = len(d['controls'])
    if d['ex']:
        b += struct.pack('<HHIIIHhhhh', 1, 0xFFFF, d['help'], d['exstyle'], d['style'], n,
                         d['x'], d['y'], d['cx'], d['cy'])
    else:
        b += struct.pack('<IIHhhhh', d['style'], d['exstyle'], n, d['x'], d['y'], d['cx'], d['cy'])
    b += _put_sz_or_ord(d['menu']) + _put_sz_or_ord(d['cls'])
    b += d['text'].encode('utf-16-le') + b'\0\0'
    if 'font' in d:
        if d['ex']:
            b += struct.pack('<HHBB', d['size'], d['weight'], d['italic'], d['charset'])
        else:
            b += struct.pack('<H', d['size'])
        b += d['font'].encode('utf-16-le') + b'\0\0'
    for c in d['controls']:
        while len(b) % 4:
            b += b'\0'
        if d['ex']:
            b += struct.pack('<IIIhhhhI', c['help'], c['exstyle'], c['style'], c['x'], c['y'], c['cx'], c['cy'], c['id'])
        else:
            b += struct.pack('<IIhhhhH', c['style'], c['exstyle'], c['x'], c['y'], c['cx'], c['cy'], c['id'])
        b += _put_sz_or_ord(c['cls']) + _put_sz_or_ord(c['text'])
        b += struct.pack('<H', len(c['extra'])) + c['extra']
    return bytes(b)


# --- texts of a resource ------------------------------------------------------

def texts(rtype, data):
    """The translatable texts of a resource, in order."""
    if rtype == RT_STRING:
        return read_strings(data)
    if rtype == RT_MENU:
        return [it['text'] for it in read_menu(data)['items']]
    d = read_dialog(data)
    return [d['text']] + [c['text'] if isinstance(c['text'], str) else None for c in d['controls']]


def with_texts(rtype, data, new):
    """The resource with its texts replaced by new (same order as texts())."""
    if rtype == RT_STRING:
        return write_strings(new)
    if rtype == RT_MENU:
        m = read_menu(data)
        for it, t in zip(m['items'], new):
            it['text'] = t
        return write_menu(m)
    d = read_dialog(data)
    d['text'] = new[0]
    for c, t in zip(d['controls'], new[1:]):
        if isinstance(c['text'], str):
            c['text'] = t
    return write_dialog(d)
