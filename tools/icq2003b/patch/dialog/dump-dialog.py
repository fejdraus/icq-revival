# Разбор шаблонов диалогов в ICQMessagePlugin.dll: какие элементы есть в окне
# сообщения и по каким смещениям лежат их стили.
import struct
import sys

import pefile

DLL = r'C:\Program Files (x86)\ICQ\ICQMessagePlugin.dll'
WANT = {9506, 9509}

CLASSES = {0x80: 'BUTTON', 0x81: 'EDIT', 0x82: 'STATIC', 0x83: 'LISTBOX',
           0x84: 'SCROLLBAR', 0x85: 'COMBOBOX'}

BS_TYPE = {0: 'PUSHBUTTON', 1: 'DEFPUSHBUTTON', 2: 'CHECKBOX', 3: 'AUTOCHECKBOX',
           4: 'RADIOBUTTON', 5: '3STATE', 6: 'AUTO3STATE', 7: 'GROUPBOX',
           8: 'USERBUTTON', 9: 'AUTORADIOBUTTON', 0x0A: 'PUSHBOX', 0x0B: 'OWNERDRAW'}

WS_VISIBLE = 0x10000000
WS_DISABLED = 0x08000000


def read_sz_or_ord(buf, pos):
    kind = struct.unpack_from('<H', buf, pos)[0]
    if kind == 0x0000:
        return None, pos + 2
    if kind == 0xFFFF:
        return struct.unpack_from('<H', buf, pos + 2)[0], pos + 4
    out = []
    while True:
        ch = struct.unpack_from('<H', buf, pos)[0]
        pos += 2
        if ch == 0:
            break
        out.append(chr(ch))
    return ''.join(out), pos


def align4(pos):
    return (pos + 3) & ~3


def dump(res_id, data, file_offset):
    ver, sig = struct.unpack_from('<HH', data, 0)
    assert sig == 0xFFFF, 'не расширенный шаблон'
    style = struct.unpack_from('<I', data, 12)[0]
    count = struct.unpack_from('<H', data, 16)[0]
    pos = 26
    for _ in range(3):  # menu, class, title
        _, pos = read_sz_or_ord(data, pos)
    if style & 0x40:  # DS_SETFONT
        pos += 6
        _, pos = read_sz_or_ord(data, pos)

    print(f'--- DIALOG {res_id}: элементов {count}')
    for i in range(count):
        pos = align4(pos)
        item_at = pos
        help_id, ex_style, item_style = struct.unpack_from('<III', data, pos)
        x, y, cx, cy = struct.unpack_from('<hhhh', data, pos + 12)
        item_id = struct.unpack_from('<I', data, pos + 20)[0]
        pos += 24
        cls, pos = read_sz_or_ord(data, pos)
        title, pos = read_sz_or_ord(data, pos)
        extra = struct.unpack_from('<H', data, pos)[0]
        pos += 2 + extra

        cls_name = CLASSES.get(cls, cls)
        kind = ''
        if cls == 0x80:
            kind = BS_TYPE.get(item_style & 0x0F, '')
        style_at = file_offset + item_at + 8
        print(f'  id={item_id:<6} {str(cls_name):<9} {kind:<14} '
              f'x={x:<4} y={y:<4} w={cx:<4} h={cy:<3} '
              f'vis={"да" if item_style & WS_VISIBLE else "нет":<3} '
              f'стиль@0x{style_at:X} = 0x{item_style:08X}  {title!r}')


pe = pefile.PE(DLL, fast_load=True)
pe.parse_data_directories([pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if e.struct.Id != 5:
        continue
    for res in e.directory.entries:
        if res.struct.Id not in WANT:
            continue
        for lang in res.directory.entries:
            rva = lang.data.struct.OffsetToData
            size = lang.data.struct.Size
            data = pe.get_memory_mapped_image()[rva:rva + size]
            dump(res.struct.Id, data, pe.get_offset_from_rva(rva))
