# Parses the geometry of the ICQ 2003b skin.
#
# The format is simple: one property after another, each of the form
#   [name in UTF-16][00 00][uint32 total length][uint32 data length][data]
# Interface elements have m_rcVisual (a rectangle of four int32 values)
# and m_bstrName (the name). The name comes AFTER the rectangle, so we collect pairs
# "last rectangle read + nearest name".

import re
import struct
import sys

PATH = r'C:\Program Files (x86)\ICQ\Skin\IcqPro.skn'
data = open(PATH, 'rb').read()

# Every occurrence of a property name in UTF-16.
prop = re.compile(rb'(?:m_[A-Za-z]{2,24}\x00)'.replace(b'm_', b'm\x00_\x00'))

# Simpler: find UTF-16 strings like m_xxx by hand.
def utf16_at(off, limit=64):
    out = []
    i = off
    while i + 1 < len(data) and len(out) < limit:
        ch = data[i] | (data[i + 1] << 8)
        if ch == 0:
            break
        if ch < 0x20 or ch > 0x7e:
            return None, i
        out.append(chr(ch))
        i += 2
    return ''.join(out), i + 2


elements = []
pending_rect = None
pending_visible = None

i = 0
while i < len(data) - 8:
    if data[i] == ord('m') and data[i + 1] == 0 and data[i + 2] == ord('_') and data[i + 3] == 0:
        name, after = utf16_at(i)
        if name and name.startswith('m_'):
            total = struct.unpack_from('<I', data, after)[0] if after + 8 <= len(data) else 0
            dlen = struct.unpack_from('<I', data, after + 4)[0] if after + 8 <= len(data) else 0
            body = after + 8
            if name == 'm_rcVisual' and dlen >= 16:
                # data: left, top, right, bottom
                vals = struct.unpack_from('<4i', data, body)
                pending_rect = (body, vals)
            elif name == 'm_bVisible' and dlen >= 4:
                pending_visible = (body, data[body])
            elif name == 'm_bstrName':
                value, _ = utf16_at(body)
                if value and pending_rect:
                    off, vals = pending_rect
                    elements.append({
                        'name': value,
                        'rect_off': off,
                        'rect': vals,
                        'vis_off': pending_visible[0] if pending_visible else None,
                        'vis': pending_visible[1] if pending_visible else None,
                    })
                pending_rect = None
                pending_visible = None
            i = body + max(dlen, 1)
            continue
    i += 1

want = sys.argv[1] if len(sys.argv) > 1 else None
print(f'elements with geometry: {len(elements)}\n')
for e in elements:
    if want and want.lower() not in e['name'].lower():
        continue
    l, t, r, b = e['rect']
    print(f"  {e['name']:<22} rc=({l},{t})-({r},{b})  {r - l}x{b - t}"
          f"  rc offset 0x{e['rect_off']:x}"
          + (f"  visible={e['vis']} @0x{e['vis_off']:x}" if e['vis_off'] else ''))
