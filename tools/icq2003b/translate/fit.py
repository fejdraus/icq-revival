"""Whether the texts of a dialog fit their controls, and room to make them fit.

Widths are measured with Windows itself (GDI), in the font the client's
skin draws dialogs with, and compared with the size of each control in
dialog units, which the dialog's own font turns into pixels. Only on
Windows, as the client.
"""

import ctypes
import re
from ctypes import wintypes

# The skin draws Latin text in the dialog font, but Cyrillic comes out in a
# wider face that Windows substitutes. Measured against the client itself:
# bold Tahoma times 0.9 splits the texts that were cut from those that were
# not, on the windows looked at. English is not measured - it fitted.
MEASURE_FONT = ('Tahoma', 8, True)
MEASURE_SCALE = 0.9
DIALOG_FONT = ('MS Sans Serif', 8, False)

_gdi = ctypes.windll.gdi32
_user = ctypes.windll.user32
_gdi.CreateFontW.restype = wintypes.HANDLE
_gdi.SelectObject.restype = wintypes.HANDLE
_gdi.SelectObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
_gdi.GetTextExtentPoint32W.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p]
_gdi.GetTextMetricsW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
_user.GetDC.restype = wintypes.HANDLE
_user.GetDC.argtypes = [wintypes.HANDLE]
_hdc = _user.GetDC(None)
_fonts = {}


class _Size(ctypes.Structure):
    _fields_ = [('cx', ctypes.c_long), ('cy', ctypes.c_long)]


class _Metric(ctypes.Structure):
    _fields_ = [(n, ctypes.c_long) for n in ('height', 'ascent', 'descent', 'internal', 'external', 'ave', 'max',
                                             'weight', 'overhang', 'dax', 'day')] + \
               [(n, ctypes.c_wchar) for n in ('first', 'last', 'default', 'brk')] + \
               [(n, ctypes.c_byte) for n in ('italic', 'under', 'struck', 'pitch', 'charset')]


def _font(spec):
    if spec not in _fonts:
        name, pt, bold = spec
        _fonts[spec] = _gdi.CreateFontW(-round(pt * 96 / 72), 0, 0, 0, 700 if bold else 400, 0, 0, 0,
                                        1, 0, 0, 5, 0, name)  # DEFAULT_CHARSET, CLEARTYPE_QUALITY
    _gdi.SelectObject(_hdc, _fonts[spec])


def width(text, spec=MEASURE_FONT):
    _font(spec)
    s = _Size()
    _gdi.GetTextExtentPoint32W(_hdc, text, len(text), ctypes.byref(s))
    return s.cx * MEASURE_SCALE if spec == MEASURE_FONT else s.cx


def line_height(spec=MEASURE_FONT):
    _font(spec)
    m = _Metric()
    _gdi.GetTextMetricsW(_hdc, ctypes.byref(m))
    return m.height


def _base_units():
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    return (width(letters, DIALOG_FONT) / 52.0), line_height(DIALOG_FONT)


BASE_X, BASE_Y = _base_units()


def du_x(px):
    return px * 4.0 / BASE_X


def px_x(du):
    return du * BASE_X / 4.0


def px_y(du):
    return du * BASE_Y / 8.0


def visible(text):
    """The text as drawn: access key marks gone."""
    return re.sub(r'&(.)', r'\1', text.replace('&&', '\0')).replace('\0', '&').split('\t')[0]


def kind(c):
    """What a control is, for measuring: button, check, group, static, or None."""
    cls = c['cls']
    style = c['style']
    if cls in (('ord', 0x80),) or (isinstance(cls, str) and cls.lower() == 'button'):
        b = style & 0xF
        if b in (2, 3, 4, 5, 6, 9):
            return 'check'
        if b == 7:
            return 'group'
        return 'button'
    if cls in (('ord', 0x82),) or (isinstance(cls, str) and cls.lower() == 'static'):
        s = style & 0x1F
        if s in (0, 1, 2, 0xB, 0xC):     # left, center, right, simple, no word wrap
            return 'static'
    return None


def wraps(c):
    k = kind(c)
    if k == 'static':
        return (c['style'] & 0x1F) in (0, 1, 2)
    if k in ('button', 'check'):
        return bool(c['style'] & 0x2000)   # BS_MULTILINE
    return False


def need(c, text):
    """Pixels the text needs on one line, with the control's own furniture."""
    w = width(visible(text))
    k = kind(c)
    if k == 'check':
        return w + 18
    if k == 'button':
        return w + 10
    if k == 'group':
        return w + 18
    return w + 2


def fits(c, text):
    """Whether text fits control c as it is sized."""
    k = kind(c)
    if not k or not text:
        return True
    have = px_x(c['cx'])
    if not wraps(c):
        return need(c, text) <= have
    lines = max(1, int(px_y(c['cy']) // line_height()))
    return _wrapped_lines(visible(text), have - (need(c, '') - 2)) <= lines


def _wrapped_lines(text, room):
    n = 0
    for para in text.split('\n'):
        n += 1
        line = ''
        for word in para.split(' '):
            trial = (line + ' ' + word) if line else word
            if width(trial) <= room:
                line = trial
            else:
                if line:
                    n += 1
                line = word
    return n


def room_right(d, i):
    """Dialog units control i may grow to the right without meeting another
    control or leaving the group box or dialog it sits in."""
    c = d['controls'][i]
    right = c['x'] + c['cx']
    top, bottom = c['y'], c['y'] + c['cy']
    limit = d['cx'] - 4
    for j, o in enumerate(d['controls']):
        if j == i:
            continue
        o_top, o_bottom = o['y'], o['y'] + o['cy']
        if kind(o) == 'group' and o['x'] <= c['x'] and o['x'] + o['cx'] >= right and o_top <= top and o_bottom >= bottom:
            limit = min(limit, o['x'] + o['cx'] - 4)        # the box it sits in
            continue
        if o_bottom <= top or o_top >= bottom:
            continue
        if o['x'] >= right - 1:
            limit = min(limit, o['x'] - 2)
    return max(0, limit - right)


def fit_dialog(d, texts):
    """Widens controls of d whose new texts do not fit, where there is room.
    texts: the dialog's texts in texts() order. Returns the ones that still
    do not fit, as (control index, text, pixels there, pixels needed)."""
    left = []
    for i, c in enumerate(d['controls']):
        t = texts[i + 1]
        if not isinstance(c['text'], str) or not t or fits(c, t):
            continue
        if not wraps(c):
            grow = int(du_x(need(c, t) - px_x(c['cx']))) + 1
            if grow <= room_right(d, i):
                c['cx'] += grow
                continue
            c['cx'] += room_right(d, i)
        left.append((i, t, int(px_x(c['cx'])), need(c, t)))
    return left
