# Убирает рамку, оставшуюся от полосы «Send By» в окне переписки.
#
# Рамку рисует не элемент окна, а слой оформления: файл Skin/IcqPro.skn — это
# набор объектов со свойствами. Нужный объект называется RgnFrame, занимает
# 334x32 в нижней полосе между «Cancel» и «Send», и у него, как у всех, есть
# свойство m_bVisible.
#
# Формат свойства: имя в UTF-16 с завершающим нулём, затем тип (dword), длина
# (dword) и значение. Меняется один байт значения — 1 на 0.
import hashlib
import io
import struct
import sys

PATH_HINT = r'Skin\IcqPro.skn'
# Смещение самого значения; имя свойства лежит перед ним:
# len('m_bVisible')*2 + 2 (завершающий ноль) + 8 (тип и длина) = 30 байт.
VALUE_AT = 0x0417B4
NAME = 'm_bVisible'
NAME_BACK = len(NAME) * 2 + 2 + 8


def sha256(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest().upper()


def patch(path, dry_run=False):
    data = bytearray(io.open(path, 'rb').read())

    name_at = VALUE_AT - NAME_BACK
    got = bytes(data[name_at:name_at + len(NAME) * 2]).decode('utf-16-le', 'ignore')
    if got != NAME:
        print(f'  перед значением не {NAME}, а {got!r} — не трогаю')
        return -1
    kind, size = struct.unpack_from('<II', data, VALUE_AT - 8)
    if kind != 8 or size != 4:
        print(f'  неожиданное свойство: тип {kind}, длина {size} — не трогаю')
        return -1

    val = VALUE_AT
    cur = struct.unpack_from('<I', data, val)[0]
    if cur == 0:
        print('  уже скрыт')
        return 0
    print(f'  0x{val:X}: видимость {cur} -> 0')
    struct.pack_into('<I', data, val, 0)
    if not dry_run:
        io.open(path, 'wb').write(bytes(data))
    return 1


if __name__ == '__main__':
    src = sys.argv[1]
    print('было :', sha256(src))
    n = patch(src, dry_run='--dry-run' in sys.argv)
    if n > 0 and '--dry-run' not in sys.argv:
        print('стало:', sha256(src))
