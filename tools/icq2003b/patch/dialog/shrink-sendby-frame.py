# Подтягивает рамку нижней полосы к кнопке Send, убирая пустую середину.
#
# Рамку рисует слой оформления: в Skin/IcqPro.skn это объект RgnFrame,
# 334x32 от x=136 до x=470. Внутри неё стояли три галочки (x=212, 265, 320),
# кнопка Send (x=380) и указатель отправки (x=442). Галочки скрыты, и середина
# осталась пустой — поэтому левый край рамки двигаем вправо, к кнопке.
#
# Прятать рамку целиком нельзя: у объекта есть свойство «влиять на область
# окна», и без неё правый край окна срезает указатель отправки.
#
# Формат свойства: имя в UTF-16 с завершающим нулём, затем тип (dword), длина
# (dword) и значение. Прямоугольник — четыре int: слева, сверху, справа, снизу.
import hashlib
import io
import struct
import sys

PATH_HINT = r'Skin\IcqPro.skn'

VISIBLE_AT = 0x0417B4          # значение m_bVisible объекта RgnFrame
RECT_AT = 0x041782             # значение m_rcVisual того же объекта
OFFSET_AT = 0x041750           # значение m_Offset того же объекта
WAS_RECT = (136, 292, 470, 324)
NEW_LEFT = 368                 # кнопка Send начинается на 380; можно задать
                               # вторым доводом командной строки

# Положение считается по якорям и смещениям, а не по прямоугольнику: у рамки
# m_Anchors = (100,100,100,100), то есть все края отсчитываются от правого и
# нижнего края родителя. Правый край родителя — 477, поэтому левому краю 368
# соответствует смещение 368 - 477 = -109. Прямоугольник правим тоже, чтобы
# файл оставался сам себе непротиворечив.
PARENT_RIGHT = 477
WAS_OFFSET_LEFT = -341
NEW_OFFSET_LEFT = NEW_LEFT - PARENT_RIGHT


def sha256(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest().upper()


def patch(path, dry_run=False, new_left=None):
    data = bytearray(io.open(path, 'rb').read())

    left = NEW_LEFT if new_left is None else new_left
    offset_left = left - PARENT_RIGHT

    rect = struct.unpack_from('<4i', data, RECT_AT)
    if rect[1:] != WAS_RECT[1:]:
        print(f'  неожиданный прямоугольник {rect} — не трогаю')
        return -1

    changed = 0
    visible = struct.unpack_from('<I', data, VISIBLE_AT)[0]
    if visible != 1:
        print(f'  видимость {visible} -> 1')
        struct.pack_into('<I', data, VISIBLE_AT, 1)
        changed += 1

    if rect[0] != left:
        print(f'  прямоугольник: левый край {rect[0]} -> {left}')
        struct.pack_into('<i', data, RECT_AT, left)
        changed += 1

    off_left = struct.unpack_from('<i', data, OFFSET_AT)[0]
    if off_left != offset_left:
        print(f'  смещение: левый край {off_left} -> {offset_left}')
        struct.pack_into('<i', data, OFFSET_AT, offset_left)
        changed += 1

    if changed and not dry_run:
        io.open(path, 'wb').write(bytes(data))
    if not changed:
        print('  уже так')
    return changed


if __name__ == '__main__':
    src = sys.argv[1]
    # Скос — часть фоновой картинки и растягивается по ширине рамки: чем она
    # уже, тем короче скос. Поэтому левый край подбирается на глаз.
    for arg in sys.argv[2:]:
        if arg.lstrip('-').isdigit():
            NEW_LEFT = int(arg)
            NEW_OFFSET_LEFT = NEW_LEFT - PARENT_RIGHT
            WAS_RECT = (WAS_RECT[0], WAS_RECT[1], WAS_RECT[2], WAS_RECT[3])
    print('было :', sha256(src))
    n = patch(src, dry_run='--dry-run' in sys.argv, new_left=NEW_LEFT)
    if n > 0 and '--dry-run' not in sys.argv:
        print('стало:', sha256(src))
