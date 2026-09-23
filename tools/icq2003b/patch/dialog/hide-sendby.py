# Прячет полосу «Send By:» в окне сообщения ICQ Pro 2003b.
#
# Прятать её через шаблон диалога бесполезно: окно перекрывает шаблон. В
# ICQMessagePlugin.dll есть подпрограмма раскладки, которая сама вызывает
# ShowWindow для группы и трёх галочек, а показать или спрятать — вычисляет:
#
#   neg eax ; sbb eax, eax ; and al, 0xFB ; add eax, 5   -> 5 (SW_SHOW) или 0
#
# Значит, достаточно занулить результат — тогда все четыре элемента прячет сам
# клиент своим же вызовом. Элементы остаются в диалоге, галочка ICQ остаётся
# отмеченной, код читает её как раньше, и кнопка Send работает.
#
# Два места: eax — для группы (id 0x3EF), edi — для галочек ICQ, SMS и Email
# (0x3F3, 0x3F2, 0x3F1), которые проталкиваются следом тем же значением.
#
# Одного этого мало: перед блоком группы стоит ветвление, которое его иногда
# перескакивает, и тогда группу никто не прячет. Поэтому вдобавок снимается
# WS_VISIBLE в самих шаблонах — начальное состояние на случай, когда код до
# элемента не доходит.
import hashlib
import io
import sys

SPOTS = [
    # Код раскладки: значение для ShowWindow всегда ноль.
    (0x7B63, bytes([0x83, 0xC0, 0x05]), bytes([0x31, 0xC0, 0x90]), 'код: группа Send By'),
    (0x7B84, bytes([0x83, 0xC7, 0x05]), bytes([0x31, 0xFF, 0x90]), 'код: галочки ICQ, SMS, Email'),
    # Шаблоны диалогов: снятый бит WS_VISIBLE (старший байт стиля 0x50 -> 0x40).
    # Нужен потому, что до группы код доходит не всегда: перед её блоком стоит
    # ветвление, которое его перескакивает, — и тогда элемент остаётся таким,
    # каким его объявил шаблон.
    (0x325A7, bytes([0x50]), bytes([0x40]), 'шаблон 9506: галочка ICQ'),
    (0x325CF, bytes([0x50]), bytes([0x40]), 'шаблон 9506: галочка SMS'),
    (0x325F7, bytes([0x50]), bytes([0x40]), 'шаблон 9506: галочка Email'),
    (0x32623, bytes([0x50]), bytes([0x40]), 'шаблон 9506: группа Send By'),
    (0x32BCF, bytes([0x50]), bytes([0x40]), 'шаблон 9509: галочка ICQ'),
    (0x32BF7, bytes([0x50]), bytes([0x40]), 'шаблон 9509: галочка SMS'),
    (0x32C1F, bytes([0x50]), bytes([0x40]), 'шаблон 9509: галочка Email'),
]


def sha256(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest().upper()


def patch(path, dry_run=False):
    data = bytearray(io.open(path, 'rb').read())
    changed = 0
    for off, was, now, what in SPOTS:
        cur = bytes(data[off:off + len(was)])
        if cur == now:
            print(f'  0x{off:X} {what}: уже наложено')
            continue
        if cur != was:
            print(f'  0x{off:X} {what}: ЧУЖИЕ БАЙТЫ {cur.hex(" ")} — не трогаю')
            return -1
        print(f'  0x{off:X} {what}: {was.hex(" ")} -> {now.hex(" ")}')
        data[off:off + len(now)] = now
        changed += 1
    if not dry_run and changed:
        io.open(path, 'wb').write(bytes(data))
    return changed


if __name__ == '__main__':
    src = sys.argv[1]
    print('было :', sha256(src))
    n = patch(src, dry_run='--dry-run' in sys.argv)
    print('изменено мест:', n)
    if n > 0 and '--dry-run' not in sys.argv:
        print('стало:', sha256(src))
