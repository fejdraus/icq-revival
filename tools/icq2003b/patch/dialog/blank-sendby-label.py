# Затирает надпись «Send By:» в окне переписки.
#
# Саму надпись рисует слой оформления (скин), а не элемент окна: опрос открытого
# окна показал, что элемента с таким текстом там нет вовсе, зато строка лежит в
# таблице строк Icq.exe рядом с «Skin file was not found», «To: ICQ» и «SMS:».
# Поэтому прячется она не стилем и не ShowWindow, а только заменой самой строки.
#
# Заменяем на пробелы той же длины: таблица строк хранит длину отдельно, сдвигать
# ничего нельзя — тот же приём, что с зашитыми в код адресами.
import hashlib
import io
import sys

# Строка 8727 (0x2217), 8 символов UTF-16.
OFFSET = 0x1C489C
WAS = 'Send By:'
NOW = ' ' * len(WAS)


def sha256(path):
    return hashlib.sha256(io.open(path, 'rb').read()).hexdigest().upper()


def patch(path, dry_run=False):
    data = bytearray(io.open(path, 'rb').read())
    size = len(WAS) * 2
    cur = bytes(data[OFFSET:OFFSET + size]).decode('utf-16-le')
    if cur == NOW:
        print('  уже затёрто')
        return 0
    if cur != WAS:
        print(f'  ЧУЖОЙ ТЕКСТ {cur!r} — не трогаю')
        return -1
    print(f'  0x{OFFSET:X}: {cur!r} -> {NOW!r}')
    data[OFFSET:OFFSET + size] = NOW.encode('utf-16-le')
    if not dry_run:
        io.open(path, 'wb').write(bytes(data))
    return 1


if __name__ == '__main__':
    src = sys.argv[1]
    print('было :', sha256(src))
    n = patch(src, dry_run='--dry-run' in sys.argv)
    if n > 0 and '--dry-run' not in sys.argv:
        print('стало:', sha256(src))
