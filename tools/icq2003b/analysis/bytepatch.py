# Точечная замена байтов в файле с проверкой того, что лежит на месте.
#   python bytepatch.py <файл> <смещение hex> <ожидаемые байты hex> <новые байты hex>
# Перед первой правкой рядом создаётся копия <файл>.antibanner-backup.

import os
import shutil
import sys

path, offset_hex, expect_hex, new_hex = sys.argv[1:5]
offset = int(offset_hex, 16)
expect = bytes.fromhex(expect_hex.replace(' ', ''))
new = bytes.fromhex(new_hex.replace(' ', ''))

backup = path + '.antibanner-backup'
if not os.path.exists(backup):
    shutil.copy2(path, backup)
    print(f'создана копия: {os.path.basename(backup)}')

with open(path, 'rb') as f:
    data = bytearray(f.read())

current = bytes(data[offset:offset + len(expect)])
if current != expect:
    print(f'на месте {current.hex(" ")}, ожидалось {expect.hex(" ")} — ничего не меняю')
    raise SystemExit(1)

data[offset:offset + len(new)] = new
with open(path, 'wb') as f:
    f.write(data)

print(f'0x{offset:x}: {expect.hex(" ")} -> {new.hex(" ")}')
