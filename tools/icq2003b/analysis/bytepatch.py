# Replaces bytes at one spot in a file, after checking what is there now.
#   python bytepatch.py <file> <offset hex> <expected bytes hex> <new bytes hex>
# Before the first change a copy, <file>.antibanner-backup, is made next to it.

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
    print(f'copy made: {os.path.basename(backup)}')

with open(path, 'rb') as f:
    data = bytearray(f.read())

current = bytes(data[offset:offset + len(expect)])
if current != expect:
    print(f'found {current.hex(" ")}, expected {expect.hex(" ")} - changing nothing')
    raise SystemExit(1)

data[offset:offset + len(new)] = new
with open(path, 'wb') as f:
    f.write(data)

print(f'0x{offset:x}: {expect.hex(" ")} -> {new.hex(" ")}')
