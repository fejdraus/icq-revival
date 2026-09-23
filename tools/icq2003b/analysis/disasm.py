# Дизассемблирование функции по имени экспорта.
#   python disasm.py <модуль> <подстрока имени> [сколько байт]

import os
import sys

import capstone
import pefile

ICQ = r'C:\Program Files (x86)\ICQ'

module = sys.argv[1]
needle = sys.argv[2]
length = int(sys.argv[3]) if len(sys.argv) > 3 else 96

path = os.path.join(ICQ, module)
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase

targets = []
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name and needle.encode() in exp.name:
        targets.append((exp.address, exp.name.decode('latin1')))

if not targets:
    print('ничего не найдено')
    raise SystemExit

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

for rva, name in targets:
    data = pe.get_data(rva, length)
    offset = pe.get_offset_from_rva(rva)
    print(f'\n=== {name}')
    print(f'    RVA 0x{rva:x}, файловое смещение 0x{offset:x}')
    for ins in md.disasm(data, base + rva):
        raw = ' '.join(f'{b:02x}' for b in ins.bytes)
        print(f'  0x{ins.address:08x}  {raw:<22}  {ins.mnemonic} {ins.op_str}')
        if ins.mnemonic == 'ret':
            break
