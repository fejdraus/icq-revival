# Находит в модуле вызовы импортированной функции по имени и печатает код вокруг.
#   python impxref.py <модуль> <подстрока имени импорта>

import os
import sys

import capstone
import pefile

ICQ = r'C:\Program Files (x86)\ICQ'
module, needle = sys.argv[1], sys.argv[2]

pe = pefile.PE(os.path.join(ICQ, module))
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__

targets = []
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode('latin1')
    for imp in entry.imports:
        if imp.name and needle.encode() in imp.name:
            targets.append((imp.address, dll, imp.name.decode('latin1')))

if not targets:
    print('импорт не найден')
    raise SystemExit

text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

for iat_va, dll, name in targets:
    print(f'\n=== {name}  из {dll}, IAT 0x{iat_va:x} ===')
    # call dword ptr [iat_va]  ->  FF 15 <адрес>
    pattern = b'\xff\x15' + iat_va.to_bytes(4, 'little')
    pos = text.PointerToRawData
    end = pos + text.SizeOfRawData
    count = 0
    while True:
        pos = data.find(pattern, pos, end)
        if pos < 0:
            break
        count += 1
        start = max(text.PointerToRawData, pos - 70)
        chunk = data[start:pos + 40]
        cva = base + text.VirtualAddress + (start - text.PointerToRawData)
        call_va = base + text.VirtualAddress + (pos - text.PointerToRawData)
        print(f'\n  --- вызов #{count}, файл 0x{pos:x} ---')
        for ins in md.disasm(bytes(chunk), cva):
            mark = '  <<<' if ins.address == call_va else ''
            fo = start + (ins.address - cva)
            print(f'    файл 0x{fo:05x}  0x{ins.address:08x}  {ins.mnemonic} {ins.op_str}{mark}')
        pos += 1
    if count == 0:
        print('  прямых вызовов не найдено')
