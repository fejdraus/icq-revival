# Finds where the code refers to a string at a known file offset,
# and disassembles the code around each reference.
#   python xref.py <module> <string offset in file, hex> [bytes before] [bytes after]

import os
import sys

import capstone
import pefile

ICQ = r'C:\Program Files (x86)\ICQ'

module = sys.argv[1]
str_off = int(sys.argv[2], 16)
before = int(sys.argv[3]) if len(sys.argv) > 3 else 40
after = int(sys.argv[4]) if len(sys.argv) > 4 else 60

path = os.path.join(ICQ, module)
pe = pefile.PE(path)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__

rva = None
for s in pe.sections:
    if s.PointerToRawData <= str_off < s.PointerToRawData + s.SizeOfRawData:
        rva = s.VirtualAddress + (str_off - s.PointerToRawData)
        break
if rva is None:
    print('offset is outside the sections')
    raise SystemExit

va = base + rva
text = data[str_off:str_off + 40].split(b'\0')[0].decode('latin1', 'replace')
print(f'string "{text}" - RVA 0x{rva:x}, VA 0x{va:x}')

needle = va.to_bytes(4, 'little')
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

found = 0
pos = 0
while True:
    pos = data.find(needle, pos)
    if pos < 0:
        break
    start = pos
    pos += 1
    # only push imm32 (68) or mov ..., imm32 (b8..bf, c7) are of interest
    op = data[start - 1]
    if op not in (0x68, 0xb8, 0xb9, 0xba, 0xbb, 0xbe, 0xbf):
        continue
    found += 1
    chunk_start = max(0, start - 1 - before)
    chunk = data[chunk_start:start - 1 + after]
    # virtual address of the start of the chunk
    sec = next(s for s in pe.sections
               if s.PointerToRawData <= chunk_start < s.PointerToRawData + s.SizeOfRawData)
    chunk_va = base + sec.VirtualAddress + (chunk_start - sec.PointerToRawData)
    print(f'\n--- reference #{found}: file offset 0x{start - 1:x} ---')
    for ins in md.disasm(chunk, chunk_va):
        mark = '  <<<' if ins.address == base + sec.VirtualAddress + (start - 1 - sec.PointerToRawData) else ''
        raw = ' '.join(f'{b:02x}' for b in ins.bytes)
        print(f'  0x{ins.address:08x}  {raw:<20}  {ins.mnemonic} {ins.op_str}{mark}')

if not found:
    print('no direct references found')
