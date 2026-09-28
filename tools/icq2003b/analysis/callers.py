import sys, os, capstone, pefile
ICQ = r'C:\Program Files (x86)\ICQ'
mod, target_rva = sys.argv[1], int(sys.argv[2], 16)
pe = pefile.PE(os.path.join(ICQ, mod))
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__
text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
start, size = text.PointerToRawData, text.SizeOfRawData
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
found = 0
for i in range(start, start + size - 5):
    if data[i] != 0xE8:
        continue
    rel = int.from_bytes(data[i+1:i+5], 'little', signed=True)
    src_rva = text.VirtualAddress + (i - start)
    dst_rva = src_rva + 5 + rel
    if dst_rva == target_rva:
        found += 1
        print(f'\n--- call from file offset 0x{i:x} (RVA 0x{src_rva:x}) ---')
        chunk = data[max(start, i-90):i+40]
        cva = base + text.VirtualAddress + (max(start, i-90) - start)
        for ins in md.disasm(bytes(chunk), cva):
            mark = '  <<< call' if ins.address == base + src_rva else ''
            raw = ' '.join(f'{b:02x}' for b in ins.bytes)
            print(f'  file 0x{start + (ins.address - base - text.VirtualAddress):05x}  {raw:<18}  {ins.mnemonic} {ins.op_str}{mark}')
print(f'\ntotal calls: {found}')
