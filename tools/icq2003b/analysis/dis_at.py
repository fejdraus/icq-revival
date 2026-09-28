import sys, capstone, pefile, os
ICQ = r'C:\Program Files (x86)\ICQ'
mod, off, ln = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3])
pe = pefile.PE(os.path.join(ICQ, mod))
base = pe.OPTIONAL_HEADER.ImageBase
sec = next(s for s in pe.sections if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData)
va = base + sec.VirtualAddress + (off - sec.PointerToRawData)
data = pe.__data__[off:off+ln]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for ins in md.disasm(bytes(data), va):
    fo = off + (ins.address - va)
    raw = ' '.join(f'{b:02x}' for b in ins.bytes)
    print(f'  file 0x{fo:05x}  0x{ins.address:08x}  {raw:<20}  {ins.mnemonic} {ins.op_str}')
