# Ищем в экспортах модулей ICQ функции, связанные с баннером и поиском.
# Эти DLL экспортируют декорированные имена C++, поэтому по именам можно
# сразу выйти на адреса нужных функций и дизассемблировать их.

import os
import re
import sys

import pefile

ICQ = r'C:\Program Files (x86)\ICQ'
PATTERN = re.compile(sys.argv[1] if len(sys.argv) > 1 else 'Banner', re.I)


def demangle_hint(name):
    """Грубо вытаскиваем имя функции и класса из декорированного имени MSVC."""
    m = re.match(r'\?(\w+)@(\w+)@', name)
    if m:
        return f'{m.group(2)}::{m.group(1)}'
    return name


for entry in sorted(os.listdir(ICQ)):
    if not entry.lower().endswith(('.dll', '.exe', '.ocx')):
        continue
    path = os.path.join(ICQ, entry)
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']]
        )
    except Exception:
        continue
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        pe.close()
        continue

    hits = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        name = exp.name.decode('latin1')
        if PATTERN.search(name):
            hits.append((exp.address, name))
    if hits:
        print(f'\n=== {entry} — совпадений {len(hits)} ===')
        for rva, name in hits[:40]:
            print(f'  RVA 0x{rva:06x}  {demangle_hint(name)}')
            print(f'             {name}')
    pe.close()
