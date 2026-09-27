# Собирает наши файлы для PluginUpdater в том виде, в каком он их качает.
#
# Сервер (deploy/oscar-legacy-web, /miranda/stable/x32 и /x64) отдаёт список
# обновлений Miranda NG со своими строками для наших файлов и сами пакеты.
# Строка списка — "<путь> <хэш> <crc32 пакета>", пакет — zip с тем же путём
# от папки Miranda внутри. Хэш — не MD5 файла, а CalculateModuleHash из
# PluginUpdater (checksum.cpp): MD5 данных секций PE после обнуления меток
# времени отладки, экспорта и ресурсов и приведения релокаций к базе 0; не-PE
# (переводы) — MD5 всего файла. Поэтому хэши считает этот скрипт, а сервер
# берёт готовые из manifest.json.
#
#   python make-update-packages.py <выходной-каталог> [--engine32 dll] [--engine64 dll]
#   python make-update-packages.py --hash <файл...>      только хэши, для сверки
#
# Результат — <каталог>/x32 и <каталог>/x64: Plugins/IcqOscarJ.zip,
# Plugins/IcqRevivalFlash.zip, Libs/FlashPlayerControl.zip, Languages/*.zip и
# manifest.json. Этот каталог и кладётся на сервер (см. README).
import argparse
import hashlib
import io
import json
import os
import struct
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..', '..'))
ENGINE = os.path.join(ROOT, 'tools', 'icq65', 'flashplayer', 'target')

# Строки, которые сервер дописывает в основной langpack_russian.txt, если их там
# нет: без них ядро не прочтёт переводы плагинов, а обновление langpack с
# сервера Miranda NG их стирает. drop — строки старых имён, которые сервер
# убирает (до 1.1 Flash-плагин назывался FlashAvatars.dll).
LANGPACK_INCLUDES = {
    'Languages\\langpack_russian.txt': {
        'add': [
            '#include langpack_russian_icq.txt',
            '#include langpack_russian_icqrevivalflash.txt',
        ],
        'drop': ['#include langpack_russian_flashavatars.txt'],
    },
}


def module_hash(path):
    """CalculateModuleHash из PluginUpdater 0.96.7, байт в байт."""
    with open(path, 'rb') as f:
        b = bytearray(f.read())
    size = len(b)
    if size < 64 + 248:  # IMAGE_DOS_HEADER + IMAGE_NT_HEADERS
        raise ValueError('not a PE and too short: ' + path)
    md5 = hashlib.md5()

    def u16(o):
        return struct.unpack_from('<H', b, o)[0]

    def u32(o):
        return struct.unpack_from('<I', b, o)[0]

    if u16(0) != 0x5A4D:
        md5.update(b)
        return md5.hexdigest()
    nt = u32(0x3C)
    if nt + 248 >= size:
        raise ValueError('corrupted PE: ' + path)
    if u32(nt) != 0x00004550:
        md5.update(b)
        return md5.hexdigest()

    machine = u16(nt + 4)
    sections = u16(nt + 6)
    opt_size = u16(nt + 20)
    magic = u16(nt + 24)
    if not sections:
        raise ValueError('no sections: ' + path)
    # как в исходнике: e_lfanew + SizeOfOptionalHeader + sizeof(IMAGE_NT_HEADERS)
    # - sizeof(IMAGE_OPTIONAL_HEADER); последние два — от той разрядности, под
    # которую собран сам PluginUpdater, но разность у обеих одна: 24
    offset = nt + opt_size + 24
    if machine == 0x14C and opt_size >= 224 and magic == 0x10B:
        dd = nt + 24 + 96
        base = u32(nt + 24 + 28)
    elif machine == 0x8664 and opt_size >= 240 and magic == 0x20B:
        dd = nt + 24 + 112
        base = struct.unpack_from('<Q', b, nt + 24 + 24)[0]
    else:
        raise ValueError('unsupported PE: ' + path)

    def ddir(i):
        return u32(dd + i * 8), u32(dd + i * 8 + 4)

    exp_addr, exp_size = ddir(0)
    res_addr, res_size = ddir(2)
    reloc_addr, reloc_size = ddir(5)
    dbg_addr, dbg_size = ddir(6)

    def section(i):
        o = offset + i * 40
        if o + 40 > size:
            raise ValueError('corrupted PE: ' + path)
        va, raw_size, raw_ptr = u32(o + 12), u32(o + 16), u32(o + 20)
        if raw_ptr + raw_size > size:
            raise ValueError('corrupted PE: ' + path)
        return va, raw_size, raw_ptr

    def contains(sec, addr, length=0):
        va, raw_size, _ = sec
        return addr >= va and addr + length <= va + raw_size

    dbg = None      # смещение первой записи отладки в файле
    reloc = None
    for i in range(sections):
        sec = section(i)
        va, _, raw_ptr = sec
        if dbg_size >= 28 and contains(sec, dbg_addr, dbg_size):
            dbg = dbg_addr - va + raw_ptr
            for k in range(dbg_size // 28):
                struct.pack_into('<I', b, dbg + k * 28 + 4, 0)
        if exp_size >= 40 and contains(sec, exp_addr, exp_size):
            struct.pack_into('<I', b, exp_addr - va + raw_ptr + 4, 0)
        if reloc_size >= 8 and contains(sec, reloc_addr, reloc_size):
            reloc = reloc_addr - va + raw_ptr

    def patch_res_dir(o, res_base):
        struct.pack_into('<I', b, o + 4, 0)
        named, ids = u16(o + 12), u16(o + 14)
        e = o + 16
        for _ in range(named + ids):
            off = u32(e + 4)
            if off & 0x80000000:
                patch_res_dir(res_base + (off & 0x7FFFFFFF), res_base)
            e += 8

    for i in range(sections):
        sec = section(i)
        va, raw_size, raw_ptr = sec
        if dbg is not None:
            d_size, d_ptr = u32(dbg + 16), u32(dbg + 24)
            if d_size > 0 and d_ptr >= raw_ptr and d_ptr + d_size <= raw_ptr + raw_size:
                b[d_ptr:d_ptr + d_size] = bytes(d_size)
        if res_size > 0 and contains(sec, res_addr, res_size):
            r = res_addr - va + raw_ptr
            patch_res_dir(r, r)
        if reloc is not None:
            blocklen = reloc_size
            p = reloc
            while True:
                blk_va, blk_size = u32(p), u32(p + 4)
                if contains(sec, blk_va) and blk_size <= blocklen:
                    shift = blk_va - va + raw_ptr
                    length = blk_size - 8
                    pw = p + 8
                    while length > 0:
                        w = u16(pw)
                        typ, addr = w >> 12, w & 0x0FFF
                        at = shift + addr
                        if typ == 3:    # HIGHLOW
                            if addr + blk_va + 4 >= va + raw_size:
                                length = 0
                            else:
                                struct.pack_into('<I', b, at, (u32(at) - base) & 0xFFFFFFFF)
                        elif typ == 10:  # DIR64
                            if addr + blk_va + 8 >= va + raw_size:
                                length = 0
                            else:
                                v = struct.unpack_from('<Q', b, at)[0]
                                struct.pack_into('<Q', b, at, (v - base) & 0xFFFFFFFFFFFFFFFF)
                        elif typ == 0:   # ABSOLUTE: конец блока
                            length = 0
                        length -= 2
                        pw += 2
                blocklen = (blocklen - blk_size) & 0xFFFFFFFF
                if blocklen <= 8:
                    break
                p += blk_size
        md5.update(b[raw_ptr:raw_ptr + raw_size])
    return md5.hexdigest()


def package(rel_path, data):
    """Zip, какой ждёт PluginUpdater: один файл, путь от папки Miranda.

    Атрибуты — как у файла DOS (архивный): PluginUpdater передаёт их в
    CreateFile как есть, и права Unix в старших битах стали бы флагами."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        info = zipfile.ZipInfo(rel_path.replace('\\', '/'), date_time=(2026, 1, 1, 0, 0, 0))
        info.create_system = 0
        info.external_attr = 0x20
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, data, compresslevel=9)
    return buf.getvalue()


def sources(platform, engine):
    build = os.path.join(HERE, 'build', platform)
    return [
        ('Plugins\\IcqOscarJ.dll', os.path.join(build, 'IcqOscarJ.dll')),
        ('Plugins\\IcqRevivalFlash.dll', os.path.join(build, 'IcqRevivalFlash.dll')),
        ('Libs\\FlashPlayerControl.dll', engine),
        ('Languages\\langpack_russian_icq.txt', os.path.join(HERE, 'langpack_russian_icq.txt')),
        ('Languages\\langpack_russian_icqrevivalflash.txt',
         os.path.join(HERE, 'langpack_russian_icqrevivalflash.txt')),
    ]


def build(out, platform, engine):
    files = []
    for rel, src in sources(platform, engine):
        if not os.path.isfile(src):
            raise SystemExit(f'нет файла {src}')
        with open(src, 'rb') as f:
            data = f.read()
        body = package(rel, data)
        url = rel.rsplit('.', 1)[0].replace('\\', '/') + '.zip'
        dest = os.path.join(out, platform, *url.split('/'))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(body)
        files.append({
            'name': rel,
            'hash': module_hash(src),
            'crc': f'{zlib.crc32(body):08x}',
            'package': url,
            'size': len(body),
        })
        print(f'{platform} {rel}: {files[-1]["hash"]} {files[-1]["crc"]} ({len(body)} bytes)')
    manifest = {'files': files, 'langpackIncludes': LANGPACK_INCLUDES}
    with open(os.path.join(out, platform, 'manifest.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write('\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('out', nargs='?')
    ap.add_argument('--engine32', default=os.path.join(ENGINE, 'i686-pc-windows-msvc', 'release', 'FlashPlayerControl.dll'))
    ap.add_argument('--engine64', default=os.path.join(ENGINE, 'x86_64-pc-windows-msvc', 'release', 'FlashPlayerControl.dll'))
    ap.add_argument('--hash', nargs='+', metavar='FILE')
    a = ap.parse_args()
    if a.hash:
        for p in a.hash:
            print(module_hash(p), p)
        return
    if not a.out:
        ap.error('нужен выходной каталог')
    build(a.out, 'x32', a.engine32)
    build(a.out, 'x64', a.engine64)


if __name__ == '__main__':
    sys.exit(main())
