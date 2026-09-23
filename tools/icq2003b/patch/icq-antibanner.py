"""Антибаннер для ICQ Pro 2003b.

Убирает рекламу и строку поиска Google четырьмя точечными правками в коде
клиента. База пользователя, скин и настройки не трогаются вообще.

    python icq-antibanner.py --status     показать состояние
    python icq-antibanner.py --apply      применить
    python icq-antibanner.py --restore    вернуть как было

Запускать от администратора (файлы лежат в Program Files) и при ЗАКРЫТОМ ICQ.

Почему именно эти четыре правки
-------------------------------
Модули ICQ экспортируют декорированные имена C++, поэтому классы клиента
подписаны и нужные функции находятся по имени, а не подбором констант:

  MCCLBannerDialog::CreatTheCLBannerCtrl  — создаёт окно баннера в списке
      контактов. Возвращает bool, __thiscall с одним аргументом, поэтому
      корректный отказ — xor eax,eax / ret 4.

  MCProBannersUtils::IsOKToDispalyBanner  — решает, показывать ли баннер в
      прочих окнах (в том числе в окне переписки). Статическая, без
      аргументов, отказ — xor eax,eax / ret.

  ICQTicker.dll!DllGetClassObject         — точка входа COM-объекта, который
      рисует строку поиска Google с кнопкой. Возврат CLASS_E_CLASSNOTAVAILABLE
      означает «такого класса нет», клиент это обрабатывает штатно.

  Icq.exe, раскладка окна списка контактов — в ветке «баннера нет» всё равно
      прибавлялись 22 пикселя под полосу тикера (cmp byte [ecx+2],0 / je /
      add eax,0x16). Условный переход заменён безусловным.

Важно про закрытие клиента
--------------------------
ICQ закрывать только штатно: значок в трее -> Exit. Крестик лишь сворачивает.
Принудительное завершение оставляет недописанным кэш контакт-листа
CL\\<UIN>.fb, после чего клиент навсегда зависает на «Logging in...», хотя на
сервере вход проходит успешно. Лечится удалением этого файла.

И ещё: правки базы пользователя (2003b\\<UIN>\\O<UIN>.fpt) ломают её — клиент
падает на старте с «The operation cannot be completed at this time». Проверено
дважды, сюда не лезть.
"""

import argparse
import ctypes
import os
import shutil
import subprocess
import sys

ICQ_ROOT = r'C:\Program Files (x86)\ICQ'
BACKUP_SUFFIX = '.antibanner-backup'

# (файл, смещение, исходные байты, новые байты, что делает)
PATCHES = [
    ('icqmutl.dll', 0x20626,
     'b8969b2220', '31c0c20400',
     'баннер в списке контактов не создаётся'),
    ('ICQProLib.dll', 0x1217b,
     'b8ba7d8924', '31c0c3',
     'баннер в окне переписки не показывается'),
    ('ICQTicker.dll', 0x750,
     '53558b6c241456', 'b811010480c20c00',
     'строка поиска Google и кнопка не создаются'),
    ('Icq.exe', 0x39aa2,
     '7441', 'eb41',
     'под них не резервируется место в раскладке'),
]


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def icq_running():
    out = subprocess.run(['tasklist', '/fi', 'imagename eq Icq.exe'],
                         capture_output=True, text=True, encoding='cp866')
    return 'Icq.exe' in (out.stdout or '')


def read(path):
    with open(path, 'rb') as f:
        return bytearray(f.read())


def state(path, offset, original, patched):
    """Что сейчас лежит по смещению: 'исходное', 'применено' или 'иное'."""
    data = read(path)
    chunk = bytes(data[offset:offset + max(len(original), len(patched))])
    if chunk.startswith(patched):
        return 'применено'
    if chunk.startswith(original):
        return 'исходное'
    return 'иное'


def do_status():
    for name, offset, orig_hex, new_hex, what in PATCHES:
        path = os.path.join(ICQ_ROOT, name)
        if not os.path.exists(path):
            print(f'  {name:<16} файл не найден')
            continue
        orig, new = bytes.fromhex(orig_hex), bytes.fromhex(new_hex)
        mark = state(path, offset, orig, new)
        backup = 'копия есть' if os.path.exists(path + BACKUP_SUFFIX) else 'копии нет'
        print(f'  {name:<16} 0x{offset:<6x} {mark:<10} {backup:<12} {what}')


def do_apply():
    for name, offset, orig_hex, new_hex, what in PATCHES:
        path = os.path.join(ICQ_ROOT, name)
        if not os.path.exists(path):
            print(f'  {name}: файл не найден, пропускаю')
            continue
        orig, new = bytes.fromhex(orig_hex), bytes.fromhex(new_hex)
        data = read(path)
        current = bytes(data[offset:offset + len(orig)])
        if current == new[:len(orig)] or bytes(data[offset:offset + len(new)]) == new:
            print(f'  {name}: уже применено')
            continue
        if current != orig:
            print(f'  {name}: по 0x{offset:x} лежит {current.hex(" ")}, '
                  f'ожидалось {orig.hex(" ")} — пропускаю')
            continue
        backup = path + BACKUP_SUFFIX
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
        data[offset:offset + len(new)] = new
        with open(path, 'wb') as f:
            f.write(data)
        print(f'  {name}: {what}')


def do_restore():
    restored = 0
    for name, *_ in PATCHES:
        path = os.path.join(ICQ_ROOT, name)
        backup = path + BACKUP_SUFFIX
        if os.path.exists(backup):
            shutil.copy2(backup, path)
            print(f'  возвращён: {name}')
            restored += 1
    if not restored:
        print('  резервных копий нет')


parser = argparse.ArgumentParser(description='Антибаннер для ICQ Pro 2003b')
group = parser.add_mutually_exclusive_group()
group.add_argument('--apply', action='store_true', help='применить правки')
group.add_argument('--restore', action='store_true', help='вернуть как было')
group.add_argument('--status', action='store_true', help='показать состояние')
args = parser.parse_args()

if args.apply or args.restore:
    if not is_admin():
        print('нужны права администратора: файлы ICQ лежат в Program Files')
        sys.exit(1)
    if icq_running():
        print('ICQ запущен. Закройте его штатно: значок в трее -> Exit.')
        print('Принудительно снимать нельзя — портится кэш контакт-листа.')
        sys.exit(1)

if args.apply:
    print('Применяю:')
    do_apply()
    print('Готово. Запустите ICQ.')
elif args.restore:
    print('Возвращаю как было:')
    do_restore()
    print('Готово.')
else:
    print(f'Состояние ({ICQ_ROOT}):')
    do_status()
