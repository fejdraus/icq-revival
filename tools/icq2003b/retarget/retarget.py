"""Переносит адрес сервера из icq-services.json в конфигурацию клиента ICQ.

Клиент ходит по HTTP на службы ICQ.com, которых давно нет: справка, «белые
страницы», веб-пейджер, панель Today. Хосты ещё резолвятся, но не отвечают,
поэтому клиент висит до TCP-таймаута. Здесь ссылки переписываются на свой
сервер (oscar-legacy-web), адрес которого задан в icq-services.json.

    python retarget.py --status     показать, куда ведут ссылки сейчас
    python retarget.py --apply      перенести адрес из конфига в клиент
    python retarget.py --restore    вернуть исходные файлы

Правятся только XML-конфиги клиента. Бинарники не трогаются, база профиля —
тем более: её правка ломает клиент насмерть.

Чего этим способом не достать
-----------------------------
Часть адресов зашита в код, а не в конфиги, и остаётся на месте:

  wwp.icq.com    Icq.exe, ICQExCt.dll, ICQIfDg.dll, ICQPref.dll — кнопка
                 веб-пейджера в окне переписки берёт адрес отсюда.
  cb.icq.com     Icq.exe — загрузка рекламных блоков. Не мешает, если
                 применён антибаннер: потребитель этих данных отключён.
  google.icq.com база профиля O<UIN>.fpt — строка поиска. Для нового профиля
                 берётся из Defaults\\Websearch.dat, для существующего уже
                 скопирована в базу, а базу трогать нельзя.

Всё это лечится только перехватом имён на уровне DNS или hosts, что требует
контроля над сетью и потому оставлено на усмотрение владельца.
"""

import argparse
import json
import os
import re
import shutil
import sys

BACKUP_SUFFIX = '.icq-retarget-backup'
CONFIG_NAME = 'icq-services.json'

URL_RE = re.compile(r'<url>\s*([^<]*?)\s*</url>', re.I)
NAME_RE = re.compile(r'<name>\s*([^<]*?)\s*</name>', re.I)
# <item> целиком: нужен, чтобы сопоставить <name> и <url> одной записи.
ITEM_RE = re.compile(r'<item>.*?</item>', re.I | re.S)
# Голая ссылка в любом месте файла: в тегах, атрибутах, текстовых узлах.
BARE_URL_RE = re.compile(r'''https?://[^\s"'<>]+''')


def load_config(path):
    with open(path, encoding='utf-8') as f:
        cfg = json.load(f)
    base = cfg.get('base', '').rstrip('/')
    if not base:
        sys.exit(f'{path}: не задан base — адрес сервера')
    cfg['base'] = base
    return cfg


def find_client_root(configured):
    """Папка с Icq.exe: из конфига, рядом со скриптом, из реестра, из типовых мест."""
    if configured and configured != 'auto':
        return configured

    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [here, os.path.dirname(here)]

    try:
        import winreg
        for hive, key in (
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Icq.exe'),
            (winreg.HKEY_LOCAL_MACHINE,
             r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Icq.exe'),
        ):
            try:
                with winreg.OpenKey(hive, key) as k:
                    candidates.append(os.path.dirname(winreg.QueryValue(k, None)))
            except OSError:
                pass
    except ImportError:
        pass

    candidates += [r'C:\Program Files (x86)\ICQ', r'C:\Program Files\ICQ']

    for c in candidates:
        if c and os.path.isfile(os.path.join(c, 'Icq.exe')):
            return c
    return None


def host_of(url):
    m = re.match(r'https?://([^/:]+)', url, re.I)
    return m.group(1).lower() if m else ''


def target_for(name, url, cfg):
    """Во что превратить ссылку: явное правило, заглушка или без изменений."""
    routes = cfg.get('routes', {})
    if name in routes:
        return routes[name].replace('{base}', cfg['base'])

    # Правила по образцу адреса: в channels.xml и atelink.xml у ссылок нет
    # <name>, опознать их можно только по самому URL.
    for rule in cfg.get('urlRoutes', []):
        if re.search(rule['match'], url, re.I):
            return rule['target'].replace('{base}', cfg['base'])

    if host_of(url) in {h.lower() for h in cfg.get('deadHosts', [])}:
        # Имя для заглушки — последний кусок пути, чтобы страница могла
        # показать, какой именно раздел запрашивали.
        leaf = url.split('?')[0].rstrip('/').split('/')[-1] or 'index'
        return cfg.get('stubUrl', '{base}/stub/{name}') \
            .replace('{base}', cfg['base']).replace('{name}', leaf)

    return None


def rewrite(text, cfg):
    """Возвращает (новый текст, список замен)."""
    changes = []

    def fix_item(match):
        item = match.group(0)
        url_m = URL_RE.search(item)
        if not url_m:
            return item
        url = url_m.group(1)
        if not url.lower().startswith('http'):
            return item
        name_m = NAME_RE.search(item)
        name = name_m.group(1) if name_m else ''
        new = target_for(name, url, cfg)
        if not new or new == url:
            return item
        changes.append((name or '(без имени)', url, new))
        return item[:url_m.start(1)] + new + item[url_m.end(1):]

    if '<item>' in text.lower():
        text = ITEM_RE.sub(fix_item, text)

    # Ссылки встречаются не только в <url>: в channels.xml и icqacc.xml они
    # лежат в других тегах и в атрибутах. Второй проход ловит всё оставшееся,
    # но трогает только адреса на мёртвых хостах, поэтому чужого не заденет.
    dead = {h.lower() for h in cfg.get('deadHosts', [])}

    def fix_bare(match):
        url = match.group(0)
        if host_of(url) not in dead:
            return url
        new = target_for('', url, cfg)
        if not new or new == url:
            return url
        changes.append(('(ссылка)', url, new))
        return new

    text = BARE_URL_RE.sub(fix_bare, text)
    return text, changes


def each_file(root, cfg):
    for rel in cfg.get('files', []):
        path = os.path.join(root, rel.replace('/', os.sep))
        if os.path.isfile(path):
            yield rel, path


def do_status(root, cfg):
    dead = {h.lower() for h in cfg.get('deadHosts', [])}
    base_host = host_of(cfg['base'])
    for rel, path in each_file(root, cfg):
        text = open(path, encoding='latin1').read()
        urls = BARE_URL_RE.findall(text)
        on_dead = sum(1 for u in urls if host_of(u) in dead)
        on_ours = sum(1 for u in urls if host_of(u) == base_host)
        backup = 'копия есть' if os.path.exists(path + BACKUP_SUFFIX) else 'копии нет'
        print(f'  {rel:28} всего {len(urls):>3}, на мёртвых {on_dead:>3}, '
              f'на нашем {on_ours:>3}   {backup}')


def do_apply(root, cfg, verbose):
    total = 0
    for rel, path in each_file(root, cfg):
        text = open(path, encoding='latin1').read()
        new_text, changes = rewrite(text, cfg)
        if not changes:
            print(f'  {rel}: менять нечего')
            continue
        backup = path + BACKUP_SUFFIX
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
        with open(path, 'w', encoding='latin1') as f:
            f.write(new_text)
        total += len(changes)
        print(f'  {rel}: переписано ссылок {len(changes)}')
        if verbose:
            for name, old, new in changes:
                print(f'      {name:24} {old[:48]:50} -> {new[:52]}')
    print(f'  итого: {total}')


def do_restore(root, cfg):
    restored = 0
    for rel, path in each_file(root, cfg):
        backup = path + BACKUP_SUFFIX
        if os.path.exists(backup):
            shutil.copy2(backup, path)
            print(f'  возвращён: {rel}')
            restored += 1
    if not restored:
        print('  резервных копий нет')


def main():
    parser = argparse.ArgumentParser(
        description='Перенос адреса сервера из icq-services.json в клиент ICQ')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--apply', action='store_true', help='перенести адрес в клиент')
    group.add_argument('--restore', action='store_true', help='вернуть исходные файлы')
    group.add_argument('--status', action='store_true', help='показать состояние')
    parser.add_argument('--config', default=None, help=f'путь к {CONFIG_NAME}')
    parser.add_argument('--verbose', action='store_true', help='показать каждую замену')
    args = parser.parse_args()

    cfg_path = args.config or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), CONFIG_NAME)
    cfg = load_config(cfg_path)

    root = find_client_root(cfg.get('clientRoot'))
    if not root:
        sys.exit('не нашёл папку с Icq.exe — укажите её в clientRoot')

    print(f'клиент: {root}')
    print(f'сервер: {cfg["base"]}')

    if args.apply:
        if not os.access(root, os.W_OK):
            sys.exit('нет прав на запись — запустите от администратора')
        print('Переношу:')
        do_apply(root, cfg, args.verbose)
        print('Готово. Перезапустите ICQ.')
    elif args.restore:
        print('Возвращаю:')
        do_restore(root, cfg)
    else:
        print('Состояние:')
        do_status(root, cfg)


if __name__ == '__main__':
    main()
