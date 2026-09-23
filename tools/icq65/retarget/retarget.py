"""Point an ICQ 6.5 installation at this server.

Superseded by ../patch/Icq6Patch.ps1, which does this and the rest in one
pass and also restores what this script changed. Kept for reference.

The client talks HTTP to ICQ.com services that are long gone: Xtraz (the picture
gallery, greetings and mini-games) on xtraz.icq.com, the help pages and guides on
labs.icq.com, updates and emoticon packs on update.icq.com. Those hosts still
resolve but never answer, so the client reports "a problem opening Xtra" and the
like. This script rewrites such addresses to our own server (oscar-legacy-web),
where the same paths are answered by topic stub pages.

    python retarget.py --status     show which links would move
    python retarget.py --apply      move the address into the client
    python retarget.py --restore    put the original files back

By default the Xtraz strip and the advertising are removed outright rather
than stubbed: the client draws them only while its local descriptors list
anything, so the <spot> entries of adConfig.xml and the <tz> entries of tzer.xml
are emptied, and the server answers the Xtraz list with a 404. Pass --keep-xtraz
to leave both in place and get the "we will do this later" pages instead.

Only pages are moved - the addresses the client opens in a window. The ones it
parses itself are deliberately left pointing at the dead hosts:

    Master.xml       content bundle descriptors
    Packages.xml     the Xtraz and update package lists
    XtraConfig.xml   the Xtraz texts (the list itself is moved: the gallery
                     window is filled from it and cannot open without one)
    tzer.xml         teaser images for the top strip
    Searches.xml     the search providers of the search box
    adConfig.xml     the advertising slots

Answering those at all is worse than not answering. With a dead host the request
times out and the client keeps its built-in defaults; with any prompt reply -
even a 404 - it treats the list as empty and drops the matching part of the
interface: the tab strip, the hint in the search box, the panel at the bottom.

Binaries are left alone. The sign-in address is not this script's business: the
user sets it in the client, under Options -> Connection -> ICQ server.

The paths are kept as they are and only the host changes, because the
oscar-legacy-web routes match the original ICQ 6 paths.
"""

import argparse
import os
import re
import shutil
import sys

BACKUP_SUFFIX = '.icq6-retarget-backup'

DEFAULT_ROOT = r'C:\Program Files (x86)\ICQ6.5'
DEFAULT_TARGET = 'chat.example.ts.net:8101'

# Hosts the client fetches over HTTP that our service answers for.
DEAD_HOSTS = [
    'xtraz.icq.com',
    'openxtraz.icq.com',
    'icq.openxtraz.com',
    'labs.icq.com',
    'update.icq.com',
    'www.icq.com',
    'cb.icq.com',
    'df.icq.com',
    'c.icq.com',
]

# Paths that open as a page. Everything else the client parses itself and must
# keep timing out, see the module docstring.
PAGE_PATHS = [
    r'/xtraz/srv/',                 # the picture gallery window
    r'/compad/',                    # help, guides, problem report
    r'/legal',                      # the legal notice
    r'/sms',                        # the SMS page
    r'/ibs/icq6/',                  # SMS number validation
    r'/download/icq6/',             # emoticon downloads
    r'/register/email_activation/',  # e-mail confirmation
    r'/xtraz2/global/',             # the Xtraz list the gallery window reads
]

URL_RE = re.compile(
    r'http://(?:' + '|'.join(re.escape(h) for h in DEAD_HOSTS) + r')'
    r'(?=(' + '|'.join(PAGE_PATHS) + r'))',
    re.I,
)


# The client checks where content comes from: XtraConfig.xml carries a
# WhiteDomainList key and tzer.xml a <whitelist> block. A host that is not listed
# is refused, and the matching part of the interface disappears - the tab strip,
# the hint in the search box, the panel at the bottom. So our host has to be
# added to both lists, not only put into the addresses.
WHITELIST_FILES = {
    'XtraConfig.xml': 'key',
    'tzer.xml': 'block',
}


def add_to_whitelists(root, host):
    """Allow our host in the client's content whitelists."""
    changed = 0
    for name, kind in WHITELIST_FILES.items():
        path = os.path.join(root, 'ConfigFiles', name)
        if not os.path.isfile(path):
            continue
        text, enc = read(path)
        if text is None or host in text:
            continue
        if kind == 'key':
            new = re.sub(r'(Key="WhiteDomainList" Value=")([^"]*)(")',
                         lambda m: m.group(1) + m.group(2) + ' ' + host + m.group(3),
                         text, count=1)
        else:
            new = text.replace('</whitelist>',
                               '   <u>' + host + '</u>\n   </whitelist>', 1)
        if new == text:
            continue
        backup = path + BACKUP_SUFFIX
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
        with open(path, 'wb') as fh:
            fh.write(new.encode(enc if enc != 'utf-8-sig' else 'utf-8-sig'))
        changed += 1
        print('whitelisted in', name)
    return changed


# The client draws the Xtraz strip and the ad slots only while its own
# descriptors list something to draw. Emptying the lists removes both from the
# interface for good, which no amount of answering their requests can do.
STRIP = {
    'adConfig.xml': r'[ \t]*<spot\b[^>]*/>[ \t]*\r?\n?',   # the ad slots
    'tzer.xml': r'[ \t]*<tz\b[^>]*/>[ \t]*\r?\n?',         # the teaser strip
    # The SMS carriers. With none of them listed the client has nowhere to
    # send a text, which is also what hides the SMS parts it builds in code.
    'SMSConfig.xml': r'[ \t]*<i n="operator"[^>]*/>[ \t]*\r?\n?',
}


def strip_ui(root):
    """Empty the descriptors of the Xtraz strip and the advertising."""
    changed = 0
    for name, pattern in STRIP.items():
        path = os.path.join(root, 'ConfigFiles', name)
        if not os.path.isfile(path):
            continue
        text, enc = read(path)
        if text is None:
            continue
        new, count = re.subn(pattern, '', text)
        if not count:
            continue
        backup = path + BACKUP_SUFFIX
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
        with open(path, 'wb') as fh:
            fh.write(new.encode(enc if enc != 'utf-8-sig' else 'utf-8-sig'))
        changed += 1
        print(f'emptied {name}: {count} entries removed')
    return changed


def config_files(root):
    cfg = os.path.join(root, 'ConfigFiles')
    if not os.path.isdir(cfg):
        sys.exit('not found: ' + cfg)
    out = []
    for dirpath, _dirs, names in os.walk(cfg):
        for n in names:
            if n.lower().endswith('.xml'):
                out.append(os.path.join(dirpath, n))
    return sorted(out)


def read(path):
    with open(path, 'rb') as fh:
        raw = fh.read()
    for enc in ('utf-8-sig', 'utf-8', 'cp1251'):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return None, None


def cmd_status(root):
    found = 0
    for path in config_files(root):
        text, _enc = read(path)
        if text is None:
            continue
        hits = URL_RE.findall(text)
        if hits:
            found += len(hits)
            name = os.path.relpath(path, root)
            print(f'{name}: ' + ', '.join(sorted(set(hits))))
    print(f'page links still on the dead hosts: {found}')
    if not found:
        print('looks like the address has already been moved')


def cmd_apply(root, target, keep_xtraz):
    changed = 0 if keep_xtraz else strip_ui(root)
    for path in config_files(root):
        text, enc = read(path)
        if text is None:
            continue
        new = URL_RE.sub('http://' + target, text)
        if new == text:
            continue
        backup = path + BACKUP_SUFFIX
        if not os.path.exists(backup):
            shutil.copy2(path, backup)
        with open(path, 'wb') as fh:
            fh.write(new.encode(enc if enc != 'utf-8-sig' else 'utf-8-sig'))
        changed += 1
        print('rewritten', os.path.relpath(path, root))
    changed += add_to_whitelists(root, target.split(':')[0])
    print(f'files changed: {changed}')
    if changed:
        print('restart the client')


def cmd_restore(root):
    restored = 0
    for path in config_files(root):
        backup = path + BACKUP_SUFFIX
        if os.path.exists(backup):
            shutil.copy2(backup, path)
            os.remove(backup)
            restored += 1
            print('restored', os.path.relpath(path, root))
    print(f'files restored: {restored}')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=DEFAULT_ROOT, help='ICQ 6.5 install directory')
    ap.add_argument('--target', default=DEFAULT_TARGET, help='host:port of our server')
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--status', action='store_true')
    g.add_argument('--apply', action='store_true')
    g.add_argument('--restore', action='store_true')
    ap.add_argument('--keep-xtraz', action='store_true',
                    help='keep the Xtraz strip and the advertising, stubbed instead of removed')
    args = ap.parse_args()

    if args.status:
        cmd_status(args.root)
    elif args.apply:
        cmd_apply(args.root, args.target, args.keep_xtraz)
    else:
        cmd_restore(args.root)


if __name__ == '__main__':
    main()
