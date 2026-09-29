# Writes THIRD-PARTY-NOTICES.txt: the copyright and license notices of every
# crate compiled into FlashPlayerControl.dll (Ruffle and its dependencies),
# which the downloads carry next to the DLL (tools/make-downloads.py).
#
#   python tools/icq65/flashplayer/make-notices.py
#
# The crates are the ones Cargo.lock resolves for the two targets the DLL is
# built for, following normal dependencies from this crate (build scripts'
# and dev dependencies do not end up in the DLL). Their sources come from the
# cargo cache (cargo metadata downloads what is missing); for each crate the
# LICENSE*/LICENCE*/COPYING*/NOTICE*/COPYRIGHT* files are collected, looking
# in the git checkout's root for crates of a git workspace (Ruffle). Identical
# texts are printed once, with the list of crates using them. Run it again
# after changing Cargo.lock and commit the result.

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'THIRD-PARTY-NOTICES.txt')
TARGETS = ('i686-pc-windows-msvc', 'x86_64-pc-windows-msvc')
LICENSE_FILE = re.compile(r'^(licen[sc]e|copying|notice|copyright)', re.I)
# "Copyright 2020 Name", "Copyright (c) Name", "COPYRIGHT (c) 2020", "© 2020
# Name", but not the license terms' own sentences ("copyright notice that
# ...", "COPYRIGHT HOLDERS BE LIABLE").
COPYRIGHT_LINE = re.compile(
    r'^\s*(Copyright\s*(\([cC]\)|©)?\s*[0-9A-Z]'
    r'|COPYRIGHT\s*(\([cC]\)|©)?\s*\d'
    r'|©\s*\d)')

# The Rust standard library is linked into the DLL as well.
RUST_STD = '''The Rust standard library (std, core, alloc and their dependencies) is
statically linked into the DLL. It is licensed under "MIT OR Apache-2.0",
Copyright (c) The Rust Project Contributors; see
https://github.com/rust-lang/rust/blob/master/COPYRIGHT. The MIT and
Apache-2.0 texts are the same as those printed below.'''

OWN = '''FlashPlayerControl.dll is part of ICQ Revival, a server for classic ICQ
clients built on Open OSCAR Server (https://github.com/mk6i/open-oscar-server).
Its own code (the "flashplayercontrol" crate) is licensed under "MIT OR
Apache-2.0". It is built on Ruffle (https://ruffle.rs,
https://github.com/ruffle-rs/ruffle), the Flash Player emulator, and the
crates listed below. Each crate's source is published on crates.io
(https://crates.io/crates/<name>/<version>) or in the repository named in its
entry. All are used unmodified except wgpu-hal, which carries a small fix
(DX12 pipeline subobject alignment on 32-bit). The MPL-2.0 crates
(symphonia*) are unmodified; their source code is available from
https://github.com/pdeljanov/Symphonia and crates.io.'''


def metadata(target):
    out = subprocess.run(
        ['cargo', 'metadata', '--format-version', '1', '--locked', '--filter-platform', target],
        cwd=HERE, check=True, capture_output=True, text=True, encoding='utf-8').stdout
    return json.loads(out)


def runtime_packages(meta):
    """Ids of the packages reachable from the root by normal dependencies."""
    nodes = {n['id']: n for n in meta['resolve']['nodes']}
    seen, todo = set(), [meta['resolve']['root']]
    while todo:
        pid = todo.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]['deps']:
            if any(k['kind'] is None for k in dep['dep_kinds']):
                todo.append(dep['pkg'])
    return seen


def git_root(path):
    """The top of the git checkout a crate of a git dependency sits in."""
    cur = path
    while True:
        parent = os.path.dirname(cur)
        # ~/.cargo/git/checkouts/<repo>-<hash>/<rev>/...
        if os.path.basename(os.path.dirname(parent)) == 'checkouts':
            return cur
        if parent == cur:
            return None
        cur = parent


def read(path):
    with open(path, 'rb') as f:
        text = f.read().decode('utf-8', errors='replace')
    return text.replace('\r\n', '\n').replace('\r', '\n').strip('\n')


def license_texts(pkg):
    """[(file name, text)] of the crate's license files."""
    root = os.path.dirname(pkg['manifest_path'])
    dirs = [root]
    if pkg['source'] and pkg['source'].startswith('git+'):
        top = git_root(root)
        if top and top != root:
            dirs.append(top)
    found = []
    for d in dirs:
        for name in sorted(os.listdir(d)):
            path = os.path.join(d, name)
            if LICENSE_FILE.match(name) and os.path.isfile(path):
                found.append((name, read(path)))
        if found:
            break
    if not found and pkg.get('license_file'):
        path = os.path.join(root, pkg['license_file'])
        if os.path.isfile(path):
            found.append((os.path.basename(path), read(path)))
    return found


APACHE_END = 'END OF TERMS AND CONDITIONS'


def canonical(text):
    """Apache-2.0 texts differ only in the appendix (how to apply the license)
    and in layout; the terms are printed once, and a copyright notice filled
    into an appendix stays in the crate's entry."""
    if 'Apache License' in text and 'Version 2.0, January 2004' in text and APACHE_END in text:
        return text[:text.index(APACHE_END) + len(APACHE_END)]
    return text


def normalized(text):
    return hashlib.sha256(' '.join(canonical(text).split()).encode()).hexdigest()


def copyright_lines(text):
    return [l.strip() for l in text.split('\n')
            if COPYRIGHT_LINE.match(l) and not re.search(r'[\[{<]yyyy[\]}>]', l, re.I)]


def main():
    pkgs, ids = {}, set()
    for target in TARGETS:
        meta = metadata(target)
        root = meta['resolve']['root']
        for p in meta['packages']:
            pkgs[p['id']] = p
        ids |= runtime_packages(meta) - {root}

    crates = sorted((pkgs[i] for i in ids), key=lambda p: (p['name'], p['version']))
    texts = {}      # hash -> (text, [crate labels])
    rows, missing = [], []
    for p in crates:
        label = f"{p['name']} {p['version']}"
        found = license_texts(p)
        if not found:
            missing.append(label)
        copyrights = []
        for name, text in found:
            h = normalized(text)
            texts.setdefault(h, (canonical(text), []))[1].append(label)
            copyrights += copyright_lines(text)
        rows.append((p, found, list(dict.fromkeys(copyrights))))

    order = {h: n for n, h in enumerate(sorted(texts, key=lambda h: (-len(texts[h][1]), texts[h][1][0])), 1)}
    ruffle = next(order[normalized(t)] for p, found, _ in rows if p['name'] == 'ruffle_core' for _, t in found)
    bar = '=' * 78
    out = [
        'THIRD-PARTY SOFTWARE NOTICES FOR FlashPlayerControl.dll',
        bar, '', OWN, '', RUST_STD, '',
        bar,
        f'CRATES COMPILED INTO THE DLL ({len(crates)})',
        bar, '',
        'Each crate: version, license (SPDX expression from its Cargo.toml),',
        'source, the copyright lines of its license files and the number of the',
        'license text below that applies to it.', '',
    ]
    for p, found, copyrights in rows:
        src = p.get('repository') or p.get('homepage') or ''
        if p['source'] is None:
            src += ' (with our 32-bit alignment fix)'
        out.append(f"{p['name']} {p['version']}")
        out.append(f"  License: {p.get('license') or 'see license file'}")
        if src:
            out.append(f'  Source: {src}')
        if p.get('authors'):
            out.append('  Authors: ' + ', '.join(p['authors']))
        for c in copyrights:
            out.append(f'  {c}')
        if found:
            nums = sorted({order[normalized(t)] for _, t in found})
            out.append('  License text: ' + ', '.join(f'#{n}' for n in nums))
        else:
            out.append('  License text: none in the published crate; the standard texts of')
            out.append(f"    its licenses are in Ruffle's license, #{ruffle}")
        out.append('')

    out += [bar, f'LICENSE TEXTS ({len(texts)})', bar, '']
    for h in sorted(texts, key=order.get):
        text, users = texts[h]
        out.append(f'-' * 78)
        out.append(f'#{order[h]} - used by: ' + ', '.join(dict.fromkeys(users)))
        out.append('-' * 78)
        out.append(text)
        out.append('')

    # Notices of what the crates embed besides code (fonts), kept in notices/.
    extra = os.path.join(HERE, 'notices')
    for name in sorted(os.listdir(extra)):
        out += [bar, 'EMBEDDED ASSETS: ' + os.path.splitext(name)[0], bar, read(os.path.join(extra, name)), '']

    # CRLF and a BOM, so that Notepad on old Windows shows it properly.
    with open(OUT, 'w', encoding='utf-8-sig', newline='\r\n') as f:
        f.write('\n'.join(out))
    print(f'{os.path.relpath(OUT)}: {len(crates)} crates, {len(texts)} license texts')
    if missing:
        print('no license file (standard text assumed): ' + ', '.join(missing))


if __name__ == '__main__':
    sys.exit(main())
