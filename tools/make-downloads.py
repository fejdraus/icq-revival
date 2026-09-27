# Builds the files /icq/download offers (deploy/downloads/, served by the
# legacy web from /icq/files/; not kept in git - the Flash engine is 15 MB):
#
#   icq-2003b-patch.exe     the ICQ Pro 2003b patch, the native C++ build
#                           (tools/patcher-cpp/out), which runs on XP to 11
#   icq-65-patch.zip        the ICQ 6.5 patch with the tZers and avatars
#                           player it installs, FlashPlayerControl-Ruffle.dll,
#                           next to it as the patch expects
#   icq-revival-miranda.zip Miranda NG: Miranda32/ and Miranda64/, each laid
#                           out like a Miranda folder (Plugins, Libs,
#                           Languages) to be copied over one
#
#   python tools/make-downloads.py [--out deploy/downloads]
#
# Build the patches (tools/common/Build-Patches.ps1, tools/patcher-cpp) and
# the Flash engine for both platforms (tools/icq65/flashplayer) first. Then
# copy the folder to deploy/downloads on the machine and send the legacy web
# a SIGHUP.

import argparse
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def src(*parts):
    path = os.path.join(REPO, *parts)
    if not os.path.isfile(path):
        sys.exit(f'missing {os.path.relpath(path, REPO)} - build it first')
    return path


def engine(target):
    return src('tools', 'icq65', 'flashplayer', 'target', target, 'release', 'FlashPlayerControl.dll')


MIRANDA = {
    'Miranda32': ('x32', 'i686-pc-windows-msvc'),
    'Miranda64': ('x64', 'x86_64-pc-windows-msvc'),
}


def add(z, path, name):
    z.write(path, name, compress_type=zipfile.ZIP_DEFLATED)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(REPO, 'deploy', 'downloads'))
    out = ap.parse_args().out
    os.makedirs(out, exist_ok=True)

    shutil.copyfile(src('tools', 'patcher-cpp', 'out', 'ICQ-2003b-Patch.exe'),
                    os.path.join(out, 'icq-2003b-patch.exe'))

    with zipfile.ZipFile(os.path.join(out, 'icq-65-patch.zip'), 'w') as z:
        add(z, src('tools', 'icq65', 'patch', 'ICQ-6.5-Patch.exe'), 'ICQ-6.5-Patch.exe')
        add(z, src('tools', 'icq65', 'patch', 'FlashPlayerControl-Ruffle.dll'), 'FlashPlayerControl-Ruffle.dll')

    mi = os.path.join('tools', 'miranda-icq')
    with zipfile.ZipFile(os.path.join(out, 'icq-revival-miranda.zip'), 'w') as z:
        for folder, (bits, target) in MIRANDA.items():
            add(z, src(mi, 'build', bits, 'IcqOscarJ.dll'), f'{folder}/Plugins/IcqOscarJ.dll')
            add(z, src(mi, 'build', bits, 'IcqRevivalFlash.dll'), f'{folder}/Plugins/IcqRevivalFlash.dll')
            add(z, engine(target), f'{folder}/Libs/FlashPlayerControl.dll')
            add(z, src(mi, 'langpack_russian_icq.txt'), f'{folder}/Languages/langpack_russian_icq.txt')
            add(z, src(mi, 'langpack_russian_icqrevivalflash.txt'), f'{folder}/Languages/langpack_russian_icqrevivalflash.txt')

    for name in sorted(os.listdir(out)):
        print(f'{name}: {os.path.getsize(os.path.join(out, name))} bytes')


if __name__ == '__main__':
    main()
