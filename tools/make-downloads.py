# Builds the files /icq/download offers (deploy/downloads/, served by the
# legacy web from /icq/files/; not kept in git - the Flash engine is 15 MB):
#
#   icq-2003b-patch.exe     the ICQ Pro 2003b patch, the native C++ build
#                           (tools/patcher-cpp/out), which runs on XP to 11
#   icq-65-patch.zip        the ICQ 6.5 patch with the tZers and avatars
#                           player it installs, FlashPlayerControl-Ruffle.dll,
#                           next to it as the patch expects, and the player's
#                           THIRD-PARTY-NOTICES.txt (Ruffle and its crates)
#   icq-revival-miranda.zip Miranda NG: Miranda32/ and Miranda64/, each laid
#                           out like a Miranda folder (Plugins, Libs) to be
#                           copied over one; Libs also holds the engine's
#                           notices. No translations: those come inside
#                           Miranda NG's main language pack, which the plugin
#                           updater fetches from our server (see
#                           tools/miranda-icq/README.md). At the top,
#                           README.txt (the plugins are GPLv2, where their
#                           source is) and COPYING.txt, the GPLv2 text
#   icq-revival-miranda-src.zip
#                           the complete source of those two GPLv2 plugins:
#                           tools/miranda-icq/IcqOscarJ (as built) and
#                           IcqRevivalFlash, IcqOscarJ.diff against upstream,
#                           COPYING.txt and a README.txt on building them
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


def add_text(z, text, name):
    """A text file for Notepad: CRLF."""
    z.writestr(name, text.replace('\n', '\r\n'), compress_type=zipfile.ZIP_DEFLATED)


def add_tree(z, folder, name):
    """Every file under the repository folder, as name/<relative path>."""
    root = os.path.join(REPO, folder)
    if not os.path.isdir(root):
        sys.exit(f'missing {folder}')
    for top, dirs, files in os.walk(root):
        dirs.sort()
        for f in sorted(files):
            path = os.path.join(top, f)
            add(z, path, name + '/' + os.path.relpath(path, root).replace(os.sep, '/'))


MI = os.path.join('tools', 'miranda-icq')
# The Miranda NG tree the plugins are built in (the tip of branch 0_96_7),
# see tools/miranda-icq/README.md, "Build".
MIRANDA_NG_COMMIT = 'cc32e4168e1e44dba4219d127106e04f924618fd'
# Upstream IcqOscarJ, the base of IcqOscarJ.diff: miranda-ng/deprecated.
DEPRECATED_COMMIT = 'eba42656f799a992f33e40e2d8ac6b87e18faa95'
# The GPLv2 text, as IcqOscarJ carries it.
GPL = (MI, 'IcqOscarJ', 'docs', 'license.txt')
NOTICES = ('tools', 'icq65', 'flashplayer', 'THIRD-PARTY-NOTICES.txt')

MIRANDA_README = r'''ICQ Revival plugins for Miranda NG 0.96.7
=========================================

Miranda32\ is for miranda32.exe, Miranda64\ for miranda64.exe. Copy the
contents of the matching folder over your Miranda NG folder:

  Plugins\IcqOscarJ.dll        the ICQ protocol (Miranda NG's IcqOscarJ,
                               ported to core 0.96.7 for ICQ Revival)
  Plugins\IcqRevivalFlash.dll  ICQ 6 animated avatars and tZers
  Libs\FlashPlayerControl.dll  the Flash engine they play with (Ruffle)

The plugins' translations come inside Miranda NG's own language pack
(Languages\langpack_<language>.txt): once the ICQ account is set up, the
plugin updater takes that pack from this server with them in it.

License
-------
IcqOscarJ.dll and IcqRevivalFlash.dll are free software under the GNU General
Public License, version 2 (IcqOscarJ: or, at your option, any later version);
the text is in COPYING.txt. They come with NO WARRANTY. Their complete source code is
icq-revival-miranda-src.zip on the same download page as this archive
(/icq/download).

FlashPlayerControl.dll is built on Ruffle (https://ruffle.rs) and many Rust
crates, under MIT, Apache-2.0, MPL-2.0 and similar licenses. Their copyright
and license notices are in Libs\FlashPlayerControl-THIRD-PARTY-NOTICES.txt.
'''

SOURCE_README = rf'''Source code of the ICQ Revival plugins for Miranda NG
=====================================================

This is the complete corresponding source of the two GPLv2 plugins in
icq-revival-miranda.zip (ICQ Revival, a server for classic ICQ clients). They
are free software under the GNU General Public License, version 2 (IcqOscarJ:
or, at your option, any later version), see COPYING.txt. They come with NO
WARRANTY.

  IcqOscarJ\        IcqOscarJ.dll: Miranda NG's ICQ protocol plugin, exactly
                    as built. Miranda NG removed it; it is kept in
                    https://github.com/miranda-ng/deprecated as
                    NotWorkingStuff/Deprecated/IcqOscarJ (commit
                    {DEPRECATED_COMMIT}),
                    and this folder is that one with IcqOscarJ.diff applied.
  IcqOscarJ.diff    our changes to it: the port to the core 0.96.7 headers,
                    the links pointed at the ICQ Revival server and the
                    features added since (tZers, receiving files, user info).
                    To apply it to the upstream folder yourself:
                    patch --binary -p1 -d IcqOscarJ < IcqOscarJ.diff
  IcqRevivalFlash\  IcqRevivalFlash.dll: ICQ 6 animated avatars and tZers,
                    our plugin, based on FlashAvatars (C) 2006 Big Muscle.
                    src\flash.tlb is the type library of the Flash engine,
                    FlashPlayerControl.dll, a separate program (MIT OR
                    Apache-2.0, built on Ruffle) that the plugin loads as
                    a COM object; its license notices come with it.

Building
--------
Both are built inside a Miranda NG source tree of the same version as the
core they run on: branch 0_96_7, commit {MIRANDA_NG_COMMIT[:9]}
(core 0.96.7.28845), with Visual Studio 2022 or its Build Tools (v143):

  git clone https://github.com/miranda-ng/miranda-ng
  cd miranda-ng
  git checkout {MIRANDA_NG_COMMIT}
  build\make_ver_stable.bat
  xcopy /e /i <this folder>\IcqOscarJ protocols\IcqOscarJ
  xcopy /e /i <this folder>\IcqRevivalFlash plugins\IcqRevivalFlash
  MSBuild protocols\IcqOscarJ\icqoscar8.vcxproj -p:Configuration=Release -p:Platform=Win32 -p:PlatformToolset=v143
  MSBuild plugins\IcqRevivalFlash\IcqRevivalFlash.vcxproj -p:Configuration=Release -p:Platform=Win32 -p:PlatformToolset=v143

For miranda64.exe use -p:Platform=x64. build\make_ver_stable.bat writes
include\m_version.h (0.96.7.28845.cc32e41), which the plugins take their
version from.
'''


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
        add(z, src(*NOTICES), 'THIRD-PARTY-NOTICES.txt')

    with zipfile.ZipFile(os.path.join(out, 'icq-revival-miranda.zip'), 'w') as z:
        add_text(z, MIRANDA_README, 'README.txt')
        add(z, src(*GPL), 'COPYING.txt')
        for folder, (bits, target) in MIRANDA.items():
            add(z, src(MI, 'build', bits, 'IcqOscarJ.dll'), f'{folder}/Plugins/IcqOscarJ.dll')
            add(z, src(MI, 'build', bits, 'IcqRevivalFlash.dll'), f'{folder}/Plugins/IcqRevivalFlash.dll')
            add(z, engine(target), f'{folder}/Libs/FlashPlayerControl.dll')
            # Miranda loads from Libs only the DLLs it is asked for, so a .txt
            # there is left alone (langpacks are Languages/langpack_*.txt).
            add(z, src(*NOTICES), f'{folder}/Libs/FlashPlayerControl-THIRD-PARTY-NOTICES.txt')

    # The GPLv2 source of the two plugins above, from the repository alone.
    with zipfile.ZipFile(os.path.join(out, 'icq-revival-miranda-src.zip'), 'w') as z:
        add_text(z, SOURCE_README, 'README.txt')
        add(z, src(*GPL), 'COPYING.txt')
        add(z, src(MI, 'IcqOscarJ.diff'), 'IcqOscarJ.diff')
        add_tree(z, os.path.join(MI, 'IcqOscarJ'), 'IcqOscarJ')
        add_tree(z, os.path.join(MI, 'IcqRevivalFlash'), 'IcqRevivalFlash')

    for name in sorted(os.listdir(out)):
        print(f'{name}: {os.path.getsize(os.path.join(out, name))} bytes')


if __name__ == '__main__':
    main()
