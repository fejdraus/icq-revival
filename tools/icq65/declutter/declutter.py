"""Remove the dead-service widgets from the ICQ 6.5 interface.

Superseded by ../patch/Icq6Patch.ps1, which does this and the rest in one
pass and also restores what this script changed. Kept for reference.

The client keeps drawing frames for services that no longer exist: the Xtraz
strip above the contact list, the entertainment panel below it, the advertising
slot under the message window, and the SMS and phone buttons of the message
toolbar. Nothing the server answers can take those away - they are part of the
interface itself.

That interface is not compiled in. It lives under the client's services/
directory as Boxely markup (.box files, plain XML), so a widget is removed by
marking it collapsed, which is how the client itself hides the parts it does not
need. Each widget is addressed by the id it carries in the markup.

    python declutter.py --status      show what would change
    python declutter.py --apply       collapse the widgets
    python declutter.py --restore     put the original markup back

Xtraz add-ons installed under packages/ are loaded from disk rather than from
the Xtraz list, so their buttons survive whatever the server answers; such a
package is disabled by renaming its directory.

Two things this cannot reach, because the client builds them in code rather than
in markup: the "Free SMS" button of the message window and the "SMS & Phone"
entry in the preferences list. The SMS button may disappear anyway - it is fed
by the Xtraz list, which the server now answers with a 404.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

BACKUP_SUFFIX = '.icq6-declutter-backup'

DEFAULT_ROOT = r'C:\Program Files (x86)\ICQ6.5'

CONTENT = os.path.join('services', 'icqApp', 'ver1', 'content')

# file under CONTENT -> ids of the widgets to collapse, with what each one is.
WIDGETS = {
    os.path.join('MUICore', 'MainDlgPanelOwner.box'): {
        'idXtrazBarArea': 'the Xtraz strip above the contact list',
        'idMainEntertainmentBox': 'the entertainment panel below it, ad slot included',
    },
    os.path.join('MUIMessage', 'MsgSessionPanel.box'): {
        'idBottomBannerContainer': 'the banner under the message window',
        'idbtnTzers': 'the tZers button of the message input bar',
    },
    os.path.join('MUIMessage', 'CommToolbar.box'): {
        'btnSMS': 'the SMS button of the message toolbar',
        'btnPhone': 'the phone button next to it',
    },
    os.path.join('MUICore', 'Preferences', 'OPrefsPanelNotifications.box'): {
        'idXtrazInvitation': 'the "Xtraz invitations" option',
    },
    os.path.join('MUICore', 'Preferences', 'OPrefsPanelMessage.box'): {
        'idAutoPlayTzers': 'the "play tZers automatically" option',
    },
    os.path.join('MUICore', 'ContactList', 'DataBoundCL.box'): {
        'sms': 'the SMS icon on a contact row',
        'phone': 'the phone icon on a contact row',
    },
    os.path.join('MUICore', 'ContactList', 'MiniUserProfileDlg.gadgets.box'): {
        'miniUserDetails.autoSmsContainer': 'the auto-SMS line of the contact card',
    },
    os.path.join('MUICore', 'PopupMenus.box'): {
        'idCommSendSMS': 'the "Send SMS" item of the contact menu',
        # Its separator follows this menu's collapsed state on its own.
        'idXtrazMenu': 'the Xtraz submenu of the contact menu',
    },
    os.path.join('MUICore', 'Preferences', 'OPrefsPanelGeneral.box'): {
        'idAutoSmsGroup': 'the auto-SMS section of the general options',
    },
    os.path.join('MUICore', 'Preferences', 'OPrefsPanelHistory.box'): {
        'idSaveXtrazInvitations': 'the "save Xtraz invitations" option',
    },
    os.path.join('MUICore', 'Preferences', 'OPrefsPanelSkin.box'): {
        'IncomingSMS': 'the incoming-SMS sound',
        'OutgoingSMS': 'the outgoing-SMS sound',
        'IncomingTzer': 'the incoming-tZer sound',
        'IncomingXtra': 'the incoming-Xtraz sound',
    },
    os.path.join('MUICore', 'HistorySearchDlg.box'): {
        'idMsgTypeSMS': 'the SMS filter of the history search',
        'idMsgTypeXtrazInvitation': 'the Xtraz-invitation filter next to it',
    },
}

# file under CONTENT -> lines to drop, matched by a distinctive fragment.
LINES = {
    os.path.join('MUICore', 'MainDlg.box'): {
        'cmdMyXtraz': 'the "My Xtraz" item of the main menu',
    },
}


THEME = os.path.join('services', 'icqApp', 'ver1', 'theme')

# file under THEME -> (what, original, replacement). Nothing here at the moment.
#
# The empty band at the foot of the message window stays: the container that
# draws it is pinned to the bottom of the window, and an unnamed spacer of the
# same height is what keeps the buttons above out of its way. Take either one
# away - collapse the container, zero its height, drop the spacer - and the
# buttons end up underneath it and stop responding to the mouse. The banner
# inside the band is collapsed, so the band is at least empty.
STYLES = {
    os.path.join('MUIMessage', 'MsgSessionDlg.style.box'): [
        # The white frame left at the foot of the message window. The band
        # itself has to stay - the emoticon and formatting panels drop down
        # into it, and the buttons above sit on the spacer that keeps them out
        # of its way - but what draws the frame is the fill of the banner
        # container, and the banner is gone. Without the fill the band is the
        # colour of the window and nothing shows while the panels are closed.
        # The ad element has to stay in the markup - the code looks it up, and
        # without it the emoticon and formatting panels stop opening - but with
        # no size left it draws nothing. Collapsing it is not enough either:
        # the code shows it a few seconds after the window opens.
        ('the ad box of the message window',
         '<style id="bannerStyle" width="468" height="60"',
         '<style id="bannerStyle" width="0" height="0"'),
        ('the white frame at the foot of the message window',
         '<part name="idBottomBannerContainer" flex="1" hAlign="center" '
         'fill="url(#image.MessageDlgXtra.window.background)"',
         '<part name="idBottomBannerContainer" flex="1" hAlign="center"'),
    ],
    os.path.join('MUICore', 'Preferences', 'OwnerPrefsDlg.style.box'): [
        # The background of a group is a 138x109 image with a nine-slice at 90:
        # its rounded bottom is the last 19 pixels and is drawn only where the
        # box is at least 109 high. "Personal settings" is 115 and ends cleanly;
        # "Advanced" was 90 and came out cut off. Predates the removal of the
        # SMS entry. The tab list inside it was 98 in a box of 90 as well.
        # The group ended in a straight cut instead of the rounded bottom its
        # background image carries. The box is 90 high, and the tab list inside
        # it was 98 - taller than the box - so the overflow covered the last
        # pixels of the background. Two entries take about 56, and the box has
        # room for that once the group label is accounted for.
        ('the cut-off bottom of the "Advanced" group',
         '<style id="advancedTabStyle" height="98"',
         '<style id="advancedTabStyle" height="56"'),
    ],
    os.path.join('MUICore', 'MainDlgPanelOwner.style.box'): [
        ('the ad box of the contact list',
         '<style id="adBoxStyle" width="120" height="90" />',
         '<style id="adBoxStyle" width="0" height="0" />'),
    ],
}


# Markup files to take out of the way entirely, as <name>.icq6-declutter-backup.
# The "SMS & Phone" entry of the preferences list is built in code - the string
# sits in MUICore.dll - so the entry itself cannot be collapsed. Taking its panel
# away is what is left: the entry may then disappear, or stay and open nothing.
FILES = {
    os.path.join('MUICore', 'Preferences', 'OPrefsPanelSMS.box'):
        'the "SMS & Phone" panel of the preferences',
}


def hidden_files(root):
    """Yield (path, backup path, what) for every markup file to take away."""
    for rel, what in FILES.items():
        path = os.path.join(root, CONTENT, rel)
        yield path, path + BACKUP_SUFFIX, what


# Byte patches, relative to the install root. The preferences list is built in
# code, not in markup: each group is described in .data by a pointer to its
# records and a count, and the records themselves - name, label key, icon, panel
# loader, 16 bytes each - are filled in by a run of mov instructions.
#
# The "Advanced" group holds three: Connection, SMS, Advanced. Blanking the SMS
# record only leaves an empty row, because the list is walked by the count. So
# the record is overwritten with the one after it and the count drops to two:
# the list becomes Connection, Advanced, and the now-unreachable third record is
# left where it is.
#
# Each patch gives the file offset, what must already be there, and what to
# write; sizes match and the expected bytes are verified before writing.
BYTES = {
    'MUICore.dll': [
        ('the "SMS & Phone" entry of the preferences list', [
            (0x258CE4, '40c9a633', '28fda733'),   # name      -> "Advanced"
            (0x258CEE, 'c4f1a733', '38f1a733'),   # label key -> OwnerPrefsDlg.Advanced
            (0x258CF8, '3cfda733', '10fda733'),   # icon      -> ic_Advanced
            (0x258D02, 'f05c9233', '705e9233'),   # loader    -> the Advanced panel
            (0x2F0190, '03000000', '02000000'),   # the group's record count
        ]),
    ],
}


def close_client(timeout=15):
    """Ask ICQ.exe to quit, then wait for it to let go of its libraries."""
    for args in (['/IM', 'ICQ.exe'], ['/F', '/IM', 'ICQ.exe']):
        subprocess.run(['taskkill'] + args,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ICQ.exe'],
                             capture_output=True, text=True).stdout
        if 'ICQ.exe' not in out:
            break
    for _ in range(timeout):
        out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ICQ.exe'],
                             capture_output=True, text=True).stdout
        if 'ICQ.exe' not in out:
            print('closed the client')
            return True
        time.sleep(1)
    print('the client is still running')
    return False


def patch_bytes(root, revert=False):
    """Apply the byte patches, or put the original bytes back."""
    changed = 0
    for name, patches in BYTES.items():
        path = os.path.join(root, name)
        if not os.path.isfile(path):
            continue
        with open(path, 'rb') as fh:
            blob = bytearray(fh.read())
        for what, edits in patches:
            want = [(off, bytes.fromhex(b if revert else a))
                    for off, a, b in edits]
            have = [(off, bytes.fromhex(a if revert else b))
                    for off, a, b in edits]
            if all(blob[off:off + len(v)] == v for off, v in have):
                continue                      # already in the wanted state
            if not all(blob[off:off + len(v)] == v for off, v in want):
                print(f'skipped (unexpected bytes): {what}')
                continue
            for off, value in have:
                blob[off:off + len(value)] = value
            backup = path + BACKUP_SUFFIX
            if not os.path.exists(backup):
                shutil.copy2(path, backup)
            try:
                with open(path, 'wb') as fh:
                    fh.write(blob)
            except PermissionError:
                # The client holds its own libraries open while it runs.
                print(f'{name} is in use - close ICQ and run --apply again')
                continue
            changed += 1
            print(('restored ' if revert else 'removed ') + what)
    return changed


# Xtraz add-ons shipped with the client and installed under packages/. They are
# loaded from disk, not from the Xtraz list, so each one keeps its button in the
# message input bar however the list is answered. A package is disabled by
# renaming its directory. The emoticon packages stay: they still work.
PACKAGES = {
    'zlango': 'the Zlango add-on and its buttons in the message input bar',
}


def package_dirs(root):
    """Yield (path, backup path, what) for every package to disable."""
    for name, what in PACKAGES.items():
        path = os.path.join(root, 'packages', name)
        yield path, path + BACKUP_SUFFIX, what


def read(path):
    with open(path, 'rb') as fh:
        raw = fh.read()
    for enc in ('utf-8-sig', 'utf-8', 'cp1251'):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return None, None


def write(path, text, enc):
    backup = path + BACKUP_SUFFIX
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    with open(path, 'wb') as fh:
        fh.write(text.encode(enc if enc != 'utf-8-sig' else 'utf-8-sig'))


def collapse(text, widget_id):
    """Mark the element carrying this id as collapsed. Returns (text, done)."""
    tag = re.search(r'<[A-Za-z][^<>]*\bid="' + re.escape(widget_id) + r'"[^<>]*>', text)
    if not tag:
        return text, False
    old = tag.group(0)
    if re.search(r'\bcollapsed="true"', old):
        return text, False
    new = re.sub(r'\bcollapsed="[^"]*"', '', old)
    new = new.rstrip('>').rstrip('/').rstrip()
    new += ' collapsed="true"' + ('/>' if old.rstrip().endswith('/>') else '>')
    return text[:tag.start()] + new + text[tag.end():], True


def subst(text, pair):
    """Replace one fragment by another. Returns (text, done)."""
    old, new = pair
    if old not in text:
        return text, False
    return text.replace(old, new, 1), True


def drop_line(text, fragment):
    """Remove the whole line holding this fragment. Returns (text, done)."""
    lines = text.split('\n')
    keep = [ln for ln in lines if fragment not in ln]
    if len(keep) == len(lines):
        return text, False
    return '\n'.join(keep), True


def apply_one(text, key, kind):
    """Run the edit this target asks for. Returns (text, done)."""
    if kind == 'collapse':
        return collapse(text, key)
    if kind == 'subst':
        return subst(text, key)
    return drop_line(text, key)


def targets(root):
    """Yield (path, id, what, kind) for every widget and line to change."""
    for rel, items in WIDGETS.items():
        for wid, what in items.items():
            yield os.path.join(root, CONTENT, rel), wid, what, 'collapse'
    for rel, items in LINES.items():
        for fragment, what in items.items():
            yield os.path.join(root, CONTENT, rel), fragment, what, 'line'
    for rel, items in STYLES.items():
        for what, old, new in items:
            yield os.path.join(root, THEME, rel), (old, new), what, 'subst'


def cmd_status(root):
    if not os.path.isdir(os.path.join(root, CONTENT)):
        sys.exit('not found: ' + os.path.join(root, CONTENT))
    pending = 0
    for path, key, what, kind in targets(root):
        text, _enc = read(path)
        if text is None:
            print(f'unreadable: {os.path.relpath(path, root)}')
            continue
        _new, done = apply_one(text, key, kind)
        pending += done
        print(f'{"to remove" if done else "already gone"}: {what}')
    for path, backup, what in list(hidden_files(root)) + list(package_dirs(root)):
        live = os.path.exists(path) and not os.path.exists(backup)
        pending += live
        print(f'{"to remove" if live else "already gone"}: {what}')
    print(f'widgets still in place: {pending}')


def cmd_apply(root):
    if not os.path.isdir(os.path.join(root, CONTENT)):
        sys.exit('not found: ' + os.path.join(root, CONTENT))
    changed = 0
    for path, key, what, kind in targets(root):
        text, enc = read(path)
        if text is None:
            continue
        new, done = apply_one(text, key, kind)
        if not done:
            continue
        write(path, new, enc)
        changed += 1
        print('removed', what)
    for path, backup, what in list(hidden_files(root)) + list(package_dirs(root)):
        if not os.path.exists(path) or os.path.exists(backup):
            continue
        os.rename(path, backup)
        changed += 1
        print('removed', what)
    changed += patch_bytes(root)
    print(f'widgets removed: {changed}')
    if changed:
        print('restart the client')


def cmd_restore(root):
    restored = 0
    seen = set()
    for path, _key, _what, _kind in targets(root):
        if path in seen:
            continue
        seen.add(path)
        backup = path + BACKUP_SUFFIX
        if os.path.exists(backup):
            shutil.copy2(backup, path)
            os.remove(backup)
            restored += 1
            print('restored', os.path.relpath(path, root))
    for path, backup, what in list(hidden_files(root)) + list(package_dirs(root)):
        if os.path.exists(backup) and not os.path.exists(path):
            os.rename(backup, path)
            restored += 1
            print('restored', what)
    restored += patch_bytes(root, revert=True)
    print(f'files restored: {restored}')


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=DEFAULT_ROOT, help='ICQ 6.5 install directory')
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--status', action='store_true')
    g.add_argument('--apply', action='store_true')
    g.add_argument('--restore', action='store_true')
    ap.add_argument('--close-icq', action='store_true',
                    help='close a running client first: it holds its own libraries open')
    args = ap.parse_args()

    if args.close_icq:
        close_client()

    if args.status:
        cmd_status(args.root)
    elif args.apply:
        cmd_apply(args.root)
    else:
        cmd_restore(args.root)


if __name__ == '__main__':
    main()
