# Builds the translation file for the ICQ plugin.
#
# Translations in Miranda are tied to a plugin by the #muuid mark: the core looks
# for the section with the plugin's UUID and, failing that, falls back to the
# strings that are not tied to any plugin. The langpack has no section for the
# ICQ protocol, it was removed together with the plugin itself, so at best half
# of it gets translated.
#
# The script pulls the translatable strings out of the plugin's sources and
# resource and pairs them with the ready translation of the same English
# strings from any section of an existing langpack. Whatever is not found is
# written at the end, commented out, to be filled in by hand.
#
# Several translation sources can be given: they are consulted in order, so it
# makes sense to put the current langpack first (modern wording) and the old
# one, from the Miranda IM days when the ICQ section still existed, after it.
#
#   python make-langpack.py [--lang ru|uk] <plugin-dir> <output-file> <langpack...>
#
# --lang picks the header of the output (language name, locale, the build
# note and the heading of the untranslated part); Russian is the default.
import io
import os
import re
import sys

MUUID = '{A5B4A32D-D2A8-4925-AE3E-1480E41A07B3}'

# Per target language: the header lines of the pack as Miranda NG's own pack
# for that language has them (=HEAD=.txt), the build note, and the heading of
# the commented-out untranslated strings.
LANGS = {
    'ru': {
        'language': 'Русский',
        'locale': '0419',
        'built': 'Собрано make-langpack.py',
        'missing': 'без перевода',
    },
    'uk': {
        'language': 'Українська',
        'locale': '0422',
        'built': 'Зібрано make-langpack.py',
        'missing': 'без перекладу',
    },
}

# Translate("x"), TranslateT("x"), LPGEN("x"), LPGENW("x") and the other wrappers.
RE_CODE = re.compile(r'\b(?:LPGENW?|Translate[TWU]?)\s*\(\s*"((?:[^"\\]|\\.)*)"')

# Control captions in the resource: the first quoted string of each declaration.
RE_RC_CTRL = re.compile(
    r'^\s*(?:CAPTION|LTEXT|RTEXT|CTEXT|CONTROL|PUSHBUTTON|DEFPUSHBUTTON|GROUPBOX'
    r'|CHECKBOX|RADIOBUTTON|MENUITEM|POPUP)\s+"((?:[^"]|"")*)"')
# Strings from a STRINGTABLE: an identifier followed by the text.
RE_RC_STR = re.compile(r'^\s*ID[A-Z_0-9]+\s+"((?:[^"]|"")*)"\s*$')


def unescape_rc(s):
    """In resources a quote is doubled."""
    return s.replace('""', '"')


def collect(plugin_dir):
    found = {}

    def add(text, where):
        text = text.strip()
        # Empty strings, separators and lone underscores have nothing to translate.
        if not text or text in ('&', '-', '...'):
            return
        if not re.search(r'[A-Za-z]', text):
            return
        found.setdefault(text, where)

    for root, _dirs, files in os.walk(plugin_dir):
        for name in files:
            path = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in ('.cpp', '.h', '.cxx', '.rc'):
                continue
            try:
                text = io.open(path, encoding='utf-8', errors='replace').read()
            except OSError:
                continue

            if ext == '.rc':
                for line in text.splitlines():
                    m = RE_RC_CTRL.match(line) or RE_RC_STR.match(line)
                    if m:
                        add(unescape_rc(m.group(1)), name)
            else:
                for m in RE_CODE.finditer(text):
                    # The langpack loader turns \" into a quote itself, so
                    # the key is written with plain quotes. It parses the other
                    # escape sequences too, so those are left as they are.
                    add(m.group(1).replace('\\"', '"'), name)

    return found


def load_langpack(path, table):
    """English string -> translation, from all sections in turn.

    Adds to the shared table without overwriting what was already found in a
    more important source. Old files sometimes carry a byte order mark; it is
    stripped.
    """
    lines = io.open(path, encoding='utf-8-sig', errors='replace').read().splitlines()
    i = 0
    while i < len(lines) - 1:
        line = lines[i].rstrip()
        if line.startswith('[') and line.endswith(']'):
            value = lines[i + 1].rstrip()
            if value and not value.startswith((';', '[', '#')):
                table.setdefault(line[1:-1], value)
                i += 2
                continue
        i += 1
    return table


def lookup(table, norm, text):
    """An exact match first, then looser ones: without '&', ignoring case,
    and ignoring a trailing colon or ellipsis."""
    if text in table:
        return table[text]
    key = normalize(text)
    return norm.get(key)


def normalize(s):
    s = s.replace('&', '')
    s = s.strip().rstrip(':.… ')
    return s.lower()


def parse_args(argv):
    """--lang <code> (or --lang=<code>) anywhere; the rest positional."""
    lang, rest = 'ru', []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--lang' and i + 1 < len(argv):
            lang = argv[i + 1]
            i += 2
            continue
        if a.startswith('--lang='):
            lang = a.split('=', 1)[1]
        else:
            rest.append(a)
        i += 1
    return lang, rest


def main():
    lang, args = parse_args(sys.argv[1:])
    if len(args) < 3 or lang not in LANGS:
        print('python make-langpack.py [--lang %s] <plugin-dir> <output-file> <langpack...>'
              % '|'.join(LANGS))
        return 1
    meta = LANGS[lang]

    plugin_dir, out_path = args[0], args[1]
    strings = collect(plugin_dir)

    table = {}
    for src in args[2:]:
        before = len(table)
        load_langpack(src, table)
        print('%-60s strings: +%d' % (os.path.basename(src), len(table) - before))

    norm = {}
    for eng, rus in table.items():
        norm.setdefault(normalize(eng), rus)

    done, missing = [], []
    for text in sorted(strings, key=str.lower):
        value = lookup(table, norm, text)
        (done if value else missing).append((text, value))

    out = [
        'Miranda Language Pack Version 1',
        'Language: ' + meta['language'],
        'Locale: ' + meta['locale'],
        '',
        ';============================================================',
        ';  File: IcqOscarJ.dll',
        ';  Plugin: ICQ protocol',
        ';  ' + meta['built'],
        ';============================================================',
        '#muuid ' + MUUID,
        '',
    ]
    for text, value in done:
        out.append('[%s]' % text)
        out.append(value)

    if missing:
        out += ['', ';--- %s ---' % meta['missing'], '']
        for text, _ in missing:
            out.append(';[%s]' % text)

    io.open(out_path, 'w', encoding='utf-8', newline='\r\n').write('\n'.join(out) + '\n')

    total = len(strings)
    print('strings found: %d' % total)
    print('translated:    %d (%.0f%%)' % (len(done), 100.0 * len(done) / total))
    print('remaining:     %d' % len(missing))
    return 0


if __name__ == '__main__':
    sys.exit(main())
