"""Collects the interface texts of ICQ Pro 2003b for translation.

    python extract.py <client folder> [uk-UA.json]

Reads every menu, dialog and string table of the client's programs and
libraries and brings the translation file up to date: a text seen for the
first time is added untranslated (null), one no longer found is kept - it
does no harm and may come back with another build. Texts that are not
words for a person - format strings, paths, registry names, addresses - are
marked to stay as they are (the value equals the key).

Also writes <translation file>.context.json next to it: where each text is
used, for whoever translates. That file is not needed to build.
"""

import glob
import json
import os
import re
import sys
from collections import OrderedDict

import pefile

import icqres

HERE = os.path.dirname(os.path.abspath(__file__))


def technical(text):
    """Whether a text is plainly meant for the program rather than a person.
    Only the obvious cases: whatever is in doubt goes to the translator, who
    gives back unchanged what is not words for a person."""
    t = text.strip()
    if not re.search(r'[A-Za-z]{2}', t):
        return True                                   # no words at all
    if t.startswith('{\\rtf') or t.startswith('\\'):
        return True                                   # rich text markup
    if re.fullmatch(r'(https?|ftp|mailto)://\S+|www\.\S+|\S+@\S+\.\S+', t, re.I):
        return True                                   # an address alone
    if ' ' not in t and re.fullmatch(r'[A-Za-z0-9_#]+', t) and re.search(r'_|\d|#', t):
        return True                                   # identifiers: ICQ_C4R4_R4SCHEMA, List2
    return False


def collect(root):
    """(text, where) for every text of the client, in file order."""
    files = sorted(glob.glob(os.path.join(root, '*.exe')) + glob.glob(os.path.join(root, '*.dll')) +
                   glob.glob(os.path.join(root, '*.ocx')))
    for path in files:
        name = os.path.basename(path)
        try:
            res = list(icqres.resources(path))
        except pefile.PEFormatError:
            continue
        for rtype, rname, lang, data in res:
            kind = icqres.KINDS[rtype]
            for i, text in enumerate(icqres.texts(rtype, data)):
                if not text:
                    continue
                where = f'{name} {kind} {rname}'
                if rtype == icqres.RT_STRING:
                    where = f'{name} string {(rname - 1) * 16 + i}'
                elif rtype == icqres.RT_DIALOG:
                    where += ' caption' if i == 0 else f' control {i - 1}'
                yield text, where


def main():
    root = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, 'uk-UA.json')
    old, rest = {}, OrderedDict()
    if os.path.exists(target):
        with open(target, encoding='utf-8') as f:
            rest = json.load(f, object_pairs_hook=OrderedDict)
        old = rest.get('texts', {})
    texts, context = OrderedDict(), OrderedDict()
    for text, where in collect(root):
        context.setdefault(text, []).append(where)
        if text not in texts:
            if text in old:
                texts[text] = old[text]
            else:
                texts[text] = text if technical(text) else None
    for text, value in old.items():   # kept, see above
        texts.setdefault(text, value)
    doc = OrderedDict([
        ('about', 'Ukrainian interface of ICQ Pro 2003b. Key: the English text as the client has it; '
                  'value: the Ukrainian one, the same text to keep it, null while not translated yet. '
                  'Keep %s, %d, %1, \\n, \\t and the & of access keys.'),
        ('texts', texts),
    ])
    for key, value in rest.items():      # "inplace" and whatever comes after
        if key not in doc:
            doc[key] = value
    with open(target, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write('\n')
    with open(os.path.splitext(target)[0] + '.context.json', 'w', encoding='utf-8', newline='\n') as f:
        json.dump(context, f, ensure_ascii=False, indent=1)
    todo = sum(1 for v in texts.values() if v is None)
    kept = sum(1 for k, v in texts.items() if v == k)
    print(f'{len(texts)} texts: {todo} to translate, {kept} kept as they are, '
          f'{len(texts) - todo - kept} translated')


if __name__ == '__main__':
    main()
