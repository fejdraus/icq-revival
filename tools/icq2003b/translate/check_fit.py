"""Tries shorter translations against the controls that were too small.

    python check_fit.py candidates.json

candidates.json: {"<English text>": "<Ukrainian candidate>", ...} for texts
listed in overflow.json (run build.py first). Prints, for each, whether the
candidate fits every control the English text sits in, measured as build.py
measures, and how many pixels it is over where it does not.
"""

import json
import os
import sys

import fit

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    with open(os.path.join(HERE, 'overflow.json'), encoding='utf-8') as f:
        overflow = json.load(f)
    with open(sys.argv[1], encoding='utf-8') as f:
        candidates = json.load(f)
    places = {}
    for o in overflow:
        c = dict(o['control'])
        if isinstance(c['cls'], list):
            c['cls'] = tuple(c['cls'])
        places.setdefault(o['en'], []).append(c)
    bad = 0
    for en, uk in candidates.items():
        if en not in places:
            print(f'NOT IN overflow.json: {en!r}')
            continue
        over = [int(fit.need(c, uk) - fit.px_x(c['cx'])) for c in places[en] if not fit.fits(c, uk)]
        if over:
            bad += 1
            print(f'TOO LONG by {max(over)}px: {uk!r}')
        else:
            print(f'fits: {uk!r}')
    print(f'{len(candidates) - bad} of {len(candidates)} fit')


if __name__ == '__main__':
    main()
