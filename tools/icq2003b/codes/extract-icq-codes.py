# Справочники кодов ICQ — из файлов самого клиента, а не придуманные.
#
# .fld:  <item><code=100><icon=00><name="Art"></item>
# .txt:  код<TAB>название
import io
import json
import re

SRC = r'C:\Program Files (x86)\ICQ\DataFiles'
OUT = r'W:\GitHub\Bots\open-oscar-server\deploy\oscar-register\icq-codes.json'

ITEM = re.compile(r'<item>(.*?)</item>', re.S)
CODE = re.compile(r'<code=(-?\d+)>')
NAME = re.compile(r'<name="(.*?)">', re.S)


def read(path):
    raw = io.open(path, 'rb').read()
    for enc in ('utf-8-sig', 'cp1252', 'latin-1'):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode('latin-1')


def from_fld(name):
    text = read(SRC + '\\' + name)
    out = {}
    for body in ITEM.findall(text):
        code, title = CODE.search(body), NAME.search(body)
        if not code or not title:
            continue
        out[int(code.group(1))] = title.group(1).strip()
    return out


def from_txt(name):
    out = {}
    for line in read(SRC + '\\' + name).splitlines():
        parts = line.split('\t')
        if len(parts) < 2 or not parts[0].strip().lstrip('-').isdigit():
            continue
        out[int(parts[0])] = parts[1].strip()
    return out


codes = {
    'countries': from_fld('countries.fld'),
    'languages': from_fld('languages.fld'),
    'interests': from_fld('Interest.fld'),
    'occupations': from_txt('Occupation.txt'),
    'past': from_txt('PastBG.txt'),
    'groups': from_txt('Group.txt'),
}

for key, table in codes.items():
    print(f'{key}: {len(table)}')
    sample = list(table.items())[:3]
    print('   ', sample)

# Ключи JSON — строки; выдерживаем порядок по коду, чтобы файл читался глазами.
ordered = {k: {str(c): n for c, n in sorted(v.items())} for k, v in codes.items()}
io.open(OUT, 'w', encoding='utf-8', newline='\n').write(
    json.dumps(ordered, ensure_ascii=False, indent=1) + '\n')
print('записано в', OUT)
