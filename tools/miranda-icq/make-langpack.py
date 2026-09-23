# Собирает файл перевода для плагина ICQ.
#
# Переводы в Miranda привязаны к плагину меткой #muuid: ядро ищет раздел с UUID
# плагина, а не найдя — откатывается на строки без привязки. Раздела для
# протокола ICQ в langpack нет, его удалили вместе с самим плагином, поэтому
# переводится хорошо если половина.
#
# Скрипт вытаскивает переводимые строки из исходников и ресурса плагина и
# подставляет к ним готовый русский перевод тех же английских строк из любого
# раздела существующего langpack. Чего не нашлось — выписывается в конец
# закомментированным, чтобы дописать руками.
#
# Источников перевода можно указать несколько: они опрашиваются по порядку, так
# что первым разумно ставить нынешний langpack (современные формулировки), а
# следом — старый, из времён Miranda IM, где раздел ICQ ещё был.
#
#   python make-langpack.py <каталог-плагина> <выходной-файл> <langpack...>
import io
import os
import re
import sys

MUUID = '{A5B4A32D-D2A8-4925-AE3E-1480E41A07B3}'

# Translate("x"), TranslateT("x"), LPGEN("x"), LPGENW("x") и прочие обёртки.
RE_CODE = re.compile(r'\b(?:LPGENW?|Translate[TWU]?)\s*\(\s*"((?:[^"\\]|\\.)*)"')

# Подписи элементов в ресурсе: первая строка в кавычках у каждого объявления.
RE_RC_CTRL = re.compile(
    r'^\s*(?:CAPTION|LTEXT|RTEXT|CTEXT|CONTROL|PUSHBUTTON|DEFPUSHBUTTON|GROUPBOX'
    r'|CHECKBOX|RADIOBUTTON|MENUITEM|POPUP)\s+"((?:[^"]|"")*)"')
# Строки из STRINGTABLE: идентификатор, за ним текст.
RE_RC_STR = re.compile(r'^\s*ID[A-Z_0-9]+\s+"((?:[^"]|"")*)"\s*$')


def unescape_rc(s):
    """В ресурсах кавычка удваивается."""
    return s.replace('""', '"')


def collect(plugin_dir):
    found = {}

    def add(text, where):
        text = text.strip()
        # Пустые, разделители и одиночные подчёркивания переводить нечего.
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
                    # Загрузчик langpack сам превращает \" в кавычку, поэтому
                    # ключ пишется с обычными кавычками. Управляющие
                    # последовательности он тоже разбирает, их оставляем как есть.
                    add(m.group(1).replace('\\"', '"'), name)

    return found


def load_langpack(path, table):
    """Английская строка -> перевод, из всех разделов подряд.

    Дописывает в общую таблицу, не затирая то, что уже нашлось в источнике
    поважнее. Метка порядка байтов у старых файлов встречается, снимаем.
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
    """Точное совпадение, затем послабления: без '&', без учёта регистра,
    с точностью до хвостовых двоеточия и многоточия."""
    if text in table:
        return table[text]
    key = normalize(text)
    return norm.get(key)


def normalize(s):
    s = s.replace('&', '')
    s = s.strip().rstrip(':.… ')
    return s.lower()


def main():
    if len(sys.argv) < 4:
        print('python make-langpack.py <каталог-плагина> <выходной-файл> <langpack...>')
        return 1

    plugin_dir, out_path = sys.argv[1], sys.argv[2]
    strings = collect(plugin_dir)

    table = {}
    for src in sys.argv[3:]:
        before = len(table)
        load_langpack(src, table)
        print('%-60s строк: +%d' % (os.path.basename(src), len(table) - before))

    norm = {}
    for eng, rus in table.items():
        norm.setdefault(normalize(eng), rus)

    done, missing = [], []
    for text in sorted(strings, key=str.lower):
        value = lookup(table, norm, text)
        (done if value else missing).append((text, value))

    out = [
        'Miranda Language Pack Version 1',
        'Language: Русский',
        'Locale: 0419',
        '',
        ';============================================================',
        ';  File: IcqOscarJ.dll',
        ';  Plugin: ICQ protocol',
        ';  Собрано make-langpack.py',
        ';============================================================',
        '#muuid ' + MUUID,
        '',
    ]
    for text, value in done:
        out.append('[%s]' % text)
        out.append(value)

    if missing:
        out += ['', ';--- без перевода ---', '']
        for text, _ in missing:
            out.append(';[%s]' % text)

    io.open(out_path, 'w', encoding='utf-8', newline='\r\n').write('\n'.join(out) + '\n')

    total = len(strings)
    print('строк найдено: %d' % total)
    print('переведено:     %d (%.0f%%)' % (len(done), 100.0 * len(done) / total))
    print('осталось:       %d' % len(missing))
    return 0


if __name__ == '__main__':
    sys.exit(main())
