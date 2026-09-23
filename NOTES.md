# Свой сервер ICQ на junior

Развёрнутый [Open OSCAR Server](https://github.com/mk6i/open-oscar-server) для друзей и
коллег: ретро-клиенты ICQ и AIM работают с ним так же, как когда-то с настоящими
серверами Mirabilis.

В этом репозитории — исходники сервера с нашей правкой, файлы развёртывания и
инструменты для клиента. Каталог `deploy/` собран с живой машины, поэтому его
содержимое совпадает с тем, что реально работает.

---

## Что где развёрнуто

Хост `junior` (SSH-хост `lan-43`, 192.168.1.43, в тайлнете — `chat.example.ts.net`,
100.77.29.116).

| что | где | порт |
|---|---|---|
| Open OSCAR Server | `/opt/open-oscar-server/` | OSCAR 5190, TOC 9898, legacy ICQ UDP 4000 |
| management API | там же | `127.0.0.1:8090` (8080 занят посторонним сервисом) |
| WebAPI | там же | 8082 |
| страница регистрации | `/opt/oscar-register/` | 8099, снаружи — HTTPS 8444 |
| админка | `/opt/oscar-admin/` | 8100 |
| TLS-фронт (nginx в контейнере) | `/etc/oscar-nginx/` | 1443, 3143, 5193, 8443 |

База: `/var/lib/open-oscar-server/oscar.sqlite`, владелец — системный пользователь `oscar`.

### Порты для клиентов

- **5190** — без шифрования; ICQ 2000b–5.1, ICQ Pro 2003b, QIP, Pidgin;
- **5193** — OSCAR поверх TLS с сертификатом Let's Encrypt от Tailscale, для Miranda NG
  и прочих современных клиентов;
- **3143** — тот же OSCAR поверх TLS, но с нашим корневым RSA-сертификатом: его
  требует AIM 6.2–7.x, чьи библиотеки NSS 2011 года не понимают ECDSA;
- **1443** — Kerberos/UAS, через него авторизуются AIM 6.2+.

Шифрование для клиентов без SSL даёт Tailscale: наружу порты не выставлены,
трафик идёт внутри WireGuard.

---

## Наша правка сервера: регистрация номера из клиента

Кнопка «Get an ICQ Number» в ICQ Pro 2003b теперь работает — сервер выдаёт номер
и заводит учётную запись.

Готовый diff: `patches/icq-registration.diff`, скрипт наложения на чистое дерево:
`patches/patch-register.py`.

**Что происходит по протоколу.** Клиент открывает отдельное соединение на тот же
порт 5190 и шлёт `SNAC(0x17,0x04)` — `BUCPRegisterRequest`. Внутри `TLV(0x0001)`
лежит блок ICQ-регистрации, **целиком в обратном порядке байт** (в отличие от
самих SNAC):

```
смещение 0   dword 0
смещение 4   word 0x0028 (длина блока 40), word 0x0003 (версия)
смещение 16  dword cookie          ← сервер обязан вернуть его в ответе
смещение 40  word длина пароля, далее пароль со завершающим нулём
```

Пароль передаётся **открытым текстом** — формат разобран по живому дампу
(`tcpdump -i any -w /tmp/reg.pcap 'tcp port 5190'`), а не по документации.

Ответ — `SNAC(0x17,0x05)` с `TLV(0x0001)`, внутри служебный блок и выданный
номер, следом пустой FLAP канала 4 как сигнал закрыть соединение. Раскладка
ответа взята из [описания протокола](https://kingant.net/oscar/?family=0x0017&subtype=0x0005);
оно помечено как незаконченное, но собранный по нему ответ клиент принял сразу.

**Изменённые файлы:**

- `wire/snacs.go` — константы `BUCPRegisterResponse` и `ICQTLVTagsRegistration`;
- `foodgroup/auth.go` — метод `AuthService.BUCPRegister`, подбор свободного номера
  (`nextFreeUIN`, перебор со 100000 с проверкой занятости), сборка ответа
  (`icqRegistrationReply`);
- `server/oscar/server.go` — ветка `BUCPRegisterRequest` в разборе фазы логина;
- `server/oscar/types.go` — метод в интерфейсе `AuthService`.

**Сборка.** По `go.mod` нужен Go 1.26, на junior стоит 1.24, поэтому через контейнер:

```bash
sudo docker run --rm -v ~/oscar-src:/src \
  -v /tmp/gocache:/root/.cache/go-build -v /tmp/gomod:/go/pkg/mod \
  -w /src golang:1.26 go build -buildvcs=false -o /src/open_oscar_server_new ./cmd/server
```

Предыдущий бинарник сохраняется как `/opt/open-oscar-server/open_oscar_server.before-register`.

Ограничение: `nextFreeUIN` перебирает номера по одному с запросом в базу на каждый.
Для десятка учёток незаметно, для тысяч нужно переделать на поиск первой дыры одним
запросом.

---

## Наша правка сервера: вход по адресу почты

В окне входа старых клиентов поле подписано «ICQ#/Email» — настоящий сервер
принимал вместо номера адрес почты. Это видно по строкам в самом `Icq.exe`:

```
ICQ#/Email:
Login By Email Options (Web)
You have tried to login using an incorrect password, ICQ number, or an email
address that was not validated.
```

Отдельного протокола тут нет: клиент шлёт в поле имени то, что ввели, а номер
по адресу находит сервер. Поэтому правка целиком серверная, клиенты трогать не
нужно.

**Какой адрес пускает ко входу.** Любой, привязанный к учётной записи, — их три
источника, и все три равноправны:

- анкета ICQ, `users.icq_basicInfo_emailAddress` (правится из клиента);
- учётная запись AIM, `users.emailAddress` (правится из клиента через ADMIN);
- адрес восстановления пароля — своя база `oscar-register`, зеркалится в
  таблицу `loginEmail` основной базы (миграции `0044`, `0045`).

Подтверждение письмом ко входу отношения не имеет: привязать адрес можно, только
зная текущий пароль учётной записи, поэтому непривязанный адрес всё равно никуда
не пускает. Подтверждение нужно самому восстановлению пароля — чтобы ссылка ушла
в ящик, который человек действительно читает.

Адрес **необязателен**. Без него всё работает как раньше: вход по номеру, забытый
пароль сбрасывает администратор.

**Один адрес — одна учётная запись.** Иначе по адресу нельзя понять, кого
впускать. Проверка стоит на каждом пути записи, а не в одном месте формы:

- `SQLiteUserStore.emailFree` — внутри `SetBasicInfo` (анкета ICQ) и
  `UpdateEmailAddress` (адрес AIM), то есть на любом сохранении профиля, откуда
  бы оно ни пришло;
- клиенту отказ приходит по протоколу, а не разрывом связи: ICQ получает
  `ICQStatusCodeFail` в ответе на сохранение анкеты, AIM —
  `AdminInfoErrorInvalidEmail`;
- `oscar-register` проверяет то же самое при привязке (`409 mail_taken`) и ещё
  раз при переходе по ссылке из письма: между этими моментами адрес мог занять
  кто-то другой. Если основная база недоступна, служба отказывает, а не рискует
  выдать адрес дважды;
- `EmailOwner` на неоднозначный адрес возвращает пусто и не впускает никого —
  на случай, если две записи всё-таки разойдутся.

`DeleteUser` стирает строку в `loginEmail`: номера выдаются повторно, и забытая
строка впустила бы прежнего владельца в чужую учётную запись.

**Изменённые файлы:**

- `state/migrations/0044_verified_email.*.sql`, `0045_login_email.*.sql`;
- `state/user_store.go` — `EmailOwner`, `emailFree`, проверки в `SetBasicInfo`
  и `UpdateEmailAddress`, очистка в `DeleteUser`;
- `foodgroup/types.go` — метод `EmailOwner` в интерфейсе `UserManager`;
- `foodgroup/auth.go` — подмена адреса на номер в `login()`; адрес, который
  никому не принадлежит, получает ошибку ICQ, а не AIM (поле «ICQ#/Email» есть
  только у ICQ);
- `foodgroup/icq.go` — отказ в ответе на сохранение анкеты (`reqAckStatus`);
- `foodgroup/admin.go` — отказ в ответе на смену адреса AIM;
- `deploy/oscar-register/server.js` — `syncLoginEmail`, `emailOwner`, тексты;
- `deploy/oscar-legacy-web/topics.json` — страница `/e` в клиенте.

---

## Веб-сервисы

Оба написаны без внешних зависимостей, на голом Node (`node:sqlite`, `node:http`),
в ретро-оформлении окон Windows 98, с поддержкой ru/en/uk по `Accept-Language`.

### Страница регистрации — `deploy/oscar-register/`

`https://chat.example.ts.net:8444/` (внутри тайлнета; HTTP-порт 8099 тоже отвечает).

Разделы:

- `/` — регистрация номера: подбор свободного, проверка занятости, необязательная
  почта для восстановления;
- `/password` — смена пароля и привязка почты;
- `/recover` — восстановление по почте, одноразовая ссылка на 30 минут;
- `/account` — смена номера и удаление учётной записи;
- `/verify` — подтверждение адреса из письма.

**Смена пароля** нужна потому, что management API умеет только менять пароль, но не
проверять текущий. Сервис сверяет хеш сам, открывая `oscar.sqlite` только на чтение;
алгоритм повторяет `wire/user.go`:

```
weakMD5Pass   = MD5(authKey + пароль + "AOL Instant Messenger (SM)")
strongMD5Pass = MD5(authKey + MD5(пароль) + "AOL Instant Messenger (SM)")
```

**Восстановление по почте.** Адреса и одноразовые ссылки — в отдельной базе
`/var/lib/oscar-register/recovery.sqlite`; в профиль ICQ адрес класть нельзя, это
поле ищется через каталог и стало бы публичным. От токена хранится только SHA-256.
SMTP-клиент написан вручную (`mail.js`): EHLO, STARTTLS, AUTH LOGIN, тема в RFC 2047,
тело base64. Настройки ящика — в `/etc/oscar-register/mail.env` (права 640, шаблон:
`deploy/config/mail.env.example`); пока `SMTP_HOST` пуст, страница честно отвечает,
что отправка не настроена.

**Смена номера.** Переименовать номер сервер не умеет — нет такого маршрута, а
`identScreenName` это первичный ключ. Поэтому: создать новый, перенести пароль,
анкету и контакт-лист, удалить старый — именно в таком порядке, чтобы при сбое
старый остался цел.

**Грабли management API:** `DELETE /user` чистит только таблицу `users`. У `feedbag`,
`profile`, `buddyListMode` и `clientSideBuddyList` внешних ключей нет, и их строки
остаются сиротами — освободившийся номер достался бы новому владельцу вместе с чужим
контакт-листом. Сервис подчищает эти четыре таблицы сам.

### Страницы вместо исчезнувших служб — `deploy/oscar-legacy-web/`

Служба `oscar-legacy-web.service`, `/opt/oscar-legacy-web`, порт 8101, снаружи —
через nginx с TLS на 8102. `ExecReload` шлёт `SIGHUP`: `services.json` и
`topics.json` перечитываются без перезапуска.

Родительский юнит держит её через `Upholds=` — как и страницу регистрации.
Без этого `PartOf=` гасил бы её вместе с сервером, но обратно не поднимал.

Страницы разделов собираются из `topics.json`. У раздела либо `use` — список
указаний, что делать, — либо `here`, одна фраза, когда делать нечего: службы
больше нет и заменить её нечем. Отдельной рамки «на этом сервере» нет: если
что-то работает, страница просто говорит как этим пользоваться.

Признак `now` отмечает разделы, предмет которых работает и сейчас, — своя
возможность клиента или нашего сервера. Их описание пишется в настоящем
времени, и подпись в шапке у них «як це працює» вместо «що це було». Из 42
разделов таких 22; у остальных прошедшее время честное — этих служб больше
нет.

### Страница профиля — `deploy/oscar-register/profile.js`

`/profile` — вход по номеру и текущему паролю, дальше вся анкета ICQ в одном
месте. Отдельным файлом, потому что разметка большая.

Печенья и сессии нет: пароль живёт только в памяти вкладки и подписывает каждое
действие — так же, как на остальных страницах этой службы.

Анкета читается и пишется **через управляющий API** (`GET`/`PUT
/user/{uin}/icq`), а не прямо в базу. Тогда правки со страницы проходят те же
проверки, что и правки из клиента, — включая «один адрес — одна учётная запись».
Занятый адрес возвращается как `409 mail_taken` (раньше этот случай выглядел как
«внутренняя ошибка»).

**Выпадающие списки** — страны, языки, род занятий, категории интересов,
прошлое, организации — собраны из файлов самого клиента, а не выдуманы:
`DataFiles/countries.fld`, `languages.fld`, `Interest.fld`, `Occupation.txt`,
`PastBG.txt`, `Group.txt`. Результат лежит в `deploy/oscar-register/icq-codes.json`,
скрипт разбора — `tools/icq2003b/codes/extract-icq-codes.py` (формат простой:
`<item><code=100><name="Art"></item>` либо `код<TAB>название`).

**Приватность** — родные флаги ICQ и только они: показывать адрес
(`PublishEmail`), требовать авторизацию, статус виден через веб, приём рассылок.
Отдельной видимости у остальных полей в протоколе не было.

**Смена пароля переехала сюда**, `/password` отвечает редиректом на `/profile`,
старая страница удалена. Смена номера и удаление учётной записи остались на
`/account`.

**Чего в форме нет и почему:**

- часовой пояс (`GMTOffset`) — в каком виде ICQ его хранит, по коду сервера не
  видно, а записать наугад значит испортить анкету. Его по-прежнему ставит клиент;
- «родом из» (`OriginallyFrom*`) — управляющий API их отдаёт, но `SetBasicInfo`
  в сторе эти столбцы не обновляет, то есть записать их нечем.

Маршрут `/user/{screenname}/icq`, на котором держится страница, описан в
`api.yml` (раньше он был реализован, но не задокументирован): `GET`/`PUT`, схемы
разделов анкеты и коды отказов, включая `409` на занятый адрес.

### Админка — `deploy/oscar-admin/`

`http://192.168.1.43:8100`, HTTP Basic, пароль в `/etc/oscar-admin/secret.env`
(в репозиторий не попадает). Умеет: список учёток с сессиями, создание, сброс пароля,
блокировку, разрыв сессии, удаление.

**Грабли:** снятие блокировки — это `PATCH /user/{name}/account` с
`{"suspended_status": ""}` (пустая строка). На `null` сервер отвечает `304 Not Modified`:
`null` трактуется как «поле не передано».

---

## TLS и сертификаты

`tailscale cert chat.example.ts.net` выдаёт настоящий Let's Encrypt, обновление —
таймером `oscar-cert-renew` раз в неделю (`deploy/scripts/oscar-cert-renew.sh`).

Для AIM пришлось выпустить **свой корневой RSA CA**: сертификат Tailscale подписан
ECDSA, а библиотеки NSS 2011 года его не понимают. Сертификат ставится в базу NSS
клиента (`%APPDATA%\acccore\nss`, формат dbm, не sqlite).

Отдельная история — nginx: AIM 6.2–7.x начинают рукопожатие приветствием в формате
SSLv2, разбор которого выкинули из OpenSSL начиная с 1.1.0. Поэтому TLS-фронт собран
с OpenSSL 1.0.2u (`ras-nginx:1.28.0-openssl-1.0.2u`).

**Грабли:** конфиг и сертификаты примонтированы в контейнер отдельными файлами, и
замена файла новым inode (`install`, `mv`, `sed -i`) контейнеру не видна. Нужен `cp`
поверх существующего файла или `docker restart oscar-nginx`. `nginx -t` при этом
честно проверяет старое содержимое и ничего не замечает.

---

## Клиенты

| клиент | статус |
|---|---|
| ICQ Pro 2003b | работает полностью, включая регистрацию из клиента и поиск |
| Miranda NG | работает, в том числе поиск по UIN и профили |
| QIP 2005 build 8092 | работает полностью |
| ICQ 6.5 | работает: анкеты, поиск, переписка. SSL не умеет вообще |
| AIM 7.5.14.8 | работает по TLS через Kerberos (1443 → 3143) |
| ICQ 7.x | вход не осилили: доходит до `getChallenge`, ответ не принимает |
| R&Q после 2019 | не подходит: из него удалили OSCAR, остался только WIM |

---

---

## Адрес сервера в ICQ 6.5

Адрес задаётся в самом клиенте: «Параметры → Соединение → вручную → Сервер ICQ»,
поля «Узел» и «Порт» (`idIcqServerHost`, `idIcqServerPort` в
`OPrefsPanelConnection.box`). Это путь для пользователя, патчить ничего не нужно.

По умолчанию там `login.icq.com` — он зашит строкой UTF-16 в `MCore.dll`. Его
можно заменить на месте, если хочется, чтобы клиент сразу шёл на наш сервер
без настройки: длина должна совпасть ровно, `login.icq.com` это 13 символов, и
адрес вида `100.77.29.116` подходит как есть. Исходный файл тогда сохраняется
рядом (`MCore.dll.oscar-backup`). Ни hosts, ни DNS не нужны ни в одном из
вариантов.

---

---

## ICQ 6.5 patch - `tools/icq65/patch/`

`Icq6Patch.exe` is what a user runs: one window, the same kind as the 2003b
patch. It finds the client, takes the server address (remembered in
`HKCU\Software\OpenOSCAR\Icq6Patch`), and in one pass removes the Xtraz,
advertising, tZers, SMS and phone parts of the interface, patches the
"SMS & Phone" entry out of `MUICore.dll`, points the ICQ.com pages at the
server and whitelists it, and empties the advertising, teaser and SMS carrier
lists. The sign-in server is left to the user: Options -> Connection -> ICQ
server. `-Apply`/`-Restore` with `-Root` and `-Server` run it without the
window.

It is checked against a pristine copy of build 2024: applied, it matches what
the two Python tools below produced byte for byte, apart from the byte order
marks those tools wrongly added to files that had none; restored, it matches
the pristine copy exactly; applied twice, the second run changes nothing. It
also restores files backed up by the Python tools, so a client patched the old
way can be returned to the original with it.

The sections below describe the findings it is built on.

## Dead ICQ 6.5 web services - `tools/icq65/retarget/`

Besides signing in, ICQ 6 fetches over HTTP from services that are long gone:
Xtraz on `xtraz.icq.com` and `df.icq.com`, help and guides on `labs.icq.com`,
updates and emoticon packs on `update.icq.com`. The addresses sit in plain text
in `ConfigFiles\*.xml`, so the tool rewrites the host and keeps the path: the
`oscar-legacy-web` routes match the original ICQ 6 paths.

**Only pages are moved.** What the client parses itself stays on the dead hosts
on purpose - `Master.xml`, `Packages.xml`, `tzer.xml`, `Searches.xml`,
`adConfig.xml`. Answering those at all is worse than not answering: with a dead
host the request times out and the client keeps its built-in defaults, while any
prompt reply - even a 404 - makes it treat the list as empty and drop that part
of the interface. That is how the tab strip, the hint in the search box and the
bottom panel disappeared during the first attempt.

**The client checks where content comes from.** `XtraConfig.xml` carries a
`WhiteDomainList` key and `tzer.xml` a `<whitelist>` block; a host that is not
listed is refused together with everything it feeds. Our host has to be added to
both, which the tool does.

**The interface itself is editable markup.** Everything the client draws lives
under `services/icqApp/ver1/` as Boxely files - `.box` markup, `.style.box`
styles, `.dtd` strings - not compiled into the binaries. A widget is removed by
marking it `collapsed="true"`, which is how the client hides its own optional
parts, and `tools/icq65/declutter` does that for the frames left behind by the
dead services: the Xtraz strip above the contact list (`idXtrazBarArea`), the
entertainment panel below it with its ad slot (`idMainEntertainmentBox`), the
banner under the message window (`idBottomBannerContainer`), the SMS and phone
buttons of the message toolbar (`btnSMS`, `btnPhone`) and the "My Xtraz" item of
the main menu.

Not everything is in the markup: the "Free SMS" button of the message window and
the "SMS & Phone" entry of the preferences list are built in code, so only their
strings live in the `.dtd` files and neither can be collapsed.

The entry comes from a table of 16-byte records in `MUICore.dll` - panel loader,
name, label key, icon - written by a run of `mov` instructions at file offset
`0x258CDA`, where the SMS record sits between "Connection" and "Advanced".
Zeroing its four fields does remove the entry and takes the whole preferences
dialog with it: the code walks the table by a count rather than stopping at an
empty record. Removing the record for real means moving every later one up and
correcting that count, which is a code change rather than a substitution. So the
entry stays and its panel is taken away instead, leaving it to open an empty
page.

Two more things the client draws by code, whatever the markup says: the ad
element and the Xtraz buttons. The ad element cannot be dropped - the code looks
it up and the emoticon and formatting panels stop opening without it - and
collapsing it does not last, because the code shows it a few seconds after the
window opens; zeroing its size in the style sheet is what works. Xtraz add-ons
installed under `packages/` are loaded from disk and keep their buttons however
the Xtraz list is answered, so such a package is disabled by renaming its
directory.

**Xtraz and the advertising are now removed, not stubbed.** The client draws
the Xtraz strip, the teaser row and the ad slots only while something describes
them: the slots come from the `<spot>` entries of `adConfig.xml`, the teasers
from the `<tz>` entries of `tzer.xml`, both local files, and the strip from the
Xtraz list fetched over HTTP. Emptying the two local lists and answering the
list request with a list that holds nothing but the welcome entry removes all
three from the interface for good. The welcome entry has to stay: "Welcome to
ICQ" in the main menu opens an entry from this same list, and an entirely empty
list takes that with it. Note the container element is `<xtraz>`, not `<xtras>`
- with the wrong name the client reads the list and finds no entries in it. A 404 is not enough for the list: the client then keeps the
copy it cached earlier and goes on drawing the buttons that copy describes.
`--keep-xtraz` leaves them in place, and the notes below describe what that
takes.

**The Xtraz gallery is fed by a list, not by a page.** `XtrazListUrl` points at
`xtrazlist.xml`, and the client fills its own window from it, so a stub page
cannot stand in. The service now serves a minimal list in the original schema
(`xtrazList / groups / xtraz`) holding one `dhtml` item that opens our "coming
later" page inside the client.

Only `type="dhtml"` opens a remote address. Most of the original entries are
`localDhtml` (a package the client unpacks on disk first) or `boxely` (its own
XUL-like runtime); such an entry fetches a page served to it and then drops it,
which looks exactly like the fetch never happening. Serving the archived list
keeps the client's own categories, so every entry in it is rebuilt into the
plain `dhtml` shape, keeping its id - the buttons find entries by id - and its
window size.

**A DTD is required.** Before parsing the list the client fetches
`XtrazStringsUrl` + `/<lang>/xtraz_list.dtd`. The original declared entities for
the translated names; ours needs none, but the fetch has to succeed - on a 404
the parse fails and the window only reports "a problem opening Xtra".

**The list is cached for `ReloadTimeout`** (21600 seconds by default), so a
change only takes effect after the client restarts, not after the window is
reopened.

Backups are kept next to the originals with the `.icq6-retarget-backup` suffix
and `--restore` puts them back. Binaries are left alone: the sign-in address
`login.icq.com` is set by the user under Options → Connection → ICQ server.

`MXtraz.dll` is only a string inside `MISB.dll`, not a missing file - the Xtraz
engine itself is `MISB.dll`, listed in `ICQ.exe.csassembly` and exporting
`XtraApi`, `XtraManager`, `DownloadManager` and `CacheManager`.

The request log in `oscar-legacy-web` (off with `LOG_REQUESTS=0`) is what settled
every one of these: three times in a row it showed what the client actually asks
for, where guessing had failed.

---

## Сохранение анкеты из QIP 2012 — шесть отдельных неисправностей

QIP пишет анкету **двумя запросами подряд**: сперва классическим `SetFullInfo`
(`0x0C3A`), следом директорным обновлением (`0x0FD2`). Побеждает второй, и
разбираться приходилось с обоими. Найденное по порядку:

1. **Ошибка разбора рвала соединение.** Любая ошибка обработчика ICQ-запроса
   обрывает сессию; клиент молча входил заново и перечитывал прежнюю анкету —
   со стороны выглядело как «сохранил, и всё очистилось». Нечитаемое поле
   теперь пропускается (`readICQField`), а не роняет сохранение целиком.
2. **Почта без признака публикации.** При пустом адресе QIP обрывает значение
   на самой строке, и разбор упирался в EOF. Разбирается в два приёма.
3. **Нумерация телефонов была смещена на единицу.** В протоколе `1` —
   домашний, `2` — рабочий, `3` — сотовый, `4` — факс, `5` — рабочий факс
   (`fam_15icqserver.cpp`, `getRecordByTLV(0x6E, 1..5)`). С отсчётом от нуля
   домашний телефон ложился в рабочий, сотовый — в факс, факс — в рабочий факс.
4. **Список телефонов дописывался поверх.** Клиент шлёт его целиком, поэтому
   список замещает все пять полей: иначе стёртый в клиенте номер оставался в
   анкете навсегда.
5. **Числовые коды приходят четырьмя байтами.** Страна, отрасль, вид интереса:
   QIP кладёт их в четыре байта, а чтение первых двух давало ноль. Читаем 1, 2
   и 4 байта, пишем четырьмя — `getNumber` у Miranda понимает любую из длин
   (`tlv.cpp`), так что старым клиентам это не мешает.
6. **Место рождения не доходило до базы.** Директорное сохранение пишет через
   `SetBasicInfo`, а в его `UPDATE` не было трёх колонок: `originCity`,
   `originState`, `originCountryCode`. Разбор при этом отрабатывал верно —
   значения просто некуда было записать.

**Длину числовых полей приходится повторять за клиентом.** Читаем терпимо —
1, 2 или 4 байта, — а пишем в той длине, в какой поле присылает сам клиент:
страну QIP шлёт четырьмя байтами и двухбайтовую не читает, а отрасль, языки и
вид интереса — двумя, и четырёхбайтовые не читает тоже. Miranda и ICQ 6
безразличны: их `getNumber` понимает все три длины (`tlv.cpp`).

**Семейное положение** (метка `0x012C`) хранить было негде — добавлена колонка
`icq_moreInfo_maritalStatus` (миграция `0046`), поле в `ICQMoreInfo`, разбор в
директорном диалекте и `marital_status` в управляющем API. Коды берутся из
списка клиента: 10 — холост, 11 — в отношениях, 12 — помолвлен, 20 — женат,
30 — разведён, 31 — раздельно, 40 — вдовец, 50 — свободные отношения.

**Справочники кодов между версиями разошлись.** Анкета хранит число, а список
названий у каждого клиента свой: код профессии `18` ICQ 6.5 показывает как
«Перевозки», а справочник из файлов ICQ 2003b (`DataFiles`, из него собран
`deploy/oscar-register/icq-codes.json`) держит на этом месте «Military», и
«Перевозок» в нём нет вовсе. Сервер тут бессилен — он передаёт число; таблицы
перевода между справочниками не существует. Белые страницы пользуются списком
2003b.

**Профессии в директорном диалекте нет.** На её месте «отрасль» (`0x0082`),
другое понятие; профессия живёт только в классическом запросе, метка `0x01CC`.
QIP шлёт оба запроса, и нулевая отрасль из второго стирала профессию,
сохранённую первым. Поэтому ноль оттуда больше ничего не затирает. У Miranda
это же место помечено в коде как `// Lost In Conversion` — её авторы наткнулись
на ту же дыру и просто отключили передачу профессии.

## Патч клиента ICQ Pro 2003b — `tools/icq2003b/patch/`

Убирает рекламу в списке контактов и в окне переписки, строку поиска Google и
пустое место под ними. Четыре точечные правки, каждая — переключение готовой
развилки в коде клиента:

| файл | смещение | было → стало | что делает |
|---|---|---|---|
| `icqmutl.dll` | `0x20626` | `B8 96 9B 22 20` → `31 C0 C2 04 00` | `MCCLBannerDialog::CreatTheCLBannerCtrl` → false |
| `ICQProLib.dll` | `0x1217B` | `B8 BA 7D 89 24` → `31 C0 C3` | `MCProBannersUtils::IsOKToDispalyBanner` → false |
| `ICQTicker.dll` | `0x750` | `53 55 8B 6C 24 14 56` → `B8 11 01 04 80 C2 0C 00` | `DllGetClassObject` → `CLASS_E_CLASSNOTAVAILABLE` |
| `Icq.exe` | `0x39AA2` | `74 41` → `EB 41` | в раскладке не прибавляются 22 px под полосу тикера |
| `ICQMessagePlugin.dll` | `0x7B63`, `0x7B84` | `83 C0 05` → `31 C0 90`, `83 C7 05` → `31 FF 90` | галочки ICQ / SMS / Email в окне сообщения спрятаны |
| `Icq.exe` | `0x1C489C` | `Send By:` → пробелы | надпись над ними |
| `Skin\IcqPro.skn` | `0x41750`, `0x41782` | `-341` → `-133`, `136` → `344` | рамка подтянута к кнопке `Send` |

**Про «Send By».** SMS и Email там — не возможности клиента, а обращения к
шлюзам ICQ.com, которых нет: письмо и SMS уходили бы в никуда, а сервер отвечал
бы «пользователь не в сети». Оставлять выбор, у которого один рабочий вариант,
незачем.

**Полоса собрана из трёх слоёв, и они не знают друг о друге** — это главное, что
стоило трёх неудачных попыток:

1. **галочки** — элементы диалога плагина, но видимость задаёт **не шаблон**, а
   подпрограмма раскладки: она сама вызывает `ShowWindow`, вычисляя аргумент как
   `neg eax; sbb eax,eax; and al,0xFB; add eax,5` — то есть 5 (`SW_SHOW`) или 0.
   Обнуление результата заставляет клиент спрятать их собственным вызовом.
   Элементы остаются в диалоге, галочка ICQ — отмеченной, поэтому код читает её
   как раньше и `Send` работает;
2. **надпись** — элемента за ней нет вовсе (опрос открытого окна показывает, что
   `1007` не создаётся): её рисует скин по строке 8727 из `Icq.exe`. Затирается
   пробелами той же длины — в таблице строк длина хранится отдельно;
3. **рамка** — объект `RgnFrame` в `Skin/IcqPro.skn`. Положение считается по
   якорям и смещениям, а не по прямоугольнику, поэтому двигать нужно `m_Offset`;
   прямоугольник правится следом, чтобы файл не противоречил сам себе. Прятать
   объект целиком нельзя: он участвует в форме окна, и без него правый край
   срезает указатель отправки.

Число 344 — предел, до которого скин рисует изгиб левого края: он часть
растягиваемой картинки и ниже этой ширины заметно сплющивается.

**Вывод на будущее:** в этом клиенте видимость решает код и скин, а не ресурсы.
Проверять правку нужно запуском и опросом живого окна
(`tools/icq2003b/patch/dialog/inspect-window.ps1`), а не разбором шаблонов —
дважды подряд разбор давал уверенный, но неверный ответ.

Контрольные суммы у записей для `Icq.exe` относятся к файлу с уже наложенными
остальными правками, поэтому состояние определяется сверкой байтов по смещению,
а сумма служит быстрым путём.

Файлы: `IcqAntibanner.exe` (окно, находит папку клиента само), `IcqAntibanner.ps1`
(исходник), `icq-antibanner.py` (то же из командной строки).

**Как это было найдено.** Модули ICQ экспортируют декорированные имена C++, то есть
все классы подписаны. Инструменты разбора — в `tools/icq2003b/analysis/`:

- `exports.py` — поиск экспортируемых функций по маске имени;
- `disasm.py` — дизассемблировать экспорт по имени;
- `dis_at.py` — дизассемблировать по файловому смещению;
- `xref.py` — кто ссылается на строку;
- `impxref.py` — кто вызывает импортированную функцию;
- `callers.py` — кто вызывает функцию по RVA;
- `bytepatch.py` — замена байтов с проверкой ожидаемого содержимого;
- `skinmap.py` — разбор геометрии скина `IcqPro.skn`.

Нужен `pip install capstone pefile`.

---

## Два диалекта анкеты ICQ — и настроения

Клиенты спрашивают анкету двумя несовместимыми способами, и выбирает способ
клиент, а не сервер: согласования в протоколе нет. Поэтому сервер обязан
понимать оба.

**Классический**, из ICQ 99–2003: запрос `0x07D0` с подтипом `0x04B2`,
`0x04BA` или `0x04D0`, ответ `0x07DA` плоскими блоками (`0x00C8` основное,
`0x00DC` дополнительное и далее). Живёт в `foodgroup/icq.go`.

**Директорный**, из ICQ 6 (Miranda зовёт его MDir): подтипы `0x0FA0` (запрос и
поиск) и `0x0FD2` (сохранение своей анкеты), поля в TLV, строки UTF-8. Живёт в
`foodgroup/icq_directory.go` и `wire/icq_directory.go`.

**Грабли:**

- **Запрос анкеты, поиск и сохранение различаются не только подкомандой.** У них
  три разные раскладки тела: у запроса за признаком блока идёт четырёхбайтовый
  счётчик, у поиска — номер страницы и счётчик по два байта, у сохранения —
  сразу длина данных. Поиск и запрос анкеты вообще ходят одной подкомандой
  `0x0002` и различаются только признаком блока (`0x03` против `0x02`).
- **Подтип ответа решает, снимется ли ожидание.** Клиент разбирает и `0x0FAA`
  («данные»), и `0x0FB4` («ответ»), но подтверждение, закрывающее окно сведений
  и поиск, шлёт только на `0x0FB4`. На `0x0FAA` окно висит вечно — тайм-аута
  там нет. «Данные» ставятся только промежуточным пакетам выдачи.
- **Выдача поиска идёт по одной записи на пакет,** и признак продолжения обязан
  стоять и в SNAC, и внутри директорного блока — клиент проверяет оба. Пустая
  выдача — отдельный пакет с нулевым счётчиком блока.

**Настроения ICQ 6 — не xStatus.** В таблице `capXStatus` плагина 86 мест, но
настоящих GUID только 32; номера выше — настроения, и возможности у них нет.
Они едут отдельным элементом `0x0E` в метке `0x1D` строкой вида `0icqmood65`,
рядом с текстом состояния (элемент `0x02`). Сервер читает оба в
`SetUserInfoFields` и кладёт обратно в сведения о контакте; без этого значок
настроения не менялся бы ни у кого. Тип заведён как `BARTTypesMood` в `wire`.

---

## Плагин ICQ для Miranda NG — `tools/miranda-icq/`

Протокол ICQ из Miranda NG удалён и лежит там как `NotWorkingStuff/Deprecated/IcqOscarJ`
— против нынешнего API не собирается. `IcqOscarJ.diff` переносит его на актуальные
заголовки и заменяет зашитые адреса icq.com на настройку `ICQ/WebBase`, для которой
добавлено поле на вкладку `Сеть → ICQ → Features`. Пусто — остаются прежние адреса.
Пути `/icq/register`, `/icq/password`, `/icq/whitepages` обслуживает `oscar-legacy-web`.

Собранные библиотеки — в `build/x32` и `build/x64`, под ядро 0.96.7. Подробности
сборки, подбора среза исходников и установки — в `tools/miranda-icq/README.md`.

**Грабли:** обе проверки на стороне ядра молчаливые.

- `dll_sniffer.cpp` сверяет версию продукта из ресурса плагина с
  `MIRANDA_VERSION_COREVERSION`. Не совпало — файл вообще не считается плагином:
  нет ни в списке, ни в загрузке, ни одного сообщения. Поэтому плагин собирается
  строго под свою версию ядра.
- `newplugins.cpp` держит `pluginBannedList`, куда UUID исходного `icqoscar8`
  внесён явно. У порта свой UUID.

**Перевод.** Строки в Miranda привязаны к плагину меткой `#muuid`, а раздела для
протокола ICQ в нынешних паках нет — удалили вместе с плагином. `langpack_russian_icq.txt`
его возвращает: кладётся в `Languages\`, и в **самый конец** основного пака дописывается
`#include langpack_russian_icq.txt`. Именно в конец — наш файл выставляет `#muuid`, и
всё, что идёт в паке после этой строки, иначе припишется нашему плагину. Собирается
`make-langpack.py`; нынешнего пака хватает на 59% строк, остальное берётся из пака
времён Miranda IM, где раздел `IcqOscarJ` ещё цел.

**Файл нельзя называть `ICQ.dll`.** `PluginUpdater` сверяет MD5 каждого файла со
списком на сервере, номер версии не смотрит. Своя сборка не совпадёт никогда,
поэтому вечно значится «Устарело!», а «Обновить» заменяет её серверной — с
запрещённым UUID, после чего плагин молча перестаёт грузиться.

---

## Грабли, которые стоили времени

**Базу пользователя ICQ 2003b править нельзя.** Любая правка `2003b\<UIN>\O<UIN>.fpt`,
даже побайтовая замена той же длины, рано или поздно ломает её: клиент падает на
старте с «The operation cannot be completed at this time» (коды 259 и 257). Все
правки — только в коде.

**ICQ нельзя снимать через `Stop-Process -Force`.** Клиент не дописывает кэш
контакт-листа `CL\<UIN>.fb`, после чего навсегда зависает на «Logging in…», хотя на
сервере вход проходит успешно (`login_ok=true`, `user signed on`, сессия живёт
минутами). Лечение: удалить `CL\<UIN>.fb`. Закрывать только штатно: трей → Exit,
крестик лишь сворачивает.

**Windows Defender блокирует PowerShell-скрипты, правящие точку входа DLL** (AMSI).
Те же правки на Python проходят — отсюда `bytepatch.py`.

**`AOLDiag\tbdiag.dll` роняет AIM и ICQ 7.** Диагностический модуль 2010 года,
который ставит инсталлятор AIM: через несколько запусков клиент начинает падать с
access violation через секунду после успешного входа. Лечение — переименовать папку
`Common Files\AOL\AOLDiag`.

**Тупики, куда не стоит возвращаться:** флаг `UpBanner` в базе на панель не влияет;
элемент скина `StatTyping` — это статусная строка, её выключение убирает индикацию
подключения и выглядит как «клиент не авторизуется»; пара геттеров 60/62 в
`icqwutl.dll` — это коды символов `<` и `>` из разбора HTML-сущностей, а не размеры.

---

## Развёртывание с нуля

1. Собрать сервер (см. выше), положить в `/opt/open-oscar-server/`.
2. Скопировать юниты из `deploy/systemd/` в `/etc/systemd/system/`, конфиг из
   `deploy/config/settings.env` в `/etc/open-oscar-server/`.
3. Веб-сервисы: `deploy/oscar-register/` и `deploy/oscar-admin/` в `/opt/`,
   пароль админки — в `/etc/oscar-admin/secret.env` (mode 600), почта — в
   `/etc/oscar-register/mail.env` (mode 640, шаблон в `deploy/config/`).
4. TLS-фронт: `deploy/nginx/nginx.conf` в `/etc/oscar-nginx/`, сертификаты рядом,
   контейнер с `--network host`.
5. `systemctl enable --now open-oscar-server oscar-register oscar-admin oscar-cert-renew.timer oscar-backup.timer`.
