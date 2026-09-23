"""Добавляет в Open OSCAR Server регистрацию нового номера из клиента.

ICQ Pro 2003b на кнопку «Get an ICQ Number» открывает отдельное соединение к
тому же порту 5190 и шлёт SNAC(0x17, 0x04) — BUCPRegisterRequest. Внутри
TLV(0x0001) лежит блок ICQ-регистрации: всё в обратном порядке байт, по
смещению 40 — длина пароля и сам пароль, по смещению 16 — случайный cookie,
который сервер обязан вернуть в ответе.

Сервер отвечает SNAC(0x17, 0x05) с выданным номером и следом шлёт пустой FLAP
канала 4 — для клиента это сигнал закрыть соединение.

Скрипт правит три файла в дереве исходников и ничего не собирает.
"""

import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'


def patch(path, anchor, addition, marker):
    """Вставляет addition после anchor, если marker ещё не встречается в файле."""
    full = f'{ROOT}/{path}'
    with open(full, encoding='utf-8') as f:
        text = f.read()
    if marker in text:
        print(f'  {path}: уже пропатчен')
        return
    if anchor not in text:
        print(f'  {path}: ЯКОРЬ НЕ НАЙДЕН — пропускаю')
        return
    text = text.replace(anchor, anchor + addition, 1)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f'  {path}: добавлено')


# --- 1. константа ответа -----------------------------------------------------

patch(
    'wire/snacs.go',
    '\tBUCPRegisterRequest          uint16 = 0x0004',
    '\n\tBUCPRegisterResponse         uint16 = 0x0005',
    'BUCPRegisterResponse',
)

# --- 2. обработчик в сервисе аутентификации ---------------------------------

AUTH_CODE = '''

// Смещения внутри блока ICQ-регистрации (TLV 0x0001 запроса SNAC(0x17,0x04)).
// Весь блок записан в обратном порядке байт, в отличие от самих SNAC.
const (
	icqRegCookieOffset   = 16
	icqRegPasswordOffset = 40
	icqRegMinLen         = icqRegPasswordOffset + 2
)

// Диапазон, из которого выдаются номера. Начинаем со 100000 — так же, как это
// делали настоящие серверы ICQ, и как подбирает номер наша страница
// регистрации.
const (
	icqUINFirst = 100000
	icqUINLast  = 2147483646
)

// BUCPRegister выдаёт новый номер ICQ и заводит под него учётную запись.
//
// Клиент шлёт SNAC(0x17,0x04) с выбранным паролем и случайным cookie, сервер
// отвечает SNAC(0x17,0x05) с присвоенным номером. Формат блока — ICQ v8,
// описание: https://kingant.net/oscar/?family=0x0017&subtype=0x0005
func (s AuthService) BUCPRegister(ctx context.Context, snacPayloadIn []byte) (wire.SNACMessage, error) {
	block := wire.TLVRestBlock{}
	if err := wire.UnmarshalBE(&block, bytes.NewReader(snacPayloadIn)); err != nil {
		return wire.SNACMessage{}, fmt.Errorf("разбор запроса регистрации: %w", err)
	}

	reg, ok := block.Bytes(wire.ICQTLVTagsRegistration)
	if !ok || len(reg) < icqRegMinLen {
		return wire.SNACMessage{}, errors.New("в запросе регистрации нет блока с данными")
	}

	cookie := binary.LittleEndian.Uint32(reg[icqRegCookieOffset:])

	passLen := int(binary.LittleEndian.Uint16(reg[icqRegPasswordOffset:]))
	from := icqRegPasswordOffset + 2
	if passLen == 0 || from+passLen > len(reg) {
		return wire.SNACMessage{}, errors.New("в запросе регистрации нет пароля")
	}
	// Клиент передаёт пароль со завершающим нулём, он в длину включён.
	password := strings.TrimRight(string(reg[from:from+passLen]), "\\x00")

	uin, err := s.nextFreeUIN(ctx)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	screenName := state.DisplayScreenName(strconv.Itoa(uin))
	if err := s.createAccount(ctx, screenName, password); err != nil {
		switch {
		case errors.Is(err, state.ErrPasswordInvalid):
			// Клиент сам проверяет длину 6–8 символов, но подстрахуемся.
			s.logger.InfoContext(ctx, "registration rejected: bad password", "uin", uin)
			return wire.SNACMessage{}, err
		default:
			return wire.SNACMessage{}, fmt.Errorf("создание учётной записи %d: %w", uin, err)
		}
	}

	s.logger.InfoContext(ctx, "registered new ICQ number", "uin", uin)

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BUCP,
			SubGroup:  wire.BUCPRegisterResponse,
		},
		Body: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICQTLVTagsRegistration, icqRegistrationReply(uint32(uin), cookie)),
			},
		},
	}, nil
}

// nextFreeUIN подбирает первый свободный номер, начиная со 100000.
func (s AuthService) nextFreeUIN(ctx context.Context) (int, error) {
	for uin := icqUINFirst; uin <= icqUINLast; uin++ {
		u, err := s.userManager.User(ctx, state.NewIdentScreenName(strconv.Itoa(uin)))
		if err != nil {
			return 0, fmt.Errorf("поиск свободного номера: %w", err)
		}
		if u == nil {
			return uin, nil
		}
	}
	return 0, errors.New("свободных номеров не осталось")
}

// icqRegistrationReply собирает тело ответа о регистрации. Все поля — в
// обратном порядке байт; постоянные значения взяты из описания протокола.
func icqRegistrationReply(uin uint32, cookie uint32) []byte {
	buf := make([]byte, 0, 52)
	put16 := func(v uint16) { buf = binary.LittleEndian.AppendUint16(buf, v) }
	put32 := func(v uint32) { buf = binary.LittleEndian.AppendUint32(buf, v) }

	put16(0x0003) // версия блока
	put32(0)
	put16(0x002d) // длина остатка, значение из описания протокола
	put16(0x0003)
	put16(0x0000)
	put16(0x58ff)
	put16(0x3dd0)
	put16(0xbaa7)
	put16(0x0000)
	put16(0x0004)
	put32(cookie) // cookie из запроса, клиент сверяет его с отправленным
	put32(0)
	put32(0)
	put32(0)
	put32(0)
	put32(uin) // выданный номер
	put32(cookie)
	put16(0x0000)

	return buf
}
'''

patch('foodgroup/auth.go', '\nfunc (s AuthService) createUser(', AUTH_CODE + '\nfunc (s AuthService) createUser(', 'BUCPRegister')
# вставка выше дублирует якорь, поэтому убираем исходный
with open(f'{ROOT}/foodgroup/auth.go', encoding='utf-8') as f:
    t = f.read()
dup = '\nfunc (s AuthService) createUser(' + AUTH_CODE + '\nfunc (s AuthService) createUser('
if dup in t:
    t = t.replace(dup, AUTH_CODE + '\nfunc (s AuthService) createUser(', 1)
    with open(f'{ROOT}/foodgroup/auth.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  foodgroup/auth.go: якорь восстановлен')

# --- 3. тег TLV с блоком регистрации ----------------------------------------

patch(
    'wire/snacs.go',
    '\tBUCPRegisterResponse         uint16 = 0x0005',
    '\n\n\t// ICQTLVTagsRegistration — TLV с блоком регистрации нового номера.\n\tICQTLVTagsRegistration uint16 = 0x0001',
    'ICQTLVTagsRegistration',
)

# --- 4. ветка в приёмнике логина --------------------------------------------

SERVER_CASE = '''
			case fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPRegisterRequest:
				payload, err := io.ReadAll(buf)
				if err != nil {
					return err
				}
				outSNAC, err := s.authService.BUCPRegister(ctx, payload)
				if err != nil {
					s.logger.Error("ICQ registration failed", "err", err.Error())
					return io.EOF
				}
				outSNAC.Frame.RequestID = fr.RequestID
				if err := flapc.SendSNAC(outSNAC.Frame, outSNAC.Body); err != nil {
					return err
				}
				// Пустой FLAP канала 4 — сигнал клиенту закрыть соединение.
				return flapc.NewSignoff(wire.TLVRestBlock{})
'''

patch(
    'server/oscar/server.go',
    '\t\t\tcase fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPLoginRequest:',
    '',  # добавим отдельно ниже, чтобы вставить ПЕРЕД веткой логина
    'BUCPRegisterRequest',
)

with open(f'{ROOT}/server/oscar/server.go', encoding='utf-8') as f:
    t = f.read()
anchor = '\t\t\tcase fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPLoginRequest:'
if 'BUCPRegisterRequest' not in t and anchor in t:
    t = t.replace(anchor, SERVER_CASE.rstrip('\n') + '\n' + anchor, 1)
    with open(f'{ROOT}/server/oscar/server.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  server/oscar/server.go: ветка регистрации добавлена')
elif 'BUCPRegisterRequest' in t:
    print('  server/oscar/server.go: уже пропатчен')

# --- 5. метод в интерфейсе ---------------------------------------------------

patch(
    'server/oscar/types.go',
    '\tBUCPLogin(ctx context.Context, inBody wire.SNAC_0x17_0x02_BUCPLoginRequest, endpointCfg config.Endpoint) (wire.SNACMessage, error)',
    '\n\tBUCPRegister(ctx context.Context, snacPayloadIn []byte) (wire.SNACMessage, error)',
    'BUCPRegister',
)

print('готово')
