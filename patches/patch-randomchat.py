"""Добавляет в Open OSCAR Server «случайный чат» ICQ.

Клиент умеет две вещи: записаться в группу по интересу и попросить подобрать
из неё собеседника. В протоколе это пара мета-запросов семейства 0x15:

    0x0758  записать меня в группу      ответ 0x0370
    0x074E  подобрать собеседника       ответ 0x0366

Номера и раскладку ответа взял из исходников licq, где эта часть реализована
целиком: номер найденного (4 байта), группа (2), внешний адрес (4, в обратном
порядке байт), порт (4), внутренний адрес (4), признак прямого соединения (1),
версия клиента (2). Коды успеха и отказа — те же 0x0A и 0x32, что уже есть.

Группы заданы числами: 1 — общая, 2 — романтика, 3 — игры, 4 — студенты,
6..9 — по возрасту, 10 и 11 — «ищу девушку» и «ищу парня», 0 — не участвую.

Группа хранится в памяти, а не в базе. Подбор идёт только среди тех, кто
сейчас в сети, поэтому переживать перезапуск ей незачем, а миграции базы
патч не требует.

Скрипт правит пять файлов и ничего не собирает.
"""

import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'


def patch(path, anchor, addition, marker, after=True):
    """Вставляет addition рядом с anchor, если marker ещё не встречается."""
    full = f'{ROOT}/{path}'
    with open(full, encoding='utf-8') as f:
        text = f.read()
    if marker in text:
        print(f'  {path}: уже пропатчен')
        return
    if anchor not in text:
        print(f'  {path}: ЯКОРЬ НЕ НАЙДЕН — пропускаю')
        return
    text = text.replace(anchor, anchor + addition if after else addition + anchor, 1)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f'  {path}: добавлено')


# --- 1. константы и структуры протокола --------------------------------------

patch(
    'wire/snacs.go',
    '\tICQDBQueryMetaReqDirectoryUpdate   uint16 = 0x0FD2',
    '\n'
    '\t// Случайный чат: записаться в группу и попросить собеседника.\n'
    '\tICQDBQueryMetaReqRandomSearch      uint16 = 0x074E\n'
    '\tICQDBQueryMetaReqSetRandomChat     uint16 = 0x0758',
    'ICQDBQueryMetaReqRandomSearch',
)

patch(
    'wire/snacs.go',
    '\tICQDBQueryMetaReplySetFullInfo     uint16 = 0x0C3F',
    '\n'
    '\tICQDBQueryMetaReplyRandomFound     uint16 = 0x0366\n'
    '\tICQDBQueryMetaReplySetRandomChat   uint16 = 0x0370',
    'ICQDBQueryMetaReplyRandomFound',
)

STRUCTS = '''
// ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat — клиент записывается в группу
// случайного чата. При ненулевой группе клиент дописывает свой адрес и версию;
// нам они не нужны, поэтому читаем только номер группы.
type ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat struct {
	Group uint16
}

// ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch — клиент просит подобрать
// собеседника из указанной группы.
type ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch struct {
	Group uint16
}

// ICQ_0x07DA_0x0366_DBQueryMetaReplyRandomFound — найденный собеседник.
// Адреса лежат в обратном порядке байт относительно остального тела, поэтому
// они объявлены массивами: так их не развернёт кодировщик.
type ICQ_0x07DA_0x0366_DBQueryMetaReplyRandomFound struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	UIN        uint32
	Group      uint16
	ExternalIP [4]byte
	Port       uint32
	InternalIP [4]byte
	Mode       uint8
	Version    uint16
}

'''

patch('wire/snacs.go', 'type ICQMetadata struct {', STRUCTS, 'DBQueryMetaReplyRandomFound struct', after=False)

# --- 2. служба -----------------------------------------------------------------

SERVICE = '''
// --------------------------------------------------------------- случайный чат

// ICQSessionLister отдаёт все живые сессии. Нужен только случайному чату:
// собеседник ищется среди тех, кто сейчас в сети.
type ICQSessionLister interface {
	AllSessions() []*state.Session
}

// BridgeSessionLister включает случайный чат. Без него запросы обслуживаются,
// но собеседник не находится никогда.
func (s *ICQService) BridgeSessionLister(lister ICQSessionLister) {
	s.sessionLister = lister
}

// SetRandomChatGroup запоминает, в какой группе пользователь готов общаться.
// Ноль означает «не участвую».
func (s *ICQService) SetRandomChatGroup(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat, seq uint16) error {
	s.randomChatMu.Lock()
	if inBody.Group == 0 {
		delete(s.randomChatGroups, instance.IdentScreenName())
	} else {
		s.randomChatGroups[instance.IdentScreenName()] = inBody.Group
	}
	s.randomChatMu.Unlock()

	s.logger.DebugContext(ctx, "random chat group set", "uin", instance.UIN(), "group", inBody.Group)

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetRandomChat, inFrame.RequestID)
}

// RandomChatSearch подбирает собеседника из той же группы среди тех, кто
// сейчас в сети. Себя не предлагаем.
func (s *ICQService) RandomChatSearch(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch, seq uint16) error {
	match := s.pickRandomChatPartner(instance.IdentScreenName(), inBody.Group)
	if match == nil {
		s.logger.DebugContext(ctx, "no random chat partner", "uin", instance.UIN(), "group", inBody.Group)
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: wire.ICQ_0x07DA_0x0366_DBQueryMetaReplyRandomFound{
				ICQMetadata: wire.ICQMetadata{
					UIN:     instance.UIN(),
					ReqType: wire.ICQDBQueryMetaReply,
					Seq:     seq,
				},
				ReqSubType: wire.ICQDBQueryMetaReplyRandomFound,
				Success:    wire.ICQStatusCodeFail,
			},
		}, inFrame.RequestID, 0)
	}

	resp := wire.ICQ_0x07DA_0x0366_DBQueryMetaReplyRandomFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyRandomFound,
		Success:    wire.ICQStatusCodeOK,
		UIN:        match.UIN(),
		Group:      inBody.Group,
		// Соединение идёт через сервер: прямое между клиентами мы не сводим.
		Mode:    0x04,
		Version: 0x000A,
	}
	if addr := randomChatAddr(match); addr != nil {
		resp.ExternalIP = *addr
		resp.InternalIP = *addr
	}

	s.logger.DebugContext(ctx, "random chat partner found",
		"uin", instance.UIN(), "partner", match.UIN(), "group", inBody.Group)

	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{Message: resp}, inFrame.RequestID, 0)
}

// pickRandomChatPartner возвращает случайную живую сессию из той же группы.
func (s *ICQService) pickRandomChatPartner(me state.IdentScreenName, group uint16) *state.Session {
	if s.sessionLister == nil || group == 0 {
		return nil
	}

	s.randomChatMu.Lock()
	wanted := make(map[state.IdentScreenName]struct{}, len(s.randomChatGroups))
	for name, g := range s.randomChatGroups {
		if g == group && name != me {
			wanted[name] = struct{}{}
		}
	}
	s.randomChatMu.Unlock()

	if len(wanted) == 0 {
		return nil
	}

	var candidates []*state.Session
	for _, sess := range s.sessionLister.AllSessions() {
		if _, ok := wanted[sess.IdentScreenName()]; !ok {
			continue
		}
		if !sess.HasLiveInstances() {
			continue
		}
		candidates = append(candidates, sess)
	}
	if len(candidates) == 0 {
		return nil
	}
	return candidates[rand.IntN(len(candidates))]
}

// randomChatAddr — адрес собеседника в том виде, в каком его ждёт клиент:
// четыре байта в обратном порядке относительно остального тела ответа.
func randomChatAddr(sess *state.Session) *[4]byte {
	for _, inst := range sess.Instances() {
		ap := inst.RemoteAddr()
		if ap == nil {
			continue
		}
		ip := ap.Addr()
		if !ip.Is4() {
			continue
		}
		b := ip.As4()
		return &b
	}
	return nil
}

'''

patch('foodgroup/icq.go', '\nfunc (s *ICQService) reqAck(', SERVICE + '\nfunc (s *ICQService) reqAck(', 'RandomChatSearch')
with open(f'{ROOT}/foodgroup/icq.go', encoding='utf-8') as f:
    t = f.read()
dup = '\nfunc (s *ICQService) reqAck(' + SERVICE + '\nfunc (s *ICQService) reqAck('
if dup in t:
    t = t.replace(dup, SERVICE + '\nfunc (s *ICQService) reqAck(', 1)
    with open(f'{ROOT}/foodgroup/icq.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  foodgroup/icq.go: якорь восстановлен')

# поля службы
patch(
    'foodgroup/icq.go',
    '\tforwardICQAuthEvents  func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error\n}',
    '',
    'randomChatGroups',
)
with open(f'{ROOT}/foodgroup/icq.go', encoding='utf-8') as f:
    t = f.read()
if 'randomChatGroups' not in t:
    t = t.replace(
        '\tforwardICQAuthEvents  func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error\n}',
        '\tforwardICQAuthEvents  func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error\n'
        '\t// Случайный чат: кто в какой группе. Живёт в памяти, см. patch-randomchat.py.\n'
        '\tsessionLister         ICQSessionLister\n'
        '\trandomChatMu          sync.Mutex\n'
        '\trandomChatGroups      map[state.IdentScreenName]uint16\n}', 1)
    t = t.replace(
        '\t\ttimeNow:               time.Now,',
        '\t\ttimeNow:               time.Now,\n'
        '\t\trandomChatGroups:      make(map[state.IdentScreenName]uint16),', 1)
    t = t.replace('\t"log/slog"\n', '\t"log/slog"\n\t"math/rand/v2"\n', 1)
    t = t.replace('\t"strings"\n', '\t"strings"\n\t"sync"\n', 1)
    with open(f'{ROOT}/foodgroup/icq.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  foodgroup/icq.go: поля и импорты добавлены')

# --- 3. разбор запросов --------------------------------------------------------

CASES = '''		case wire.ICQDBQueryMetaReqSetRandomChat:
			req := wire.ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.SetRandomChatGroup(ctx, instance, inFrame, req, icqMD.Seq); err != nil {
				return err
			}
		case wire.ICQDBQueryMetaReqRandomSearch:
			req := wire.ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch{}
			if err := wire.UnmarshalLE(&req, buf); err != nil {
				return err
			}
			if err := rt.RandomChatSearch(ctx, instance, inFrame, req, icqMD.Seq); err != nil {
				return err
			}
'''

patch(
    'server/oscar/handler.go',
    '\t\tcase wire.ICQDBQueryMetaReqSetPermissions:',
    '',
    'ICQDBQueryMetaReqSetRandomChat',
)
with open(f'{ROOT}/server/oscar/handler.go', encoding='utf-8') as f:
    t = f.read()
anchor = '\t\tcase wire.ICQDBQueryMetaReqSetPermissions:'
if 'ICQDBQueryMetaReqSetRandomChat' not in t and anchor in t:
    t = t.replace(anchor, CASES + anchor, 1)
    with open(f'{ROOT}/server/oscar/handler.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  server/oscar/handler.go: разбор запросов добавлен')

# --- 4. интерфейс --------------------------------------------------------------

patch(
    'server/oscar/types.go',
    '\tSetPermissions(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions, seq uint16) error',
    '\n\tSetRandomChatGroup(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat, seq uint16) error'
    '\n\tRandomChatSearch(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch, seq uint16) error',
    'RandomChatSearch',
)

# --- 5. включение в сборке -----------------------------------------------------

patch(
    'cmd/server/factory.go',
    '\tc.icqService = foodgroup.NewICQService(\n'
    '\t\tc.inMemorySessionManager,\n'
    '\t\tc.sqLiteUserStore,\n'
    '\t\tc.sqLiteUserStore,\n'
    '\t\tc.logger,\n'
    '\t\tc.inMemorySessionManager,\n'
    '\t\tc.sqLiteUserStore,\n'
    '\t)',
    '\n\t// Случайный чат подбирает собеседника среди живых сессий.\n'
    '\tc.icqService.BridgeSessionLister(c.inMemorySessionManager)',
    'BridgeSessionLister',
)

print('готово')
