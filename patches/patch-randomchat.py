"""Adds ICQ "random chat" to Open OSCAR Server.

The client can do two things: join an interest group and ask for a partner
from it. In the protocol these are a pair of meta requests in family 0x15:

    0x0758  put me in a group           reply 0x0370
    0x074E  find me a partner           reply 0x0366

The numbers and the reply layout come from the licq sources, where this part
is implemented in full: the found user's number (4 bytes), group (2), external
address (4, in reverse byte order), port (4), internal address (4), direct
connection flag (1), client version (2). The success and failure codes are the
same 0x0A and 0x32 that already exist.

Groups are numbers: 1 - general, 2 - romance, 3 - games, 4 - students,
6..9 - by age, 10 and 11 - "seeking a girl" and "seeking a guy", 0 - not
taking part.

The group is kept in memory, not in the database. Partners are only picked
among the users who are online, so it has no need to survive a restart, and
the patch needs no database migration.

The script edits five files and builds nothing.
"""

import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'


def patch(path, anchor, addition, marker, after=True):
    """Inserts addition next to anchor unless marker already occurs."""
    full = f'{ROOT}/{path}'
    with open(full, encoding='utf-8') as f:
        text = f.read()
    if marker in text:
        print(f'  {path}: already patched')
        return
    if anchor not in text:
        print(f'  {path}: ANCHOR NOT FOUND - skipping')
        return
    text = text.replace(anchor, anchor + addition if after else addition + anchor, 1)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f'  {path}: added')


# --- 1. protocol constants and structures -----------------------------------

patch(
    'wire/snacs.go',
    '\tICQDBQueryMetaReqDirectoryUpdate   uint16 = 0x0FD2',
    '\n'
    '\t// Random chat: join a group and ask for a partner.\n'
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
// ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat joins a random chat group. For
// a non-zero group the client appends its address and version; the server does
// not need them, so only the group number is read.
type ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat struct {
	Group uint16
}

// ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch asks for a partner from the
// given group.
type ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch struct {
	Group uint16
}

// ICQ_0x07DA_0x0366_DBQueryMetaReplyRandomFound carries the partner that was
// found. The addresses use the opposite byte order from the rest of the body,
// so they are declared as arrays to keep the marshaller from swapping them.
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

# --- 2. the service -----------------------------------------------------------

SERVICE = '''
// ------------------------------------------------------------------ random chat

// ICQSessionLister returns every live session. Only random chat needs it: a
// partner is picked among the users who are online right now.
type ICQSessionLister interface {
	AllSessions() []*state.Session
}

// BridgeSessionLister enables random chat. Without it the requests are still
// served, but a partner is never found.
func (s *ICQService) BridgeSessionLister(lister ICQSessionLister) {
	s.sessionLister = lister
}

// SetRandomChatGroup records the group the user is willing to chat in. Zero
// means they are not taking part.
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

// RandomChatSearch picks a partner from the same group among the users who are
// online. The caller is never offered to themselves.
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
		// The conversation goes through the server; no peer-to-peer link is set up.
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

// pickRandomChatPartner returns a random live session from the same group.
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

// randomChatAddr is the partner's address in the form the client expects: four
// bytes in the opposite order from the rest of the reply body.
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
    print('  foodgroup/icq.go: anchor restored')

# service fields
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
        '\t// Random chat: who is in which group. Kept in memory, see patch-randomchat.py.\n'
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
    print('  foodgroup/icq.go: fields and imports added')

# --- 3. request parsing -------------------------------------------------------

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
    print('  server/oscar/handler.go: request parsing added')

# --- 4. the interface ---------------------------------------------------------

patch(
    'server/oscar/types.go',
    '\tSetPermissions(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions, seq uint16) error',
    '\n\tSetRandomChatGroup(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0758_DBQueryMetaReqSetRandomChat, seq uint16) error'
    '\n\tRandomChatSearch(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x074E_DBQueryMetaReqRandomSearch, seq uint16) error',
    'RandomChatSearch',
)

# --- 5. wiring it into the build ----------------------------------------------

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
    '\n\t// Random chat picks a partner among the live sessions.\n'
    '\tc.icqService.BridgeSessionLister(c.inMemorySessionManager)',
    'BridgeSessionLister',
)

print('done')
