"""Adds registration of a new number from the client to Open OSCAR Server.

On the "Get an ICQ Number" button ICQ Pro 2003b opens a separate connection to
the same port 5190 and sends SNAC(0x17, 0x04), BUCPRegisterRequest. TLV(0x0001)
inside it carries the ICQ registration block, all of it little-endian: at
offset 40 the password length and the password itself, at offset 16 a random
cookie the server must return in its reply.

The server answers SNAC(0x17, 0x05) with the number it handed out and then
sends an empty channel 4 FLAP, which tells the client to close the connection.

The script edits three files in the source tree and builds nothing.
"""

import re
import sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'


def patch(path, anchor, addition, marker):
    """Inserts addition after anchor unless marker already occurs in the file."""
    full = f'{ROOT}/{path}'
    with open(full, encoding='utf-8') as f:
        text = f.read()
    if marker in text:
        print(f'  {path}: already patched')
        return
    if anchor not in text:
        print(f'  {path}: ANCHOR NOT FOUND - skipping')
        return
    text = text.replace(anchor, anchor + addition, 1)
    with open(full, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f'  {path}: added')


# --- 1. the reply constant ---------------------------------------------------

patch(
    'wire/snacs.go',
    '\tBUCPRegisterRequest          uint16 = 0x0004',
    '\n\tBUCPRegisterResponse         uint16 = 0x0005',
    'BUCPRegisterResponse',
)

# --- 2. the handler in the auth service ------------------------------------

AUTH_CODE = '''

// Offsets inside the ICQ registration block (TLV 0x0001 of SNAC(0x17,0x04)).
// The whole block is little-endian, unlike the SNACs around it.
const (
	icqRegCookieOffset   = 16
	icqRegPasswordOffset = 40
	icqRegMinLen         = icqRegPasswordOffset + 2
)

// The range numbers are handed out from. It starts at 100000, the way the real
// ICQ servers did and the way our own registration page picks a
// number.
const (
	icqUINFirst = 100000
	icqUINLast  = 2147483646
)

// BUCPRegister hands out a new ICQ number and creates an account for it.
//
// The client sends SNAC(0x17,0x04) with the chosen password and a random cookie;
// the server answers SNAC(0x17,0x05) with the assigned number. The block is ICQ v8,
// described at https://kingant.net/oscar/?family=0x0017&subtype=0x0005
func (s AuthService) BUCPRegister(ctx context.Context, snacPayloadIn []byte) (wire.SNACMessage, error) {
	block := wire.TLVRestBlock{}
	if err := wire.UnmarshalBE(&block, bytes.NewReader(snacPayloadIn)); err != nil {
		return wire.SNACMessage{}, fmt.Errorf("parsing registration request: %w", err)
	}

	reg, ok := block.Bytes(wire.ICQTLVTagsRegistration)
	if !ok || len(reg) < icqRegMinLen {
		return wire.SNACMessage{}, errors.New("registration request carries no data block")
	}

	cookie := binary.LittleEndian.Uint32(reg[icqRegCookieOffset:])

	passLen := int(binary.LittleEndian.Uint16(reg[icqRegPasswordOffset:]))
	from := icqRegPasswordOffset + 2
	if passLen == 0 || from+passLen > len(reg) {
		return wire.SNACMessage{}, errors.New("registration request carries no password")
	}
	// The client sends the password with a trailing NUL counted in the length.
	password := strings.TrimRight(string(reg[from:from+passLen]), "\\x00")

	uin, err := s.nextFreeUIN(ctx)
	if err != nil {
		return wire.SNACMessage{}, err
	}

	screenName := state.DisplayScreenName(strconv.Itoa(uin))
	if err := s.createAccount(ctx, screenName, password); err != nil {
		switch {
		case errors.Is(err, state.ErrPasswordInvalid):
			// The client checks the 6-8 character length itself; guard anyway.
			s.logger.InfoContext(ctx, "registration rejected: bad password", "uin", uin)
			return wire.SNACMessage{}, err
		default:
			return wire.SNACMessage{}, fmt.Errorf("creating account %d: %w", uin, err)
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

// nextFreeUIN picks the first free number starting at 100000.
func (s AuthService) nextFreeUIN(ctx context.Context) (int, error) {
	for uin := icqUINFirst; uin <= icqUINLast; uin++ {
		u, err := s.userManager.User(ctx, state.NewIdentScreenName(strconv.Itoa(uin)))
		if err != nil {
			return 0, fmt.Errorf("looking for a free number: %w", err)
		}
		if u == nil {
			return uin, nil
		}
	}
	return 0, errors.New("no free numbers left")
}

// icqRegistrationReply builds the body of the registration reply. Every field
// is little-endian; the constants come from the protocol description.
func icqRegistrationReply(uin uint32, cookie uint32) []byte {
	buf := make([]byte, 0, 52)
	put16 := func(v uint16) { buf = binary.LittleEndian.AppendUint16(buf, v) }
	put32 := func(v uint32) { buf = binary.LittleEndian.AppendUint32(buf, v) }

	put16(0x0003) // block version
	put32(0)
	put16(0x002d) // length of the rest, a constant from the protocol description
	put16(0x0003)
	put16(0x0000)
	put16(0x58ff)
	put16(0x3dd0)
	put16(0xbaa7)
	put16(0x0000)
	put16(0x0004)
	put32(cookie) // cookie from the request; the client matches it with its own
	put32(0)
	put32(0)
	put32(0)
	put32(0)
	put32(uin) // the number handed out
	put32(cookie)
	put16(0x0000)

	return buf
}
'''

patch('foodgroup/auth.go', '\nfunc (s AuthService) createUser(', AUTH_CODE + '\nfunc (s AuthService) createUser(', 'BUCPRegister')
# the insertion above duplicates the anchor, so remove the original one
with open(f'{ROOT}/foodgroup/auth.go', encoding='utf-8') as f:
    t = f.read()
dup = '\nfunc (s AuthService) createUser(' + AUTH_CODE + '\nfunc (s AuthService) createUser('
if dup in t:
    t = t.replace(dup, AUTH_CODE + '\nfunc (s AuthService) createUser(', 1)
    with open(f'{ROOT}/foodgroup/auth.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  foodgroup/auth.go: anchor restored')

# --- 3. the TLV tag of the registration block ------------------------------

patch(
    'wire/snacs.go',
    '\tBUCPRegisterResponse         uint16 = 0x0005',
    '\n\n\t// ICQTLVTagsRegistration holds the registration block for a new number.\n\tICQTLVTagsRegistration uint16 = 0x0001',
    'ICQTLVTagsRegistration',
)

# --- 4. the branch in the login receiver ------------------------------------

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
				// An empty channel 4 FLAP tells the client to close the connection.
				return flapc.NewSignoff(wire.TLVRestBlock{})
'''

patch(
    'server/oscar/server.go',
    '\t\t\tcase fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPLoginRequest:',
    '',  # added separately below, so it goes BEFORE the login branch
    'BUCPRegisterRequest',
)

with open(f'{ROOT}/server/oscar/server.go', encoding='utf-8') as f:
    t = f.read()
anchor = '\t\t\tcase fr.FoodGroup == wire.BUCP && fr.SubGroup == wire.BUCPLoginRequest:'
if 'BUCPRegisterRequest' not in t and anchor in t:
    t = t.replace(anchor, SERVER_CASE.rstrip('\n') + '\n' + anchor, 1)
    with open(f'{ROOT}/server/oscar/server.go', 'w', encoding='utf-8') as f:
        f.write(t)
    print('  server/oscar/server.go: registration branch added')
elif 'BUCPRegisterRequest' in t:
    print('  server/oscar/server.go: already patched')

# --- 5. the interface method -------------------------------------------------

patch(
    'server/oscar/types.go',
    '\tBUCPLogin(ctx context.Context, inBody wire.SNAC_0x17_0x02_BUCPLoginRequest, endpointCfg config.Endpoint) (wire.SNACMessage, error)',
    '\n\tBUCPRegister(ctx context.Context, snacPayloadIn []byte) (wire.SNACMessage, error)',
    'BUCPRegister',
)

print('done')
