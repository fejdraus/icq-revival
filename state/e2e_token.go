package state

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// e2eTokenMagic opens every key directory token's payload. It keeps the
// tokens apart from the login cookies signed with the same key: a login
// cookie's payload opens with its service number, never 0xFFFF, and the
// 0xFF after it would be a 255-byte screen name, longer than the rest of a
// token's payload, so a token never unpacks as a ServerCookie either.
var e2eTokenMagic = [6]byte{0xFF, 0xFF, 0xFF, 'E', '2', 'E'}

// E2EToken is what a key directory token vouches for: the session of the
// account it was issued to. It is bound to one session instance, so it dies
// with that instance or at its expiry, whichever comes first.
type E2EToken struct {
	ScreenName IdentScreenName
	// SignonTime is the session's sign-on time, which tells this session from
	// a later one of the same account.
	SignonTime time.Time
	// InstanceNum is the session instance the token was issued to.
	InstanceNum uint8
}

type e2eTokenPayload struct {
	Magic       [6]byte
	ScreenName  string `oscar:"len_prefix=uint8"`
	SignonNanos uint64
	InstanceNum uint8
}

// IssueE2EToken mints a key directory token for a session instance that is
// valid for ttl, signed by baker (an HMACCookieBaker).
func IssueE2EToken(baker interface {
	Issue(data []byte, ttl time.Duration) ([]byte, error)
}, instance *SessionInstance, ttl time.Duration) ([]byte, error) {
	buf := &bytes.Buffer{}
	err := wire.MarshalBE(e2eTokenPayload{
		Magic:       e2eTokenMagic,
		ScreenName:  instance.IdentScreenName().String(),
		SignonNanos: uint64(instance.Session().SignonTime().UnixNano()),
		InstanceNum: instance.Num(),
	}, buf)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal e2e token: %w", err)
	}
	token, err := baker.Issue(buf.Bytes(), ttl)
	if err != nil {
		return nil, err
	}
	return trimHMACToken(token), nil
}

// trimHMACToken drops the zero padding that HMACCookieBaker.Issue adds for
// the clients that want a 256-byte login cookie; Crack does not need it, and
// a key directory token travels in an HTTP header.
func trimHMACToken(token []byte) []byte {
	if len(token) < 2 {
		return token
	}
	sigAt := 2 + int(binary.BigEndian.Uint16(token))
	if len(token) < sigAt+2 {
		return token
	}
	end := sigAt + 2 + int(binary.BigEndian.Uint16(token[sigAt:]))
	if end > len(token) {
		return token
	}
	return token[:end]
}

// CrackE2EToken checks a key directory token's signature and expiry with
// baker (an HMACCookieBaker) and returns what it vouches for and when it
// expires. It does not check that the session is still alive; see
// E2EToken.Live.
func CrackE2EToken(baker interface {
	Crack(data []byte) ([]byte, time.Time, error)
}, token []byte) (E2EToken, time.Time, error) {
	data, expiry, err := baker.Crack(token)
	if err != nil {
		return E2EToken{}, time.Time{}, err
	}
	var p e2eTokenPayload
	if err := wire.UnmarshalBE(&p, bytes.NewReader(data)); err != nil {
		return E2EToken{}, time.Time{}, fmt.Errorf("unable to unmarshal e2e token: %w", err)
	}
	if p.Magic != e2eTokenMagic {
		return E2EToken{}, time.Time{}, errors.New("not an e2e token")
	}
	return E2EToken{
		ScreenName:  NewIdentScreenName(p.ScreenName),
		SignonTime:  time.Unix(0, int64(p.SignonNanos)),
		InstanceNum: p.InstanceNum,
	}, expiry, nil
}

// Live returns the session instance the token was issued to if it is still
// open, or nil. The instance may still be signing on: the token comes in the
// MOTD, before ClientOnline completes the sign-on, and a client may use it at
// once.
func (t E2EToken) Live(sessions interface {
	RetrieveSessionSigningOn(screenName IdentScreenName) *Session
}) *SessionInstance {
	sess := sessions.RetrieveSessionSigningOn(t.ScreenName)
	if sess == nil || sess.IsClosed() || !sess.SignonTime().Equal(t.SignonTime) {
		return nil
	}
	instance := sess.Instance(t.InstanceNum)
	if instance == nil || instance.IsClosed() {
		return nil
	}
	return instance
}
