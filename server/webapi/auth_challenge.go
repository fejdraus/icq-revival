package webapi

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/wire"
)

// challengeRealm is the realm getChallenge names. The client digests its
// password as MD5(challengeWord + MD5(password) + realm), so with the user's
// BUCP auth key as the challenge word and this realm the digest it sends is
// exactly the strong MD5 hash BUCP stores for the account.
const challengeRealm = "AOL Instant Messenger (SM)"

// ChallengeData is the getChallenge payload. ICQ 7 (the AIM client core it is
// built on) asks for one before clientLogin whenever it has no TLS, so that the
// password never crosses the wire.
//
// normalize and truncate are left out: absent, the client reads both as false,
// which is the hash BUCP stores (the whole password, as typed).
type ChallengeData struct {
	ChallengeWord string `json:"challengeWord" xml:"challengeWord"`
	// TID identifies the challenge; the client echoes it in clientLogin.
	TID   string `json:"tid" xml:"tid"`
	Realm string `json:"realm" xml:"realm"`
}

// GetChallenge handles POST /auth/getChallenge. The client names the account in
// "s", or in "alias" when it signs in with an email address.
//
// An account that does not exist still gets a challenge, a random one, so the
// endpoint does not tell which accounts exist; clientLogin then fails the usual
// way.
func (h *AuthHandler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		SendError(w, r, http.StatusBadRequest, "invalid form data")
		return
	}

	login := r.FormValue("s")
	if login == "" {
		login = r.FormValue("alias")
	}
	if login == "" {
		SendErrorDetail(w, r, http.StatusBadRequest, statusMissingParameter, 0, "s required")
		return
	}

	authKey, err := h.challengeWord(r, login)
	if err != nil {
		h.Logger.ErrorContext(r.Context(), "getChallenge failed", "login", login, "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	SendOK(w, r, &ChallengeData{
		ChallengeWord: authKey,
		TID:           uuid.New().String(),
		Realm:         challengeRealm,
	}, h.Logger)
}

// challengeWord returns the account's BUCP auth key, or a random word for an
// account BUCP does not know.
func (h *AuthHandler) challengeWord(r *http.Request, login string) (string, error) {
	req := wire.SNAC_0x17_0x06_BUCPChallengeRequest{}
	req.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, login))

	msg, err := h.AuthService.BUCPChallenge(r.Context(), req, uuid.New)
	if err != nil {
		return "", fmt.Errorf("BUCPChallenge: %w", err)
	}
	if body, ok := msg.Body.(wire.SNAC_0x17_0x07_BUCPChallengeResponse); ok {
		return body.AuthKey, nil
	}
	return uuid.New().String(), nil
}

// passwordDigest decodes the pwd a client sends with digest=1: the base64 MD5
// digest it computed from the getChallenge reply.
func passwordDigest(pwd string) ([]byte, error) {
	pwd = strings.ReplaceAll(strings.TrimSpace(pwd), " ", "+")
	digest, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return nil, fmt.Errorf("digest is not base64: %w", err)
	}
	if len(digest) != 16 {
		return nil, fmt.Errorf("digest is %d bytes, want 16", len(digest))
	}
	return digest, nil
}

// errBadDHParams reports Diffie-Hellman parameters that cannot be used.
var errBadDHParams = errors.New("unusable Diffie-Hellman parameters")

// dhServerPublic answers the client's half of a Diffie-Hellman exchange with the
// server's. A client without TLS sends dh_modulus and dh_base as decimal numbers
// and dh_consumer_public as base64 big-endian bytes, and derives its session key
// as HMAC-SHA256(shared secret, sessionSecret).
//
// The key is ephemeral and the shared secret is not kept: nothing on this
// server checks the signatures made with that session key.
//
// The result is base64 escaped for a URL, because the client URL-decodes
// dhServerPublic before decoding the base64, which would turn a '+' into a
// space. The client reads the bytes as a signed number, so one that would
// have its top bit set gets a leading zero byte.
func dhServerPublic(modulus, base, consumerPublic string) (string, error) {
	p, ok := new(big.Int).SetString(strings.TrimSpace(modulus), 10)
	if !ok || p.Cmp(big.NewInt(3)) < 0 {
		return "", errBadDHParams
	}
	g, ok := new(big.Int).SetString(strings.TrimSpace(base), 10)
	if !ok || g.Cmp(big.NewInt(2)) < 0 || g.Cmp(p) >= 0 {
		return "", errBadDHParams
	}
	// A '+' the client left unescaped arrives as a space.
	consumerPublic = strings.ReplaceAll(strings.TrimSpace(consumerPublic), " ", "+")
	pub, err := base64.StdEncoding.DecodeString(consumerPublic)
	if err != nil {
		return "", errBadDHParams
	}
	y := new(big.Int).SetBytes(pub)
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(p) >= 0 {
		return "", errBadDHParams
	}

	x, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil {
		return "", err
	}
	x.Add(x, big.NewInt(1))

	b := new(big.Int).Exp(g, x, p).Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return url.QueryEscape(base64.StdEncoding.EncodeToString(b)), nil
}
