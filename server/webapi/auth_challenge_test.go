package webapi

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

// icq7Modulus and icq7Base are the Diffie-Hellman group the ICQ 7.2 client
// (coolcore59.dll) sends as dh_modulus and dh_base.
const (
	icq7Modulus = "15517289818147369747123225776371553991572480196691540447970779531405762937854191"
	icq7Base    = "5"
)

// clientDigest computes pwd the way the ICQ 7 client does for a getChallenge
// reply that sets neither normalize nor truncate:
// base64(MD5(challengeWord + MD5(password) + realm)).
func clientDigest(challengeWord, password, realm string) string {
	inner := md5.Sum([]byte(password))
	h := md5.New()
	h.Write([]byte(challengeWord))
	h.Write(inner[:])
	h.Write([]byte(realm))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// challengeFor answers BUCPChallenge with authKey for known and an error
// response for anyone else, as the real auth service does.
func challengeFor(known, authKey string) func(context.Context, wire.SNAC_0x17_0x06_BUCPChallengeRequest) (wire.SNACMessage, error) {
	return func(_ context.Context, in wire.SNAC_0x17_0x06_BUCPChallengeRequest) (wire.SNACMessage, error) {
		sn, _ := in.String(wire.LoginTLVTagsScreenName)
		if sn != known {
			return wire.SNACMessage{Body: wire.SNAC_0x17_0x03_BUCPLoginResponse{}}, nil
		}
		return wire.SNACMessage{Body: wire.SNAC_0x17_0x07_BUCPChallengeResponse{AuthKey: authKey}}, nil
	}
}

// getChallengeXML is the shape the client deserializes: the challenge fields
// sit directly under data, in the login namespace.
type getChallengeXML struct {
	XMLName    xml.Name `xml:"https://api.login.aol.com response"`
	StatusCode int      `xml:"https://api.login.aol.com statusCode"`
	Data       struct {
		ChallengeWord string `xml:"https://api.login.aol.com challengeWord"`
		TID           string `xml:"https://api.login.aol.com tid"`
		Realm         string `xml:"https://api.login.aol.com realm"`
	} `xml:"https://api.login.aol.com data"`
}

func postForm(target, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestAuthHandler_GetChallenge(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantWord string // empty: any non-empty word
		wantCode int
	}{
		{name: "known account gets its auth key", body: "devId=k1&f=xml&s=100001", wantWord: "the-auth-key", wantCode: 200},
		{name: "email login names the account in alias", body: "devId=k1&f=xml&alias=100001", wantWord: "the-auth-key", wantCode: 200},
		{name: "unknown account gets a random word", body: "devId=k1&f=xml&s=100099", wantCode: 200},
		{name: "no account named", body: "devId=k1&f=xml", wantCode: statusMissingParameter},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &AuthHandler{
				AuthService: &testAuthService{bucpChallenge: challengeFor("100001", "the-auth-key")},
				Logger:      slog.Default(),
			}
			rr := httptest.NewRecorder()
			handler.GetChallenge(rr, postForm("/auth/getChallenge", tt.body))

			if tt.wantCode != 200 {
				assert.Contains(t, rr.Body.String(), "<statusCode>460</statusCode>")
				return
			}
			assert.Contains(t, rr.Body.String(), `<response xmlns="https://api.login.aol.com">`)

			var got getChallengeXML
			require.NoError(t, xml.Unmarshal(rr.Body.Bytes(), &got), rr.Body.String())
			assert.Equal(t, 200, got.StatusCode)
			assert.Equal(t, challengeRealm, got.Data.Realm)
			assert.NotEmpty(t, got.Data.TID)
			if tt.wantWord != "" {
				assert.Equal(t, tt.wantWord, got.Data.ChallengeWord)
			} else {
				assert.NotEmpty(t, got.Data.ChallengeWord)
			}
		})
	}
}

// The digest the client computes from the challenge is the account's strong
// BUCP hash, so the server checks it without ever seeing the password.
func TestClientDigestIsTheStrongBUCPHash(t *testing.T) {
	const authKey, password = "1234567", "test-password"
	digest, err := passwordDigest(clientDigest(authKey, password, challengeRealm))
	require.NoError(t, err)
	assert.Equal(t, wire.StrongMD5PasswordHash(password, authKey), digest)
}

func TestAuthHandler_ClientLogin_Digest(t *testing.T) {
	const authKey, password = "1234567", "test-password"

	t.Run("digest is checked as the BUCP password hash", func(t *testing.T) {
		var got wire.FLAPSignonFrame
		handler := &AuthHandler{
			AuthService: &testAuthService{
				flapLogin: func(_ context.Context, in wire.FLAPSignonFrame, _ config.Endpoint) (wire.TLVRestBlock, error) {
					got = in
					return successfulLoginBlock(), nil
				},
			},
			Logger: slog.Default(),
		}
		form := url.Values{
			"s": {"100001"}, "pwd": {clientDigest(authKey, password, challengeRealm)}, "digest": {"1"},
			"f": {"xml"}, "k": {"gu19PNBblQjCdbMU"}, "tid": {"x"}, "tokenType": {"shortterm"}, "idType": {"ICQ"},
		}
		rr := httptest.NewRecorder()
		handler.ClientLogin(rr, postForm("/auth/clientLogin", form.Encode()))

		assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		hash, ok := got.Bytes(wire.LoginTLVTagsPasswordHash)
		assert.True(t, ok, "digest should reach the auth service as a password hash")
		assert.Equal(t, wire.StrongMD5PasswordHash(password, authKey), hash)
		assert.False(t, got.HasTag(wire.LoginTLVTagsPlaintextPassword))
		assert.Contains(t, rr.Body.String(), `<response xmlns="https://api.login.aol.com">`)
	})

	t.Run("a digest that is not 16 bytes of base64 is refused", func(t *testing.T) {
		handler := &AuthHandler{AuthService: &testAuthService{}, Logger: slog.Default()}
		rr := httptest.NewRecorder()
		handler.ClientLogin(rr, postForm("/auth/clientLogin", "s=100001&pwd=notadigest&digest=1"))
		assert.Contains(t, rr.Body.String(), `"statusCode":462`)
	})
}

func TestAuthHandler_ClientLogin_DiffieHellman(t *testing.T) {
	p, _ := new(big.Int).SetString(icq7Modulus, 10)
	a := big.NewInt(0x1234567)
	consumer := new(big.Int).Exp(big.NewInt(5), a, p)

	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(context.Context, wire.FLAPSignonFrame, config.Endpoint) (wire.TLVRestBlock, error) {
				return successfulLoginBlock(), nil
			},
		},
		Logger: slog.Default(),
	}
	form := url.Values{
		"s": {"100001"}, "pwd": {clientDigest("k", "pw", challengeRealm)}, "digest": {"1"}, "f": {"xml"},
		"dh_modulus": {icq7Modulus}, "dh_base": {icq7Base},
		"dh_consumer_public": {base64.StdEncoding.EncodeToString(consumer.Bytes())},
	}
	rr := httptest.NewRecorder()
	handler.ClientLogin(rr, postForm("/auth/clientLogin", form.Encode()))
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var resp struct {
		Data struct {
			SessionSecret  string `xml:"sessionSecret"`
			DHServerPublic string `xml:"dhServerPublic"`
		} `xml:"data"`
	}
	require.NoError(t, xml.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.SessionSecret)

	// The client URL-decodes, then base64-decodes, then reads a signed number.
	unescaped, err := url.QueryUnescape(resp.Data.DHServerPublic)
	require.NoError(t, err)
	raw, err := base64.StdEncoding.DecodeString(unescaped)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	assert.Zero(t, raw[0]&0x80, "a leading byte with the top bit set would read as negative")
	y := new(big.Int).SetBytes(raw)
	assert.Equal(t, 1, y.Cmp(big.NewInt(1)))
	assert.Equal(t, -1, y.Cmp(p))
}

func TestDHServerPublic_RejectsUnusableParameters(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(big.NewInt(12345).Bytes())
	tests := []struct {
		name, modulus, base, public string
	}{
		{"modulus not a number", "abc", icq7Base, good},
		{"base out of range", icq7Modulus, "1", good},
		{"public not base64", icq7Modulus, icq7Base, "!!"},
		{"public of one", icq7Modulus, icq7Base, base64.StdEncoding.EncodeToString([]byte{1})},
		{"public not below the modulus", "23", icq7Base, base64.StdEncoding.EncodeToString([]byte{23})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dhServerPublic(tt.modulus, tt.base, tt.public)
			assert.ErrorIs(t, err, errBadDHParams)
		})
	}
}

// A failed exchange leaves dhServerPublic out rather than failing the sign-in.
func TestAuthHandler_ClientLogin_DiffieHellmanFailureStillSignsIn(t *testing.T) {
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(context.Context, wire.FLAPSignonFrame, config.Endpoint) (wire.TLVRestBlock, error) {
				return successfulLoginBlock(), nil
			},
		},
		Logger: slog.Default(),
	}
	rr := httptest.NewRecorder()
	handler.ClientLogin(rr, postForm("/auth/clientLogin", "s=100001&pwd=pw&f=xml&dh_modulus=abc&dh_base=5&dh_consumer_public=AQ%3D%3D"))
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), "dhServerPublic")
}

func TestXMLNamespaceByPath(t *testing.T) {
	assert.Equal(t, xmlnsLogin, xmlNamespace(httptest.NewRequest(http.MethodPost, "/auth/clientLogin", nil)))
	assert.Equal(t, xmlnsAIM, xmlNamespace(httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession", nil)))
	assert.Equal(t, []byte(`<response xmlns="ns"><a></a></response>`), withXMLNamespace([]byte(`<response><a></a></response>`), "ns"))
}
