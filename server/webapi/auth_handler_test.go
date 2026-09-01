package webapi

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// testAuthService implements AuthService for ClientLogin tests (only FLAPLogin and
// CrackCookie are exercised).
type testAuthService struct {
	flapLogin   func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error)
	crackCookie func(authCookie []byte) (state.ServerCookie, time.Time, error)
}

func (t *testAuthService) BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error) {
	return wire.SNACMessage{}, nil
}

func (t *testAuthService) BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, endpointCfg config.Endpoint) (wire.SNACMessage, error) {
	return wire.SNACMessage{}, nil
}

func (t *testAuthService) CrackCookie(authCookie []byte) (state.ServerCookie, time.Time, error) {
	if t.crackCookie != nil {
		return t.crackCookie(authCookie)
	}
	return state.ServerCookie{}, time.Now().Add(shortTermTTL), nil
}

// signedCookieFor stands in for a CookieBaker-signed cookie naming screenName.
func signedCookieFor(screenName string) []byte {
	return []byte("signed:" + screenName)
}

// crackSignedCookie accepts only cookies produced by signedCookieFor, standing in
// for the signature check the real baker performs. The token reads as freshly
// minted; crackSignedCookieExpiring stands in for an older one.
func crackSignedCookie(authCookie []byte) (state.ServerCookie, time.Time, error) {
	return crackSignedCookieExpiring(shortTermTTL)(authCookie)
}

// crackSignedCookieExpiring cracks like crackSignedCookie, reporting a token
// with remaining life left on it.
func crackSignedCookieExpiring(remaining time.Duration) func([]byte) (state.ServerCookie, time.Time, error) {
	return func(authCookie []byte) (state.ServerCookie, time.Time, error) {
		name, ok := strings.CutPrefix(string(authCookie), "signed:")
		if !ok {
			return state.ServerCookie{}, time.Time{}, errors.New("bad signature")
		}
		return state.ServerCookie{ScreenName: state.DisplayScreenName(name)}, time.Now().Add(remaining), nil
	}
}

func (t *testAuthService) RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie, conf func(sess *state.Session)) (*state.SessionInstance, error) {
	return nil, nil
}

func (t *testAuthService) FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
	if t.flapLogin != nil {
		return t.flapLogin(ctx, inFrame, endpointCfg)
	}
	return wire.TLVRestBlock{}, nil
}

func (t *testAuthService) Signout(ctx context.Context, session *state.Session) {}

func (t *testAuthService) SignoutChat(ctx context.Context, sess *state.Session) {}

func successfulLoginBlock() wire.TLVRestBlock {
	var b wire.TLVRestBlock
	b.Append(wire.NewTLVBE(wire.LoginTLVTagsAuthorizationCookie, loginBlockCookie))
	return b
}

// loginBlockCookie is the cookie successfulLoginBlock reports as minted by the auth
// service. Handlers must hand this exact value back rather than mint their own.
var loginBlockCookie = signedCookieFor("testuser")

// blockWithoutCookie is a login response that reports neither an error nor a cookie.
func blockWithoutCookie() wire.TLVRestBlock {
	var b wire.TLVRestBlock
	b.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, "testuser"))
	return b
}

func failedLoginBlock() wire.TLVRestBlock {
	var b wire.TLVRestBlock
	b.Append(wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, uint16(1)))
	return b
}

func TestAuthHandler_GetToken(t *testing.T) {
	validToken := base64.URLEncoding.EncodeToString(signedCookieFor("testuser"))

	tests := []struct {
		name  string
		query string
		// remaining is the life left in the parked token; 0 means a fresh one.
		remaining time.Duration
		cookies   []*http.Cookie
		checkBody func(*testing.T, string)
	}{
		{
			name:  "Success_TokenCookie",
			query: "f=json&attributes=loginId&devId=ao1yOLlHVHhsa3o6&c=_callbacks_._0mq8wqdav",
			cookies: []*http.Cookie{
				{Name: bosTokenCookie, Value: validToken},
			},
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "_callbacks_._0mq8wqdav(")
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"loginId":"testuser"`)
				// The parked token is handed straight back, not re-minted.
				assert.Contains(t, body, `"a":"`+validToken+`"`)
				assert.Contains(t, body, `"expiresIn":"86400"`)
			},
		},
		{
			// getToken hands back the token minted at sign-in, so a browser that
			// sat on it for most of a day must be told the life that is actually
			// left, not the life the token was born with.
			name:      "Success_AgedTokenReportsRemainingLife",
			query:     "f=json&attributes=loginId&devId=ao1yOLlHVHhsa3o6&c=_callbacks_._0mq8wqdav",
			remaining: time.Hour,
			cookies: []*http.Cookie{
				{Name: bosTokenCookie, Value: validToken},
			},
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"expiresIn":"3600"`)
				assert.NotContains(t, body, `"expiresIn":"86400"`)
			},
		},
		{
			name:  "Unauthorized_NoCookie",
			query: "f=json&attributes=loginId&devId=ao1yOLlHVHhsa3o6&c=_callbacks_._abc",
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":401`)
				assert.Contains(t, body, `"redirectURL"`)
			},
		},
		{
			// A token past its brief life no longer cracks, which is what makes a
			// later visit sign in again.
			name:  "Unauthorized_UnsignedToken",
			query: "f=json&attributes=loginId&devId=dev123&c=_callbacks_._xyz",
			cookies: []*http.Cookie{
				{Name: bosTokenCookie, Value: base64.URLEncoding.EncodeToString([]byte("victim"))},
			},
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":401`)
				assert.Contains(t, body, `"redirectURL"`)
				assert.NotContains(t, body, "victim")
			},
		},
		{
			// The screen name comes only from a signature-verified token, so these
			// forgeable plaintext cookies must not authenticate anyone.
			name:  "Unauthorized_ForgedSSOCookies",
			query: "f=json&attributes=loginId&devId=dev123&c=_callbacks_._xyz",
			cookies: []*http.Cookie{
				{Name: "RSP_USER", Value: "victim"},
				{Name: "RSP_LOCAL", Value: "victim"},
				{Name: "localAuthUser", Value: "victim||victim"},
			},
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":401`)
				assert.Contains(t, body, `"redirectURL"`)
				assert.NotContains(t, body, "victim")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crack := crackSignedCookie
			if tt.remaining > 0 {
				crack = crackSignedCookieExpiring(tt.remaining)
			}
			handler := &AuthHandler{
				AuthService: &testAuthService{crackCookie: crack},
				Logger:      slog.Default(),
			}

			req, err := http.NewRequest(http.MethodGet, "/auth/getToken?"+tt.query, nil)
			assert.NoError(t, err)
			for _, c := range tt.cookies {
				req.AddCookie(c)
			}

			rr := httptest.NewRecorder()
			handler.GetToken(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			tt.checkBody(t, rr.Body.String())

			// Spent either way, so a reload has nothing to sign in with.
			assert.True(t, tokenCookieCleared(rr), "getToken should expire the token cookie")
		})
	}
}

// tokenCookieCleared reports whether the response expires the token cookie.
func tokenCookieCleared(rr *httptest.ResponseRecorder) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == bosTokenCookie && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// A second getToken must fail even inside the token's own lifetime: the cookie is
// gone after the first, so every reload lands on the login page.
func TestAuthHandler_GetToken_IsOneShot(t *testing.T) {
	handler := &AuthHandler{
		AuthService: &testAuthService{crackCookie: crackSignedCookie},
		Logger:      slog.Default(),
	}
	validToken := base64.URLEncoding.EncodeToString(signedCookieFor("testuser"))

	get := func(withCookie bool) string {
		req := httptest.NewRequest(http.MethodGet, "/auth/getToken?f=json&attributes=loginId&devId=dev1", nil)
		if withCookie {
			req.AddCookie(&http.Cookie{Name: bosTokenCookie, Value: validToken})
		}
		rr := httptest.NewRecorder()
		handler.GetToken(rr, req)
		return rr.Body.String()
	}

	assert.Contains(t, get(true), `"statusCode":200`)
	// The browser dropped the cookie, so the follow-up presents nothing.
	assert.Contains(t, get(false), `"statusCode":401`)
}

func TestAuthHandler_ClientLogin(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		contentType string
		body        string
		// query is appended to the request URL, to prove it is not read.
		query              string
		auth               *testAuthService
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_FormEncoded",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&devId=dev123",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				// The token is the cookie the auth service minted, not a re-mint.
				assert.Contains(t, body, `"a":"`+base64.URLEncoding.EncodeToString(loginBlockCookie)+`"`)
				assert.Contains(t, body, `"loginId":"testuser"`)
				assert.Contains(t, body, `"screenName":"testuser"`)
				assert.Contains(t, body, `"token"`)
				assert.Contains(t, body, `"sessionSecret"`)
			},
		},
		{
			// The legacy aliases the form path has always accepted alongside the
			// spec's s and pwd.
			name:        "Success_LegacyFieldNames",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "username=testuser&password=testpass&devId=dev123",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"loginId":"testuser"`)
			},
		},
		{
			// "longterm" is a year, and the response reports what was granted.
			name:        "Success_TokenTypeLongterm",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&devId=dev123&tokenType=longterm",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"expiresIn":"31536000"`)
				assert.Contains(t, body, `"tokenExpiresIn":31536000`)
			},
		},
		{
			// A bare count of seconds is a valid tokenType.
			name:        "Success_TokenTypeSeconds",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&devId=dev123&tokenType=3600",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"expiresIn":"3600"`)
				assert.Contains(t, body, `"tokenExpiresIn":3600`)
			},
		},
		{
			// Omitting tokenType is "shortterm", a day.
			name:        "Success_TokenTypeDefaultsToShortterm",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&devId=dev123",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"expiresIn":"86400"`)
				assert.Contains(t, body, `"tokenExpiresIn":86400`)
			},
		},
		{
			// A tokenType the server cannot honour is a parameter error, and the
			// credentials are never checked.
			name:               "Error_TokenTypeUnparsable",
			method:             "POST",
			contentType:        "application/x-www-form-urlencoded",
			body:               "s=testuser&pwd=testpass&tokenType=forever",
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":462`)
			},
		},
		{
			name:               "Error_TokenTypeBeyondMax",
			method:             "POST",
			contentType:        "application/x-www-form-urlencoded",
			body:               "s=testuser&pwd=testpass&tokenType=31536001",
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":462`)
			},
		},
		{
			// The spec puts these in the body, and a password in a URL is one
			// that has already been logged. Credentials in the query string are
			// not credentials at all.
			name:               "Error_CredentialsInQueryStringAreIgnored",
			method:             "POST",
			contentType:        "application/x-www-form-urlencoded",
			body:               "",
			query:              "?s=testuser&pwd=testpass&devId=dev123",
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":460`)
			},
		},
		{
			// A body value stands on its own; the query is not consulted even to
			// fill a gap.
			name:        "Success_BodyWinsOverQueryString",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&tokenType=longterm",
			query:       "?tokenType=600",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"expiresIn":"31536000"`)
			},
		},
		{
			name:               "Error_MissingUsername",
			method:             "POST",
			contentType:        "application/x-www-form-urlencoded",
			body:               "pwd=testpass",
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				// The code a client reads as "you left something out", which is
				// not the code that means the credentials were wrong.
				assert.Contains(t, body, `"statusCode":460`)
				assert.NotContains(t, body, "statusDetailCode")
				assert.Contains(t, body, "username and password required")
			},
		},
		{
			name:               "Error_MissingPassword",
			method:             "POST",
			contentType:        "application/x-www-form-urlencoded",
			body:               "s=testuser",
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":460`)
				assert.Contains(t, body, "username and password required")
			},
		},
		{
			name:        "Error_AuthFailed",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=wrongpass",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return failedLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, body string) {
				// The codes a client maps to "incorrect password".
				assert.Contains(t, body, `"statusCode":330`)
				assert.Contains(t, body, `"statusDetailCode":3011`)
			},
		},
		{
			name:        "Error_FLAPLoginError",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return wire.TLVRestBlock{}, errors.New("boom")
				},
			},
			expectedStatusCode: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "internal server error")
			},
		},
		{
			// A POST carries "f" in its body, the only place clientLogin states it.
			name:        "Error_AuthFailed_XMLRequestedInBody",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=wrongpass&f=xml",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return failedLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "<statusCode>330</statusCode>")
				assert.Contains(t, body, "<statusDetailCode>3011</statusDetailCode>")
			},
		},
		{
			name:        "Error_LoginResponseHasNoCookie",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
					return blockWithoutCookie(), nil
				},
			},
			expectedStatusCode: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "internal server error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()

			handler := &AuthHandler{
				AuthService: tt.auth,
				Logger:      logger,
			}

			req, err := http.NewRequest(tt.method, "/auth/clientLogin"+tt.query, strings.NewReader(tt.body))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", tt.contentType)

			rr := httptest.NewRecorder()

			handler.ClientLogin(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			responseBody := strings.TrimSpace(rr.Body.String())
			if tt.checkResponse != nil {
				tt.checkResponse(t, responseBody)
			}
		})
	}
}

func TestAuthHandler_ClientLogin_SendsClientIdentity(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedClientID string
	}{
		{
			name:             "DevIDNamesTheClient",
			body:             "s=testuser&pwd=testpass&devId=dev123",
			expectedClientID: "dev123",
		},
		{
			name:             "MissingDevIDFallsBack",
			body:             "s=testuser&pwd=testpass",
			expectedClientID: "WebAIM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got wire.FLAPSignonFrame
			handler := &AuthHandler{
				AuthService: &testAuthService{
					flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
						got = inFrame
						return successfulLoginBlock(), nil
					},
				},
				Logger: slog.Default(),
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/clientLogin", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			handler.ClientLogin(httptest.NewRecorder(), req)

			clientID, ok := got.String(wire.LoginTLVTagsClientIdentity)
			assert.True(t, ok, "signon frame should carry a client identity")
			assert.Equal(t, tt.expectedClientID, clientID)
		})
	}
}

func TestAuthHandler_ClientLogin_SendsRequestedTokenTTL(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantTTL uint32
	}{
		{
			name:    "OmittedIsShortterm",
			body:    "s=testuser&pwd=testpass",
			wantTTL: 86400,
		},
		{
			name:    "Shortterm",
			body:    "s=testuser&pwd=testpass&tokenType=shortterm",
			wantTTL: 86400,
		},
		{
			name:    "Longterm",
			body:    "s=testuser&pwd=testpass&tokenType=longterm",
			wantTTL: 31536000,
		},
		{
			name:    "ExplicitSeconds",
			body:    "s=testuser&pwd=testpass&tokenType=600",
			wantTTL: 600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got wire.FLAPSignonFrame
			handler := &AuthHandler{
				AuthService: &testAuthService{
					flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
						got = inFrame
						return successfulLoginBlock(), nil
					},
				},
				Logger: slog.Default(),
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/clientLogin", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			handler.ClientLogin(httptest.NewRecorder(), req)

			// What the client asked for is what login is asked to mint.
			ttl, ok := got.Uint32BE(wire.LoginTLVTagsTokenTTL)
			assert.True(t, ok, "signon frame should carry a token TTL")
			assert.Equal(t, tt.wantTTL, ttl)
		})
	}
}

func TestTokenTypeTTL(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
		want      time.Duration
		wantErr   bool
	}{
		{name: "omitted", tokenType: "", want: shortTermTTL},
		{name: "shortterm", tokenType: "shortterm", want: shortTermTTL},
		{name: "shortterm mixed case", tokenType: "ShortTerm", want: shortTermTTL},
		{name: "longterm", tokenType: "longterm", want: longTermTTL},
		{name: "longterm padded", tokenType: "  longterm  ", want: longTermTTL},
		{name: "seconds", tokenType: "3600", want: time.Hour},
		{name: "one second", tokenType: "1", want: time.Second},
		{name: "exactly the max", tokenType: "31536000", want: longTermTTL},
		{name: "zero seconds", tokenType: "0", wantErr: true},
		{name: "one past the max", tokenType: "31536001", wantErr: true},
		// large enough that scaling to a Duration would overflow int64
		{name: "overflowing seconds", tokenType: "99999999999999999", wantErr: true},
		{name: "negative", tokenType: "-1", wantErr: true},
		{name: "unrecognized word", tokenType: "forever", wantErr: true},
		{name: "float", tokenType: "60.5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenTypeTTL(tt.tokenType)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthHandler_LoginPSP_GET(t *testing.T) {
	handler := &AuthHandler{Logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "/_cqr/login/login.psp?devId=dev1&succUrl=http%3A%2F%2Flocalhost%3A8000%2F", nil)
	rr := httptest.NewRecorder()

	handler.LoginPSP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rr.Body.String(), "AIM Sign In")
	assert.Contains(t, rr.Body.String(), `name="devId" value="dev1"`)
}

func TestAuthHandler_Logout(t *testing.T) {
	handler := &AuthHandler{Logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "/auth/logout?f=json&a=sometoken&devId=dev1&succUrl=http%3A%2F%2Flocalhost%3A8000%2F.client%2F", nil)
	rr := httptest.NewRecorder()

	handler.Logout(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)

	loc, err := url.Parse(rr.Header().Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, "/_cqr/login/login.psp", loc.Path)
	assert.Equal(t, "dev1", loc.Query().Get("devId"))
	assert.Equal(t, "http://localhost:8000/.client/", loc.Query().Get("succUrl"))

	// Signing out spends the token cookie, whether or not getToken already did.
	// A 24h token left behind would sign the next person in as this account.
	cleared := rr.Result().Cookies()
	if assert.Len(t, cleared, 1) {
		assert.Equal(t, bosTokenCookie, cleared[0].Name)
		assert.Empty(t, cleared[0].Value)
		assert.Less(t, cleared[0].MaxAge, 1)
	}
}

func TestAuthHandler_LoginPSP_POST_Success(t *testing.T) {
	var got wire.FLAPSignonFrame
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				got = inFrame
				return successfulLoginBlock(), nil
			},
		},
		Logger: slog.Default(),
	}

	form := url.Values{}
	form.Set("loginId", "testuser")
	form.Set("password", "secret")
	form.Set("devId", "dev1")
	form.Set("succUrl", "http://localhost:8000/")
	req := httptest.NewRequest(http.MethodPost, "/_cqr/login/login.psp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.LoginPSP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "http://localhost:8000/", rr.Header().Get("Location"))

	set := make(map[string]*http.Cookie)
	for _, c := range rr.Result().Cookies() {
		set[c.Name] = c
	}

	// The cookie carries the BOS token from the login response, unchanged.
	tokenCookie := set[bosTokenCookie]
	if assert.NotNil(t, tokenCookie) {
		assert.True(t, tokenCookie.HttpOnly)
		raw, err := base64.URLEncoding.DecodeString(tokenCookie.Value)
		assert.NoError(t, err)
		assert.Equal(t, loginBlockCookie, raw)
		// The browser drops it on the same schedule the server stops honouring it.
		assert.Equal(t, 86400, tokenCookie.MaxAge)
	}

	for _, name := range []string{"RSP_USER", "RSP_LOCAL", "localAuthUser"} {
		assert.NotContains(t, set, name)
	}

	// The Web API asks login for a token that outlives the browser round trip.
	ttl, ok := got.Uint32BE(wire.LoginTLVTagsTokenTTL)
	assert.True(t, ok)
	assert.Equal(t, uint32(86400), ttl)

	// The devId names the client on the resulting session.
	clientID, ok := got.String(wire.LoginTLVTagsClientIdentity)
	assert.True(t, ok, "signon frame should carry a client identity")
	assert.Equal(t, "dev1", clientID)
}

func TestAuthHandler_LoginPSP_POST_ServiceErrors(t *testing.T) {
	tests := []struct {
		name      string
		flapLogin func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error)
	}{
		{
			name: "LoginResponseHasNoCookie",
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				return blockWithoutCookie(), nil
			},
		},
		{
			name: "AuthServiceUnreachable",
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				return wire.TLVRestBlock{}, errors.New("boom")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &AuthHandler{
				AuthService: &testAuthService{flapLogin: tt.flapLogin},
				Logger:      slog.Default(),
			}

			form := url.Values{}
			form.Set("loginId", "testuser")
			form.Set("password", "secret")
			req := httptest.NewRequest(http.MethodPost, "/_cqr/login/login.psp", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			handler.LoginPSP(rr, req)

			// A broken auth service must not read as a mistyped password.
			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.NotContains(t, rr.Body.String(), "Invalid screen name or password")
			assert.Empty(t, rr.Result().Cookies())
		})
	}
}

func TestAuthHandler_LoginPSP_POST_InvalidCredentials(t *testing.T) {
	handler := &AuthHandler{
		AuthService: &testAuthService{
			flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error) {
				return failedLoginBlock(), nil
			},
		},
		Logger: slog.Default(),
	}

	form := url.Values{}
	form.Set("loginId", "testuser")
	form.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/_cqr/login/login.psp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	handler.LoginPSP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid screen name or password")
}

func TestDefaultLoginSuccURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://ras.dev/_cqr/login/login.psp", nil)
	assert.Equal(t, "http://ras.dev/", defaultLoginSuccURL(req))

	// TLS terminated upstream, so the scheme only survives in the header.
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "https://ras.dev/", defaultLoginSuccURL(req))
}

func TestSafeLoginRedirectURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/_cqr/login/login.psp", nil)

	assert.Equal(t, "http://localhost:8000/", safeLoginRedirectURL(req, "http://localhost:8000/"))
	assert.Equal(t, "http://localhost/", safeLoginRedirectURL(req, "http://evil.example/"))
}
