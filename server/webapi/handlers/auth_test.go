package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// testAuthService implements AuthService for ClientLogin tests (only FLAPLogin and
// CrackCookie are exercised).
type testAuthService struct {
	flapLogin   func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error)
	crackCookie func(authCookie []byte) (state.ServerCookie, error)
}

func (t *testAuthService) BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error) {
	return wire.SNACMessage{}, nil
}

func (t *testAuthService) BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, advertisedHost string) (wire.SNACMessage, error) {
	return wire.SNACMessage{}, nil
}

func (t *testAuthService) CrackCookie(authCookie []byte) (state.ServerCookie, error) {
	if t.crackCookie != nil {
		return t.crackCookie(authCookie)
	}
	return state.ServerCookie{}, nil
}

// signedCookieFor stands in for a CookieBaker-signed cookie naming screenName.
func signedCookieFor(screenName string) []byte {
	return []byte("signed:" + screenName)
}

// crackSignedCookie accepts only cookies produced by signedCookieFor, standing in
// for the signature check the real baker performs.
func crackSignedCookie(authCookie []byte) (state.ServerCookie, error) {
	name, ok := strings.CutPrefix(string(authCookie), "signed:")
	if !ok {
		return state.ServerCookie{}, errors.New("bad signature")
	}
	return state.ServerCookie{ScreenName: state.DisplayScreenName(name)}, nil
}

func (t *testAuthService) RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie, conf func(sess *state.Session)) (*state.SessionInstance, error) {
	return nil, nil
}

func (t *testAuthService) FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
	if t.flapLogin != nil {
		return t.flapLogin(ctx, inFrame, advertisedHost)
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
		name      string
		query     string
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
				assert.Contains(t, body, `"expiresIn":"60"`)
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
			handler := &AuthHandler{
				AuthService: &testAuthService{crackCookie: crackSignedCookie},
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
		name               string
		method             string
		contentType        string
		body               string
		auth               *testAuthService
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_JSONBody",
			method:      "POST",
			contentType: "application/json",
			body:        `{"username":"testuser","password":"testpass","devId":"dev123"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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
			// A caller that states a charset is still sending JSON.
			name:        "Success_JSONBodyWithCharset",
			method:      "POST",
			contentType: "application/json; charset=utf-8",
			body:        `{"username":"testuser","password":"testpass","devId":"dev123"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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
			name:        "Success_FormEncoded",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&devId=dev123",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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
			name:               "Error_MissingUsername",
			method:             "POST",
			contentType:        "application/json",
			body:               `{"username":"","password":"testpass"}`,
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
			contentType:        "application/json",
			body:               `{"username":"testuser","password":""}`,
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
			contentType: "application/json",
			body:        `{"username":"testuser","password":"wrongpass"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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
			contentType: "application/json",
			body:        `{"username":"testuser","password":"testpass"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
					return wire.TLVRestBlock{}, errors.New("boom")
				},
			},
			expectedStatusCode: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "internal server error")
			},
		},
		{
			name:               "Error_InvalidJSON",
			method:             "POST",
			contentType:        "application/json",
			body:               `{invalid json`,
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid JSON format")
			},
		},
		{
			// A POST carries "f" in its body, the only place clientLogin states it.
			name:        "Error_AuthFailed_XMLRequestedInBody",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=wrongpass&f=xml",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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
			contentType: "application/json",
			body:        `{"username":"testuser","password":"testpass"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
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

			req, err := http.NewRequest(tt.method, "/auth/clientLogin", strings.NewReader(tt.body))
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
			body:             `{"username":"testuser","password":"testpass","devId":"dev123"}`,
			expectedClientID: "dev123",
		},
		{
			name:             "MissingDevIDFallsBack",
			body:             `{"username":"testuser","password":"testpass"}`,
			expectedClientID: "WebAIM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got wire.FLAPSignonFrame
			handler := &AuthHandler{
				AuthService: &testAuthService{
					flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
						got = inFrame
						return successfulLoginBlock(), nil
					},
				},
				Logger: slog.Default(),
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/clientLogin", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			handler.ClientLogin(httptest.NewRecorder(), req)

			clientID, ok := got.String(wire.LoginTLVTagsClientIdentity)
			assert.True(t, ok, "signon frame should carry a client identity")
			assert.Equal(t, tt.expectedClientID, clientID)
		})
	}
}
