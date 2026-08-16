package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/webapi/middleware"
	"github.com/mk6i/open-oscar-server/state"
)

// testListener is a listener group whose SSL half is present only when the
// test asks for it.
func testListener(sslAvailable bool) config.ListenerGroup {
	g := config.ListenerGroup{
		Name:                   "local",
		BOSListenAddress:       "0.0.0.0:5190",
		BOSAdvertisedHostPlain: "bos.example.com:5190",
	}
	if sslAvailable {
		g.BOSListenAddressSSL = "0.0.0.0:5191"
		g.BOSAdvertisedHostSSL = "ssl.example.com:5193"
	}
	return g
}

// bridgeRequest builds a startOSCARSession request carrying the API key the
// middleware would have put on the context.
func bridgeRequest(query string, apiKey *state.WebAPIKey) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession?"+query, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyAPIKey, apiKey))
	}
	return req
}

// bridgeData is the data object of a successful startOSCARSession response.
type bridgeData struct {
	Response struct {
		StatusCode int `json:"statusCode"`
		Data       struct {
			Host        string `json:"host"`
			Port        int    `json:"port"`
			Cookie      string `json:"cookie"`
			TLSCertName string `json:"tlsCertName"`
		} `json:"data"`
	} `json:"response"`
}

func TestOSCARBridgeHandler_StartOSCARSession(t *testing.T) {
	validToken := base64.URLEncoding.EncodeToString(signedCookieFor("testuser"))
	unrestrictedKey := &state.WebAPIKey{DevID: "dev123"}

	tests := []struct {
		name         string
		query        string
		apiKey       *state.WebAPIKey
		sslAvailable bool
		expectedCode int
		checkBody    func(t *testing.T, body string)
	}{
		{
			// No tlsCertName, which is how the client reads "connect in the clear".
			name:         "Success_Plaintext",
			query:        "a=" + validToken,
			apiKey:       unrestrictedKey,
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				got := decodeBridgeData(t, body)
				assert.Equal(t, 200, got.Response.StatusCode)
				assert.Equal(t, "bos.example.com", got.Response.Data.Host)
				assert.Equal(t, 5190, got.Response.Data.Port)
				assert.Empty(t, got.Response.Data.TLSCertName)
			},
		},
		{
			name:         "Success_TLS",
			query:        "a=" + validToken + "&useTLS=1",
			apiKey:       unrestrictedKey,
			sslAvailable: true,
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				got := decodeBridgeData(t, body)
				assert.Equal(t, "ssl.example.com", got.Response.Data.Host)
				assert.Equal(t, 5193, got.Response.Data.Port)
				// The certificate is issued to the host the client is sent to.
				assert.Equal(t, "ssl.example.com", got.Response.Data.TLSCertName)
			},
		},
		{
			// Encryption the server cannot provide degrades to a plaintext host
			// rather than failing the handoff.
			name:         "TLSRequestedButUnavailable_DegradesToPlaintext",
			query:        "a=" + validToken + "&useTLS=true",
			apiKey:       unrestrictedKey,
			sslAvailable: false,
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				got := decodeBridgeData(t, body)
				assert.Equal(t, "bos.example.com", got.Response.Data.Host)
				assert.Empty(t, got.Response.Data.TLSCertName)
			},
		},
		{
			name:         "Error_MissingToken",
			query:        "",
			apiKey:       unrestrictedKey,
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "authentication token required")
			},
		},
		{
			name:         "Error_TokenNotBase64",
			query:        "a=not!valid!base64",
			apiKey:       unrestrictedKey,
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid or expired token")
			},
		},
		{
			// A well-formed token the baker refuses to crack: wrong signature or
			// past its expiry.
			name:         "Error_TokenFailsSignatureCheck",
			query:        "a=" + base64.URLEncoding.EncodeToString([]byte("forged")),
			apiKey:       unrestrictedKey,
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid or expired token")
			},
		},
		{
			name:         "Error_NoAPIKeyOnContext",
			query:        "a=" + validToken,
			apiKey:       nil,
			expectedCode: http.StatusInternalServerError,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "internal server error")
			},
		},
		{
			name:         "Error_APIKeyLacksBridgeCapability",
			query:        "a=" + validToken,
			apiKey:       &state.WebAPIKey{DevID: "dev123", Capabilities: []string{"presence"}},
			expectedCode: http.StatusForbidden,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "OSCAR bridge not enabled")
			},
		},
		{
			name:         "Success_APIKeyGrantsBridgeCapability",
			query:        "a=" + validToken,
			apiKey:       &state.WebAPIKey{DevID: "dev123", Capabilities: []string{"presence", "oscar_bridge"}},
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				assert.Equal(t, 200, decodeBridgeData(t, body).Response.StatusCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &OSCARBridgeHandler{
				OSCARAuthService: &testAuthService{crackCookie: crackSignedCookie},
				Listener:         testListener(tt.sslAvailable),
				Logger:           slog.Default(),
			}

			rr := httptest.NewRecorder()
			handler.StartOSCARSession(rr, bridgeRequest(tt.query, tt.apiKey))

			assert.Equal(t, tt.expectedCode, rr.Code)
			tt.checkBody(t, rr.Body.String())
		})
	}
}

// The token arrives URL-safe, the way clientLogin minted it, and goes back out in
// standard base64, the alphabet the client decodes the sign-on cookie with. The
// cookie bytes here encode differently under each.
func TestOSCARBridgeHandler_StartOSCARSession_ReencodesCookie(t *testing.T) {
	rawCookie := []byte{0xff, 0xef, 0xbe}
	urlSafe := base64.URLEncoding.EncodeToString(rawCookie)
	standard := base64.StdEncoding.EncodeToString(rawCookie)
	assert.NotEqual(t, urlSafe, standard, "test cookie must distinguish the two alphabets")

	var cracked []byte
	handler := &OSCARBridgeHandler{
		OSCARAuthService: &testAuthService{
			crackCookie: func(authCookie []byte) (state.ServerCookie, error) {
				cracked = authCookie
				return state.ServerCookie{ScreenName: "testuser"}, nil
			},
		},
		Listener: testListener(false),
		Logger:   slog.Default(),
	}

	rr := httptest.NewRecorder()
	handler.StartOSCARSession(rr, bridgeRequest("a="+urlSafe, &state.WebAPIKey{DevID: "dev123"}))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, rawCookie, cracked, "the baker sees the decoded cookie")
	assert.Equal(t, standard, decodeBridgeData(t, rr.Body.String()).Response.Data.Cookie)
}

func decodeBridgeData(t *testing.T, body string) bridgeData {
	t.Helper()
	got := bridgeData{}
	assert.NoError(t, json.Unmarshal([]byte(body), &got))
	return got
}
