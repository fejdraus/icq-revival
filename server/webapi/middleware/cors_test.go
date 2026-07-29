package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
)

// stubValidator records how many times a key was looked up so the tests can
// assert that CORSMiddleware and the auth layer share a single lookup.
type stubValidator struct {
	key    *state.WebAPIKey
	lookup int
}

func (s *stubValidator) GetAPIKeyByDevKey(_ context.Context, devKey string) (*state.WebAPIKey, error) {
	s.lookup++
	if s.key == nil || s.key.DevKey != devKey {
		return nil, nil
	}
	return s.key, nil
}

func (s *stubValidator) UpdateLastUsed(context.Context, string) error { return nil }

func newTestMiddleware(v APIKeyValidator) *AuthMiddleware {
	return NewAuthMiddleware(v, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// The Web AIM client permanently downgrades to JSONP when a cross-origin
// response arrives without Access-Control-Allow-Origin, so every response the
// auth layer rejects must still carry CORS headers. That only holds while
// CORSMiddleware wraps the auth middleware.
func TestCORSMiddleware_HeadersOnAuthRejection(t *testing.T) {
	// The auth layer reports failures in the response envelope rather than the
	// HTTP status, so the envelope's statusCode is what identifies a rejection.
	tests := []struct {
		name         string
		query        string
		validator    *stubValidator
		wantEnvelope string
	}{
		{
			name:         "missing credentials",
			query:        "?f=json",
			validator:    &stubValidator{},
			wantEnvelope: `"statusCode":400`,
		},
		{
			name:         "unknown api key",
			query:        "?k=nosuchkey",
			validator:    &stubValidator{},
			wantEnvelope: `"statusCode":403`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMiddleware(tt.validator)
			var reachedHandler bool
			h := m.CORSMiddleware(m.AuthenticateFlexible(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reachedHandler = true
					w.WriteHeader(http.StatusOK)
				})))

			r := httptest.NewRequest(http.MethodGet, "/im/sendIM"+tt.query, nil)
			r.Header.Set("Origin", "http://localhost:8000")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			assert.False(t, reachedHandler, "auth layer should have rejected the request")
			assert.Contains(t, w.Body.String(), tt.wantEnvelope)
			assert.Equal(t, "http://localhost:8000", w.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "Origin", w.Header().Get("Vary"))
		})
	}
}

// A 404 for an endpoint this server does not implement (/service/getAttributes,
// /metrics/sendIM) must reach the client as a 404 rather than as a blocked
// response.
func TestCORSMiddleware_HeadersOn404(t *testing.T) {
	m := newTestMiddleware(&stubValidator{})
	h := m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	r := httptest.NewRequest(http.MethodGet, "/service/getAttributes?f=json&aimsid=abc", nil)
	r.Header.Set("Origin", "http://localhost:8000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "http://localhost:8000", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_PreflightShortCircuits(t *testing.T) {
	m := newTestMiddleware(&stubValidator{})
	var reachedNext bool
	h := m.CORSMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reachedNext = true
	}))

	r := httptest.NewRequest(http.MethodOptions, "/im/sendIM", nil)
	r.Header.Set("Origin", "http://localhost:8000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.False(t, reachedNext, "preflight must not reach the wrapped handler")
	assert.Equal(t, "http://localhost:8000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
}

// CORSMiddleware runs ahead of authentication and so resolves the API key
// itself; the auth layer behind it must reuse that lookup rather than repeat it.
func TestCORSMiddleware_SharesKeyLookupWithAuth(t *testing.T) {
	v := &stubValidator{key: &state.WebAPIKey{
		DevID:     "dev1",
		DevKey:    "goodkey",
		IsActive:  true,
		RateLimit: 100,
	}}
	m := newTestMiddleware(v)

	var served bool
	h := m.CORSMiddleware(m.Authenticate(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			served = true
			key, ok := r.Context().Value(ContextKeyAPIKey).(*state.WebAPIKey)
			require.True(t, ok, "handler should see the validated key")
			assert.Equal(t, "dev1", key.DevID)
			w.WriteHeader(http.StatusOK)
		})))

	r := httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession?k=goodkey", nil)
	r.Header.Set("Origin", "http://localhost:8000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.True(t, served)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, v.lookup, "key should be resolved once per request, not once per middleware")
}

// Per-key origin allowlists must keep working now that the origin decision is
// made before authentication.
func TestCORSMiddleware_PerKeyOriginAllowlist(t *testing.T) {
	v := &stubValidator{key: &state.WebAPIKey{
		DevID:          "dev1",
		DevKey:         "goodkey",
		IsActive:       true,
		RateLimit:      100,
		AllowedOrigins: []string{"http://allowed.example"},
	}}
	m := newTestMiddleware(v)
	h := m.CORSMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("allowed origin", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/im/sendIM?k=goodkey", nil)
		r.Header.Set("Origin", "http://allowed.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Equal(t, "http://allowed.example", w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("disallowed origin", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/im/sendIM?k=goodkey", nil)
		r.Header.Set("Origin", "http://evil.example")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})
}

// A POST body must survive the middleware chain: CORSMiddleware reads the API
// key from the query string only, so it never parses the form.
func TestCORSMiddleware_DoesNotConsumePOSTBody(t *testing.T) {
	m := newTestMiddleware(&stubValidator{})
	h := m.CORSMiddleware(m.AuthenticateFlexible(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			assert.Equal(t, "message=hello", string(body))
			w.WriteHeader(http.StatusOK)
		})))

	r := httptest.NewRequest(http.MethodPost, "/im/sendIM?aimsid=abc", strings.NewReader("message=hello"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://localhost:8000")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

// The auth layer's own rejections must be JSONP-wrapped too, otherwise a client
// already in JSONP mode gets a script-tag syntax error instead of the reason.
func TestAuthErrorsHonorJSONP(t *testing.T) {
	m := newTestMiddleware(&stubValidator{})

	t.Run("session error", func(t *testing.T) {
		h := m.RequireSession(&stubSessionResolver{}, func(http.ResponseWriter, *http.Request, *state.WebAPISession) {
			t.Fatal("handler should not run")
		})

		r := httptest.NewRequest(http.MethodGet, "/im/sendIM?c=_callbacks_._x&r=7", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		body := w.Body.String()
		assert.True(t, strings.HasPrefix(body, "_callbacks_._x("), "got %s", body)
		assert.True(t, strings.HasSuffix(body, ");"), "got %s", body)
		assert.Contains(t, body, `"statusCode":400`)
		assert.Contains(t, body, `"requestId":"7"`)
		// A 4xx would stop the browser executing the script tag.
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("missing credentials", func(t *testing.T) {
		h := m.AuthenticateFlexible(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler should not run")
		}))

		r := httptest.NewRequest(http.MethodGet, "/im/sendIM?c=cb&r=9", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		body := w.Body.String()
		assert.True(t, strings.HasPrefix(body, "cb("), "got %s", body)
		assert.Contains(t, body, `"statusCode":400`)
		assert.Contains(t, body, `"requestId":"9"`)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("without a callback the session error keeps its HTTP status", func(t *testing.T) {
		h := m.RequireSession(&stubSessionResolver{}, func(http.ResponseWriter, *http.Request, *state.WebAPISession) {
			t.Fatal("handler should not run")
		})

		r := httptest.NewRequest(http.MethodGet, "/im/sendIM", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Header().Get("Content-Type"), "json")
	})
}

// stubSessionResolver never resolves a session, so RequireSession always rejects.
type stubSessionResolver struct{}

func (stubSessionResolver) GetSession(context.Context, string) (*state.WebAPISession, error) {
	return nil, assert.AnError
}

func (stubSessionResolver) TouchSession(context.Context, string) error { return nil }
