package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// tightRateLimitClasses returns rate classes scaled down so tests run fast.
//
// OSCAR's moving average tracks the interval between requests in milliseconds,
// seeded at MaxLevel, and each back-to-back request halves it at WindowSize 2.
// So from 200 the sequence is 100 (clear), 50 (limited), 25, 12, 6 — the second
// request trips the limit, and none of the first five fall below the disconnect
// threshold. Recovering past ClearLevel takes a ~150ms pause rather than the
// several seconds the production classes would need.
func tightRateLimitClasses() wire.RateLimitClasses {
	var classes [5]wire.RateClass
	for i := range classes {
		classes[i] = wire.RateClass{
			ID:              wire.RateLimitClassID(i + 1),
			WindowSize:      2,
			ClearLevel:      100,
			AlertLevel:      80,
			LimitLevel:      70,
			DisconnectLevel: 2,
			MaxLevel:        200,
		}
	}
	return wire.NewRateLimitClasses(classes)
}

// newTestOSCARInstance builds an OSCAR session with rate limit state
// initialized, mirroring what RegisterBOSSession does at startSession time.
func newTestOSCARInstance(t *testing.T, classes wire.RateLimitClasses) *state.SessionInstance {
	t.Helper()

	instance := state.NewSession().AddInstance()
	instance.Session().SetIdentScreenName(state.NewIdentScreenName("me"))
	instance.Session().SetDisplayScreenName("me")
	instance.Session().SetRateClasses(time.Now(), classes)

	return instance
}

// newTestWebAPISessionOn builds a WebAPI session over an existing OSCAR
// instance. Two of them model two browser tabs signed in as the same account:
// each tab holds its own aimsid and its own WebAPISession, but the account has
// one OSCAR session and therefore one set of rate limit states.
func newTestWebAPISessionOn(aimsid string, instance *state.SessionInstance) *state.WebAPISession {
	return &state.WebAPISession{
		AimSID:       aimsid,
		ScreenName:   "me",
		OSCARSession: instance,
		EventQueue:   types.NewEventQueue(10),
	}
}

// newTestWebAPISession builds a WebAPI session backed by a real OSCAR session
// with rate limit state initialized.
func newTestWebAPISession(t *testing.T, classes wire.RateLimitClasses) *state.WebAPISession {
	t.Helper()

	return newTestWebAPISessionOn("aimsid-1", newTestOSCARInstance(t, classes))
}

func newTestRateLimitMiddleware() *RateLimitMiddleware {
	return NewRateLimitMiddleware(wire.DefaultSNACRateLimits(), slog.New(slog.DiscardHandler))
}

// rateLimitEventStatuses returns the status string of every rateLimit event
// queued on the session, in order.
func rateLimitEventStatuses(t *testing.T, session *state.WebAPISession) []string {
	t.Helper()

	var statuses []string
	for _, event := range session.EventQueue.GetAllEvents() {
		if event.Type != types.EventTypeRateLimit {
			continue
		}
		payload, ok := event.Data.(types.RateLimitEvent)
		if !assert.True(t, ok, "rateLimit event carried %T", event.Data) {
			continue
		}
		if assert.Len(t, payload.Classes, 1) {
			statuses = append(statuses, payload.Classes[0].Status)
		}
	}
	return statuses
}

// assertRateLimited checks that a response is the Web API's rate limit
// rejection: HTTP 200 at the transport level so the client parses the body,
// with envelope code 430 carrying the rejection inside. wantRetryAfter is the
// expected Retry-After header, "" for a rejection that carries none.
func assertRateLimited(t *testing.T, rec *httptest.ResponseRecorder, wantRetryAfter string) {
	t.Helper()

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, wantRetryAfter, rec.Header().Get("Retry-After"))

	var envelope struct {
		Response struct {
			StatusCode int    `json:"statusCode"`
			StatusText string `json:"statusText"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	assert.Equal(t, rateLimitStatusCode, envelope.Response.StatusCode)
	assert.Equal(t, "rate limit exceeded", envelope.Response.StatusText)
}

func TestRateLimitMiddleware_OSCAR(t *testing.T) {
	tests := []struct {
		name string
		// foodGroup/subGroup passed to the middleware
		foodGroup uint16
		subGroup  uint16
		// requests is how many times the wrapped handler is invoked
		requests int
		// wantCalls is how many of those requests reach the handler
		wantCalls int
		// wantRetryAfter is the Retry-After header on the final rejection, "" for
		// a rejection that carries none
		wantRetryAfter string
	}{
		{
			name:      "first request is allowed",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			requests:  1,
			wantCalls: 1,
		},
		{
			name:      "a burst trips the limit",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			requests:  5,
			wantCalls: 1,
			// retryAfterFor rounds the sub-second wait these tight classes need
			// up to the minRetryAfter floor.
			wantRetryAfter: "1",
		},
		{
			name:      "sustained abuse escalates to disconnect",
			foodGroup: wire.ICBM,
			subGroup:  wire.ICBMChannelMsgToHost,
			// the 7th request drives the average below DisconnectLevel
			requests:  7,
			wantCalls: 1,
			// a disconnected session has no aimsid left to retry with
			wantRetryAfter: "",
		},
		{
			// A non-IM class is enforced the same way. The middleware only ever
			// rejects; notifying the client is the per-account monitor's job, and
			// it surfaces only the IM class to the alert.
			name:           "a non-IM class is still enforced",
			foodGroup:      wire.Feedbag,
			subGroup:       wire.FeedbagInsertItem,
			requests:       5,
			wantCalls:      1,
			wantRetryAfter: "1",
		},
		{
			name: "unmapped SNAC fails open",
			// 0xFFFF is not a food group, so no rate class maps to it
			foodGroup: 0xFFFF,
			subGroup:  0xFFFF,
			requests:  5,
			wantCalls: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newTestWebAPISession(t, tightRateLimitClasses())
			middleware := newTestRateLimitMiddleware()

			calls := 0
			handler := middleware.OSCAR(tt.foodGroup, tt.subGroup)(
				func(w http.ResponseWriter, r *http.Request, s *state.WebAPISession) {
					calls++
					w.WriteHeader(http.StatusOK)
				})

			var last *httptest.ResponseRecorder
			for range tt.requests {
				last = httptest.NewRecorder()
				handler(last, httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
			}

			assert.Equal(t, tt.wantCalls, calls)
			// The middleware enforces the limit but never pushes rate limit
			// events; that is the per-account monitor's responsibility.
			assert.Empty(t, rateLimitEventStatuses(t, session))

			if tt.wantCalls < tt.requests {
				assertRateLimited(t, last, tt.wantRetryAfter)
			} else {
				assert.Equal(t, http.StatusOK, last.Code)
			}
		})
	}
}

// The monitor broadcasts transitions, not current state, so without a seed a
// session signing on mid-limit shows no banner while its sends are rejected — and
// the client's alert is sticky, so the eventual "clear" has nothing to dismiss.
func TestSeedRateLimitAlert(t *testing.T) {
	imClass, ok := wire.DefaultSNACRateLimits().RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	require.True(t, ok)

	// limitedSession returns a session on an account already in the limited state.
	limitedSession := func(t *testing.T) *state.WebAPISession {
		t.Helper()

		session := newTestWebAPISession(t, tightRateLimitClasses())
		sess := session.OSCARSession.Session()
		for i := 0; sess.RateLimitStates()[imClass-1].CurrentStatus != wire.RateLimitStatusLimited; i++ {
			require.Less(t, i, 100, "class never reached the limited state")
			sess.EvaluateRateLimit(time.Now(), imClass)
		}
		return session
	}

	t.Run("a session starting on a limited account is told", func(t *testing.T) {
		session := limitedSession(t)

		seedRateLimitAlert(session, imClass)

		assert.Equal(t, []string{"limit"}, rateLimitEventStatuses(t, session))
	})

	t.Run("a session starting on a clear account is told nothing", func(t *testing.T) {
		session := newTestWebAPISession(t, tightRateLimitClasses())

		seedRateLimitAlert(session, imClass)

		assert.Empty(t, rateLimitEventStatuses(t, session))
	})

	t.Run("a zero class id disables the alert", func(t *testing.T) {
		session := limitedSession(t)

		seedRateLimitAlert(session, 0)

		assert.Empty(t, rateLimitEventStatuses(t, session))
	})
}

// Retry-After must name a wait that actually clears the limit. A rejected
// request is still charged, so a client retrying on the advertised interval
// drives the moving average toward that interval: a hint below the class's
// ClearLevel holds the average under the bar and the client stays limited
// forever.
func TestRetryAfterFor_clearsTheLimit(t *testing.T) {
	classes := wire.DefaultRateLimitClasses()

	for _, class := range classes.All() {
		t.Run(fmt.Sprintf("class %d", class.ID), func(t *testing.T) {
			sess := state.NewSession()
			sess.AddInstance()

			now := time.Now()
			sess.SetRateClasses(now, classes)

			// Burst until the class trips.
			var status wire.RateLimitStatus
			for status != wire.RateLimitStatusLimited {
				now = now.Add(100 * time.Millisecond)
				status = sess.EvaluateRateLimit(now, class.ID)
				require.NotEqual(t, wire.RateLimitStatusDisconnect, status, "burst escalated past limited")
			}

			// Wait exactly as long as the rejection advertised, then retry.
			retryAfter := retryAfterFor(sess.RateLimitStates()[class.ID-1])
			now = now.Add(retryAfter)

			assert.Equal(t, wire.RateLimitStatusClear, sess.EvaluateRateLimit(now, class.ID),
				"honoring a Retry-After of %s did not clear the limit", retryAfter)
		})
	}
}

// The rejection advertises the wait computed for the class it charged, not a
// flat one.
func TestRateLimitMiddleware_OSCAR_retryAfterMatchesClass(t *testing.T) {
	session := newTestWebAPISession(t, wire.DefaultRateLimitClasses())
	middleware := newTestRateLimitMiddleware()

	handler := middleware.OSCAR(wire.ICBM, wire.ICBMChannelMsgToHost)(
		func(w http.ResponseWriter, r *http.Request, s *state.WebAPISession) {})

	classID, ok := wire.DefaultSNACRateLimits().RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	require.True(t, ok)

	// Back-to-back requests trip the limit; keep going until one is rejected.
	var rec *httptest.ResponseRecorder
	for range 20 {
		rec = httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM", nil), session)
		if rec.Header().Get("Retry-After") != "" {
			break
		}
	}

	want := retryAfterFor(session.OSCARSession.Session().RateLimitStates()[classID-1])
	assert.Equal(t, fmt.Sprintf("%d", int(want.Seconds())), rec.Header().Get("Retry-After"))
	// The production IM class clears at 5100ms, so the wait is necessarily
	// longer than the flat 5s hint this replaced.
	assert.Greater(t, want, 5*time.Second)
}

// The rejection is encoded in whatever format the request negotiates, via the
// same SendResponse path a normal handler uses.
func TestRateLimitMiddleware_sendRateLimited(t *testing.T) {
	tests := []struct {
		name string
		// query is appended to the request URL
		query string
		// wantCode is the transport status
		wantCode int
		// wantBody is the exact response body
		wantBody string
		// wantContentType is a substring of the Content-Type header
		wantContentType string
	}{
		{
			name:            "plain JSON",
			query:           "",
			wantCode:        http.StatusOK,
			wantBody:        `{"response":{"statusCode":430,"statusText":"rate limit exceeded","data":{}}}`,
			wantContentType: "application/json",
		},
		{
			name:            "JSONP callback",
			query:           "?c=myCallback",
			wantCode:        http.StatusOK,
			wantBody:        `myCallback({"response":{"statusCode":430,"statusText":"rate limit exceeded","data":{}}});`,
			wantContentType: "application/javascript",
		},
		{
			// The client correlates a JSONP reply solely by response.requestId,
			// so the request's "r" param must be echoed back or the request hangs.
			name:            "JSONP callback echoes requestId",
			query:           "?c=myCallback&r=42",
			wantCode:        http.StatusOK,
			wantBody:        `myCallback({"response":{"statusCode":430,"statusText":"rate limit exceeded","requestId":"42","data":{}}});`,
			wantContentType: "application/javascript",
		},
		{
			// Parens would let the callback name inject script; SendResponse
			// rejects the malformed callback rather than reflecting it.
			name:     "invalid JSONP callback is rejected",
			query:    "?c=alert(1)",
			wantCode: http.StatusBadRequest,
			// sendJSONError encodes with json.Encoder, which appends a newline.
			wantBody:        "{\"response\":{\"statusCode\":400,\"statusText\":\"invalid callback parameter\",\"data\":{}}}\n",
			wantContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM"+tt.query, nil), 5*time.Second)

			body, err := io.ReadAll(rec.Body)
			assert.NoError(t, err)

			assert.Equal(t, tt.wantCode, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), tt.wantContentType)
			assert.Equal(t, tt.wantBody, string(body))
		})
	}
}

// A client asking for XML or AMF (via f= or the Accept header) still gets a
// parseable rejection envelope rather than JSON, since the rejection rides the
// same SendResponse path as a normal handler.
func TestRateLimitMiddleware_sendRateLimited_nonJSONFormats(t *testing.T) {
	t.Run("f=xml", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM?f=xml", nil), 5*time.Second)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "xml")
		body := rec.Body.String()
		assert.Contains(t, body, "<statusCode>430</statusCode>")
		assert.Contains(t, body, "rate limit exceeded")
	})

	t.Run("f=amf", func(t *testing.T) {
		rec := httptest.NewRecorder()
		newTestRateLimitMiddleware().sendRateLimited(rec, httptest.NewRequest(http.MethodGet, "/im/sendIM?f=amf", nil), 5*time.Second)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "5", rec.Header().Get("Retry-After"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "amf")
		assert.NotEmpty(t, rec.Body.Bytes())
	})

	t.Run("Accept amf", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/im/sendIM", nil)
		req.Header.Set("Accept", "application/x-amf")
		newTestRateLimitMiddleware().sendRateLimited(rec, req, 5*time.Second)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "amf")
		assert.NotEmpty(t, rec.Body.Bytes())
	})
}

func TestRateLimitStatusName(t *testing.T) {
	tests := []struct {
		name   string
		status wire.RateLimitStatus
		want   string
	}{
		{name: "clear", status: wire.RateLimitStatusClear, want: "clear"},
		{name: "alert maps to the client's warn", status: wire.RateLimitStatusAlert, want: "warn"},
		{name: "limited", status: wire.RateLimitStatusLimited, want: "limit"},
		{name: "disconnect", status: wire.RateLimitStatusDisconnect, want: "disconnect"},
		{name: "unknown status has no client equivalent", status: wire.RateLimitStatus(0), want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rateLimitStatusName(tt.status))
		})
	}
}
