package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttachRequestID(t *testing.T) {
	t.Run("sets requestId from r query param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/buddylist/addBuddy?r=abc123", nil)
		data := attachRequestID(req, BaseResponse{
			Response: ResponseBody{
				StatusCode: 200,
				StatusText: "OK",
			},
		})

		br, ok := data.(BaseResponse)
		assert.True(t, ok)
		assert.Equal(t, "abc123", br.Response.RequestID)
	})

	t.Run("preserves explicit requestId", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/buddylist/addBuddy?r=abc123", nil)
		data := attachRequestID(req, BaseResponse{
			Response: ResponseBody{
				StatusCode: 200,
				StatusText: "OK",
				RequestID:  "existing",
			},
		})

		br, ok := data.(BaseResponse)
		assert.True(t, ok)
		assert.Equal(t, "existing", br.Response.RequestID)
	})

	t.Run("no-op without r param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/buddylist/addBuddy", nil)
		data := attachRequestID(req, BaseResponse{
			Response: ResponseBody{
				StatusCode: 200,
				StatusText: "OK",
			},
		})

		br, ok := data.(BaseResponse)
		assert.True(t, ok)
		assert.Empty(t, br.Response.RequestID)
	})
}

func TestSendResponseIncludesRequestID(t *testing.T) {
	req := httptest.NewRequest("GET", "/buddylist/addBuddy?r=req-42&f=json", nil)
	rr := httptest.NewRecorder()

	resp := BaseResponse{
		Response: ResponseBody{
			StatusCode: 200,
			StatusText: "OK",
			Data:       map[string]string{"resultCode": "success"},
		},
	}
	SendResponse(rr, req, resp, slog.Default())

	assert.Equal(t, http.StatusOK, rr.Code)
	body := strings.TrimSpace(rr.Body.String())
	assert.Equal(t, `{"response":{"statusCode":200,"statusText":"OK","requestId":"req-42","data":{"resultCode":"success"}}}`, body)
}

// A JSONP error must arrive as an executable callback, not as bare JSON in a
// <script> tag, which the Web AIM client reports as "Failed to load script tag".
func TestSendErrorJSONP(t *testing.T) {
	t.Run("wraps the envelope in the callback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/im/sendIM?c=_callbacks_._0mq8&r=42", nil)
		w := httptest.NewRecorder()

		SendError(w, req, http.StatusUnauthorized, "invalid or expired session")

		body := w.Body.String()
		assert.True(t, strings.HasPrefix(body, "_callbacks_._0mq8("), "body should open with the callback: %s", body)
		assert.True(t, strings.HasSuffix(body, ");"), "body should close the call: %s", body)
		assert.Contains(t, body, `"statusCode":401`)
		assert.Contains(t, body, `"statusText":"invalid or expired session"`)
		assert.Contains(t, w.Header().Get("Content-Type"), "javascript")
	})

	t.Run("uses HTTP 200 so the script executes", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/im/sendIM?c=cb&r=42", nil)
		w := httptest.NewRecorder()

		SendError(w, req, http.StatusUnauthorized, "nope")

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("echoes requestId so the client can match the reply", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/im/sendIM?c=cb&r=42", nil)
		w := httptest.NewRecorder()

		SendError(w, req, http.StatusBadRequest, "bad")

		assert.Contains(t, w.Body.String(), `"requestId":"42"`)
	})

	t.Run("accepts the callback alias", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/im/sendIM?callback=cb", nil)
		w := httptest.NewRecorder()

		SendError(w, req, http.StatusBadRequest, "bad")

		assert.True(t, strings.HasPrefix(w.Body.String(), "cb("))
	})

	t.Run("rejects an unsafe callback name rather than reflecting it", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/im/sendIM?c=alert(1)//", nil)
		w := httptest.NewRecorder()

		SendError(w, req, http.StatusBadRequest, "bad")

		assert.NotContains(t, w.Body.String(), "alert(1)")
		assert.Contains(t, w.Header().Get("Content-Type"), "json")
	})
}

// Without a callback the response stays plain JSON carrying the HTTP status.
func TestSendErrorJSONFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/im/sendIM?r=42", nil)
	w := httptest.NewRecorder()

	SendError(w, req, http.StatusNotFound, "not found")

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "json")
	assert.Contains(t, w.Body.String(), `"statusCode":404`)
}
