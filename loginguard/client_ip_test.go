package loginguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequestClientIP(t *testing.T) {
	trusted, err := ParsePrefixes([]string{"127.0.0.0/8", "::1", "10.0.0.5"})
	assert.NoError(t, err)

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string][]string
		want       string
	}{
		{
			name:       "direct client, socket address",
			remoteAddr: "198.51.100.7:40000",
			want:       "198.51.100.7",
		},
		{
			name:       "direct client cannot spoof its address",
			remoteAddr: "198.51.100.7:40000",
			headers:    map[string][]string{"X-Real-Ip": {"192.0.2.1"}, "X-Forwarded-For": {"192.0.2.1"}},
			want:       "198.51.100.7",
		},
		{
			name:       "local proxy, X-Real-IP",
			remoteAddr: "127.0.0.1:50000",
			headers:    map[string][]string{"X-Real-Ip": {"203.0.113.9"}},
			want:       "203.0.113.9",
		},
		{
			name:       "local IPv6 proxy, X-Forwarded-For last untrusted hop",
			remoteAddr: "[::1]:50000",
			headers:    map[string][]string{"X-Forwarded-For": {"192.0.2.1, 203.0.113.9, 10.0.0.5"}},
			want:       "203.0.113.9",
		},
		{
			name:       "local proxy without headers",
			remoteAddr: "127.0.0.1:50000",
			want:       "127.0.0.1",
		},
		{
			name:       "local proxy with garbage header",
			remoteAddr: "127.0.0.1:50000",
			headers:    map[string][]string{"X-Real-Ip": {"nonsense"}},
			want:       "127.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				r.Header[k] = v
			}
			assert.Equal(t, tt.want, RequestClientIP(r, trusted))
		})
	}
}

func TestClientIPMiddleware(t *testing.T) {
	var got string
	h := ClientIPMiddleware(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ClientIP(r.Context())
	}))
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Real-IP", "203.0.113.9")
	h.ServeHTTP(httptest.NewRecorder(), r)
	assert.Equal(t, "127.0.0.1", got, "no proxy is trusted unless listed")
}

func TestClientIPContext(t *testing.T) {
	assert.Equal(t, "", ClientIP(context.Background()))
	assert.Equal(t, "192.0.2.1:5190", ClientIP(WithClientIP(context.Background(), "192.0.2.1:5190")))
}

func TestParsePrefixes(t *testing.T) {
	got, err := ParsePrefixes([]string{" 127.0.0.0/8 ", "", "::1", "10.1.2.3/16"})
	assert.NoError(t, err)
	if assert.Len(t, got, 3) {
		assert.Equal(t, "127.0.0.0/8", got[0].String())
		assert.Equal(t, "::1/128", got[1].String())
		assert.Equal(t, "10.1.0.0/16", got[2].String())
	}
	_, err = ParsePrefixes([]string{"not-an-ip"})
	assert.Error(t, err)
}
