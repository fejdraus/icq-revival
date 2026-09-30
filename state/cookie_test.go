package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHMACCookieBaker_IssueCrackTTL(t *testing.T) {
	tests := []struct {
		name    string
		ttl     time.Duration
		wantErr string
	}{
		{
			name: "default TTL",
			ttl:  DefaultCookieTTL,
		},
		{
			name: "year-long TTL",
			ttl:  365 * 24 * time.Hour,
		},
		{
			name:    "already expired",
			ttl:     -time.Second,
			wantErr: "HMAC cookie expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baker, err := NewHMACCookieBaker()
			require.NoError(t, err)

			cookie, err := baker.Issue([]byte("the-payload"), tc.ttl)
			require.NoError(t, err)
			assert.Len(t, cookie, authCookieLen)

			payload, expiry, err := baker.Crack(cookie)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []byte("the-payload"), payload)
			// second-granularity in the wire format, so allow a second of slop
			assert.WithinDuration(t, time.Now().Add(tc.ttl), expiry, time.Second)
		})
	}
}

func TestNewPersistentHMACCookieBaker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookie.key")

	first, err := NewPersistentHMACCookieBaker(path)
	assert.NoError(t, err)
	token, err := first.Issue([]byte("data"), time.Hour)
	assert.NoError(t, err)

	// a restart reads the same key back, and the token still holds
	second, err := NewPersistentHMACCookieBaker(path)
	assert.NoError(t, err)
	data, _, err := second.Crack(token)
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	// a key file of the wrong length is replaced
	assert.NoError(t, os.WriteFile(path, []byte("short"), 0o600))
	third, err := NewPersistentHMACCookieBaker(path)
	assert.NoError(t, err)
	key, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.Len(t, key, cookieKeyLen)
	_, _, err = third.Crack(token)
	assert.Error(t, err)
}
