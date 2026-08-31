package state

import (
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
