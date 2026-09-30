package state

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

func TestE2EToken(t *testing.T) {
	baker, err := NewHMACCookieBaker()
	require.NoError(t, err)

	sm := NewInMemorySessionManager(slog.Default())
	instance, err := sm.AddSession(context.Background(), "Alice", false)
	require.NoError(t, err)
	instance.Session().SetSignonTime(time.Now())
	instance.SetSignonComplete()

	token, err := IssueE2EToken(baker, instance, time.Hour)
	require.NoError(t, err)
	assert.Less(t, len(token), 128, "the login cookie padding is dropped")

	got, expiry, err := CrackE2EToken(baker, token)
	require.NoError(t, err)
	assert.Equal(t, NewIdentScreenName("alice"), got.ScreenName)
	assert.Equal(t, instance.Num(), got.InstanceNum)
	assert.WithinDuration(t, time.Now().Add(time.Hour), expiry, 2*time.Second)
	assert.Same(t, instance, got.Live(sm))

	t.Run("dies with its session instance", func(t *testing.T) {
		stale := got
		stale.SignonTime = got.SignonTime.Add(-time.Second)
		assert.Nil(t, stale.Live(sm), "a later session of the account")

		gone := got
		gone.InstanceNum = got.InstanceNum + 1
		assert.Nil(t, gone.Live(sm))

		other := got
		other.ScreenName = NewIdentScreenName("bob")
		assert.Nil(t, other.Live(sm))
	})

	t.Run("tampered token", func(t *testing.T) {
		bad := bytes.Clone(token)
		bad[len(bad)/2] ^= 0x01
		_, _, err := CrackE2EToken(baker, bad)
		assert.Error(t, err)
	})

	t.Run("other key", func(t *testing.T) {
		otherBaker, err := NewHMACCookieBaker()
		require.NoError(t, err)
		_, _, err = CrackE2EToken(otherBaker, token)
		assert.Error(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		old, err := IssueE2EToken(baker, instance, -time.Second)
		require.NoError(t, err)
		_, _, err = CrackE2EToken(baker, old)
		assert.Error(t, err)
	})

	t.Run("login cookie is not a token", func(t *testing.T) {
		buf := &bytes.Buffer{}
		require.NoError(t, wire.MarshalBE(ServerCookie{Service: wire.BOS, ScreenName: "alice"}, buf))
		cookie, err := baker.Issue(buf.Bytes(), time.Hour)
		require.NoError(t, err)
		_, _, err = CrackE2EToken(baker, cookie)
		assert.Error(t, err)
	})

	t.Run("token is not a login cookie", func(t *testing.T) {
		data, _, err := baker.Crack(token)
		require.NoError(t, err)
		var c ServerCookie
		assert.Error(t, wire.UnmarshalBE(&c, bytes.NewReader(data)))
	})
}
