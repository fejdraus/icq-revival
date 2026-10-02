package loginguard

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testConfig = Config{
	AccountFreeFailures: 5,
	AccountBaseDelay:    time.Second,
	AccountMaxDelay:     15 * time.Minute,
	IPMaxFailures:       30,
	IPWindow:            10 * time.Minute,
	KnownAddressTTL:     720 * time.Hour,
}

// clock is a settable time source for a Guard.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestGuard(cfg Config) (*Guard, *clock, *bytes.Buffer) {
	logs := &bytes.Buffer{}
	g := New(cfg, slog.New(slog.NewTextHandler(logs, nil)))
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	g.now = c.now
	return g, c, logs
}

func TestGuard_AccountBackoff(t *testing.T) {
	tests := []struct {
		name      string
		failures  int
		wantAllow bool
		wantRetry time.Duration
	}{
		{name: "below the free failures", failures: 4, wantAllow: true},
		{name: "free failures used up", failures: 5, wantRetry: time.Second},
		{name: "one more doubles the pause", failures: 6, wantRetry: 2 * time.Second},
		{name: "keeps doubling", failures: 10, wantRetry: 32 * time.Second},
		{name: "capped", failures: 20, wantRetry: 15 * time.Minute},
		{name: "stays capped", failures: 60, wantRetry: 15 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, c, _ := newTestGuard(testConfig)
			for range tt.failures {
				// each failure is made once the previous pause is over, as a
				// guesser that respects the pause would
				_, wait := g.Allow("victim", "")
				c.advance(wait)
				g.Failure("victim", "")
			}
			allowed, retry := g.Allow("victim", "")
			assert.Equal(t, tt.wantAllow, allowed)
			assert.Equal(t, tt.wantRetry, retry)

			// other accounts are not affected
			allowed, _ = g.Allow("bystander", "")
			assert.True(t, allowed)

			// a pause always ends
			c.advance(retry)
			allowed, _ = g.Allow("victim", "")
			assert.True(t, allowed)
		})
	}
}

func TestGuard_SuccessResetsAccount(t *testing.T) {
	g, c, _ := newTestGuard(testConfig)
	for range 7 {
		_, wait := g.Allow("owner", "")
		c.advance(wait)
		g.Failure("owner", "")
	}
	_, wait := g.Allow("owner", "")
	c.advance(wait)
	g.Success("owner", "")

	for range 4 {
		g.Failure("owner", "")
	}
	allowed, _ := g.Allow("owner", "")
	assert.True(t, allowed, "the counter starts over after a success")
	g.Failure("owner", "")
	_, retry := g.Allow("owner", "")
	assert.Equal(t, time.Second, retry, "and so does the backoff")
}

func TestGuard_AccountForgottenAfterQuietSpell(t *testing.T) {
	g, c, _ := newTestGuard(testConfig)
	for range 4 {
		g.Failure("acct", "")
	}
	c.advance(15 * time.Minute)
	g.Failure("acct", "")
	allowed, _ := g.Allow("acct", "")
	assert.True(t, allowed, "old failures expire")
}

func TestGuard_AddressBudget(t *testing.T) {
	tests := []struct {
		name      string
		failures  int
		elapsed   time.Duration
		wantAllow bool
	}{
		{name: "within the budget", failures: 29, wantAllow: true},
		{name: "budget used up", failures: 30, wantAllow: false},
		{name: "one attempt earned back after window/budget", failures: 30, elapsed: 20 * time.Second, wantAllow: true},
		{name: "not yet earned back", failures: 30, elapsed: 19 * time.Second, wantAllow: false},
		{name: "a whole window later", failures: 30, elapsed: 10 * time.Minute, wantAllow: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, c, _ := newTestGuard(testConfig)
			for i := range tt.failures {
				// a different account each time: only the address limit applies
				g.Failure("acct"+string(rune('a'+i)), "198.51.100.7:1234")
			}
			c.advance(tt.elapsed)
			allowed, retry := g.Allow("fresh", "198.51.100.7")
			assert.Equal(t, tt.wantAllow, allowed)
			if !tt.wantAllow {
				assert.Greater(t, retry, time.Duration(0))
			}
			allowed, _ = g.Allow("fresh", "198.51.100.8")
			assert.True(t, allowed, "other addresses are not affected")
		})
	}
}

func TestGuard_IPv6CountsPer64(t *testing.T) {
	g, _, _ := newTestGuard(testConfig)
	for range 30 {
		g.Failure("", "[2001:db8:1:2::1]:5190")
	}
	allowed, _ := g.Allow("", "2001:db8:1:2:ffff::9")
	assert.False(t, allowed)
	allowed, _ = g.Allow("", "2001:db8:1:3::1")
	assert.True(t, allowed)
}

func TestGuard_KnownAddressNotPausedByOthers(t *testing.T) {
	g, c, _ := newTestGuard(testConfig)
	g.Success("owner", "192.0.2.10")

	// a guesser elsewhere pauses the account
	for range 8 {
		_, wait := g.Allow("owner", "203.0.113.5")
		c.advance(wait)
		g.Failure("owner", "203.0.113.5")
	}
	allowed, _ := g.Allow("owner", "203.0.113.5")
	assert.False(t, allowed)

	// the owner's own address is not paused
	allowed, _ = g.Allow("owner", "192.0.2.10")
	assert.True(t, allowed)

	// but the owner's address has its own counter
	for range 5 {
		g.Failure("owner", "192.0.2.10")
	}
	allowed, _ = g.Allow("owner", "192.0.2.10")
	assert.False(t, allowed)
}

func TestGuard_DisabledLimits(t *testing.T) {
	g, _, _ := newTestGuard(Config{})
	for range 100 {
		g.Failure("acct", "192.0.2.1")
	}
	allowed, retry := g.Allow("acct", "192.0.2.1")
	assert.True(t, allowed)
	assert.Zero(t, retry)
}

func TestGuard_LogsOncePerThrottle(t *testing.T) {
	g, c, logs := newTestGuard(testConfig)
	for range 4 {
		g.Failure("victim", "")
	}
	assert.Empty(t, logs.String(), "nothing is logged per failed attempt")
	g.Failure("victim", "")
	assert.Equal(t, 1, strings.Count(logs.String(), "sign-in throttled"))
	assert.Contains(t, logs.String(), "screen_name=victim")

	// refused attempts are not failures and log nothing
	for range 10 {
		allowed, _ := g.Allow("victim", "")
		assert.False(t, allowed)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "sign-in throttled"))

	c.advance(time.Second)
	logs.Reset()
	for range 30 {
		g.Failure("", "192.0.2.1")
	}
	g.Failure("", "192.0.2.1")
	assert.Equal(t, 1, strings.Count(logs.String(), "sign-in throttled"), "an address is logged once when it runs out")
	assert.Contains(t, logs.String(), "ip=192.0.2.1")
}

func TestGuard_Sweep(t *testing.T) {
	g, c, _ := newTestGuard(testConfig)
	g.Failure("acct", "192.0.2.1")
	g.Success("other", "192.0.2.2")
	c.advance(time.Hour)
	g.Allow("x", "")
	assert.Empty(t, g.accounts)
	assert.Empty(t, g.addresses)
	assert.Len(t, g.known, 1, "known addresses outlive the sweep until their TTL")
	c.advance(720 * time.Hour)
	g.Allow("x", "")
	assert.Empty(t, g.known)
}
