package e2e

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/state"
)

// usedSignatures remembers signatures that were accepted until they expire,
// so a signed request is taken only once.
type usedSignatures struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newUsedSignatures() *usedSignatures {
	return &usedSignatures{seen: make(map[string]time.Time)}
}

// use records sig, valid until expires, and reports whether it was new.
// Signatures past their expiry are forgotten first.
func (u *usedSignatures) use(sig string, expires, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for s, until := range u.seen {
		if now.After(until) {
			delete(u.seen, s)
		}
	}
	if _, ok := u.seen[sig]; ok {
		return false
	}
	u.seen[sig] = expires
	return true
}

// accountLimiter holds a token bucket per account for the requests that need
// a token, so one account cannot flood the directory or drain other
// accounts' one-time keys. Buckets idle for longer than it takes them to
// refill are dropped.
type accountLimiter struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	buckets   map[state.IdentScreenName]*accountBucket
	lastSweep time.Time
}

type accountBucket struct {
	limiter *rate.Limiter
	lastUse time.Time
}

func newAccountLimiter(limit rate.Limit, burst int) *accountLimiter {
	return &accountLimiter{
		limit:   limit,
		burst:   burst,
		buckets: make(map[state.IdentScreenName]*accountBucket),
	}
}

// allow takes one token from the account's bucket at now.
func (l *accountLimiter) allow(sn state.IdentScreenName, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	idle := time.Duration(float64(l.burst)/float64(l.limit)*float64(time.Second)) + time.Minute
	if now.Sub(l.lastSweep) > idle {
		for k, b := range l.buckets {
			if now.Sub(b.lastUse) > idle {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.buckets[sn]
	if !ok {
		b = &accountBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[sn] = b
	}
	b.lastUse = now
	return b.limiter.AllowN(now, 1)
}
