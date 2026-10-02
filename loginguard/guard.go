// Package loginguard slows down password guessing on every sign-in path.
//
// Only failed sign-ins count. An account that keeps failing is refused for a
// while, the pause doubling with every further failure up to a cap, and an
// address that keeps failing on any accounts is refused once it has used up its
// budget. A refused attempt must be answered with the protocol's own "try again
// later" error without checking the password, so it costs the guesser a round
// trip and tells them nothing, whether the account exists or not.
//
// The rightful owner is never locked out for good: every pause ends on its own,
// and an address the owner has signed in from before is counted on its own
// rather than with the account's failures from elsewhere, so a guesser on
// another network cannot keep the owner out.
//
// All state is in memory and forgotten after a quiet spell.
package loginguard

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// Config sets how much failure the guard tolerates.
type Config struct {
	// AccountFreeFailures is how many failed sign-ins an account gets before it
	// is paused. Zero turns the account limit off.
	AccountFreeFailures int
	// AccountBaseDelay is the first pause; each further failure doubles it.
	AccountBaseDelay time.Duration
	// AccountMaxDelay caps the pause. An account that has not failed for this
	// long after its pause ended starts over.
	AccountMaxDelay time.Duration
	// IPMaxFailures is how many failed sign-ins an address gets per IPWindow,
	// on any accounts. Zero turns the address limit off.
	IPMaxFailures int
	// IPWindow is the period IPMaxFailures is spread over: an address that
	// used its budget earns one attempt back every IPWindow/IPMaxFailures.
	IPWindow time.Duration
	// KnownAddressTTL is how long an address an account signed in from is
	// remembered as the owner's. Failures from it are counted apart from the
	// account's other failures. Zero turns this off.
	KnownAddressTTL time.Duration
}

// maxKnownAddresses bounds the addresses remembered per account.
const maxKnownAddresses = 8

// sweepInterval is how often expired entries are dropped.
const sweepInterval = time.Minute

// backoff is the failure count and pause of an account, or of an account on
// one of its known addresses.
type backoff struct {
	failures     int
	lastFailure  time.Time
	blockedUntil time.Time
}

// addressBudget is a leaky bucket of an address's recent failures.
type addressBudget struct {
	level     float64
	updated   time.Time
	throttled bool
}

// Guard keeps the failed sign-in counts. It is safe for concurrent use.
type Guard struct {
	cfg    Config
	logger *slog.Logger
	now    func() time.Time

	mu        sync.Mutex
	accounts  map[string]*backoff
	pairs     map[string]*backoff
	addresses map[string]*addressBudget
	known     map[string]map[string]time.Time
	lastSweep time.Time
}

// New returns a Guard with the given limits.
func New(cfg Config, logger *slog.Logger) *Guard {
	return &Guard{
		cfg:       cfg,
		logger:    logger,
		now:       time.Now,
		accounts:  map[string]*backoff{},
		pairs:     map[string]*backoff{},
		addresses: map[string]*addressBudget{},
		known:     map[string]map[string]time.Time{},
	}
}

// Allow reports whether a sign-in to account from ip may be checked now. When
// it may not, retryAfter says how long until it may, and the caller must refuse
// the attempt without looking at the password. account is the normalised
// screen name or UIN; ip may be empty when the address is not known.
func (g *Guard) Allow(account, ip string) (allowed bool, retryAfter time.Duration) {
	ip = addressKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.sweep(now)

	if b := g.backoffFor(account, ip, false); b != nil && now.Before(b.blockedUntil) {
		retryAfter = b.blockedUntil.Sub(now)
	}
	if a := g.addresses[ip]; a != nil && g.cfg.IPMaxFailures > 0 {
		g.drain(a, now)
		if over := a.level - float64(g.cfg.IPMaxFailures) + 1; over > 0 {
			wait := time.Duration(over * float64(g.cfg.IPWindow) / float64(g.cfg.IPMaxFailures))
			retryAfter = max(retryAfter, wait)
		} else {
			a.throttled = false
		}
	}
	return retryAfter == 0, retryAfter
}

// Failure records a failed sign-in to account from ip: a wrong password, or an
// account that does not exist, which is counted the same way.
func (g *Guard) Failure(account, ip string) {
	ip = addressKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.sweep(now)

	if b := g.backoffFor(account, ip, true); b != nil {
		b.failures++
		b.lastFailure = now
		if b.failures >= g.cfg.AccountFreeFailures {
			b.blockedUntil = now.Add(g.delay(b.failures))
			attrs := []any{"screen_name", account, "failed_attempts", b.failures, "retry_after", b.blockedUntil.Sub(now)}
			if g.isKnown(account, ip, now) {
				attrs = append(attrs, "ip", ip)
			}
			g.logger.Info("sign-in throttled: too many failed attempts on the account", attrs...)
		}
	}

	if ip != "" && g.cfg.IPMaxFailures > 0 {
		a := g.addresses[ip]
		if a == nil {
			a = &addressBudget{updated: now}
			g.addresses[ip] = a
		}
		g.drain(a, now)
		a.level++
		if a.level >= float64(g.cfg.IPMaxFailures) && !a.throttled {
			a.throttled = true
			g.logger.Info("sign-in throttled: too many failed attempts from the address",
				"ip", ip, "failed_attempts", int(a.level))
		}
	}
}

// Success records a sign-in to account from ip that passed the password check:
// the account's failures are forgotten and ip is remembered as the owner's.
func (g *Guard) Success(account, ip string) {
	ip = addressKey(ip)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()

	delete(g.accounts, account)
	if ip == "" {
		return
	}
	delete(g.pairs, pairKey(account, ip))
	if g.cfg.KnownAddressTTL <= 0 {
		return
	}
	addrs := g.known[account]
	if addrs == nil {
		addrs = map[string]time.Time{}
		g.known[account] = addrs
	}
	addrs[ip] = now.Add(g.cfg.KnownAddressTTL)
	for len(addrs) > maxKnownAddresses {
		var oldest string
		for a, exp := range addrs {
			if oldest == "" || exp.Before(addrs[oldest]) {
				oldest = a
			}
		}
		delete(addrs, oldest)
	}
}

// backoffFor returns the counter a sign-in to account from ip is judged by:
// the account and address pair when ip is one the owner signed in from, the
// account otherwise. With create, a missing or expired counter is made fresh;
// without it, nil is returned for one.
func (g *Guard) backoffFor(account, ip string, create bool) *backoff {
	if account == "" || g.cfg.AccountFreeFailures <= 0 {
		return nil
	}
	now := g.now()
	m, key := g.accounts, account
	if g.isKnown(account, ip, now) {
		m, key = g.pairs, pairKey(account, ip)
	}
	b := m[key]
	if b != nil && g.backoffExpired(b, now) {
		delete(m, key)
		b = nil
	}
	if b == nil && create {
		b = &backoff{}
		m[key] = b
	}
	return b
}

func (g *Guard) isKnown(account, ip string, now time.Time) bool {
	if ip == "" {
		return false
	}
	exp, ok := g.known[account][ip]
	return ok && now.Before(exp)
}

// backoffExpired reports whether b has been quiet long enough to forget.
func (g *Guard) backoffExpired(b *backoff, now time.Time) bool {
	last := b.lastFailure
	if b.blockedUntil.After(last) {
		last = b.blockedUntil
	}
	return !now.Before(last.Add(g.cfg.AccountMaxDelay))
}

// delay is the pause after the given number of failures.
func (g *Guard) delay(failures int) time.Duration {
	d := g.cfg.AccountBaseDelay
	for i := g.cfg.AccountFreeFailures; i < failures; i++ {
		if d >= g.cfg.AccountMaxDelay {
			break
		}
		d *= 2
	}
	return min(d, g.cfg.AccountMaxDelay)
}

// drain lets out of a what has leaked since it was last updated.
func (g *Guard) drain(a *addressBudget, now time.Time) {
	elapsed := now.Sub(a.updated)
	if elapsed > 0 && g.cfg.IPWindow > 0 {
		a.level -= float64(g.cfg.IPMaxFailures) * float64(elapsed) / float64(g.cfg.IPWindow)
		if a.level < 0 {
			a.level = 0
		}
	}
	a.updated = now
}

// sweep drops the entries that have nothing left to remember.
func (g *Guard) sweep(now time.Time) {
	if now.Sub(g.lastSweep) < sweepInterval {
		return
	}
	g.lastSweep = now
	for k, b := range g.accounts {
		if g.backoffExpired(b, now) {
			delete(g.accounts, k)
		}
	}
	for k, b := range g.pairs {
		if g.backoffExpired(b, now) {
			delete(g.pairs, k)
		}
	}
	for k, a := range g.addresses {
		g.drain(a, now)
		if a.level == 0 {
			delete(g.addresses, k)
		}
	}
	for account, addrs := range g.known {
		for a, exp := range addrs {
			if !now.Before(exp) {
				delete(addrs, a)
			}
		}
		if len(addrs) == 0 {
			delete(g.known, account)
		}
	}
}

func pairKey(account, ip string) string {
	return account + "\x00" + ip
}

// addressKey turns an address, with or without a port, into the key it is
// counted under. An IPv6 address counts as its /64, the block one subscriber
// is usually given. Anything unparsable is kept as it is.
func addressKey(ip string) string {
	if ip == "" {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		ap, perr := netip.ParseAddrPort(ip)
		if perr != nil {
			return ip
		}
		addr = ap.Addr()
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}
