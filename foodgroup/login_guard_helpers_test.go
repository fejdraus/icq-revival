package foodgroup

import (
	"log/slog"
	"time"

	"github.com/mk6i/open-oscar-server/loginguard"
)

// testLoginGuardConfig is the guard the auth tests run with: five free
// failures per account, thirty per address. The first pause is long enough
// that no test outlives it.
var testLoginGuardConfig = loginguard.Config{
	AccountFreeFailures: 5,
	AccountBaseDelay:    time.Minute,
	AccountMaxDelay:     15 * time.Minute,
	IPMaxFailures:       30,
	IPWindow:            10 * time.Minute,
	KnownAddressTTL:     720 * time.Hour,
}

// newTestLoginGuard returns a fresh guard with testLoginGuardConfig.
func newTestLoginGuard() *loginguard.Guard {
	return loginguard.New(testLoginGuardConfig, slog.Default())
}
