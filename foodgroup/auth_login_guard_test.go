package foodgroup

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/loginguard"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// guardTestUser is the account the login guard tests sign in to.
func guardTestUser(t *testing.T) state.User {
	user := state.User{
		AuthKey:           "auth_key",
		DisplayScreenName: "Victim",
		IdentScreenName:   state.NewIdentScreenName("Victim"),
	}
	assert.NoError(t, user.HashPassword("the_password"))
	return user
}

// guardSignIn makes one sign-in attempt by one of the auth methods and returns
// the error subcode of the reply, or 0 for a successful sign-in.
type guardSignIn func(t *testing.T, svc *AuthService, ctx context.Context, screenName, password string) uint16

func flapSignIn(passwordTLV func(password string) wire.TLV) guardSignIn {
	return func(t *testing.T, svc *AuthService, ctx context.Context, screenName, password string) uint16 {
		block, err := svc.FLAPLogin(ctx, wire.FLAPSignonFrame{TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
			wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName),
			passwordTLV(password),
		}}}, config.Endpoint{})
		assert.NoError(t, err)
		code, _ := block.Uint16BE(wire.LoginTLVTagsErrorSubcode)
		return code
	}
}

func bucpSignIn(t *testing.T, svc *AuthService, ctx context.Context, screenName, password string) uint16 {
	out, err := svc.BUCPLogin(ctx, wire.SNAC_0x17_0x02_BUCPLoginRequest{TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, screenName),
		wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, wire.StrongMD5PasswordHash(password, "auth_key")),
	}}}, config.Endpoint{})
	assert.NoError(t, err)
	body := out.Body.(wire.SNAC_0x17_0x03_BUCPLoginResponse)
	code, _ := body.Uint16BE(wire.LoginTLVTagsErrorSubcode)
	return code
}

// kerberosSignIn maps the Kerberos reply onto the OSCAR codes the other
// methods answer with, telling the throttled reply by its message.
func kerberosSignIn(t *testing.T, svc *AuthService, ctx context.Context, screenName, password string) uint16 {
	out, err := svc.KerberosLogin(ctx, wire.SNAC_0x050C_0x0002_KerberosLoginRequest{
		ClientPrincipal: screenName,
		TicketRequestMetadata: wire.TLVBlock{TLVList: wire.TLVList{
			wire.NewTLVBE(wire.KerberosTLVTicketRequest, wire.KerberosLoginRequestTicket{Password: []byte(password)}),
		}},
	}, config.Endpoint{})
	assert.NoError(t, err)
	errBody, failed := out.Body.(wire.SNAC_0x050C_0x0004_KerberosLoginErrResponse)
	switch {
	case !failed:
		return 0
	case errBody.Message == "Rate limit exceeded. Try again later.":
		assert.Equal(t, wire.KerberosErrAuthFailure, errBody.ErrCode)
		return wire.LoginErrRateLimitExceeded
	default:
		return wire.LoginErrInvalidPassword
	}
}

var guardSignInMethods = map[string]guardSignIn{
	"FLAP roasted": flapSignIn(func(p string) wire.TLV {
		return wire.NewTLVBE(wire.LoginTLVTagsRoastedPassword, wire.RoastOSCARPassword([]byte(p)))
	}),
	"TOC roasted": flapSignIn(func(p string) wire.TLV {
		return wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, wire.RoastTOCPassword([]byte(p)))
	}),
	"plaintext (WebAPI, legacy ICQ)": flapSignIn(func(p string) wire.TLV {
		return wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, p)
	}),
	"WebAPI challenge digest": flapSignIn(func(p string) wire.TLV {
		return wire.NewTLVBE(wire.LoginTLVTagsPasswordHash, wire.StrongMD5PasswordHash(p, "auth_key"))
	}),
	"BUCP":     bucpSignIn,
	"Kerberos": kerberosSignIn,
}

// newGuardTestService returns an AuthService whose user store knows only
// user, and counts how often it is asked.
func newGuardTestService(t *testing.T, user state.User, guard LoginGuard) (*AuthService, *int) {
	lookups := 0
	userManager := newMockUserManager(t)
	userManager.EXPECT().User(matchContext(), mock.Anything).
		RunAndReturn(func(_ context.Context, sn state.IdentScreenName) (*state.User, error) {
			lookups++
			if sn == user.IdentScreenName {
				u := user
				return &u, nil
			}
			return nil, nil
		}).Maybe()
	cookieBaker := newMockCookieBaker(t)
	cookieBaker.EXPECT().Issue(mock.Anything, mock.Anything).Return([]byte("the-cookie"), nil).Maybe()
	feedbagManager := newMockFeedbagManager(t)
	feedbagManager.EXPECT().Feedbag(matchContext(), mock.Anything).Return(nil, nil).Maybe()
	sessionRetriever := newMockSessionRetriever(t)
	sessionRetriever.EXPECT().RetrieveSession(mock.Anything).Return(nil).Maybe()

	svc := NewAuthService(config.Config{}, nil, sessionRetriever, nil, userManager, cookieBaker, nil, nil, nil,
		feedbagManager, wire.DefaultRateLimitClasses(), nil, guard, slog.Default())
	return svc, &lookups
}

func TestAuthService_LoginGuard(t *testing.T) {
	type attempt struct {
		screenName string
		password   string
		ip         string
		// wantCode is the error subcode expected, 0 for success
		wantCode uint16
		// wantLookup is whether the account is looked up, which a throttled
		// attempt must not do
		wantLookup bool
	}
	const (
		good    = "the_password"
		bad     = "guess"
		limited = wire.LoginErrRateLimitExceeded
	)
	wrong := func(n int, sn, ip string, code uint16) []attempt {
		var out []attempt
		for range n {
			out = append(out, attempt{screenName: sn, password: bad, ip: ip, wantCode: code, wantLookup: true})
		}
		return out
	}
	concat := func(parts ...[]attempt) []attempt {
		var out []attempt
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	tests := []struct {
		name     string
		attempts []attempt
	}{
		{
			name: "wrong passwords pause the account, even for the right password, without a lookup",
			attempts: concat(
				wrong(5, "Victim", "", wire.LoginErrInvalidPassword),
				[]attempt{
					{screenName: "Victim", password: good, wantCode: limited},
					{screenName: "V I C T I M", password: bad, wantCode: limited},
				},
			),
		},
		{
			name: "an unknown account is paused the same way",
			attempts: concat(
				wrong(5, "nobody", "", wire.LoginErrInvalidUsernameOrPassword),
				[]attempt{{screenName: "nobody", password: bad, wantCode: limited}},
			),
		},
		{
			name: "a successful sign-in starts the count over",
			attempts: concat(
				wrong(4, "Victim", "", wire.LoginErrInvalidPassword),
				[]attempt{{screenName: "Victim", password: good, wantCode: 0, wantLookup: true}},
				wrong(4, "Victim", "", wire.LoginErrInvalidPassword),
				[]attempt{{screenName: "Victim", password: good, wantCode: 0, wantLookup: true}},
			),
		},
		{
			name: "an address that used its budget is refused on any account",
			attempts: concat(
				func() []attempt {
					var out []attempt
					for i := range 30 {
						out = append(out, wrong(1, fmt.Sprintf("acct%d", i), "198.51.100.7:4000", wire.LoginErrInvalidUsernameOrPassword)...)
					}
					return out
				}(),
				[]attempt{
					{screenName: "Victim", password: good, ip: "198.51.100.7:4001", wantCode: limited},
					{screenName: "Victim", password: good, ip: "198.51.100.8:4000", wantCode: 0, wantLookup: true},
				},
			),
		},
		{
			name: "the owner's known address is not paused by a guesser elsewhere",
			attempts: concat(
				[]attempt{{screenName: "Victim", password: good, ip: "192.0.2.10", wantCode: 0, wantLookup: true}},
				wrong(5, "Victim", "203.0.113.5", wire.LoginErrInvalidPassword),
				[]attempt{
					{screenName: "Victim", password: good, ip: "203.0.113.5", wantCode: limited},
					{screenName: "Victim", password: good, ip: "192.0.2.10", wantCode: 0, wantLookup: true},
				},
			),
		},
	}

	for methodName, signIn := range guardSignInMethods {
		for _, tt := range tests {
			t.Run(methodName+"/"+tt.name, func(t *testing.T) {
				user := guardTestUser(t)
				svc, lookups := newGuardTestService(t, user, newTestLoginGuard())
				for i, a := range tt.attempts {
					before := *lookups
					ctx := context.Background()
					if a.ip != "" {
						ctx = loginguard.WithClientIP(ctx, a.ip)
					}
					code := signIn(t, svc, ctx, a.screenName, a.password)
					if methodName == "Kerberos" && a.wantCode != 0 && a.wantCode != limited {
						a.wantCode = wire.LoginErrInvalidPassword
					}
					assert.Equal(t, a.wantCode, code, "attempt %d", i)
					assert.Equal(t, a.wantLookup, *lookups > before, "attempt %d looked up the account", i)
				}
			})
		}
	}
}

func TestAuthService_LoginGuard_BackoffGrows(t *testing.T) {
	user := guardTestUser(t)
	guard := newTestLoginGuard()
	svc, _ := newGuardTestService(t, user, guard)
	ctx := context.Background()
	signIn := guardSignInMethods["FLAP roasted"]

	for range 5 {
		assert.Equal(t, wire.LoginErrInvalidPassword, signIn(t, svc, ctx, "Victim", "guess"))
	}
	_, first := guard.Allow("victim", "")
	assert.Greater(t, first, time.Duration(0))
	assert.LessOrEqual(t, first, testLoginGuardConfig.AccountBaseDelay)
	assert.Equal(t, wire.LoginErrRateLimitExceeded, signIn(t, svc, ctx, "Victim", "the_password"))
}
