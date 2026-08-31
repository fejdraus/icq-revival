package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// AuthToken is the opaque credential the client presents on later requests.
//
// ExpiresIn is a string because that is the shape the client is given, even
// though ClientLoginData.TokenExpiresIn carries the same quantity as a number.
type AuthToken struct {
	A         string `json:"a" xml:"a"`
	ExpiresIn string `json:"expiresIn" xml:"expiresIn"`
}

// GetTokenData is the getToken payload.
type GetTokenData struct {
	Token    AuthToken `json:"token" xml:"token"`
	UserData UserData  `json:"userData" xml:"userData"`
}

// UserData wraps the attributes getToken reports about the account.
type UserData struct {
	Attributes UserAttributes `json:"attributes" xml:"attributes"`
}

// UserAttributes names the account the token belongs to.
type UserAttributes struct {
	LoginID string `json:"loginId" xml:"loginId"`
}

// ClientLoginData is the clientLogin payload.
type ClientLoginData struct {
	Token          AuthToken `json:"token" xml:"token"`
	LoginID        string    `json:"loginId" xml:"loginId"`
	ScreenName     string    `json:"screenName" xml:"screenName"`
	SessionSecret  string    `json:"sessionSecret" xml:"sessionSecret"`
	HostTime       int64     `json:"hostTime" xml:"hostTime"`
	TokenExpiresIn int       `json:"tokenExpiresIn" xml:"tokenExpiresIn"`
}

// RedirectData sends an unauthenticated client to the login page.
type RedirectData struct {
	RedirectURL string `json:"redirectURL" xml:"redirectURL"`
}

// AuthHandler handles Web AIM API authentication endpoints.
type AuthHandler struct {
	AuthService AuthService
	Logger      *slog.Logger
}

type OServiceService interface {
	ClientOnline(ctx context.Context, service uint16, inBody wire.SNAC_0x01_0x02_OServiceClientOnline, instance *state.SessionInstance) error
	RateParamsSubAdd(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd)
}

// GetToken handles GET /auth/getToken requests.
// The Web AIM client uses this JSONP endpoint to exchange SSO session cookies for an API token.
func (h *AuthHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devID := r.URL.Query().Get("devId")

	// The cookie is spent either way: consumed on success, and cleared on failure
	// so a browser holding a dead token stops presenting it.
	clearBOSTokenCookie(w)

	loginID, authCookie, expiry, ok := h.resolveGetTokenSession(r)
	if !ok {
		h.Logger.DebugContext(ctx, "getToken: no token, returning redirect",
			"devId", devID,
			"host", r.Host)
		resp := BaseResponse{}
		resp.Response.StatusCode = 401
		resp.Response.StatusText = "Unauthorized"
		resp.Response.Data = &RedirectData{RedirectURL: h.loginRedirectURL(r)}
		SendResponse(w, r, resp, h.Logger)
		return
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &GetTokenData{
		Token: AuthToken{
			A:         base64.URLEncoding.EncodeToString(authCookie),
			ExpiresIn: strconv.Itoa(int(math.Round(time.Until(expiry).Seconds()))),
		},
		UserData: UserData{Attributes: UserAttributes{LoginID: string(loginID)}},
	}
	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "getToken succeeded", "loginId", loginID, "devId", devID)
}

// resolveGetTokenSession identifies the caller from the BOS token parked at
// sign-in.
func (h *AuthHandler) resolveGetTokenSession(r *http.Request) (state.DisplayScreenName, []byte, time.Time, bool) {
	c, err := r.Cookie(bosTokenCookie)
	if err != nil || c.Value == "" {
		return "", nil, time.Time{}, false
	}
	token, err := url.QueryUnescape(c.Value)
	if err != nil {
		token = c.Value
	}
	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", nil, time.Time{}, false
	}
	serverCookie, expiry, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		return "", nil, time.Time{}, false
	}
	return serverCookie.ScreenName, rawCookie, expiry, true
}

// Web API status codes, which a client reads from the envelope rather than from
// the HTTP status. A failed sign-in is a demand for better credentials, not an
// error: statusMoreAuthRequired plus the detail code naming what was wrong is
// what tells a client to say "incorrect password".
const (
	statusMoreAuthRequired = 330
	statusMissingParameter = 460
	// statusParameterError is for a parameter that is present but unusable
	statusParameterError = 462

	detailBadPassword = 3011
)

// The lifetimes the clientLogin tokenType parameter names.
const (
	shortTermTTL = 24 * time.Hour
	longTermTTL  = 365 * 24 * time.Hour
)

// tokenTypeTTL resolves the clientLogin tokenType parameter to a token lifetime.
// The parameter is "shortterm" (the default), "longterm", or a count of seconds,
// and the server grants no more than longTermTTL either way.
func tokenTypeTTL(tokenType string) (time.Duration, error) {
	tokenType = strings.TrimSpace(tokenType)

	switch strings.ToLower(tokenType) {
	case "", "shortterm":
		return shortTermTTL, nil
	case "longterm":
		return longTermTTL, nil
	}

	secs, err := strconv.ParseUint(tokenType, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("tokenType %q is not shortterm, longterm, or a count of seconds", tokenType)
	}
	// bound the count before scaling it, so an absurd value is an error rather
	// than an overflowed duration
	maxSecs := uint64(longTermTTL / time.Second)
	if secs == 0 || secs > maxSecs {
		return 0, fmt.Errorf("tokenType %q is outside the range 1-%d seconds", tokenType, maxSecs)
	}
	return time.Duration(secs) * time.Second, nil
}

// errInvalidCredentials reports that the auth service rejected the screen name or
// password, as opposed to failing to answer at all.
var errInvalidCredentials = errors.New("invalid screen name or password")

// authenticateCredentials verifies the credentials and returns the auth cookie minted
// by the OSCAR auth service. It returns errInvalidCredentials when the credentials are
// rejected.
func (h *AuthHandler) authenticateCredentials(ctx context.Context, username, password, clientID string, ttl time.Duration) ([]byte, error) {
	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, username))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, password))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, clientID))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsTokenTTL, uint32(ttl.Seconds())))

	block, err := h.AuthService.FLAPLogin(ctx, signonFrame, config.Endpoint{})
	if err != nil {
		return nil, fmt.Errorf("FLAPLogin: %w", err)
	}
	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		return nil, errInvalidCredentials
	}
	authCookie, ok := block.Bytes(wire.LoginTLVTagsAuthorizationCookie)
	if !ok {
		return nil, fmt.Errorf("login response carries no authorization cookie")
	}
	return authCookie, nil
}

// clientIDForDevID names the client on the session for callers that only know the
// Web API devId.
func clientIDForDevID(devID string) string {
	if devID == "" {
		return "WebAIM"
	}
	return devID
}

func (h *AuthHandler) loginRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/_cqr/login/login.psp", scheme, r.Host)
}

// Logout clears the token cookie and sends the browser to the login page. A
// sign-in whose getToken never ran leaves a token in the browser for the rest of
// its life, so signing out has to spend it rather than trust that something
// else already did.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	clearBOSTokenCookie(w)

	loginURL := h.loginRedirectURL(r)
	q := url.Values{}
	if devID := r.URL.Query().Get("devId"); devID != "" {
		q.Set("devId", devID)
	}
	if succURL := r.URL.Query().Get("succUrl"); succURL != "" {
		q.Set("succUrl", succURL)
	}
	if enc := q.Encode(); enc != "" {
		loginURL += "?" + enc
	}

	h.Logger.InfoContext(r.Context(), "logout", "devId", r.URL.Query().Get("devId"))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// ClientLogin handles POST /auth/clientLogin requests.
// This endpoint authenticates users and returns an authentication token.
func (h *AuthHandler) ClientLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.Logger.Error("failed to parse form data", "error", err)
		SendError(w, r, http.StatusBadRequest, "invalid form data")
		return
	}

	username := r.PostFormValue("s")
	if username == "" {
		username = r.PostFormValue("username")
	}
	password := r.PostFormValue("pwd")
	if password == "" {
		password = r.PostFormValue("password")
	}
	devID := r.PostFormValue("devId")
	tokenType := r.PostFormValue("tokenType")

	h.Logger.Debug("clientLogin attempt",
		"username", username,
		"has_password", password != "",
		"devId", devID,
		"form", r.Form)

	// Validate required fields
	if username == "" || password == "" {
		SendErrorDetail(w, r, http.StatusBadRequest, statusMissingParameter, 0, "username and password required")
		return
	}

	ttl, err := tokenTypeTTL(tokenType)
	if err != nil {
		h.Logger.DebugContext(r.Context(), "clientLogin rejected tokenType", "tokenType", tokenType, "error", err)
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0, err.Error())
		return
	}

	authCookie, err := h.authenticateCredentials(r.Context(), username, password, clientIDForDevID(devID), ttl)
	if err != nil {
		h.Logger.DebugContext(r.Context(), "clientLogin failed", "username", username, "error", err)
		if errors.Is(err, errInvalidCredentials) {
			SendErrorDetail(w, r, http.StatusUnauthorized, statusMoreAuthRequired, detailBadPassword,
				"invalid screen name or password")
			return
		}
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// No cookie here: this endpoint's caller receives the token in the response
	// body and presents it to startSession itself.

	// Generate session secret (for signing subsequent requests)
	sessionSecret, err := h.generateToken()
	if err != nil {
		h.Logger.Error("failed to generate session secret", "error", err)
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// Build response
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = &ClientLoginData{
		Token: AuthToken{
			A:         base64.URLEncoding.EncodeToString(authCookie),
			ExpiresIn: strconv.Itoa(int(ttl.Seconds())),
		},
		LoginID:       username,
		ScreenName:    username,
		SessionSecret: sessionSecret,
		HostTime:      time.Now().Unix(),
		// A number here where token.expiresIn is a string, as the client expects.
		TokenExpiresIn: int(ttl.Seconds()),
	}

	// Send response in requested format (JSON, JSONP, XML, or AMF)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.Info("user authenticated successfully",
		"username", username,
		"screenName", username,
		"tokenTTL", ttl)
}

// generateToken generates a secure random token.
func (h *AuthHandler) generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
