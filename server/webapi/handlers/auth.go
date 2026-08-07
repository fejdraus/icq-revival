package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

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

// ClientLoginRequest represents the request body for clientLogin.
type ClientLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	DevID    string `json:"devId"`
}

// GetToken handles GET /auth/getToken requests.
// The Web AIM client uses this JSONP endpoint to exchange SSO session cookies for an API token.
func (h *AuthHandler) GetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devID := r.URL.Query().Get("devId")

	// The cookie is spent either way: consumed on success, and cleared on failure
	// so a browser holding a dead token stops presenting it.
	clearBOSTokenCookie(w)

	loginID, authCookie, ok := h.resolveGetTokenSession(r)
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
			A: base64.URLEncoding.EncodeToString(authCookie),
			// A string, not a number: that is how the client is given it.
			ExpiresIn: strconv.Itoa(int(bosTokenTTL.Seconds())),
		},
		UserData: UserData{Attributes: UserAttributes{LoginID: string(loginID)}},
	}
	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "getToken succeeded", "loginId", loginID, "devId", devID)
}

// resolveGetTokenSession identifies the caller from the BOS token parked at
// sign-in. That cookie is the only credential getToken ever receives: the client
// sends no token of its own, only f, attributes, devId and r. A token past its
// brief life fails to crack and reads the same as no token at all.
func (h *AuthHandler) resolveGetTokenSession(r *http.Request) (state.DisplayScreenName, []byte, bool) {
	c, err := r.Cookie(bosTokenCookie)
	if err != nil || c.Value == "" {
		return "", nil, false
	}
	token, err := url.QueryUnescape(c.Value)
	if err != nil {
		token = c.Value
	}
	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", nil, false
	}
	serverCookie, err := h.AuthService.CrackCookie(rawCookie)
	if err != nil {
		return "", nil, false
	}
	return serverCookie.ScreenName, rawCookie, true
}

// Web API status codes, which a client reads from the envelope rather than from
// the HTTP status. A failed sign-in is a demand for better credentials, not an
// error: statusMoreAuthRequired plus the detail code naming what was wrong is
// what tells a client to say "incorrect password".
const (
	statusMoreAuthRequired = 330
	statusMissingParameter = 460

	detailBadPassword = 3011
)

// errInvalidCredentials reports that the auth service rejected the screen name or
// password, as opposed to failing to answer at all.
var errInvalidCredentials = errors.New("invalid screen name or password")

// authenticateCredentials verifies the credentials and returns the auth cookie minted
// by the OSCAR auth service. It returns errInvalidCredentials when the credentials are
// rejected.
func (h *AuthHandler) authenticateCredentials(ctx context.Context, username, password, clientID string) ([]byte, error) {
	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, username))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsPlaintextPassword, password))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsClientIdentity, clientID))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))

	block, err := h.AuthService.FLAPLogin(ctx, signonFrame, "")
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

// Logout sends the browser to the login page. There is nothing to clear: the
// token cookie is spent by the getToken that signed this client in, and nothing
// else survives a request.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
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
	var username, password, devID string

	// The media type alone decides how to read the body: a caller that states a
	// charset sends "application/json; charset=utf-8", which is still JSON.
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	if mediaType == "application/json" {
		// Parse JSON body
		var req ClientLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.Logger.Error("failed to parse JSON clientLogin request", "error", err)
			SendError(w, r, http.StatusBadRequest, "invalid JSON format")
			return
		}
		username = req.Username
		password = req.Password
		devID = req.DevID
	} else {
		// Parse form-encoded or URL parameters
		if err := r.ParseForm(); err != nil {
			h.Logger.Error("failed to parse form data", "error", err)
			SendError(w, r, http.StatusBadRequest, "invalid form data")
			return
		}

		// Try form values first, then fall back to query parameters
		username = r.FormValue("s")
		if username == "" {
			username = r.FormValue("username")
		}
		password = r.FormValue("pwd")
		if password == "" {
			password = r.FormValue("password")
		}
		devID = r.FormValue("devId")

		h.Logger.Debug("form-encoded login attempt",
			"username", username,
			"has_password", password != "",
			"devId", devID,
			"form", r.Form)
	}

	// Validate required fields
	if username == "" || password == "" {
		SendErrorDetail(w, r, http.StatusBadRequest, statusMissingParameter, 0, "username and password required")
		return
	}

	authCookie, err := h.authenticateCredentials(r.Context(), username, password, clientIDForDevID(devID))
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
			ExpiresIn: strconv.Itoa(int(bosTokenTTL.Seconds())),
		},
		LoginID:       username,
		ScreenName:    username,
		SessionSecret: sessionSecret,
		HostTime:      time.Now().Unix(),
		// A number here where token.expiresIn is a string, as the client expects.
		TokenExpiresIn: int(bosTokenTTL.Seconds()),
	}

	// Send response in requested format (JSON, JSONP, XML, or AMF)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.Info("user authenticated successfully",
		"username", username,
		"screenName", username)
}

// generateToken generates a secure random token.
func (h *AuthHandler) generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
