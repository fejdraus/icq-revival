package handlers

import (
	"encoding/base64"
	"encoding/xml"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/webapi/middleware"
	"github.com/mk6i/open-oscar-server/state"
)

// OSCARBridgeHandler handles the handoff from the Web API's HTTP login to the
// native OSCAR protocol, telling a client where to connect and what credential
// to present.
type OSCARBridgeHandler struct {
	OSCARAuthService OSCARAuthService
	Listener         config.ListenerGroup
	Logger           *slog.Logger
}

// OSCARAuthService verifies the credential a client presents to the bridge.
type OSCARAuthService interface {
	CrackCookie(authCookie []byte) (state.ServerCookie, time.Time, error)
}

// StartOSCARSessionResponse represents the response for startOSCARSession endpoint.
type StartOSCARSessionResponse struct {
	Response struct {
		StatusCode int    `json:"statusCode" xml:"statusCode"`
		StatusText string `json:"statusText" xml:"statusText"`
		Data       struct {
			Host   string `json:"host" xml:"host"`
			Port   int    `json:"port" xml:"port"`
			Cookie string `json:"cookie" xml:"cookie"`
			// TLSCertName is the certificate name the client verifies BOS against.
			// Omitted rather than sent empty: its absence means connect in the clear.
			TLSCertName string `json:"tlsCertName,omitempty" xml:"tlsCertName,omitempty"`
		} `json:"data" xml:"data"`
	} `json:"response"`
}

// MarshalXML renders the envelope with the same flat root as BaseResponse.
func (s StartOSCARSessionResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return e.EncodeElement(s.Response, xml.StartElement{Name: xml.Name{Local: "response"}})
}

// StartOSCARSession handles GET /aim/startOSCARSession requests, which hand a
// client that authenticated over HTTP the address of a BOS server and the
// cookie to sign on with. The token in "a" is the auth cookie clientLogin
// minted, already what BOS expects, so it is handed straight back.
//
// The sig_sha256 the client computes over the query string is not checked: that
// signature is keyed by HMAC(password, sessionSecret), and clientLogin keeps
// neither past the response.
func (h *OSCARBridgeHandler) StartOSCARSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.Logger.InfoContext(ctx, "startOSCARSession requested",
		"method", r.Method,
		"remote_addr", r.RemoteAddr,
		"user_agent", r.UserAgent())

	// Get API key info from context (set by auth middleware)
	apiKey, ok := ctx.Value(middleware.ContextKeyAPIKey).(*state.WebAPIKey)
	if !ok {
		h.Logger.Error("API key not found in context")
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}

	// Verify that this API key has permission to create OSCAR sessions
	if !h.hasOSCARBridgeCapability(apiKey) {
		h.Logger.Warn("API key lacks OSCAR bridge capability",
			"dev_id", apiKey.DevID)
		SendError(w, r, http.StatusForbidden, "OSCAR bridge not enabled for this application")
		return
	}

	params := r.URL.Query()

	token := params.Get("a")
	if token == "" {
		h.Logger.Warn("missing authentication token")
		SendError(w, r, http.StatusUnauthorized, "authentication token required")
		return
	}

	rawCookie, err := base64.URLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		h.Logger.WarnContext(ctx, "invalid authentication token (base64)", "err", err.Error())
		SendError(w, r, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	cookie, _, err := h.OSCARAuthService.CrackCookie(rawCookie)
	if err != nil {
		h.Logger.WarnContext(ctx, "invalid authentication token", "err", err.Error())
		SendError(w, r, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Encryption the server cannot provide degrades to a plaintext host, which a
	// client doing opportunistic encryption expects when no certificate is named.
	// The sign-on cookie then crosses the wire in the clear, so the downgrade is
	// logged rather than left to be inferred from the absent tlsCertName.
	useTLS := h.parseBoolParam(params.Get("useTLS"))
	endpoint := h.Listener.PlainEndpoint()
	if useTLS {
		ssl, ok := h.Listener.SSLEndpoint()
		if !ok {
			h.Logger.WarnContext(ctx, "TLS requested but no SSL listener is configured, advertising a plaintext BOS host",
				"screen_name", cookie.ScreenName)
			useTLS = false
		} else {
			endpoint = ssl
		}
	}

	host, portStr, err := net.SplitHostPort(endpoint.AdvertisedHost())
	if err != nil {
		h.Logger.ErrorContext(ctx, "unable to split advertised BOS host", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}
	port, _ := strconv.Atoi(portStr)

	resp := &StartOSCARSessionResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data.Host = host
	resp.Response.Data.Port = port
	// Base64, the encoding the client decodes the cookie with.
	resp.Response.Data.Cookie = base64.StdEncoding.EncodeToString(rawCookie)
	if useTLS {
		// The advertised SSL host is the name the certificate is issued to.
		resp.Response.Data.TLSCertName = host
	}

	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "OSCAR session bridge created",
		"screen_name", cookie.ScreenName,
		"bos_host", host,
		"bos_port", port,
		"use_tls", useTLS)
}

// hasOSCARBridgeCapability checks if the API key has permission to create OSCAR bridges.
func (h *OSCARBridgeHandler) hasOSCARBridgeCapability(apiKey *state.WebAPIKey) bool {
	if len(apiKey.Capabilities) == 0 {
		return true // No restrictions if capabilities not specified
	}

	// Check if OSCAR bridge is explicitly enabled
	for _, cap := range apiKey.Capabilities {
		if cap == "oscar_bridge" || cap == "*" {
			return true
		}
	}

	return false
}

// parseBoolParam parses a boolean parameter from query string.
func (h *OSCARBridgeHandler) parseBoolParam(value string) bool {
	value = strings.ToLower(value)
	return value == "true" || value == "1" || value == "yes"
}
