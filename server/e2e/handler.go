package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
)

// Limits on what one request may carry.
const (
	// maxBodyBytes is the largest request body read.
	maxBodyBytes = 64 << 10
	// keyLen is the length of every public key the directory holds, Ed25519
	// and Curve25519 alike.
	keyLen = 32
	// maxOneTimeKeysPerUpload is how many one-time keys one upload may carry.
	maxOneTimeKeysPerUpload = 100
	// maxLinkBlobLen is the largest device-link request or reply blob.
	maxLinkBlobLen = 16 << 10
	// maxPendingLinks is how many unexpired device-link requests an account
	// may have.
	maxPendingLinks = 4
	// maxScreenNameLen bounds the {uin} path segment.
	maxScreenNameLen = 64
)

// Rate limit of the requests that need a token, per account.
const (
	accountRate  = rate.Limit(5)
	accountBurst = 30
)

// keyIDPattern is what a key id may look like: vodozemac's base64 KeyId, or
// any other short id in the base64 and base64url alphabets.
var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{1,64}$`)

// linkIDPattern is the form of the device-link request ids the server makes.
var linkIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Handler serves the key directory under /e2e/v1/.
type Handler struct {
	cfg      config.E2EConfig
	store    Store
	baker    CookieBaker
	sessions SessionRetriever
	logger   *slog.Logger
	limiter  *accountLimiter
	now      func() time.Time
}

// NewHandler returns the key directory handler. baker is the key the BOS
// server signs the tokens with (see state.IssueE2EToken).
func NewHandler(cfg config.E2EConfig, store Store, baker CookieBaker, sessions SessionRetriever, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:      cfg,
		store:    store,
		baker:    baker,
		sessions: sessions,
		logger:   logger,
		limiter:  newAccountLimiter(accountRate, accountBurst),
		now:      time.Now,
	}
}

// Register adds the key directory's routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /e2e/v1/token", h.authed(h.refreshToken))

	mux.Handle("PUT /e2e/v1/account", h.authed(h.putAccount))
	mux.Handle("GET /e2e/v1/devices/{device_id}", h.authed(h.getOwnDevice))
	mux.Handle("PUT /e2e/v1/devices/{device_id}", h.authed(h.putDevice))
	mux.Handle("DELETE /e2e/v1/devices/{device_id}", h.authed(h.revokeDevice))
	mux.Handle("POST /e2e/v1/devices/{device_id}/one-time-keys", h.authed(h.addOneTimeKeys))
	mux.Handle("PUT /e2e/v1/devices/{device_id}/fallback-key", h.authed(h.putFallbackKey))

	mux.HandleFunc("GET /e2e/v1/users/{uin}/account", h.getAccount)
	mux.HandleFunc("GET /e2e/v1/users/{uin}/devices", h.getDevices)
	mux.HandleFunc("GET /e2e/v1/users/{uin}/account-history", h.getAccountHistory)
	mux.Handle("POST /e2e/v1/users/{uin}/devices/{device_id}/claim", h.authed(h.claim))

	mux.Handle("POST /e2e/v1/link", h.authed(h.createLink))
	mux.Handle("GET /e2e/v1/link", h.authed(h.listLinks))
	mux.Handle("GET /e2e/v1/link/{id}", h.authed(h.getLink))
	mux.Handle("POST /e2e/v1/link/{id}/reply", h.authed(h.replyLink))
	mux.Handle("DELETE /e2e/v1/link/{id}", h.authed(h.deleteLink))
}

// caller is who a request with a valid token comes from.
type caller struct {
	screenName state.IdentScreenName
	instance   *state.SessionInstance
}

// authed wraps a handler that needs a token: "Authorization: Bearer <token>",
// the token in base64url as the BOS server handed it out. The token must be
// genuine and unexpired, and the session instance it was issued to still
// signed on. The account's rate limit applies.
func (h *Handler) authed(next func(w http.ResponseWriter, r *http.Request, c caller)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		scheme, encoded, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(encoded), "="))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "malformed token")
			return
		}
		tok, _, err := state.CrackE2EToken(h.baker, raw)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}
		instance := tok.Live(h.sessions)
		if instance == nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "the session of this token has ended")
			return
		}
		if !h.limiter.allow(tok.ScreenName, h.now()) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next(w, r, caller{screenName: tok.ScreenName, instance: instance})
	})
}

type tokenJSON struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// refreshToken issues a fresh token for the caller's session, so a client
// signed on for longer than E2E_TOKEN_TTL keeps working.
func (h *Handler) refreshToken(w http.ResponseWriter, r *http.Request, c caller) {
	token, err := state.IssueE2EToken(h.baker, c.instance, h.cfg.TokenTTL)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenJSON{
		Token:     base64.RawURLEncoding.EncodeToString(token),
		ExpiresAt: h.now().Add(h.cfg.TokenTTL).Unix(),
	})
}

type deviceSignatureJSON struct {
	DeviceID         uint32 `json:"device_id"`
	AccountSignature b64    `json:"account_signature"`
}

type putAccountRequest struct {
	AccountKey    b64                   `json:"account_key"`
	SelfSignature b64                   `json:"self_signature"`
	Proof         b64                   `json:"proof,omitempty"`
	Devices       []deviceSignatureJSON `json:"devices,omitempty"`
}

// putAccount publishes the account key, or replaces it: with a proof signed
// by the current key (a rotation, which carries new signatures for the
// devices to keep), or without one once every device is revoked (a reset).
func (h *Handler) putAccount(w http.ResponseWriter, r *http.Request, c caller) {
	var req putAccountRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.AccountKey) != keyLen {
		writeError(w, http.StatusBadRequest, "invalid_key", "account_key must be 32 bytes")
		return
	}
	if !verify(req.AccountKey, AccountMessage(c.screenName, req.AccountKey), req.SelfSignature) {
		writeError(w, http.StatusBadRequest, "invalid_signature", "self_signature does not verify")
		return
	}

	ctx := r.Context()
	now := h.now()
	cur, err := h.store.E2EAccount(ctx, c.screenName)
	if err != nil {
		h.internalError(w, r, err)
		return
	}

	switch {
	case cur == nil || string(cur.Key) == string(req.AccountKey):
		if req.Proof != nil || req.Devices != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "proof and devices are for replacing the account key")
			return
		}
		err = h.store.E2EPublishAccountKey(ctx, c.screenName, req.AccountKey, now)
	case req.Proof != nil:
		if !verify(cur.Key, RotateMessage(c.screenName, cur.Key, req.AccountKey), req.Proof) {
			writeError(w, http.StatusBadRequest, "invalid_signature", "proof does not verify against the current account key")
			return
		}
		resigned, ok := h.checkResigned(w, r, c.screenName, req.AccountKey, req.Devices)
		if !ok {
			return
		}
		err = h.store.E2ERotateAccountKey(ctx, c.screenName, cur.Key, req.AccountKey, resigned, now)
	default:
		if req.Devices != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "devices need a proof")
			return
		}
		err = h.store.E2EResetAccountKey(ctx, c.screenName, cur.Key, req.AccountKey, now)
	}
	if err != nil {
		h.storeError(w, r, err)
		return
	}

	acc, err := h.store.E2EAccount(ctx, c.screenName)
	if err != nil || acc == nil {
		h.internalError(w, r, fmt.Errorf("account gone after put: %w", err))
		return
	}
	status := http.StatusOK
	if cur == nil {
		status = http.StatusCreated
	}
	writeJSON(w, status, newAccountJSON(c.screenName, *acc))
}

// checkResigned checks the new account signatures a rotation carries: each
// for an active device of the account, once, verifying against newKey.
func (h *Handler) checkResigned(w http.ResponseWriter, r *http.Request, sn state.IdentScreenName, newKey []byte, sigs []deviceSignatureJSON) ([]state.E2EDeviceSignature, bool) {
	seen := make(map[uint32]bool, len(sigs))
	out := make([]state.E2EDeviceSignature, 0, len(sigs))
	for _, s := range sigs {
		if seen[s.DeviceID] {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("device %d listed twice", s.DeviceID))
			return nil, false
		}
		seen[s.DeviceID] = true
		dev, err := h.store.E2EDevice(r.Context(), sn, s.DeviceID)
		if err != nil {
			h.internalError(w, r, err)
			return nil, false
		}
		switch {
		case dev == nil:
			h.storeError(w, r, fmt.Errorf("device %d: %w", s.DeviceID, state.ErrE2EDeviceNotFound))
			return nil, false
		case dev.Revoked():
			h.storeError(w, r, fmt.Errorf("device %d: %w", s.DeviceID, state.ErrE2EDeviceRevoked))
			return nil, false
		}
		if !verify(newKey, DeviceMessage(sn, dev.DeviceID, dev.Curve25519Key, dev.Ed25519Key), s.AccountSignature) {
			writeError(w, http.StatusBadRequest, "invalid_signature",
				fmt.Sprintf("account_signature of device %d does not verify against the new account key", s.DeviceID))
			return nil, false
		}
		out = append(out, state.E2EDeviceSignature{DeviceID: s.DeviceID, AccountSignature: s.AccountSignature})
	}
	return out, true
}

type putDeviceRequest struct {
	Curve25519Key    b64 `json:"curve25519_key"`
	Ed25519Key       b64 `json:"ed25519_key"`
	AccountSignature b64 `json:"account_signature"`
}

type ownDeviceJSON struct {
	Device          deviceJSON `json:"device"`
	OneTimeKeyCount int        `json:"one_time_key_count"`
	HasFallbackKey  bool       `json:"has_fallback_key"`
}

// putDevice publishes one of the caller's devices, or refreshes it.
func (h *Handler) putDevice(w http.ResponseWriter, r *http.Request, c caller) {
	deviceID, ok := deviceIDParam(w, r)
	if !ok {
		return
	}
	var req putDeviceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Curve25519Key) != keyLen || len(req.Ed25519Key) != keyLen {
		writeError(w, http.StatusBadRequest, "invalid_key", "curve25519_key and ed25519_key must be 32 bytes")
		return
	}

	ctx := r.Context()
	acc, err := h.store.E2EAccount(ctx, c.screenName)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	if acc == nil {
		h.storeError(w, r, state.ErrE2EAccountNotFound)
		return
	}
	if !verify(acc.Key, DeviceMessage(c.screenName, deviceID, req.Curve25519Key, req.Ed25519Key), req.AccountSignature) {
		writeError(w, http.StatusBadRequest, "invalid_signature", "account_signature does not verify against the account key")
		return
	}
	created, err := h.store.E2EPutDevice(ctx, c.screenName, acc.Key, state.E2EDevice{
		DeviceID:         deviceID,
		Curve25519Key:    req.Curve25519Key,
		Ed25519Key:       req.Ed25519Key,
		AccountSignature: req.AccountSignature,
	}, h.cfg.MaxDevices, h.now())
	if err != nil {
		h.storeError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	h.writeOwnDevice(w, r, c.screenName, deviceID, status)
}

// getOwnDevice reports one of the caller's devices with the state of its
// key pool, so the client knows when to upload more one-time keys.
func (h *Handler) getOwnDevice(w http.ResponseWriter, r *http.Request, c caller) {
	deviceID, ok := deviceIDParam(w, r)
	if !ok {
		return
	}
	h.writeOwnDevice(w, r, c.screenName, deviceID, http.StatusOK)
}

func (h *Handler) writeOwnDevice(w http.ResponseWriter, r *http.Request, sn state.IdentScreenName, deviceID uint32, status int) {
	dev, err := h.store.E2EDevice(r.Context(), sn, deviceID)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	if dev == nil {
		h.storeError(w, r, state.ErrE2EDeviceNotFound)
		return
	}
	count, hasFallback, err := h.store.E2EKeyStatus(r.Context(), sn, deviceID)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeJSON(w, status, ownDeviceJSON{Device: newDeviceJSON(*dev), OneTimeKeyCount: count, HasFallbackKey: hasFallback})
}

// revokeDevice revokes one of the caller's devices.
func (h *Handler) revokeDevice(w http.ResponseWriter, r *http.Request, c caller) {
	deviceID, ok := deviceIDParam(w, r)
	if !ok {
		return
	}
	if err := h.store.E2ERevokeDevice(r.Context(), c.screenName, deviceID, h.now()); err != nil {
		h.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type addOneTimeKeysRequest struct {
	Keys []signedKeyJSON `json:"keys"`
}

type keyCountJSON struct {
	OneTimeKeyCount int `json:"one_time_key_count"`
}

// addOneTimeKeys adds a batch of signed one-time keys to one of the caller's
// devices.
func (h *Handler) addOneTimeKeys(w http.ResponseWriter, r *http.Request, c caller) {
	deviceID, ok := deviceIDParam(w, r)
	if !ok {
		return
	}
	var req addOneTimeKeysRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Keys) == 0 || len(req.Keys) > maxOneTimeKeysPerUpload {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("keys must hold 1 to %d keys", maxOneTimeKeysPerUpload))
		return
	}
	dev, ok := h.activeDevice(w, r, c.screenName, deviceID)
	if !ok {
		return
	}
	seen := make(map[string]bool, len(req.Keys))
	keys := make([]state.E2ESignedKey, 0, len(req.Keys))
	for _, k := range req.Keys {
		if seen[k.KeyID] {
			writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("key id %q listed twice", k.KeyID))
			return
		}
		seen[k.KeyID] = true
		key, ok := checkSignedKey(w, dev, k, OneTimeKeyMessage(c.screenName, deviceID, k.KeyID, k.PublicKey))
		if !ok {
			return
		}
		keys = append(keys, key)
	}
	count, err := h.store.E2EAddOneTimeKeys(r.Context(), c.screenName, deviceID, keys, h.cfg.MaxOneTimeKeys, h.now())
	if err != nil {
		h.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, keyCountJSON{OneTimeKeyCount: count})
}

// putFallbackKey replaces the fallback key of one of the caller's devices.
func (h *Handler) putFallbackKey(w http.ResponseWriter, r *http.Request, c caller) {
	deviceID, ok := deviceIDParam(w, r)
	if !ok {
		return
	}
	var req signedKeyJSON
	if !decodeBody(w, r, &req) {
		return
	}
	dev, ok := h.activeDevice(w, r, c.screenName, deviceID)
	if !ok {
		return
	}
	key, ok := checkSignedKey(w, dev, req, FallbackKeyMessage(c.screenName, deviceID, req.KeyID, req.PublicKey))
	if !ok {
		return
	}
	if err := h.store.E2ESetFallbackKey(r.Context(), c.screenName, deviceID, key, h.now()); err != nil {
		h.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// activeDevice returns one of the account's devices that is not revoked.
func (h *Handler) activeDevice(w http.ResponseWriter, r *http.Request, sn state.IdentScreenName, deviceID uint32) (*state.E2EDevice, bool) {
	dev, err := h.store.E2EDevice(r.Context(), sn, deviceID)
	if err != nil {
		h.internalError(w, r, err)
		return nil, false
	}
	switch {
	case dev == nil:
		h.storeError(w, r, state.ErrE2EDeviceNotFound)
		return nil, false
	case dev.Revoked():
		h.storeError(w, r, state.ErrE2EDeviceRevoked)
		return nil, false
	}
	return dev, true
}

// checkSignedKey checks a fallback or one-time key: its id, its size, and the
// device's signature over msg.
func checkSignedKey(w http.ResponseWriter, dev *state.E2EDevice, k signedKeyJSON, msg []byte) (state.E2ESignedKey, bool) {
	if !keyIDPattern.MatchString(k.KeyID) {
		writeError(w, http.StatusBadRequest, "bad_request", "key_id must be 1 to 64 characters of the base64 or base64url alphabet")
		return state.E2ESignedKey{}, false
	}
	if len(k.PublicKey) != keyLen {
		writeError(w, http.StatusBadRequest, "invalid_key", fmt.Sprintf("public_key of %q must be 32 bytes", k.KeyID))
		return state.E2ESignedKey{}, false
	}
	if !verify(dev.Ed25519Key, msg, k.Signature) {
		writeError(w, http.StatusBadRequest, "invalid_signature",
			fmt.Sprintf("signature of %q does not verify against the device's ed25519_key", k.KeyID))
		return state.E2ESignedKey{}, false
	}
	return state.E2ESignedKey{KeyID: k.KeyID, PublicKey: k.PublicKey, Signature: k.Signature}, true
}

// getAccount returns an account's key. No token needed.
func (h *Handler) getAccount(w http.ResponseWriter, r *http.Request) {
	sn, ok := screenNameParam(w, r)
	if !ok {
		return
	}
	acc, ok := h.account(w, r, sn)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, newAccountJSON(sn, *acc))
}

type devicesJSON struct {
	ScreenName string       `json:"screen_name"`
	AccountKey b64          `json:"account_key"`
	Devices    []deviceJSON `json:"devices"`
}

// getDevices returns an account's key and its devices, revoked ones
// included, with their signatures, so the caller can check everything
// itself. No token needed.
func (h *Handler) getDevices(w http.ResponseWriter, r *http.Request) {
	sn, ok := screenNameParam(w, r)
	if !ok {
		return
	}
	acc, ok := h.account(w, r, sn)
	if !ok {
		return
	}
	devices, err := h.store.E2EDevices(r.Context(), sn)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := devicesJSON{ScreenName: sn.String(), AccountKey: acc.Key, Devices: make([]deviceJSON, 0, len(devices))}
	for _, d := range devices {
		out.Devices = append(out.Devices, newDeviceJSON(d))
	}
	writeJSON(w, http.StatusOK, out)
}

type accountHistoryJSON struct {
	ScreenName string              `json:"screen_name"`
	Changes    []accountChangeJSON `json:"changes"`
}

type accountChangeJSON struct {
	Kind      string `json:"kind"`
	OldKey    b64    `json:"old_key,omitempty"`
	NewKey    b64    `json:"new_key"`
	ChangedAt int64  `json:"changed_at"`
}

// getAccountHistory returns every change of an account's key, oldest first,
// for safety-number warnings. No token needed.
func (h *Handler) getAccountHistory(w http.ResponseWriter, r *http.Request) {
	sn, ok := screenNameParam(w, r)
	if !ok {
		return
	}
	changes, err := h.store.E2EAccountKeyHistory(r.Context(), sn)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := accountHistoryJSON{ScreenName: sn.String(), Changes: make([]accountChangeJSON, 0, len(changes))}
	for _, c := range changes {
		out.Changes = append(out.Changes, accountChangeJSON{
			Kind: c.Kind, OldKey: c.OldKey, NewKey: c.NewKey, ChangedAt: unixTime(c.ChangedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type claimJSON struct {
	ScreenName  string         `json:"screen_name"`
	AccountKey  b64            `json:"account_key"`
	Device      deviceJSON     `json:"device"`
	OneTimeKey  *signedKeyJSON `json:"one_time_key,omitempty"`
	FallbackKey *signedKeyJSON `json:"fallback_key,omitempty"`
}

// claim hands a sender what it needs to open an Olm session with a device of
// another account: the account key, the device, and one one-time key,
// consumed, or the fallback key when the pool is empty. Any signed-on
// account may claim; the claims count against its rate limit.
func (h *Handler) claim(w http.ResponseWriter, r *http.Request, _ caller) {
	sn, ok := screenNameParam(w, r)
	if !ok {
		return
	}
	deviceID, ok := deviceIDParam(w, r)
	if !ok {
		return
	}
	acc, ok := h.account(w, r, sn)
	if !ok {
		return
	}
	claim, err := h.store.E2EClaimKey(r.Context(), sn, deviceID)
	if err != nil {
		h.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, claimJSON{
		ScreenName:  sn.String(),
		AccountKey:  acc.Key,
		Device:      newDeviceJSON(claim.Device),
		OneTimeKey:  newSignedKeyJSON(claim.OneTimeKey),
		FallbackKey: newSignedKeyJSON(claim.FallbackKey),
	})
}

// account returns the account's key record; an account without one is 404.
func (h *Handler) account(w http.ResponseWriter, r *http.Request, sn state.IdentScreenName) (*state.E2EAccount, bool) {
	acc, err := h.store.E2EAccount(r.Context(), sn)
	if err != nil {
		h.internalError(w, r, err)
		return nil, false
	}
	if acc == nil {
		h.storeError(w, r, state.ErrE2EAccountNotFound)
		return nil, false
	}
	return acc, true
}

type createLinkRequest struct {
	EphemeralKey b64 `json:"ephemeral_key"`
	Request      b64 `json:"request,omitempty"`
}

// createLink opens a device-link request: a new device of the caller's
// account leaves its ephemeral key, and optionally a blob, for the account's
// existing devices.
func (h *Handler) createLink(w http.ResponseWriter, r *http.Request, c caller) {
	var req createLinkRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.EphemeralKey) != keyLen {
		writeError(w, http.StatusBadRequest, "invalid_key", "ephemeral_key must be 32 bytes")
		return
	}
	if len(req.Request) > maxLinkBlobLen {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("request must be at most %d bytes", maxLinkBlobLen))
		return
	}
	id, err := newLinkID()
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	now := h.now()
	link := state.E2ELinkRequest{
		ID:           id,
		ScreenName:   c.screenName,
		EphemeralKey: req.EphemeralKey,
		RequestBlob:  req.Request,
		CreatedAt:    now,
		ExpiresAt:    now.Add(h.cfg.LinkTTL),
	}
	if err := h.store.E2ECreateLinkRequest(r.Context(), link, maxPendingLinks, now); err != nil {
		h.storeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, newLinkJSON(link))
}

type linksJSON struct {
	Links []linkJSON `json:"links"`
}

// listLinks returns the caller's pending device-link requests, which the
// account's existing devices poll for.
func (h *Handler) listLinks(w http.ResponseWriter, r *http.Request, c caller) {
	links, err := h.store.E2ELinkRequests(r.Context(), c.screenName, h.now())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := linksJSON{Links: make([]linkJSON, 0, len(links))}
	for _, l := range links {
		out.Links = append(out.Links, newLinkJSON(l))
	}
	writeJSON(w, http.StatusOK, out)
}

// getLink returns one of the caller's device-link requests, which the new
// device polls for the reply.
func (h *Handler) getLink(w http.ResponseWriter, r *http.Request, c caller) {
	id, ok := linkIDParam(w, r)
	if !ok {
		return
	}
	link, err := h.store.E2ELinkRequest(r.Context(), c.screenName, id, h.now())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	if link == nil {
		h.storeError(w, r, state.ErrE2ELinkNotFound)
		return
	}
	writeJSON(w, http.StatusOK, newLinkJSON(*link))
}

type replyLinkRequest struct {
	Reply b64 `json:"reply"`
}

// replyLink stores an existing device's encrypted reply to a device-link
// request of the same account.
func (h *Handler) replyLink(w http.ResponseWriter, r *http.Request, c caller) {
	id, ok := linkIDParam(w, r)
	if !ok {
		return
	}
	var req replyLinkRequest
	if !decodeBody(w, r, &req) {
		return
	}
	switch {
	case len(req.Reply) == 0:
		writeError(w, http.StatusBadRequest, "bad_request", "reply is empty")
		return
	case len(req.Reply) > maxLinkBlobLen:
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("reply must be at most %d bytes", maxLinkBlobLen))
		return
	}
	if err := h.store.E2EReplyLinkRequest(r.Context(), c.screenName, id, req.Reply, h.now()); err != nil {
		h.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteLink drops one of the caller's device-link requests: the new device
// has its reply, or the user cancelled.
func (h *Handler) deleteLink(w http.ResponseWriter, r *http.Request, c caller) {
	id, ok := linkIDParam(w, r)
	if !ok {
		return
	}
	if err := h.store.E2EDeleteLinkRequest(r.Context(), c.screenName, id); err != nil {
		h.storeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newLinkID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// deviceIDParam parses the {device_id} path segment: a decimal 32-bit id
// other than zero.
func deviceIDParam(w http.ResponseWriter, r *http.Request) (uint32, bool) {
	id, err := strconv.ParseUint(r.PathValue("device_id"), 10, 32)
	if err != nil || id == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "device_id must be a decimal number from 1 to 4294967295")
		return 0, false
	}
	return uint32(id), true
}

// screenNameParam parses the {uin} path segment: a UIN, or any screen name.
func screenNameParam(w http.ResponseWriter, r *http.Request) (state.IdentScreenName, bool) {
	raw := r.PathValue("uin")
	sn := state.NewIdentScreenName(raw)
	if sn.String() == "" || len(raw) > maxScreenNameLen {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid uin")
		return sn, false
	}
	return sn, true
}

// linkIDParam parses the {id} path segment of a device-link request.
func linkIDParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !linkIDPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "no_link", "no such link request")
		return "", false
	}
	return id, true
}

// storeError answers a request the store refused.
func (h *Handler) storeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, state.ErrE2EAccountExists):
		writeError(w, http.StatusConflict, "account_exists", err.Error())
	case errors.Is(err, state.ErrE2EAccountNotFound):
		writeError(w, http.StatusNotFound, "no_account", err.Error())
	case errors.Is(err, state.ErrE2EAccountKeyChanged):
		writeError(w, http.StatusConflict, "account_key_changed", err.Error())
	case errors.Is(err, state.ErrE2EActiveDevices):
		writeError(w, http.StatusConflict, "active_devices", err.Error())
	case errors.Is(err, state.ErrE2EDeviceConflict):
		writeError(w, http.StatusConflict, "device_conflict", err.Error())
	case errors.Is(err, state.ErrE2EDeviceNotFound):
		writeError(w, http.StatusNotFound, "no_device", err.Error())
	case errors.Is(err, state.ErrE2EDeviceRevoked):
		writeError(w, http.StatusGone, "device_revoked", err.Error())
	case errors.Is(err, state.ErrE2ETooManyDevices):
		writeError(w, http.StatusConflict, "too_many_devices", err.Error())
	case errors.Is(err, state.ErrE2EKeyPoolFull):
		writeError(w, http.StatusConflict, "pool_full", err.Error())
	case errors.Is(err, state.ErrE2ELinkNotFound):
		writeError(w, http.StatusNotFound, "no_link", err.Error())
	case errors.Is(err, state.ErrE2ELinkReplied):
		writeError(w, http.StatusConflict, "link_replied", err.Error())
	case errors.Is(err, state.ErrE2ETooManyLinks):
		writeError(w, http.StatusConflict, "too_many_links", err.Error())
	default:
		h.internalError(w, r, err)
	}
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.ErrorContext(r.Context(), "e2e key directory error", "method", r.Method, "path", r.URL.Path, "err", err.Error())
	writeError(w, http.StatusInternalServerError, "internal", "internal server error")
}
