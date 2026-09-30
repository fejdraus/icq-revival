package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
)

// testDirectory is a key directory over a real store, cookie baker and
// session manager.
type testDirectory struct {
	t        *testing.T
	mux      *http.ServeMux
	store    *state.SQLiteUserStore
	baker    state.HMACCookieBaker
	sessions *state.InMemorySessionManager
	handler  *Handler
}

func newTestDirectory(t *testing.T) *testDirectory {
	t.Helper()
	store, err := state.NewSQLiteUserStore(filepath.Join(t.TempDir(), "e2e.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	baker, err := state.NewHMACCookieBaker()
	require.NoError(t, err)
	sessions := state.NewInMemorySessionManager(slog.Default())

	h := NewHandler(config.E2EConfig{
		TokenTTL:       time.Hour,
		MaxDevices:     3,
		MaxOneTimeKeys: 5,
		LinkTTL:        10 * time.Minute,
	}, store, baker, sessions, slog.Default())
	mux := http.NewServeMux()
	h.Register(mux)
	return &testDirectory{t: t, mux: mux, store: store, baker: baker, sessions: sessions, handler: h}
}

// signOn signs the user on and returns the token the BOS server would have
// handed out, and the session instance.
func (d *testDirectory) signOn(sn string) (string, *state.SessionInstance) {
	d.t.Helper()
	require.NoError(d.t, d.store.InsertUser(context.Background(), state.User{
		IdentScreenName:   state.NewIdentScreenName(sn),
		DisplayScreenName: state.DisplayScreenName(sn),
		IsICQ:             true,
	}))
	instance, err := d.sessions.AddSession(context.Background(), state.DisplayScreenName(sn), false)
	require.NoError(d.t, err)
	instance.Session().SetSignonTime(time.Now())
	instance.SetSignonComplete()
	token, err := state.IssueE2EToken(d.baker, instance, time.Hour)
	require.NoError(d.t, err)
	return base64.RawURLEncoding.EncodeToString(token), instance
}

type response struct {
	status int
	body   map[string]any
}

func (d *testDirectory) do(method, path, token string, body any) response {
	d.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = bytes.NewBufferString(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(d.t, err)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	d.mux.ServeHTTP(rec, req)
	res := response{status: rec.Code}
	if rec.Body.Len() > 0 {
		require.NoError(d.t, json.Unmarshal(rec.Body.Bytes(), &res.body), rec.Body.String())
	}
	return res
}

func enc(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// testDevice is a device's keys. Curve25519 keys are random bytes here: the
// server checks only their size.
type testDevice struct {
	id    uint32
	curve []byte
	edPub ed25519.PublicKey
	edKey ed25519.PrivateKey
}

func newTestDevice(t *testing.T, id uint32) testDevice {
	pub, priv := newKey(t)
	curve := make([]byte, 32)
	_, _ = rand.Read(curve)
	return testDevice{id: id, curve: curve, edPub: pub, edKey: priv}
}

func accountBody(sn state.IdentScreenName, pub ed25519.PublicKey, priv ed25519.PrivateKey) map[string]any {
	return map[string]any{
		"account_key":    enc(pub),
		"self_signature": enc(ed25519.Sign(priv, AccountMessage(sn, pub))),
	}
}

func deviceBody(sn state.IdentScreenName, dev testDevice, account ed25519.PrivateKey) map[string]any {
	return map[string]any{
		"curve25519_key":    enc(dev.curve),
		"ed25519_key":       enc(dev.edPub),
		"account_signature": enc(ed25519.Sign(account, DeviceMessage(sn, dev.id, dev.curve, dev.edPub))),
	}
}

func signedKey(sn state.IdentScreenName, dev testDevice, keyID string, fallback bool) map[string]any {
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	msg := OneTimeKeyMessage(sn, dev.id, keyID, pub)
	if fallback {
		msg = FallbackKeyMessage(sn, dev.id, keyID, pub)
	}
	return map[string]any{"key_id": keyID, "public_key": enc(pub), "signature": enc(ed25519.Sign(dev.edKey, msg))}
}

func TestHandler_Auth(t *testing.T) {
	d := newTestDirectory(t)
	token, instance := d.signOn("100001")

	otherBaker, err := state.NewHMACCookieBaker()
	require.NoError(t, err)
	forged, err := state.IssueE2EToken(otherBaker, instance, time.Hour)
	require.NoError(t, err)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{name: "no token", want: http.StatusUnauthorized},
		{name: "not bearer", header: "Basic " + token, want: http.StatusUnauthorized},
		{name: "not base64", header: "Bearer !!!", want: http.StatusUnauthorized},
		{name: "signed with another key", header: "Bearer " + base64.RawURLEncoding.EncodeToString(forged), want: http.StatusUnauthorized},
		{name: "valid", header: "Bearer " + token, want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/e2e/v1/link", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			d.mux.ServeHTTP(rec, req)
			assert.Equal(t, tc.want, rec.Code)
		})
	}

	t.Run("refresh gives a working token", func(t *testing.T) {
		res := d.do(http.MethodPost, "/e2e/v1/token", token, nil)
		require.Equal(t, http.StatusOK, res.status)
		fresh := res.body["token"].(string)
		assert.Equal(t, http.StatusOK, d.do(http.MethodGet, "/e2e/v1/link", fresh, nil).status)
	})

	t.Run("token dies with its session", func(t *testing.T) {
		instance.CloseInstance()
		assert.Equal(t, http.StatusUnauthorized, d.do(http.MethodGet, "/e2e/v1/link", token, nil).status)
	})
}

func TestHandler_RateLimit(t *testing.T) {
	d := newTestDirectory(t)
	token, _ := d.signOn("100001")
	now := time.Unix(1_700_000_000, 0)
	d.handler.now = func() time.Time { return now }

	for i := 0; i < accountBurst; i++ {
		require.Equal(t, http.StatusOK, d.do(http.MethodGet, "/e2e/v1/link", token, nil).status, "request %d", i)
	}
	assert.Equal(t, http.StatusTooManyRequests, d.do(http.MethodGet, "/e2e/v1/link", token, nil).status)

	now = now.Add(time.Second)
	assert.Equal(t, http.StatusOK, d.do(http.MethodGet, "/e2e/v1/link", token, nil).status, "the bucket refills")
}

func TestHandler_Account(t *testing.T) {
	d := newTestDirectory(t)
	token, _ := d.signOn("100001")
	sn := state.NewIdentScreenName("100001")
	pub, priv := newKey(t)

	res := d.do(http.MethodGet, "/e2e/v1/users/100001/account", "", nil)
	assert.Equal(t, http.StatusNotFound, res.status)
	assert.Equal(t, "no_account", res.body["error"])

	cases := []struct {
		name string
		body any
		want int
		code string
	}{
		{name: "unknown field", body: `{"account_key":"","self_signature":"","extra":1}`, want: http.StatusBadRequest, code: "bad_request"},
		{name: "trailing data", body: `{"account_key":"","self_signature":""} {}`, want: http.StatusBadRequest, code: "bad_request"},
		{name: "short key", body: map[string]any{"account_key": enc(pub[:31]), "self_signature": enc(make([]byte, 64))}, want: http.StatusBadRequest, code: "invalid_key"},
		{name: "self signature by another key", body: func() any {
			b := accountBody(sn, pub, priv)
			_, other := newKey(t)
			b["self_signature"] = enc(ed25519.Sign(other, AccountMessage(sn, pub)))
			return b
		}(), want: http.StatusBadRequest, code: "invalid_signature"},
		{name: "self signature for another account", body: map[string]any{
			"account_key":    enc(pub),
			"self_signature": enc(ed25519.Sign(priv, AccountMessage(state.NewIdentScreenName("100002"), pub))),
		}, want: http.StatusBadRequest, code: "invalid_signature"},
		{name: "first publish", body: accountBody(sn, pub, priv), want: http.StatusCreated},
		{name: "same key again", body: accountBody(sn, pub, priv), want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := d.do(http.MethodPut, "/e2e/v1/account", token, tc.body)
			assert.Equal(t, tc.want, res.status, res.body)
			if tc.code != "" {
				assert.Equal(t, tc.code, res.body["error"])
			}
		})
	}

	res = d.do(http.MethodGet, "/e2e/v1/users/100001/account", "", nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, enc(pub), res.body["account_key"])
}

func TestHandler_AccountReplace(t *testing.T) {
	d := newTestDirectory(t)
	token, _ := d.signOn("100001")
	sn := state.NewIdentScreenName("100001")
	oldPub, oldPriv := newKey(t)
	require.Equal(t, http.StatusCreated, d.do(http.MethodPut, "/e2e/v1/account", token, accountBody(sn, oldPub, oldPriv)).status)
	keep, drop := newTestDevice(t, 1), newTestDevice(t, 2)
	for _, dev := range []testDevice{keep, drop} {
		require.Equal(t, http.StatusCreated, d.do(http.MethodPut, fmt.Sprintf("/e2e/v1/devices/%d", dev.id), token, deviceBody(sn, dev, oldPriv)).status)
	}
	newPub, newPriv := newKey(t)

	res := d.do(http.MethodPut, "/e2e/v1/account", token, accountBody(sn, newPub, newPriv))
	assert.Equal(t, http.StatusConflict, res.status, "no proof while devices are active")
	assert.Equal(t, "active_devices", res.body["error"])

	rotate := accountBody(sn, newPub, newPriv)
	_, stranger := newKey(t)
	rotate["proof"] = enc(ed25519.Sign(stranger, RotateMessage(sn, oldPub, newPub)))
	res = d.do(http.MethodPut, "/e2e/v1/account", token, rotate)
	assert.Equal(t, http.StatusBadRequest, res.status, "proof by a stranger")

	rotate["proof"] = enc(ed25519.Sign(oldPriv, RotateMessage(sn, oldPub, newPub)))
	rotate["devices"] = []map[string]any{{"device_id": keep.id, "account_signature": enc(ed25519.Sign(oldPriv, DeviceMessage(sn, keep.id, keep.curve, keep.edPub)))}}
	res = d.do(http.MethodPut, "/e2e/v1/account", token, rotate)
	assert.Equal(t, http.StatusBadRequest, res.status, "device re-signed by the old key")

	rotate["devices"] = []map[string]any{{"device_id": keep.id, "account_signature": enc(ed25519.Sign(newPriv, DeviceMessage(sn, keep.id, keep.curve, keep.edPub)))}}
	res = d.do(http.MethodPut, "/e2e/v1/account", token, rotate)
	require.Equal(t, http.StatusOK, res.status, res.body)
	assert.Equal(t, enc(newPub), res.body["account_key"])

	res = d.do(http.MethodGet, "/e2e/v1/users/100001/devices", "", nil)
	require.Equal(t, http.StatusOK, res.status)
	devices := res.body["devices"].([]any)
	require.Len(t, devices, 2)
	assert.Nil(t, devices[0].(map[string]any)["revoked_at"], "re-signed device stays")
	assert.NotNil(t, devices[1].(map[string]any)["revoked_at"], "the other is revoked")

	// Every device gone: a reset needs no proof.
	require.Equal(t, http.StatusNoContent, d.do(http.MethodDelete, "/e2e/v1/devices/1", token, nil).status)
	resetPub, resetPriv := newKey(t)
	require.Equal(t, http.StatusOK, d.do(http.MethodPut, "/e2e/v1/account", token, accountBody(sn, resetPub, resetPriv)).status)

	res = d.do(http.MethodGet, "/e2e/v1/users/100001/account-history", "", nil)
	require.Equal(t, http.StatusOK, res.status)
	changes := res.body["changes"].([]any)
	require.Len(t, changes, 3)
	var kinds []string
	for _, c := range changes {
		kinds = append(kinds, c.(map[string]any)["kind"].(string))
	}
	assert.Equal(t, []string{"publish", "rotate", "reset"}, kinds)
	assert.Equal(t, enc(oldPub), changes[1].(map[string]any)["old_key"])
}

func TestHandler_Devices(t *testing.T) {
	d := newTestDirectory(t)
	token, _ := d.signOn("100001")
	sn := state.NewIdentScreenName("100001")
	pub, priv := newKey(t)
	dev := newTestDevice(t, 7)

	res := d.do(http.MethodPut, "/e2e/v1/devices/7", token, deviceBody(sn, dev, priv))
	assert.Equal(t, http.StatusNotFound, res.status, "no account key yet")

	require.Equal(t, http.StatusCreated, d.do(http.MethodPut, "/e2e/v1/account", token, accountBody(sn, pub, priv)).status)
	_, stranger := newKey(t)

	cases := []struct {
		name string
		path string
		body any
		want int
		code string
	}{
		{name: "device id zero", path: "/e2e/v1/devices/0", body: deviceBody(sn, dev, priv), want: http.StatusBadRequest},
		{name: "device id too large", path: "/e2e/v1/devices/4294967296", body: deviceBody(sn, dev, priv), want: http.StatusBadRequest},
		{name: "signed by a stranger", path: "/e2e/v1/devices/7", body: deviceBody(sn, dev, stranger), want: http.StatusBadRequest, code: "invalid_signature"},
		{name: "signature for another id", path: "/e2e/v1/devices/8", body: deviceBody(sn, dev, priv), want: http.StatusBadRequest, code: "invalid_signature"},
		{name: "new device", path: "/e2e/v1/devices/7", body: deviceBody(sn, dev, priv), want: http.StatusCreated},
		{name: "refresh", path: "/e2e/v1/devices/7", body: deviceBody(sn, dev, priv), want: http.StatusOK},
		{name: "same id other keys", path: "/e2e/v1/devices/7", body: func() any {
			other := newTestDevice(t, 7)
			return deviceBody(sn, other, priv)
		}(), want: http.StatusConflict, code: "device_conflict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := d.do(http.MethodPut, tc.path, token, tc.body)
			assert.Equal(t, tc.want, res.status, res.body)
			if tc.code != "" {
				assert.Equal(t, tc.code, res.body["error"])
			}
		})
	}

	res = d.do(http.MethodGet, "/e2e/v1/users/100001/devices", "", nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, enc(pub), res.body["account_key"])
	got := res.body["devices"].([]any)[0].(map[string]any)
	assert.Equal(t, float64(7), got["device_id"])
	sig, err := base64.RawStdEncoding.DecodeString(got["account_signature"].(string))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(pub, DeviceMessage(sn, 7, dev.curve, dev.edPub), sig), "a caller can check the device itself")

	for i := uint32(8); i <= 9; i++ {
		require.Equal(t, http.StatusCreated, d.do(http.MethodPut, fmt.Sprintf("/e2e/v1/devices/%d", i), token, deviceBody(sn, newTestDevice(t, i), priv)).status)
	}
	res = d.do(http.MethodPut, "/e2e/v1/devices/10", token, deviceBody(sn, newTestDevice(t, 10), priv))
	assert.Equal(t, http.StatusConflict, res.status)
	assert.Equal(t, "too_many_devices", res.body["error"])

	assert.Equal(t, http.StatusNoContent, d.do(http.MethodDelete, "/e2e/v1/devices/7", token, nil).status)
	assert.Equal(t, http.StatusNotFound, d.do(http.MethodDelete, "/e2e/v1/devices/77", token, nil).status)
	res = d.do(http.MethodPut, "/e2e/v1/devices/7", token, deviceBody(sn, dev, priv))
	assert.Equal(t, http.StatusGone, res.status, "a revoked id is not reused")
}

func TestHandler_KeysAndClaim(t *testing.T) {
	d := newTestDirectory(t)
	aliceToken, _ := d.signOn("100001")
	bobToken, _ := d.signOn("100002")
	sn := state.NewIdentScreenName("100001")
	pub, priv := newKey(t)
	dev := newTestDevice(t, 1)
	require.Equal(t, http.StatusCreated, d.do(http.MethodPut, "/e2e/v1/account", aliceToken, accountBody(sn, pub, priv)).status)
	require.Equal(t, http.StatusCreated, d.do(http.MethodPut, "/e2e/v1/devices/1", aliceToken, deviceBody(sn, dev, priv)).status)

	badSig := signedKey(sn, dev, "AAAAAQ", false)
	badSig["signature"] = enc(make([]byte, 64))
	cases := []struct {
		name string
		keys []map[string]any
		want int
	}{
		{name: "empty batch", keys: []map[string]any{}, want: http.StatusBadRequest},
		{name: "bad signature", keys: []map[string]any{badSig}, want: http.StatusBadRequest},
		{name: "fallback signature on a one-time key", keys: []map[string]any{signedKey(sn, dev, "AAAAAQ", true)}, want: http.StatusBadRequest},
		{name: "bad key id", keys: []map[string]any{signedKey(sn, dev, "not an id", false)}, want: http.StatusBadRequest},
		{name: "duplicate id in batch", keys: []map[string]any{signedKey(sn, dev, "AAAAAQ", false), signedKey(sn, dev, "AAAAAQ", false)}, want: http.StatusBadRequest},
		{name: "over the pool cap", keys: []map[string]any{
			signedKey(sn, dev, "k1", false), signedKey(sn, dev, "k2", false), signedKey(sn, dev, "k3", false),
			signedKey(sn, dev, "k4", false), signedKey(sn, dev, "k5", false), signedKey(sn, dev, "k6", false),
		}, want: http.StatusConflict},
		{name: "valid batch", keys: []map[string]any{signedKey(sn, dev, "k1", false), signedKey(sn, dev, "k2", false)}, want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := d.do(http.MethodPost, "/e2e/v1/devices/1/one-time-keys", aliceToken, map[string]any{"keys": tc.keys})
			assert.Equal(t, tc.want, res.status, res.body)
		})
	}

	fallback := signedKey(sn, dev, "fb", true)
	assert.Equal(t, http.StatusBadRequest, d.do(http.MethodPut, "/e2e/v1/devices/1/fallback-key", aliceToken, signedKey(sn, dev, "fb", false)).status)
	require.Equal(t, http.StatusNoContent, d.do(http.MethodPut, "/e2e/v1/devices/1/fallback-key", aliceToken, fallback).status)

	res := d.do(http.MethodGet, "/e2e/v1/devices/1", aliceToken, nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, float64(2), res.body["one_time_key_count"])
	assert.Equal(t, true, res.body["has_fallback_key"])

	// Bob claims both one-time keys, then gets the fallback key.
	claimed := map[string]bool{}
	for i := 0; i < 2; i++ {
		res := d.do(http.MethodPost, "/e2e/v1/users/100001/devices/1/claim", bobToken, nil)
		require.Equal(t, http.StatusOK, res.status, res.body)
		assert.Equal(t, enc(pub), res.body["account_key"])
		otk := res.body["one_time_key"].(map[string]any)
		assert.False(t, claimed[otk["key_id"].(string)])
		claimed[otk["key_id"].(string)] = true
		assert.Nil(t, res.body["fallback_key"])
	}
	res = d.do(http.MethodPost, "/e2e/v1/users/100001/devices/1/claim", bobToken, nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Nil(t, res.body["one_time_key"])
	assert.Equal(t, "fb", res.body["fallback_key"].(map[string]any)["key_id"])

	assert.Equal(t, http.StatusUnauthorized, d.do(http.MethodPost, "/e2e/v1/users/100001/devices/1/claim", "", nil).status)
	assert.Equal(t, http.StatusNotFound, d.do(http.MethodPost, "/e2e/v1/users/100001/devices/2/claim", bobToken, nil).status)
	assert.Equal(t, http.StatusNotFound, d.do(http.MethodPost, "/e2e/v1/users/100009/devices/1/claim", bobToken, nil).status)

	// Bob cannot upload keys to Alice's device: his token names his account.
	res = d.do(http.MethodPost, "/e2e/v1/devices/1/one-time-keys", bobToken, map[string]any{"keys": []map[string]any{signedKey(sn, dev, "k9", false)}})
	assert.Equal(t, http.StatusNotFound, res.status)
}

func TestHandler_Link(t *testing.T) {
	d := newTestDirectory(t)
	token, _ := d.signOn("100001")
	otherToken, _ := d.signOn("100002")
	eph := make([]byte, 32)

	assert.Equal(t, http.StatusBadRequest, d.do(http.MethodPost, "/e2e/v1/link", token, map[string]any{"ephemeral_key": enc(eph[:16])}).status)
	assert.Equal(t, http.StatusRequestEntityTooLarge,
		d.do(http.MethodPost, "/e2e/v1/link", token, map[string]any{"ephemeral_key": enc(eph), "request": enc(make([]byte, maxLinkBlobLen+1))}).status)

	res := d.do(http.MethodPost, "/e2e/v1/link", token, map[string]any{"ephemeral_key": enc(eph), "request": enc([]byte("hi"))})
	require.Equal(t, http.StatusCreated, res.status, res.body)
	id := res.body["id"].(string)
	path := "/e2e/v1/link/" + id

	res = d.do(http.MethodGet, "/e2e/v1/link", token, nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Len(t, res.body["links"].([]any), 1)
	assert.Len(t, d.do(http.MethodGet, "/e2e/v1/link", otherToken, nil).body["links"].([]any), 0)

	assert.Equal(t, http.StatusNotFound, d.do(http.MethodGet, path, otherToken, nil).status, "another account")
	assert.Equal(t, http.StatusNotFound, d.do(http.MethodGet, "/e2e/v1/link/nope", token, nil).status)
	assert.Equal(t, http.StatusBadRequest, d.do(http.MethodPost, path+"/reply", token, map[string]any{"reply": ""}).status)

	require.Equal(t, http.StatusNoContent, d.do(http.MethodPost, path+"/reply", token, map[string]any{"reply": enc([]byte("secret"))}).status)
	assert.Equal(t, http.StatusConflict, d.do(http.MethodPost, path+"/reply", token, map[string]any{"reply": enc([]byte("again"))}).status)

	res = d.do(http.MethodGet, path, token, nil)
	require.Equal(t, http.StatusOK, res.status)
	assert.Equal(t, enc([]byte("secret")), res.body["reply"])
	assert.NotNil(t, res.body["replied_at"])

	require.Equal(t, http.StatusNoContent, d.do(http.MethodDelete, path, token, nil).status)
	assert.Equal(t, http.StatusNotFound, d.do(http.MethodGet, path, token, nil).status)

	for i := 0; i < maxPendingLinks; i++ {
		require.Equal(t, http.StatusCreated, d.do(http.MethodPost, "/e2e/v1/link", token, map[string]any{"ephemeral_key": enc(eph)}).status)
	}
	assert.Equal(t, http.StatusConflict, d.do(http.MethodPost, "/e2e/v1/link", token, map[string]any{"ephemeral_key": enc(eph)}).status)
}

func TestHandler_BodyLimit(t *testing.T) {
	d := newTestDirectory(t)
	token, _ := d.signOn("100001")
	big := `{"ephemeral_key":"` + string(bytes.Repeat([]byte("A"), maxBodyBytes)) + `"}`
	assert.Equal(t, http.StatusRequestEntityTooLarge, d.do(http.MethodPost, "/e2e/v1/link", token, big).status)
}
