package e2e

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
)

// b64 is binary data carried in JSON as standard base64. It is written
// without padding, the way vodozemac writes its keys, and read with or
// without it.
type b64 []byte

func (b b64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawStdEncoding.EncodeToString(b))
}

func (b *b64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("expected a base64 string")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return errors.New("invalid base64")
	}
	*b = raw
	return nil
}

// unixTime is a time carried in JSON as Unix seconds.
func unixTime(t time.Time) int64 {
	return t.Unix()
}

// unixTimePtr is unixTime for a time that may be unset, which is left out.
func unixTimePtr(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	v := t.Unix()
	return &v
}

type accountJSON struct {
	ScreenName string `json:"screen_name"`
	AccountKey b64    `json:"account_key"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

func newAccountJSON(sn state.IdentScreenName, a state.E2EAccount) accountJSON {
	return accountJSON{
		ScreenName: sn.String(),
		AccountKey: a.Key,
		CreatedAt:  unixTime(a.CreatedAt),
		UpdatedAt:  unixTime(a.UpdatedAt),
	}
}

type deviceJSON struct {
	DeviceID         uint32 `json:"device_id"`
	Curve25519Key    b64    `json:"curve25519_key"`
	Ed25519Key       b64    `json:"ed25519_key"`
	AccountSignature b64    `json:"account_signature"`
	CreatedAt        int64  `json:"created_at"`
	LastSeenAt       int64  `json:"last_seen_at"`
	RevokedAt        *int64 `json:"revoked_at,omitempty"`
}

func newDeviceJSON(d state.E2EDevice) deviceJSON {
	return deviceJSON{
		DeviceID:         d.DeviceID,
		Curve25519Key:    d.Curve25519Key,
		Ed25519Key:       d.Ed25519Key,
		AccountSignature: d.AccountSignature,
		CreatedAt:        unixTime(d.CreatedAt),
		LastSeenAt:       unixTime(d.LastSeenAt),
		RevokedAt:        unixTimePtr(d.RevokedAt),
	}
}

type signedKeyJSON struct {
	KeyID     string `json:"key_id"`
	PublicKey b64    `json:"public_key"`
	Signature b64    `json:"signature"`
}

func newSignedKeyJSON(k *state.E2ESignedKey) *signedKeyJSON {
	if k == nil {
		return nil
	}
	return &signedKeyJSON{KeyID: k.KeyID, PublicKey: k.PublicKey, Signature: k.Signature}
}

type linkJSON struct {
	ID           string `json:"id"`
	EphemeralKey b64    `json:"ephemeral_key"`
	Request      b64    `json:"request,omitempty"`
	Reply        b64    `json:"reply,omitempty"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	RepliedAt    *int64 `json:"replied_at,omitempty"`
}

func newLinkJSON(l state.E2ELinkRequest) linkJSON {
	return linkJSON{
		ID:           l.ID,
		EphemeralKey: l.EphemeralKey,
		Request:      l.RequestBlob,
		Reply:        l.ReplyBlob,
		CreatedAt:    unixTime(l.CreatedAt),
		ExpiresAt:    unixTime(l.ExpiresAt),
		RepliedAt:    unixTimePtr(l.RepliedAt),
	}
}

type errorJSON struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// writeJSON sends v with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError sends an error body: a stable machine-readable code and a
// human-readable message.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorJSON{Error: code, Message: message})
}

// decodeBody reads a JSON request body of at most maxBodyBytes into v,
// refusing unknown fields and trailing data. It reports false once it has
// sent the error.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil && dec.Decode(&struct{}{}) != io.EOF {
		err = errors.New("unexpected data after the JSON object")
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	return true
}
