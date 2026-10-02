package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/mod/sumdb/note"

	"github.com/mk6i/open-oscar-server/state"
)

// The key transparency log's public endpoints (docs/e2e/KEY-TRANSPARENCY.md).

// DefaultKTOrigin is the log's name when E2E_KT_ORIGIN is not set.
const DefaultKTOrigin = "open-oscar-server/e2e-kt"

// logKeys is the log's signer and verifier key, made from the key in the
// store on first use.
type logKeys struct {
	mu       sync.Mutex
	signer   note.Signer
	verifier string
}

func (h *Handler) ktOrigin() string {
	if h.cfg.KTOrigin != "" {
		return h.cfg.KTOrigin
	}
	return DefaultKTOrigin
}

// logSigner returns the log's note signer and verifier key.
func (h *Handler) logSigner(ctx context.Context) (note.Signer, string, error) {
	h.keys.mu.Lock()
	defer h.keys.mu.Unlock()
	if h.keys.signer != nil {
		return h.keys.signer, h.keys.verifier, nil
	}
	priv, err := h.store.E2EKTSigningKey(ctx)
	if err != nil {
		return nil, "", err
	}
	signer, verifier, err := newLogSigner(h.ktOrigin(), priv)
	if err != nil {
		return nil, "", err
	}
	h.keys.signer, h.keys.verifier = signer, verifier
	return signer, verifier, nil
}

// newLogSigner makes the note signer of an Ed25519 key, and its verifier key
// "<name>+<key hash>+<base64(0x01 || public key)>".
func newLogSigner(name string, priv ed25519.PrivateKey) (note.Signer, string, error) {
	vkey, err := note.NewEd25519VerifierKey(name, priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(vkey, "+")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("e2e log verifier key %q", vkey)
	}
	skey := "PRIVATE+KEY+" + name + "+" + parts[1] + "+" +
		base64.StdEncoding.EncodeToString(append([]byte{1}, priv.Seed()...))
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, "", err
	}
	return signer, vkey, nil
}

// getLogCheckpoint answers GET /e2e/v1/log/checkpoint: the log's size and
// root hash as a signed note (c2sp.org/tlog-checkpoint).
func (h *Handler) getLogCheckpoint(w http.ResponseWriter, r *http.Request) {
	signer, _, err := h.logSigner(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	size, root, err := h.store.E2EKTState(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	text := fmt.Sprintf("%s\n%d\n%s\n", h.ktOrigin(), size, base64.StdEncoding.EncodeToString(root[:]))
	msg, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeText(w, msg)
}

// getLogKey answers GET /e2e/v1/log/key: the log's verifier key.
func (h *Handler) getLogKey(w http.ResponseWriter, r *http.Request) {
	_, verifier, err := h.logSigner(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	writeText(w, []byte(verifier+"\n"))
}

// logEntriesJSON is the answer to GET /e2e/v1/log/entries.
type logEntriesJSON struct {
	Start   int64 `json:"start"`
	Entries []b64 `json:"entries"`
}

// getLogEntries answers GET /e2e/v1/log/entries?start=N&count=M: up to M
// leaves from index N, at most state.E2EKTMaxEntries.
func (h *Handler) getLogEntries(w http.ResponseWriter, r *http.Request) {
	start, err := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
	if err != nil || start < 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "start must be a log index")
		return
	}
	count := int64(state.E2EKTMaxEntries)
	if c := r.URL.Query().Get("count"); c != "" {
		count, err = strconv.ParseInt(c, 10, 64)
		if err != nil || count < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "count must be a positive number")
			return
		}
	}
	leaves, err := h.store.E2EKTEntries(r.Context(), start, count)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	out := logEntriesJSON{Start: start, Entries: make([]b64, 0, len(leaves))}
	for _, l := range leaves {
		out.Entries = append(out.Entries, l)
	}
	writeJSON(w, http.StatusOK, out)
}

func writeText(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
