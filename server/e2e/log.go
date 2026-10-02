package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

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
	// The base64 key may itself hold plus signs.
	parts := strings.SplitN(vkey, "+", 3)
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
	text := checkpointBody(h.ktOrigin(), size, root[:])
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

// --- auditors (stage 2) -----------------------------------------------------

// maxCosignatureSkew is how far an auditor's clock may be from ours.
const maxCosignatureSkew = 10 * time.Minute

// auditors returns the auditors of E2E_KT_AUDITORS; a key that does not read
// is logged and left out.
func (h *Handler) auditors() []Cosigner {
	var out []Cosigner
	for _, k := range h.cfg.KTAuditors {
		if strings.TrimSpace(k) == "" {
			continue
		}
		c, err := ParseCosigner(k)
		if err != nil {
			h.logger.Error("E2E_KT_AUDITORS: key left out", "key", k, "err", err)
			continue
		}
		out = append(out, c)
	}
	return out
}

// getLogAuditors answers GET /e2e/v1/log/auditors: the auditors' verifier
// keys, one per line.
func (h *Handler) getLogAuditors(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	for _, c := range h.auditors() {
		b.WriteString(CosignerKey(c.Name, c.Key) + "\n")
	}
	writeText(w, []byte(b.String()))
}

type cosignatureRequest struct {
	Checkpoint  string `json:"checkpoint"`
	Cosignature string `json:"cosignature"`
}

// postLogCosignature answers POST /e2e/v1/log/cosignature: an auditor hands in
// its cosignature over a checkpoint of this log. It needs no token: only a
// cosignature that verifies under a configured auditor's key, over a
// checkpoint this log really had, is kept.
func (h *Handler) postLogCosignature(w http.ResponseWriter, r *http.Request) {
	var req cosignatureRequest
	if !decodeBody(w, r, &req) {
		return
	}
	origin, size, root, err := parseCheckpointBody(req.Checkpoint)
	if err != nil || origin != h.ktOrigin() {
		writeError(w, http.StatusBadRequest, "bad_request", "not a checkpoint of this log")
		return
	}
	var auditor *Cosigner
	var at uint64
	for _, c := range h.auditors() {
		if t, err := c.VerifyCosignature(req.Checkpoint, req.Cosignature); err == nil {
			auditor, at = &c, t
			break
		}
	}
	if auditor == nil {
		writeError(w, http.StatusForbidden, "unknown_auditor", "the cosignature is not by a configured auditor")
		return
	}
	now := h.now()
	if d := now.Sub(time.Unix(int64(at), 0)); d > maxCosignatureSkew || d < -maxCosignatureSkew {
		writeError(w, http.StatusBadRequest, "bad_time", "the cosignature's time is too far from the server's")
		return
	}
	cur, _, err := h.store.E2EKTState(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	if size < 1 || size > cur {
		writeError(w, http.StatusConflict, "unknown_checkpoint", "this log never had that checkpoint")
		return
	}
	want, err := h.store.E2EKTRoot(r.Context(), size)
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	if !bytes.Equal(want[:], root) {
		h.logger.Error("e2e key log: an auditor cosigned a root this log never had", "auditor", auditor.Name, "size", size)
		writeError(w, http.StatusConflict, "unknown_checkpoint", "this log never had that checkpoint")
		return
	}
	if err := h.store.E2EKTSetCosignature(r.Context(), state.E2EKTCosignature{
		Auditor: auditor.Name, Size: size, Time: int64(at), Line: strings.TrimSpace(req.Cosignature),
	}); err != nil {
		h.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type cosignedJSON struct {
	Checkpoints []string `json:"checkpoints"`
}

// getLogCosigned answers GET /e2e/v1/log/cosigned: for each configured
// auditor, the latest checkpoint it cosigned, as a note signed by the log and
// cosigned by the auditor.
func (h *Handler) getLogCosigned(w http.ResponseWriter, r *http.Request) {
	signer, _, err := h.logSigner(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	cosigs, err := h.store.E2EKTCosignatures(r.Context())
	if err != nil {
		h.internalError(w, r, err)
		return
	}
	configured := map[string]bool{}
	for _, c := range h.auditors() {
		configured[c.Name] = true
	}
	out := cosignedJSON{Checkpoints: []string{}}
	for _, c := range cosigs {
		if !configured[c.Auditor] {
			continue
		}
		root, err := h.store.E2EKTRoot(r.Context(), c.Size)
		if err != nil {
			h.internalError(w, r, err)
			return
		}
		msg, err := note.Sign(&note.Note{Text: checkpointBody(h.ktOrigin(), c.Size, root[:])}, signer)
		if err != nil {
			h.internalError(w, r, err)
			return
		}
		out.Checkpoints = append(out.Checkpoints, string(msg)+c.Line+"\n")
	}
	writeJSON(w, http.StatusOK, out)
}
