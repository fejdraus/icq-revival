package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/mk6i/open-oscar-server/state"
)

// The auditor of the key log (docs/e2e/KEY-TRANSPARENCY.md, stage 2), as
// Signal's key transparency has one: a party apart from the server that
// follows the log, checks that it only ever grows and that every entry keeps
// the directory's rules, and cosigns each checkpoint it checked. Clients take
// a log only together with a recent cosignature that agrees with their own
// copy, so a server that shows one user a different log than everyone else
// is caught. cmd/e2e-kt-auditor runs it.
//
// The rules an entry must keep, replayed from the start of the log:
//   - publish: only for an account that has no key (or was deleted);
//   - rotate: the proof is the old key's signature over the rotate message;
//   - reset: only once every device of the account is revoked;
//   - device: a device id the account has not used, signed by its key;
//   - resign: an active device, signed by the account's (new) key;
//   - revoke: an active device;
//   - delete: an account that has a key.
//
// An entry that breaks one is a violation: the auditor stops cosigning for
// good, so every client soon warns that the log is no longer audited.

// AuditState is what an auditor keeps between runs.
type AuditState struct {
	// LogKey is the log's verifier key, pinned on first sight.
	LogKey string `json:"log_key"`
	Size   int64  `json:"size"`
	// Edge is the right edge of the tree: the hashes of its complete
	// subtrees, largest first.
	Edge     [][]byte                 `json:"edge"`
	Accounts map[string]*auditAccount `json:"accounts"`
	// Violation, once set, is why the auditor no longer cosigns.
	Violation string `json:"violation,omitempty"`
}

type auditAccount struct {
	Key     []byte                  `json:"key"`
	Devices map[uint32]*auditDevice `json:"devices"`
	// Used are the device ids this account has had, revoked ones included.
	Used map[uint32]bool `json:"used"`
}

type auditDevice struct {
	Curve25519 []byte `json:"curve25519"`
	Ed25519    []byte `json:"ed25519"`
}

// ErrViolation wraps what the log did wrong.
var ErrViolation = errors.New("key log violation")

func violation(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrViolation, fmt.Sprintf(format, a...))
}

func leafHash(leaf []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, leaf...))
	return h[:]
}

func nodeHash(l, r []byte) []byte {
	h := sha256.Sum256(append(append([]byte{1}, l...), r...))
	return h[:]
}

func (s *AuditState) push(leaf []byte) {
	h := leafHash(leaf)
	for n := s.Size; n&1 == 1; n >>= 1 {
		h = nodeHash(s.Edge[len(s.Edge)-1], h)
		s.Edge = s.Edge[:len(s.Edge)-1]
	}
	s.Edge = append(s.Edge, h)
	s.Size++
}

func (s *AuditState) root() []byte {
	if len(s.Edge) == 0 {
		return nil
	}
	r := s.Edge[len(s.Edge)-1]
	for i := len(s.Edge) - 2; i >= 0; i-- {
		r = nodeHash(s.Edge[i], r)
	}
	return r
}

// ktFields splits a leaf into its fields after the context.
func ktFields(leaf []byte) ([][]byte, bool) {
	rest, ok := bytes.CutPrefix(leaf, []byte(state.E2EKTContext))
	if !ok {
		return nil, false
	}
	var out [][]byte
	for len(rest) > 0 {
		if len(rest) < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(rest))
		if len(rest) < 2+n {
			return nil, false
		}
		out = append(out, rest[2:2+n])
		rest = rest[2+n:]
	}
	return out, len(out) >= 3 && len(out[2]) == 8
}

// apply checks one leaf against the rules and replays it.
func (s *AuditState) apply(index int64, leaf []byte) error {
	f, ok := ktFields(leaf)
	if !ok {
		return violation("entry %d is not a log entry", index)
	}
	kind, sn, args := string(f[0]), state.NewIdentScreenName(string(f[1])), f[3:]
	if s.Accounts == nil {
		s.Accounts = map[string]*auditAccount{}
	}
	acc := s.Accounts[sn.String()]
	bad := func(why string) error { return violation("entry %d (%s %s): %s", index, kind, sn.String(), why) }
	id := func(b []byte) (uint32, bool) {
		if len(b) != 4 {
			return 0, false
		}
		return binary.BigEndian.Uint32(b), true
	}
	switch kind {
	case state.E2EKTAccount:
		if len(args) < 2 || len(args[1]) != keyLen {
			return bad("not an account key")
		}
		change, key := string(args[0]), args[1]
		switch change {
		case state.E2EKeyPublished:
			if len(args) != 2 {
				return bad("a publish carries no proof")
			}
			if acc != nil {
				return bad("the account already has a key: a new key needs a rotation or a reset")
			}
			s.Accounts[sn.String()] = &auditAccount{Key: key, Devices: map[uint32]*auditDevice{}, Used: map[uint32]bool{}}
		case state.E2EKeyRotated:
			if acc == nil {
				return bad("no key to rotate")
			}
			if len(args) != 3 || !verify(acc.Key, RotateMessage(sn, acc.Key, key), args[2]) {
				return bad("the rotation is not signed by the old key")
			}
			acc.Key = key
		case state.E2EKeyReset:
			if acc == nil {
				return bad("no key to reset")
			}
			if len(args) != 2 {
				return bad("a reset carries no proof")
			}
			if len(acc.Devices) > 0 {
				return bad("a reset while the account still has active devices")
			}
			acc.Key = key
		default:
			return bad("unknown change " + change)
		}
	case state.E2EKTDevice:
		if acc == nil {
			return bad("no account")
		}
		d, ok := id(args[0])
		if len(args) != 4 || !ok || len(args[1]) != keyLen || len(args[2]) != keyLen {
			return bad("not a device")
		}
		if acc.Used[d] {
			return bad("the device id was used before")
		}
		if !verify(acc.Key, DeviceMessage(sn, d, args[1], args[2]), args[3]) {
			return bad("the device is not signed by the account key")
		}
		acc.Used[d] = true
		acc.Devices[d] = &auditDevice{Curve25519: args[1], Ed25519: args[2]}
	case state.E2EKTResign:
		if acc == nil || len(args) != 2 {
			return bad("not a re-signature of a device")
		}
		d, _ := id(args[0])
		dev := acc.Devices[d]
		if dev == nil {
			return bad("no such active device")
		}
		if !verify(acc.Key, DeviceMessage(sn, d, dev.Curve25519, dev.Ed25519), args[1]) {
			return bad("the new signature is not by the account key")
		}
	case state.E2EKTRevoke:
		if acc == nil || len(args) != 1 {
			return bad("not a revocation")
		}
		d, _ := id(args[0])
		if acc.Devices[d] == nil {
			return bad("no such active device")
		}
		delete(acc.Devices, d)
	case state.E2EKTDelete:
		if acc == nil || len(args) != 0 {
			return bad("no account to delete")
		}
		delete(s.Accounts, sn.String())
	default:
		return bad("unknown kind")
	}
	return nil
}

// Auditor follows one log.
type Auditor struct {
	// Base is the key directory's URL, ending in /e2e/v1/.
	Base   string
	Name   string
	Key    ed25519.PrivateKey
	Client *http.Client
	Now    func() time.Time
}

func (a *Auditor) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return body, nil
}

// Step brings st up to date with the log and, when everything checks out,
// cosigns the log's checkpoint and hands the cosignature to the server. A
// returned error wrapping ErrViolation is permanent and recorded in st;
// any other is worth retrying.
func (a *Auditor) Step(ctx context.Context, st *AuditState) error {
	if st.Violation != "" {
		return fmt.Errorf("%w: %s", ErrViolation, st.Violation)
	}
	if st.LogKey == "" {
		k, err := a.get(ctx, "log/key")
		if err != nil {
			return err
		}
		st.LogKey = strings.TrimSpace(string(k))
	}
	verifier, err := note.NewVerifier(st.LogKey)
	if err != nil {
		return fmt.Errorf("log key: %w", err)
	}
	msg, err := a.get(ctx, "log/checkpoint")
	if err != nil {
		return err
	}
	n, err := note.Open(msg, note.VerifierList(verifier))
	if err != nil {
		return a.record(st, violation("the checkpoint is not signed by the log's key: %v", err))
	}
	origin, size, root, err := parseCheckpointBody(n.Text)
	if err != nil || origin != verifier.Name() {
		return a.record(st, violation("the checkpoint is not one of this log"))
	}
	if size < st.Size {
		return a.record(st, violation("the log shrank from %d to %d entries", st.Size, size))
	}

	next := st.clone()
	for next.Size < size {
		count := min(size-next.Size, state.E2EKTMaxEntries)
		raw, err := a.get(ctx, fmt.Sprintf("log/entries?start=%d&count=%d", next.Size, count))
		if err != nil {
			return err
		}
		var page logEntriesJSON
		if err := json.Unmarshal(raw, &page); err != nil {
			return fmt.Errorf("log entries: %w", err)
		}
		if page.Start != next.Size || len(page.Entries) == 0 {
			return fmt.Errorf("log entries from %d: got %d from %d", next.Size, len(page.Entries), page.Start)
		}
		for _, leaf := range page.Entries {
			if next.Size == size {
				break
			}
			if err := next.apply(next.Size, leaf); err != nil {
				return a.record(st, err)
			}
			next.push(leaf)
		}
	}
	if size > 0 && !bytes.Equal(next.root(), root) {
		return a.record(st, violation("the entries do not add up to the signed root at %d", size))
	}
	*st = *next

	line := Cosign(a.Name, a.Key, n.Text, uint64(a.Now().Unix()))
	body, _ := json.Marshal(cosignatureRequest{Checkpoint: n.Text, Cosignature: line})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.Base+"log/cosignature", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		why, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST log/cosignature: %s %s", resp.Status, strings.TrimSpace(string(why)))
	}
	return nil
}

func (a *Auditor) record(st *AuditState, err error) error {
	if errors.Is(err, ErrViolation) {
		st.Violation = strings.TrimPrefix(err.Error(), ErrViolation.Error()+": ")
	}
	return err
}

func (s *AuditState) clone() *AuditState {
	raw, _ := json.Marshal(s)
	var c AuditState
	_ = json.Unmarshal(raw, &c)
	return &c
}
