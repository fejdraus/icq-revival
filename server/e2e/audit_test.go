package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/sumdb/note"

	"github.com/mk6i/open-oscar-server/state"
)

const testAuditor = "auditor.test/icq"

// auditedDirectory is a key directory whose log names one auditor, served
// over HTTP for it.
func auditedDirectory(t *testing.T) (*testDirectory, *httptest.Server, *Auditor) {
	t.Helper()
	d := newTestDirectory(t)
	_, priv := newKey(t)
	d.handler.cfg.KTAuditors = []string{CosignerKey(testAuditor, priv.Public().(ed25519.PublicKey))}
	srv := httptest.NewServer(d.mux)
	t.Cleanup(srv.Close)
	return d, srv, &Auditor{
		Base: srv.URL + "/e2e/v1/", Name: testAuditor, Key: priv,
		Client: srv.Client(), Now: time.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// account publishes a real account key and n devices signed by it.
func account(t *testing.T, d *testDirectory, sn string, n int) (state.IdentScreenName, ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	d.signOn(sn)
	who := state.NewIdentScreenName(sn)
	pub, priv := newKey(t)
	require.NoError(t, d.store.E2EPublishAccountKey(ctx, who, pub, time.Now()))
	for i := 1; i <= n; i++ {
		dev := newTestDevice(t, uint32(i))
		_, err := d.store.E2EPutDevice(ctx, who, pub, state.E2EDevice{
			DeviceID: dev.id, Curve25519Key: dev.curve, Ed25519Key: dev.edPub,
			AccountSignature: ed25519.Sign(priv, DeviceMessage(who, dev.id, dev.curve, dev.edPub)),
		}, 10, time.Now())
		require.NoError(t, err)
	}
	return who, priv
}

func TestAuditor_CosignsALogThatKeepsTheRules(t *testing.T) {
	d, _, a := auditedDirectory(t)
	ctx := context.Background()
	alice, alicePriv := account(t, d, "100001", 2)
	account(t, d, "100002", 1)

	// A rotation that keeps device 1, a revocation, and a deleted account.
	oldPub := alicePriv.Public().(ed25519.PublicKey)
	devs, err := d.store.E2EDevices(ctx, alice)
	require.NoError(t, err)
	newPub, newPriv := newKey(t)
	require.NoError(t, d.store.E2ERotateAccountKey(ctx, alice, oldPub, newPub,
		ed25519.Sign(alicePriv, RotateMessage(alice, oldPub, newPub)),
		[]state.E2EDeviceSignature{{DeviceID: 1, AccountSignature: ed25519.Sign(newPriv,
			DeviceMessage(alice, 1, devs[0].Curve25519Key, devs[0].Ed25519Key))}}, time.Now()))
	require.NoError(t, d.store.DeleteUser(ctx, state.NewIdentScreenName("100002")))

	var st AuditState
	require.NoError(t, a.Step(ctx, &st))
	size, root := d.checkpoint()
	assert.Equal(t, size, st.Size)
	assert.Equal(t, root[:], st.root())
	assert.Empty(t, st.Violation)
	assert.NotContains(t, st.Accounts, "100002")

	// The cosigned checkpoint as clients get it: the log's signature and the
	// auditor's.
	code, body := d.get("/e2e/v1/log/cosigned")
	require.Equal(t, http.StatusOK, code)
	var out cosignedJSON
	require.NoError(t, json.Unmarshal([]byte(body), &out))
	require.Len(t, out.Checkpoints, 1)
	_, vkey := d.get("/e2e/v1/log/key")
	verifier, err := note.NewVerifier(strings.TrimSpace(vkey))
	require.NoError(t, err)
	n, err := note.Open([]byte(out.Checkpoints[0]), note.VerifierList(verifier))
	require.NoError(t, err)
	cosigner, err := ParseCosigner(d.handler.cfg.KTAuditors[0])
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out.Checkpoints[0]), "\n")
	when, err := cosigner.VerifyCosignature(n.Text, lines[len(lines)-1])
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Unix(), int64(when), 5)

	_, auditors := d.get("/e2e/v1/log/auditors")
	assert.Equal(t, d.handler.cfg.KTAuditors[0]+"\n", auditors)

	// Nothing new: cosigned again, later.
	require.NoError(t, a.Step(ctx, &st))
}

func TestAuditor_StopsForGoodAtABrokenRule(t *testing.T) {
	d, _, a := auditedDirectory(t)
	ctx := context.Background()
	who, _ := account(t, d, "100001", 1)
	var st AuditState
	require.NoError(t, a.Step(ctx, &st))

	// The server slips in a device the account key did not sign.
	dev := newTestDevice(t, 9)
	_, err := d.store.E2EPutDevice(ctx, who, mustAccountKey(t, d, who), state.E2EDevice{
		DeviceID: 9, Curve25519Key: dev.curve, Ed25519Key: dev.edPub, AccountSignature: make([]byte, 64),
	}, 10, time.Now())
	require.NoError(t, err)

	err = a.Step(ctx, &st)
	require.ErrorIs(t, err, ErrViolation)
	assert.Contains(t, st.Violation, "not signed by the account key")
	require.ErrorIs(t, a.Step(ctx, &st), ErrViolation, "never again")
}

func mustAccountKey(t *testing.T, d *testDirectory, who state.IdentScreenName) []byte {
	acc, err := d.store.E2EAccount(context.Background(), who)
	require.NoError(t, err)
	return acc.Key
}

func TestAuditState_Rules(t *testing.T) {
	sn := state.NewIdentScreenName("100001")
	pub, priv, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	curve, ed := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	devSig := ed25519.Sign(priv, DeviceMessage(sn, 1, curve, ed))
	at := time.Unix(1, 0)
	be := func(n int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(n)) }
	publish := state.E2EKTLeaf("account", sn, at, []byte("publish"), pub)
	device := state.E2EKTLeaf("device", sn, at, []byte{0, 0, 0, 1}, curve, ed, devSig)
	revoke := state.E2EKTLeaf("revoke", sn, at, []byte{0, 0, 0, 1})
	ownerRevoke := state.E2EKTLeaf("owner-revoke", sn, at, []byte{0, 0, 0, 1}, be(7), ed25519.Sign(priv, RevokeMessage(sn, 1, 7)))
	forgedRevoke := state.E2EKTLeaf("owner-revoke", sn, at, []byte{0, 0, 0, 1}, be(7), ed25519.Sign(priv2, RevokeMessage(sn, 1, 7)))
	recoveryRevoke := state.E2EKTLeaf("recovery-revoke", sn, at, []byte{0, 0, 0, 1}, []byte("lost laptop"))
	reset := state.E2EKTLeaf("account", sn, at, []byte("reset"), pub2)
	rotate := state.E2EKTLeaf("account", sn, at, []byte("rotate"), pub2, ed25519.Sign(priv, RotateMessage(sn, pub, pub2)))
	resign := state.E2EKTLeaf("resign", sn, at, []byte{0, 0, 0, 1}, ed25519.Sign(priv2, DeviceMessage(sn, 1, curve, ed)))
	del := state.E2EKTLeaf("delete", sn, at)
	ownerDelete := state.E2EKTLeaf("owner-delete", sn, at, be(9), ed25519.Sign(priv, DeleteMessage(sn, 9)))
	forgedDelete := state.E2EKTLeaf("owner-delete", sn, at, be(9), ed25519.Sign(priv2, DeleteMessage(sn, 9)))
	recoveryDelete := state.E2EKTLeaf("recovery-delete", sn, at, []byte("the account was deleted"))
	cases := []struct {
		name   string
		leaves [][]byte
		why    string
		// recovered are the entries the auditor logs as the operator's.
		recovered []int
	}{
		{name: "publish over a key", leaves: [][]byte{publish, publish}, why: "already has a key"},
		{name: "reset with an active device", leaves: [][]byte{publish, device, reset}, why: "still has active devices"},
		{name: "rotation without the old key", leaves: [][]byte{publish, state.E2EKTLeaf("account", sn, at, []byte("rotate"), pub2, ed25519.Sign(priv2, RotateMessage(sn, pub, pub2)))}, why: "not signed by the old key"},
		{name: "device id used again", leaves: [][]byte{publish, device, ownerRevoke, revoke, device}, why: "used before"},
		{name: "revoke twice", leaves: [][]byte{publish, device, ownerRevoke, revoke, ownerRevoke}, why: "no such active device"},
		{name: "unknown kind", leaves: [][]byte{publish, state.E2EKTLeaf("future", sn, at)}, why: "unknown kind"},
		{name: "device of no account", leaves: [][]byte{device}, why: "no account"},
		// Second audit of 2026-10, finding 1.
		{name: "a revoke without the owner's signature", leaves: [][]byte{publish, device, revoke}, why: "without the owner's signature or a recovery entry"},
		{name: "a revoke signed by another key", leaves: [][]byte{publish, device, forgedRevoke}, why: "not signed by the account key"},
		{name: "a revoke signed for another time", leaves: [][]byte{publish, device, state.E2EKTLeaf("owner-revoke", sn, at, []byte{0, 0, 0, 1}, be(8), ed25519.Sign(priv, RevokeMessage(sn, 1, 7)))}, why: "not signed by the account key"},
		{name: "an owner's revoke not followed by its revoke", leaves: [][]byte{publish, device, ownerRevoke, reset}, why: "not followed by its revoke"},
		{name: "a recovery not followed by its revoke", leaves: [][]byte{publish, device, recoveryRevoke, publish}, why: "not followed by its revoke"},
		{name: "a delete without the owner's signature", leaves: [][]byte{publish, del}, why: "without the owner's signature or a recovery entry"},
		{name: "a delete signed by another key", leaves: [][]byte{publish, forgedDelete}, why: "not signed by the account key"},
		{name: "a re-signed device needs the owner to revoke it", leaves: [][]byte{publish, device, rotate, resign, revoke}, why: "without the owner's signature or a recovery entry"},
		{name: "signed revokes and deletes", leaves: [][]byte{publish, device, ownerRevoke, revoke, ownerDelete, del, publish}},
		{name: "a device a rotation left unsigned", leaves: [][]byte{publish, device, rotate, revoke}},
		{name: "the operator's recovery is taken and flagged", leaves: [][]byte{publish, device, recoveryRevoke, revoke, reset}, recovered: []int{2, 4}},
		{name: "a key after the operator deleted the account is flagged", leaves: [][]byte{publish, recoveryDelete, del, publish}, recovered: []int{1, 3}},
		{name: "a log of publishes and devices only", leaves: [][]byte{publish, device}},
		{name: "fine", leaves: [][]byte{publish, device, ownerRevoke, revoke, reset, state.E2EKTLeaf("account", sn, at, []byte("rotate"), pub, ed25519.Sign(priv2, RotateMessage(sn, pub2, pub))), ownerDelete, del, publish}, recovered: []int{4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var st AuditState
			var err error
			var recovered []int
			for i, l := range tc.leaves {
				var what string
				if what, err = st.apply(int64(i), l); err != nil {
					break
				}
				if what != "" {
					recovered = append(recovered, i)
				}
			}
			if tc.why == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.recovered, recovered)
			} else {
				require.ErrorIs(t, err, ErrViolation)
				assert.Contains(t, err.Error(), tc.why)
			}
		})
	}
}

// An auditor's state from before the authority entries has devices without
// the stale flag: a bare revoke of one is still refused, and its state reads.
func TestAuditState_OldStateRefusesABareRevoke(t *testing.T) {
	sn := state.NewIdentScreenName("100001")
	pub, priv, _ := ed25519.GenerateKey(nil)
	curve, ed := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	var st AuditState
	for i, l := range [][]byte{
		state.E2EKTLeaf("account", sn, time.Unix(1, 0), []byte("publish"), pub),
		state.E2EKTLeaf("device", sn, time.Unix(1, 0), []byte{0, 0, 0, 1}, curve, ed, ed25519.Sign(priv, DeviceMessage(sn, 1, curve, ed))),
	} {
		_, err := st.apply(int64(i), l)
		require.NoError(t, err)
	}
	raw, err := json.Marshal(st)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "stale")
	assert.NotContains(t, string(raw), "pending")
	var old AuditState
	require.NoError(t, json.Unmarshal(raw, &old))
	_, err = old.apply(2, state.E2EKTLeaf("revoke", sn, time.Unix(1, 0), []byte{0, 0, 0, 1}))
	assert.ErrorIs(t, err, ErrViolation)
}

// Second audit of 2026-10, finding 1, through the real server: the owner's
// revoke and delete are cosigned quietly; the operator's revoke, a reset, a
// user the operator deleted and the key published on that number afterwards
// are cosigned too - the auditor does not stop at a legitimate recovery - but
// each one is a warning in its log.
func TestAuditor_TellsTheOwnerFromTheOperator(t *testing.T) {
	d, _, a := auditedDirectory(t)
	var logged bytes.Buffer
	a.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	ctx := context.Background()

	token, instance := d.signOn("100001")
	sn := state.NewIdentScreenName("100001")
	pub, priv := newKey(t)
	instance.SetE2EAccountKey(pub)
	require.Equal(t, http.StatusCreated, d.do(http.MethodPut, "/e2e/v1/account", token, accountBody(sn, pub, priv)).status)
	for _, id := range []uint32{1, 2} {
		require.Equal(t, http.StatusCreated, d.do(http.MethodPut, fmt.Sprintf("/e2e/v1/devices/%d", id), token, deviceBody(sn, newTestDevice(t, id), priv)).status)
	}
	require.Equal(t, http.StatusNoContent, d.do(http.MethodDelete, "/e2e/v1/devices/1", token, revokeBody(sn, 1, priv, time.Now())).status)
	var st AuditState
	require.NoError(t, a.Step(ctx, &st))
	assert.NotContains(t, logged.String(), "recovery", "the owner's revoke is no recovery")

	// The operator revokes the other device and the user resets.
	require.NoError(t, d.store.E2ERevokeDevice(ctx, sn, 2, state.E2ERecovery("revoked by the operator (management API)"), time.Now()))
	pub2, priv2 := newKey(t)
	instance.SetE2EAccountKey(pub2)
	require.Equal(t, http.StatusOK, d.do(http.MethodPut, "/e2e/v1/account", token, accountBody(sn, pub2, priv2)).status)
	// Another account: deleted by the operator, then published again.
	bob, _ := account(t, d, "100002", 1)
	require.NoError(t, d.store.DeleteUser(ctx, bob))
	require.NoError(t, d.store.InsertUser(ctx, state.User{IdentScreenName: bob, DisplayScreenName: "100002", IsICQ: true}))
	bobPub, _ := newKey(t)
	require.NoError(t, d.store.E2EPublishAccountKey(ctx, bob, bobPub, time.Now()))

	require.NoError(t, a.Step(ctx, &st), "a recovery is cosigned")
	assert.Empty(t, st.Violation)
	out := logged.String()
	for _, want := range []string{
		"device 2 revoked without the owner's key (revoked by the operator (management API))",
		"a new account key without the old key's proof (reset)",
		"the account deleted without the owner's key (the account was deleted)",
		"a new account key after the operator deleted the account",
	} {
		assert.Contains(t, out, want)
	}
	assert.Equal(t, 4, strings.Count(out, "level=WARN"), out)

	// The owner deletes its keys with a signed request: quiet again.
	logged.Reset()
	at := time.Now()
	body := map[string]any{"issued_at": at.Unix(), "signature": enc(ed25519.Sign(priv2, DeleteMessage(sn, at.Unix())))}
	require.Equal(t, http.StatusNoContent, d.do(http.MethodDelete, "/e2e/v1/account", token, body).status)
	require.NoError(t, a.Step(ctx, &st))
	assert.NotContains(t, st.Accounts, "100001")
	assert.Empty(t, logged.String())
}

func TestHandler_RefusesCosignaturesItCannotTrust(t *testing.T) {
	d, _, a := auditedDirectory(t)
	account(t, d, "100001", 1)
	size, root := d.checkpoint()
	body := checkpointBody(DefaultKTOrigin, size, root[:])
	post := func(cp, line string) int {
		raw, _ := json.Marshal(cosignatureRequest{Checkpoint: cp, Cosignature: line})
		rec := httptest.NewRecorder()
		d.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/e2e/v1/log/cosignature", bytes.NewReader(raw)))
		return rec.Code
	}
	now := uint64(time.Now().Unix())
	_, stranger := newKey(t)
	assert.Equal(t, http.StatusForbidden, post(body, Cosign(testAuditor, stranger, body, now)))
	assert.Equal(t, http.StatusBadRequest, post(body, Cosign(testAuditor, a.Key, body, now-3600)))
	other := checkpointBody(DefaultKTOrigin, size, bytes.Repeat([]byte{7}, 32))
	assert.Equal(t, http.StatusConflict, post(other, Cosign(testAuditor, a.Key, other, now)))
	bigger := checkpointBody(DefaultKTOrigin, size+5, root[:])
	assert.Equal(t, http.StatusConflict, post(bigger, Cosign(testAuditor, a.Key, bigger, now)))
	assert.Equal(t, http.StatusNoContent, post(body, Cosign(testAuditor, a.Key, body, now)))
}

func TestCosignature_KeyAndLine(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	vkey := CosignerKey("w.example/x", priv.Public().(ed25519.PublicKey))
	c, err := ParseCosigner(vkey)
	require.NoError(t, err)
	body := "log\n3\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
	line := Cosign("w.example/x", priv, body, 1679315147)
	got, err := c.VerifyCosignature(body, line)
	require.NoError(t, err)
	assert.EqualValues(t, 1679315147, got)
	_, err = c.VerifyCosignature(strings.Replace(body, "3", "4", 1), line)
	assert.Error(t, err)
	_, err = ParseCosigner(strings.Replace(vkey, "w.example/x", "w.example/y", 1))
	assert.Error(t, err, "the id is for another name")
}

// Several auditors: E2E_KT_AUDITORS names them all, /log/auditors lists each
// once in that order, each one's cosignature is taken, and /log/cosigned hands
// out the latest checkpoint of every one of them; a key that does not read is
// left out of both.
func TestHandler_SeveralAuditors(t *testing.T) {
	d, srv, first := auditedDirectory(t)
	ctx := context.Background()
	account(t, d, "100001", 1)
	names := []string{testAuditor, "b.test/icq", "c.test/icq"}
	auditors := []*Auditor{first}
	for _, name := range names[1:] {
		_, priv := newKey(t)
		d.handler.cfg.KTAuditors = append(d.handler.cfg.KTAuditors, CosignerKey(name, priv.Public().(ed25519.PublicKey)))
		auditors = append(auditors, &Auditor{
			Base: srv.URL + "/e2e/v1/", Name: name, Key: priv, Client: srv.Client(), Now: time.Now,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}
	configured := append([]string(nil), d.handler.cfg.KTAuditors...)
	d.handler.cfg.KTAuditors = append(d.handler.cfg.KTAuditors, "not+a+key", " ")

	_, listed := d.get("/e2e/v1/log/auditors")
	assert.Equal(t, strings.Join(configured, "\n")+"\n", listed)

	// The first two cosign; the third has not yet.
	for _, a := range auditors[:2] {
		var st AuditState
		require.NoError(t, a.Step(ctx, &st))
	}
	cosigned := func() map[string]string {
		code, body := d.get("/e2e/v1/log/cosigned")
		require.Equal(t, http.StatusOK, code)
		var out cosignedJSON
		require.NoError(t, json.Unmarshal([]byte(body), &out))
		by := map[string]string{}
		for _, cp := range out.Checkpoints {
			lines := strings.Split(strings.TrimSpace(cp), "\n")
			n, err := note.Open([]byte(cp), note.VerifierList(mustLogVerifier(t, d)))
			require.NoError(t, err)
			for i, k := range configured {
				c, err := ParseCosigner(k)
				require.NoError(t, err)
				if _, err := c.VerifyCosignature(n.Text, lines[len(lines)-1]); err == nil {
					by[names[i]] = n.Text
				}
			}
		}
		assert.Len(t, by, len(out.Checkpoints), "each checkpoint cosigned by one configured auditor")
		return by
	}
	got := cosigned()
	assert.Len(t, got, 2)
	assert.Contains(t, got, testAuditor)
	assert.Contains(t, got, "b.test/icq")

	// The log grows; the third cosigns the new checkpoint and the first two
	// keep theirs until they look again.
	account(t, d, "100002", 1)
	var st AuditState
	require.NoError(t, auditors[2].Step(ctx, &st))
	got = cosigned()
	require.Len(t, got, 3)
	assert.NotEqual(t, got[testAuditor], got["c.test/icq"])
	assert.Equal(t, got[testAuditor], got["b.test/icq"])
}

func mustLogVerifier(t *testing.T, d *testDirectory) note.Verifier {
	t.Helper()
	_, vkey := d.get("/e2e/v1/log/key")
	v, err := note.NewVerifier(strings.TrimSpace(vkey))
	require.NoError(t, err)
	return v
}

// sharedKTVectors are key log leaves of account 100001 (account keys from the
// Ed25519 seeds 32 x 01 and 32 x 05, device 1 with Curve25519 key 32 x 03 and
// Ed25519 key 32 x 02, time 1700000000): a publish by the first key, device
// 1, the owner's revoke of it, the revoke, an owner's revoke signed by the
// second key, a recovery revoke, a reset to the second key, a recovery
// delete, the delete, a publish of the second key and the owner's delete.
// tools/icq-e2e/core/src/kt.rs replays the same leaves in the same
// sequences and must come to the same verdicts (second audit of 2026-10,
// finding 1: the client's replay matches the auditor).
var sharedKTVectors = []string{
	"T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAdwdWJsaXNoACCKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXA==",
	"T1NDQVItRTJFLUtULXYxAAZkZXZpY2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEAIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgBAymZM6VU7E6HkcvkIbyPYI3F+7UxZBkwaxvlPxTFkyMnL/5uAFJ6R2mFh1CuFjbt5t3+xcBgdP4/BPob0Kj3qBQ==",
	"T1NDQVItRTJFLUtULXYxAAxvd25lci1yZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEACAAAAABlU/EAAEBtqTL0mQxf5xJahj15TZDec+7FG277JwFmOjAaE5mXzbSjatUjZLkSw/JxUXnsqSxE837cBwxn3KzjnMHrj6kE",
	"T1NDQVItRTJFLUtULXYxAAZyZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAE=",
	"T1NDQVItRTJFLUtULXYxAAxvd25lci1yZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEACAAAAABlU/EAAED7hSQ8ksBojn+or+VHOMtZQ4C0BYnf64M9ej/d7/TbsAi0iqcXOGyiPf5Xfk+ZjP5+4RCuw7YlBGMUXOldfvED",
	"T1NDQVItRTJFLUtULXYxAA9yZWNvdmVyeS1yZXZva2UABjEwMDAwMQAIAAAAAGVT8QAABAAAAAEAC2xvc3QgbGFwdG9w",
	"T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAVyZXNldAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/E=",
	"T1NDQVItRTJFLUtULXYxAA9yZWNvdmVyeS1kZWxldGUABjEwMDAwMQAIAAAAAGVT8QAAF3RoZSBhY2NvdW50IHdhcyBkZWxldGVk",
	"T1NDQVItRTJFLUtULXYxAAZkZWxldGUABjEwMDAwMQAIAAAAAGVT8QA=",
	"T1NDQVItRTJFLUtULXYxAAdhY2NvdW50AAYxMDAwMDEACAAAAABlU/EAAAdwdWJsaXNoACBuehzdKbC3j9E69MVZj+/07yqXFm48pvLk+/zNgFBb8Q==",
	"T1NDQVItRTJFLUtULXYxAAxvd25lci1kZWxldGUABjEwMDAwMQAIAAAAAGVT8QAACAAAAABlU/EAAEBOWgjh6PMWip+xhnXoAOk4Xy37Uwfp719ulO0e2KzgtRoi7KlikRgHbJXAw/v+U10Ta1Q3fw3En5cZFIcZ5cAA",
}

// sharedKTSequences are the sequences of sharedKTVectors and their verdict:
// a violation, or the positions the auditor logs as the operator's recovery.
var sharedKTSequences = []struct {
	leaves    []int
	violation bool
	recovered []int
}{
	{leaves: []int{0, 1, 2, 3}},
	{leaves: []int{0, 1, 3}, violation: true},
	{leaves: []int{0, 1, 4}, violation: true},
	{leaves: []int{0, 1, 5, 3, 6}, recovered: []int{2, 4}},
	{leaves: []int{0, 7, 8, 9}, recovered: []int{1, 3}},
	{leaves: []int{0, 8}, violation: true},
	{leaves: []int{0, 10, 8}},
	{leaves: []int{0, 10, 9}, violation: true},
}

func TestAuditState_SharedVectors(t *testing.T) {
	sn := state.NewIdentScreenName("100001")
	k1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	k2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))
	curve, ed := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{2}, 32)
	at := time.Unix(1_700_000_000, 0)
	be := binary.BigEndian.AppendUint64(nil, uint64(at.Unix()))
	built := [][]byte{
		state.E2EKTLeaf("account", sn, at, []byte("publish"), k1.Public().(ed25519.PublicKey)),
		state.E2EKTLeaf("device", sn, at, []byte{0, 0, 0, 1}, curve, ed, ed25519.Sign(k1, DeviceMessage(sn, 1, curve, ed))),
		state.E2EKTLeaf("owner-revoke", sn, at, []byte{0, 0, 0, 1}, be, ed25519.Sign(k1, RevokeMessage(sn, 1, at.Unix()))),
		state.E2EKTLeaf("revoke", sn, at, []byte{0, 0, 0, 1}),
		state.E2EKTLeaf("owner-revoke", sn, at, []byte{0, 0, 0, 1}, be, ed25519.Sign(k2, RevokeMessage(sn, 1, at.Unix()))),
		state.E2EKTLeaf("recovery-revoke", sn, at, []byte{0, 0, 0, 1}, []byte("lost laptop")),
		state.E2EKTLeaf("account", sn, at, []byte("reset"), k2.Public().(ed25519.PublicKey)),
		state.E2EKTLeaf("recovery-delete", sn, at, []byte("the account was deleted")),
		state.E2EKTLeaf("delete", sn, at),
		state.E2EKTLeaf("account", sn, at, []byte("publish"), k2.Public().(ed25519.PublicKey)),
		state.E2EKTLeaf("owner-delete", sn, at, be, ed25519.Sign(k1, DeleteMessage(sn, at.Unix()))),
	}
	require.Len(t, sharedKTVectors, len(built))
	for i, l := range built {
		assert.Equal(t, sharedKTVectors[i], base64.StdEncoding.EncodeToString(l), "leaf %d", i)
	}
	for _, tc := range sharedKTSequences {
		var st AuditState
		var err error
		var recovered []int
		for pos, i := range tc.leaves {
			var what string
			if what, err = st.apply(int64(pos), built[i]); err != nil {
				break
			}
			if what != "" {
				recovered = append(recovered, pos)
			}
		}
		if tc.violation {
			assert.ErrorIs(t, err, ErrViolation, "%v", tc.leaves)
		} else {
			assert.NoError(t, err, "%v", tc.leaves)
			assert.Equal(t, tc.recovered, recovered, "%v", tc.leaves)
		}
	}
}
