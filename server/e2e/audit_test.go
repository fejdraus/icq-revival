package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
		Client: srv.Client(), Now: time.Now,
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
	publish := state.E2EKTLeaf("account", sn, at, []byte("publish"), pub)
	device := state.E2EKTLeaf("device", sn, at, []byte{0, 0, 0, 1}, curve, ed, devSig)
	revoke := state.E2EKTLeaf("revoke", sn, at, []byte{0, 0, 0, 1})
	reset := state.E2EKTLeaf("account", sn, at, []byte("reset"), pub2)
	cases := []struct {
		name   string
		leaves [][]byte
		why    string
	}{
		{"publish over a key", [][]byte{publish, publish}, "already has a key"},
		{"reset with an active device", [][]byte{publish, device, reset}, "still has active devices"},
		{"rotation without the old key", [][]byte{publish, state.E2EKTLeaf("account", sn, at, []byte("rotate"), pub2, ed25519.Sign(priv2, RotateMessage(sn, pub, pub2)))}, "not signed by the old key"},
		{"device id used again", [][]byte{publish, device, revoke, device}, "used before"},
		{"revoke twice", [][]byte{publish, device, revoke, revoke}, "no such active device"},
		{"unknown kind", [][]byte{publish, state.E2EKTLeaf("future", sn, at)}, "unknown kind"},
		{"device of no account", [][]byte{device}, "no account"},
		{"fine", [][]byte{publish, device, revoke, reset, state.E2EKTLeaf("account", sn, at, []byte("rotate"), pub, ed25519.Sign(priv2, RotateMessage(sn, pub2, pub))), state.E2EKTLeaf("delete", sn, at), publish}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var st AuditState
			var err error
			for i, l := range tc.leaves {
				if err = st.apply(int64(i), l); err != nil {
					break
				}
			}
			if tc.why == "" {
				assert.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrViolation)
				assert.Contains(t, err.Error(), tc.why)
			}
		})
	}
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
