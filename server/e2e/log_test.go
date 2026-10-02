package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/mk6i/open-oscar-server/state"
)

func (d *testDirectory) get(path string) (int, string) {
	d.t.Helper()
	rec := httptest.NewRecorder()
	d.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.String()
}

// checkpoint fetches the log's key and checkpoint, checks the signature and
// returns the size and root hash.
func (d *testDirectory) checkpoint() (int64, tlog.Hash) {
	d.t.Helper()
	code, vkey := d.get("/e2e/v1/log/key")
	require.Equal(d.t, http.StatusOK, code)
	verifier, err := note.NewVerifier(strings.TrimSpace(vkey))
	require.NoError(d.t, err)
	assert.Equal(d.t, DefaultKTOrigin, verifier.Name())

	code, msg := d.get("/e2e/v1/log/checkpoint")
	require.Equal(d.t, http.StatusOK, code)
	n, err := note.Open([]byte(msg), note.VerifierList(verifier))
	require.NoError(d.t, err)
	lines := strings.Split(n.Text, "\n")
	require.Len(d.t, lines, 4)
	assert.Equal(d.t, DefaultKTOrigin, lines[0])
	assert.Empty(d.t, lines[3])
	size, err := strconv.ParseInt(lines[1], 10, 64)
	require.NoError(d.t, err)
	raw, err := base64.StdEncoding.DecodeString(lines[2])
	require.NoError(d.t, err)
	var root tlog.Hash
	require.Len(d.t, raw, tlog.HashSize)
	copy(root[:], raw)
	return size, root
}

// entries fetches leaves from start.
func (d *testDirectory) entries(query string) (int, logEntriesJSON) {
	d.t.Helper()
	code, body := d.get("/e2e/v1/log/entries?" + query)
	var out logEntriesJSON
	if code == http.StatusOK {
		require.NoError(d.t, json.Unmarshal([]byte(body), &out))
	}
	return code, out
}

// treeOf builds the root hash of the leaves the way a client would.
func treeOf(t *testing.T, leaves []b64) tlog.Hash {
	t.Helper()
	var stored []tlog.Hash
	r := tlog.HashReaderFunc(func(idx []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(idx))
		for i, x := range idx {
			out[i] = stored[x]
		}
		return out, nil
	})
	for i, l := range leaves {
		hs, err := tlog.StoredHashes(int64(i), l, r)
		require.NoError(t, err)
		stored = append(stored, hs...)
	}
	root, err := tlog.TreeHash(int64(len(leaves)), r)
	require.NoError(t, err)
	return root
}

func TestHandler_Log(t *testing.T) {
	d := newTestDirectory(t)
	ctx := context.Background()

	size, _ := d.checkpoint()
	assert.Zero(t, size)

	d.signOn("100001")
	alice := state.NewIdentScreenName("100001")
	pub, _ := newKey(t)
	require.NoError(t, d.store.E2EPublishAccountKey(ctx, alice, pub, time.Unix(1_700_000_000, 0)))
	for i := uint32(1); i <= 3; i++ {
		dev := newTestDevice(t, i)
		_, err := d.store.E2EPutDevice(ctx, alice, pub, state.E2EDevice{
			DeviceID: i, Curve25519Key: dev.curve, Ed25519Key: dev.edPub, AccountSignature: make([]byte, 64),
		}, 10, time.Unix(1_700_000_000, 0))
		require.NoError(t, err)
	}

	size, root := d.checkpoint()
	assert.EqualValues(t, 4, size)

	code, all := d.entries("start=0")
	require.Equal(t, http.StatusOK, code)
	assert.EqualValues(t, 0, all.Start)
	require.Len(t, all.Entries, 4)
	assert.Equal(t, root, treeOf(t, all.Entries))

	code, part := d.entries("start=1&count=2")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, all.Entries[1:3], part.Entries)

	code, end := d.entries("start=9")
	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, end.Entries)
	assert.NotNil(t, end.Entries)

	for _, q := range []string{"", "start=-1", "start=x", "start=0&count=0", "start=0&count=x"} {
		code, _ := d.entries(q)
		assert.Equal(t, http.StatusBadRequest, code, q)
	}

	// The key stays the same across handlers over the same store.
	_, k1 := d.get("/e2e/v1/log/key")
	h2 := NewHandler(d.handler.cfg, d.store, d.baker, d.sessions, d.handler.logger)
	mux := http.NewServeMux()
	h2.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/e2e/v1/log/key", nil))
	assert.Equal(t, k1, rec.Body.String())
}
