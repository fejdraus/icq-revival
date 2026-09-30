package e2e

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
)

// The signed messages are a contract with the clients
// (docs/e2e/KEY-DIRECTORY-API.md); these vectors pin their bytes.
func TestSignedMessages(t *testing.T) {
	sn := state.NewIdentScreenName("123456")
	k1 := bytes.Repeat([]byte{0x11}, 32)
	k2 := bytes.Repeat([]byte{0x22}, 32)
	hex32 := func(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

	// "OSCAR-E2E-v1", then for each field a 16-bit big-endian length and
	// the bytes. "123456" is 0006 313233343536.
	const prefix = "4f534341522d4532452d7631"
	const snField = "0006" + "313233343536"

	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{
			name: "account",
			got:  AccountMessage(sn, k1),
			want: prefix + "0007" + hex.EncodeToString([]byte("account")) + snField + "0020" + hex32(0x11),
		},
		{
			name: "rotate",
			got:  RotateMessage(sn, k1, k2),
			want: prefix + "0006" + hex.EncodeToString([]byte("rotate")) + snField + "0020" + hex32(0x11) + "0020" + hex32(0x22),
		},
		{
			name: "device",
			got:  DeviceMessage(sn, 0x01020304, k1, k2),
			want: prefix + "0006" + hex.EncodeToString([]byte("device")) + snField + "0004" + "01020304" + "0020" + hex32(0x11) + "0020" + hex32(0x22),
		},
		{
			name: "one-time key",
			got:  OneTimeKeyMessage(sn, 7, "AAAAAQ", k1),
			want: prefix + "000c" + hex.EncodeToString([]byte("one-time-key")) + snField + "0004" + "00000007" + "0006" + hex.EncodeToString([]byte("AAAAAQ")) + "0020" + hex32(0x11),
		},
		{
			name: "fallback key",
			got:  FallbackKeyMessage(sn, 7, "AAAAAQ", k1),
			want: prefix + "000c" + hex.EncodeToString([]byte("fallback-key")) + snField + "0004" + "00000007" + "0006" + hex.EncodeToString([]byte("AAAAAQ")) + "0020" + hex32(0x11),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hex.EncodeToString(tc.got))
		})
	}
}
