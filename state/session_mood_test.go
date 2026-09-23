package state

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/wire"
)

// The ICQ 6 mood arrives and leaves as an item of the 0x1D tag next to the
// status text. The test checks that it survives the store-and-broadcast round
// trip and that the layout matches what the client parses (IcqOscarJ,
// unpackSessionDataItem): type, flags, length, data.
func TestSessionStatusMood(t *testing.T) {
	mood := wire.BARTID{
		Type:     wire.BARTTypesMood,
		BARTInfo: wire.BARTInfo{Hash: []byte("0icqmood65")},
	}

	sess := NewSession()

	t.Run("no mood, no tag", func(t *testing.T) {
		_, ok := sess.StatusMood()
		assert.False(t, ok)
	})

	sess.SetStatusMood(mood)

	t.Run("what was stored comes back", func(t *testing.T) {
		got, ok := sess.StatusMood()
		assert.True(t, ok)
		assert.Equal(t, wire.BARTTypesMood, got.Type)
		assert.Equal(t, "0icqmood65", string(got.Hash))
	})

	t.Run("reaches the buddy info", func(t *testing.T) {
		info := sess.TLVUserInfo()
		blob, ok := info.Bytes(wire.OServiceUserInfoBARTInfo)
		assert.True(t, ok, "the 0x1D tag must be present")

		// Parse it the way the client does: type, flags, length, data.
		buf := bytes.NewBuffer(blob)
		found := ""
		for buf.Len() >= 4 {
			var itemType uint16
			var flags, size uint8
			assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemType))
			assert.NoError(t, binary.Read(buf, binary.BigEndian, &flags))
			assert.NoError(t, binary.Read(buf, binary.BigEndian, &size))
			if int(size) > buf.Len() {
				break
			}
			data := buf.Next(int(size))
			if itemType == wire.BARTTypesMood {
				found = string(data)
			}
		}
		assert.Equal(t, "0icqmood65", found)
	})

	t.Run("an empty mood is not broadcast", func(t *testing.T) {
		sess.SetStatusMood(wire.BARTID{Type: wire.BARTTypesMood})
		_, ok := sess.StatusMood()
		assert.False(t, ok, "an empty string would wipe what the client already shows")
	})
}
