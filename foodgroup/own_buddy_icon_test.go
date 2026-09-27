package foodgroup

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestSendOwnBuddyIcon(t *testing.T) {
	icon := wire.BARTID{
		Type:     wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: bytes.Repeat([]byte{0xAB}, 16)},
	}
	pending := icon
	pending.Flags |= wire.BARTFlagsUnknown

	tests := []struct {
		name     string
		instance *state.SessionInstance
		wantSent bool
	}{
		{name: "QIP learns its own icon", instance: newTestInstance("100001", sessOptQIP, sessOptBuddyIcon(icon)), wantSent: true},
		{name: "ICQ 6 manages its own icon", instance: newTestInstance("100001", sessOptICQ6, sessOptBuddyIcon(icon))},
		{name: "no icon, nothing to tell", instance: newTestInstance("100001", sessOptQIP)},
		{name: "an icon still waiting for its upload", instance: newTestInstance("100001", sessOptQIP, sessOptBuddyIcon(pending))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relayer := newMockMessageRelayer(t)
			if tt.wantSent {
				relayer.EXPECT().RelayToSelf(mock.Anything, tt.instance, wire.SNACMessage{
					Frame: wire.SNACFrame{
						FoodGroup: wire.OService,
						SubGroup:  wire.OServiceBartReply,
						RequestID: wire.ReqIDFromServer,
					},
					Body: wire.SNAC_0x01_0x21_OServiceBARTReply{BARTID: icon},
				})
			}
			sendOwnBuddyIcon(t.Context(), relayer, tt.instance)
		})
	}
}

func TestWithJFIF(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := range img.Pix {
		img.Pix[i] = 0x80
	}
	img.Set(1, 1, color.Black)
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, nil))
	plain := buf.Bytes()
	require.NotEqual(t, []byte("JFIF"), plain[6:10], "Go's encoder writes no JFIF segment")

	out := withJFIF(plain)
	assert.Equal(t, []byte{0xFF, 0xD8, 0xFF, 0xE0}, out[:4])
	assert.Equal(t, []byte("JFIF\x00"), out[6:11])
	assert.Equal(t, plain[2:], out[2+len(jfifAPP0):], "the rest of the picture is untouched")

	decoded, err := jpeg.Decode(bytes.NewReader(out))
	require.NoError(t, err)
	assert.Equal(t, img.Bounds(), decoded.Bounds())

	assert.Equal(t, out, withJFIF(out), "a picture with the segment is left as it is")
	assert.Equal(t, []byte("GIF89a"), withJFIF([]byte("GIF89a")), "not a JPEG, left alone")
}

// The normalised copy starts with a JFIF segment, so every client can tell it
// is a JPEG by its first bytes.
func TestNormaliseBuddyIcon_JFIF(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 200, 200))
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}))
	out, err := normaliseBuddyIcon(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, []byte("JFIF"), out[6:10])
	assert.LessOrEqual(t, len(out), maxBuddyIconBytes)
}
