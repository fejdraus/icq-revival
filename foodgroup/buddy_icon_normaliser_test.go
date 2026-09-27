package foodgroup

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestBuddyIconConforms(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    bool
		wantErr bool
	}{
		{
			// what ICQ 6.5 uploaded for the user QIP 2012 showed no picture of
			name: "a 360x360 progressive JPEG under 7 KB",
			data: readTestdata(t, "progressive-360.jpg"),
		},
		{
			name: "a small progressive JPEG",
			data: readTestdata(t, "progressive-48.jpg"),
		},
		{
			name: "a small baseline JPEG",
			data: encodeTestJPEG(t, testPicture(48, 48, false), 90),
			want: true,
		},
		{
			name: "a 64x64 baseline JPEG",
			data: encodeTestJPEG(t, testPicture(64, 64, false), 90),
			want: true,
		},
		{
			name: "a baseline JPEG wider than 64 pixels",
			data: encodeTestJPEG(t, testPicture(65, 40, false), 90),
		},
		{
			name: "a small baseline JPEG over 7 KB",
			data: append(encodeTestJPEG(t, testPicture(48, 48, false), 90), make([]byte, maxBuddyIconBytes)...),
		},
		{
			name: "a small PNG",
			data: encodeTestPNG(t, testPicture(48, 48, true)),
		},
		{
			name: "a small GIF",
			data: encodeTestGIF(t, testPicture(48, 48, false)),
			want: true,
		},
		{
			name: "a small BMP",
			data: encodeTestBMP(testPicture(32, 32, false)),
			want: true,
		},
		{
			name: "a BMP taller than 64 pixels",
			data: encodeTestBMP(testPicture(32, 80, false)),
		},
		{
			name:    "not a picture",
			data:    []byte("not a picture at all"),
			wantErr: true,
		},
		{
			name:    "a broken JPEG",
			data:    []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buddyIconConforms(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormaliseBuddyIcon(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		// wantW and wantH are the copy's size
		wantW, wantH int
		// wantCorner is roughly the color of the copy's top left pixel
		wantCorner *color.RGBA
		wantErr    bool
	}{
		{
			name:  "a 360x360 progressive JPEG",
			data:  readTestdata(t, "progressive-360.jpg"),
			wantW: 64, wantH: 64,
		},
		{
			name:  "a small progressive JPEG is not enlarged",
			data:  readTestdata(t, "progressive-48.jpg"),
			wantW: 48, wantH: 48,
		},
		{
			name:  "a transparent PNG is laid on white",
			data:  encodeTestPNG(t, testPicture(200, 100, true)),
			wantW: 64, wantH: 32,
			wantCorner: &color.RGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF},
		},
		{
			name:  "a tall BMP keeps its aspect",
			data:  encodeTestBMP(testPicture(90, 300, false)),
			wantW: 19, wantH: 64,
		},
		{
			name:  "a big noisy picture still fits in 7 KB",
			data:  encodeTestPNG(t, noisePicture(64, 64)),
			wantW: 64, wantH: 64,
		},
		{
			name:    "not a picture",
			data:    []byte("not a picture at all"),
			wantErr: true,
		},
		{
			name:    "a picture too large to decode",
			data:    encodeTestBMPHeader(maxBuddyIconDecodeSide+1, 10),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normaliseBuddyIcon(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.LessOrEqual(t, len(got), maxBuddyIconBytes)
			assert.True(t, isBaselineJPEG(got), "the copy is a baseline JPEG")
			conforms, err := buddyIconConforms(got)
			assert.NoError(t, err)
			assert.True(t, conforms)

			img, err := jpeg.Decode(bytes.NewReader(got))
			require.NoError(t, err)
			assert.Equal(t, tt.wantW, img.Bounds().Dx())
			assert.Equal(t, tt.wantH, img.Bounds().Dy())
			if tt.wantCorner != nil {
				r, g, b, _ := img.At(0, 0).RGBA()
				assert.InDelta(t, tt.wantCorner.R, r>>8, 8)
				assert.InDelta(t, tt.wantCorner.G, g>>8, 8)
				assert.InDelta(t, tt.wantCorner.B, b>>8, 8)
			}
		})
	}
}

func TestFitWithin(t *testing.T) {
	tests := []struct {
		w, h, wantW, wantH int
	}{
		{w: 360, h: 360, wantW: 64, wantH: 64},
		{w: 200, h: 100, wantW: 64, wantH: 32},
		{w: 100, h: 200, wantW: 32, wantH: 64},
		{w: 1000, h: 1, wantW: 64, wantH: 1},
		{w: 64, h: 64, wantW: 64, wantH: 64},
		{w: 10, h: 20, wantW: 10, wantH: 20},
	}
	for _, tt := range tests {
		w, h := fitWithin(tt.w, tt.h, maxBuddyIconSide)
		assert.Equal(t, [2]int{tt.wantW, tt.wantH}, [2]int{w, h}, "%dx%d", tt.w, tt.h)
	}
}

func TestBuddyIconNormaliser_UserInfoFor(t *testing.T) {
	progressive := readTestdata(t, "progressive-360.jpg")
	baseline := encodeTestJPEG(t, testPicture(48, 48, false), 90)
	iconOf := func(data []byte) wire.BARTID {
		hash := md5.Sum(data)
		return wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash[:]}}
	}
	flash := wire.BARTID{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("pirate")}}
	flashStill := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("pirate still")}}

	tests := []struct {
		name string
		// ownerOpts set up the owner, an ICQ 6 user
		ownerOpts []func(*state.SessionInstance)
		// recipientOpts set up the buddy the owner's user info is sent to
		recipientOpts []func(*state.SessionInstance)
		// icon is the owner's own buddy icon, and data its picture
		icon wire.BARTID
		data []byte
		// wantRead is whether the icon is read from the BART store
		wantRead bool
		// wantCopy is whether a copy is made, stored, announced and then
		// sent in place of the icon
		wantCopy bool
		// wantFirst is the buddy icon sent first, before any copy is ready;
		// the icon itself when nil
		wantFirst *wire.BARTID
	}{
		{
			name:          "QIP gets a copy of a large progressive JPEG",
			recipientOpts: []func(*state.SessionInstance){sessOptQIP},
			icon:          iconOf(progressive),
			data:          progressive,
			wantRead:      true,
			wantCopy:      true,
		},
		{
			name:          "AIM gets a copy of a large progressive JPEG",
			recipientOpts: []func(*state.SessionInstance){sessOptAIM},
			icon:          iconOf(progressive),
			data:          progressive,
			wantRead:      true,
			wantCopy:      true,
		},
		{
			name:          "Miranda gets a copy of a large progressive JPEG",
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaICQ},
			icon:          iconOf(progressive),
			data:          progressive,
			wantRead:      true,
			wantCopy:      true,
		},
		{
			name:          "Miranda with the Flash plugin gets a copy of a large progressive JPEG",
			recipientOpts: []func(*state.SessionInstance){sessOptMirandaFlashAvatars},
			icon:          iconOf(progressive),
			data:          progressive,
			wantRead:      true,
			wantCopy:      true,
		},
		{
			name:          "ICQ 6 gets the original",
			recipientOpts: []func(*state.SessionInstance){sessOptICQ6},
			icon:          iconOf(progressive),
			data:          progressive,
		},
		{
			name:          "a small baseline JPEG is sent as it is",
			recipientOpts: []func(*state.SessionInstance){sessOptQIP},
			icon:          iconOf(baseline),
			data:          baseline,
			wantRead:      true,
		},
		{
			name:          "a picture that can't be decoded is sent as it is",
			recipientOpts: []func(*state.SessionInstance){sessOptQIP},
			icon:          iconOf([]byte("garbage")),
			data:          []byte("garbage"),
			wantRead:      true,
		},
		{
			name:          "the still of a Flash avatar takes the place of the icon, which is not normalised",
			ownerOpts:     []func(*state.SessionInstance){sessOptAvatarItem(flash)},
			recipientOpts: []func(*state.SessionInstance){sessOptQIP, sessOptFlashAvatarStill(flash, flashStill)},
			icon:          iconOf(progressive),
			data:          progressive,
			wantFirst:     &flashStill,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner := newTestInstance("owner", append([]func(*state.SessionInstance){sessOptICQ6, sessOptBuddyIcon(tt.icon)}, tt.ownerOpts...)...)
			recipient := newTestInstance("buddy", tt.recipientOpts...)

			bartItemManager := newMockBARTItemManager(t)
			if tt.wantRead {
				bartItemManager.EXPECT().BARTItem(mock.Anything, tt.icon.Hash).Return(tt.data, nil).Once()
			}
			broadcaster := newMockbuddyBroadcaster(t)
			var stored []byte
			if tt.wantCopy {
				bartItemManager.EXPECT().
					InsertBARTItem(mock.Anything, mock.Anything, mock.Anything, wire.BARTTypesBuddyIcon).
					Run(func(_ context.Context, hash []byte, blob []byte, _ uint16) {
						sum := md5.Sum(blob)
						assert.Equal(t, sum[:], hash)
						stored = blob
					}).
					Return(nil)
				broadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, owner.IdentScreenName(), mock.Anything).
					Return(nil)
			}
			sessionRetriever := newMockSessionRetriever(t)
			sessionRetriever.EXPECT().RetrieveSession(owner.IdentScreenName()).Return(owner.Session()).Maybe()

			icons := NewBuddyIconNormaliser(bartItemManager, nil, nil, sessionRetriever, slog.Default())
			icons.buddyBroadcaster = broadcaster
			recipient.Session().SetNormalisedBuddyIcons(icons)

			wantFirst := tt.icon
			if tt.wantFirst != nil {
				wantFirst = *tt.wantFirst
			}

			// the first user info goes out before the copy is ready
			first := recipient.UserInfoFor(owner.Session().TLVUserInfo())
			icons.jobs.Wait()
			firstIcon, _ := first.BuddyIconItem()
			assert.Equal(t, wantFirst, firstIcon)

			// the next ones, by the session and by the instance, with it
			for _, info := range []wire.TLVUserInfo{
				recipient.Session().UserInfoFor(owner.Session().TLVUserInfo()),
				recipient.UserInfoFor(owner.Session().TLVUserInfo()),
			} {
				got, _ := info.BuddyIconItem()
				if tt.wantCopy {
					require.NotNil(t, stored)
					sum := md5.Sum(stored)
					assert.Equal(t, wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: sum[:]}}, got)
				} else {
					assert.Equal(t, wantFirst, got)
				}
			}
			icons.jobs.Wait()

			// the owner's own client keeps its own icon
			selfIcon, _ := findBARTID(userInfoBARTIDs(t, sessionUserInfo(owner, false)), wire.BARTTypesBuddyIcon)
			assert.Equal(t, tt.icon, selfIcon)
		})
	}
}

func TestBuddyIconNormaliser_NothingToNormalise(t *testing.T) {
	owner := state.NewIdentScreenName("owner")
	// no expectations: nothing is read, stored or announced
	icons := NewBuddyIconNormaliser(newMockBARTItemManager(t), nil, nil, newMockSessionRetriever(t), slog.Default())

	for _, icon := range []wire.BARTID{
		{Type: wire.BARTTypesBuddyIcon},
		{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: wire.GetClearIconHash()}},
		{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom | wire.BARTFlagsUnknown, Hash: []byte("not uploaded yet")}},
		{Type: wire.BARTTypesFlashAvatar, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("not an icon")}},
	} {
		_, ok := icons.NormalisedBuddyIcon(owner, icon)
		assert.False(t, ok)
	}
	icons.jobs.Wait()
}

func TestBuddyIconNormaliser_RetriesAfterFailure(t *testing.T) {
	icon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("garbage")}}
	owner := state.NewIdentScreenName("owner")

	bartItemManager := newMockBARTItemManager(t)
	bartItemManager.EXPECT().BARTItem(mock.Anything, icon.Hash).Return([]byte("garbage"), nil).Times(2)
	icons := NewBuddyIconNormaliser(bartItemManager, nil, nil, newMockSessionRetriever(t), slog.Default())
	now := icons.nowFn()
	icons.nowFn = func() time.Time { return now }

	_, ok := icons.NormalisedBuddyIcon(owner, icon)
	icons.jobs.Wait()
	assert.False(t, ok)

	// not tried again right away
	_, ok = icons.NormalisedBuddyIcon(owner, icon)
	icons.jobs.Wait()
	assert.False(t, ok)

	// but once the wait is over
	now = now.Add(buddyIconNormaliseRetryAfter)
	_, ok = icons.NormalisedBuddyIcon(owner, icon)
	icons.jobs.Wait()
	assert.False(t, ok)
}

func TestBuddyIconNormaliser_ChecksOnce(t *testing.T) {
	data := encodeTestJPEG(t, testPicture(48, 48, false), 90)
	hash := md5.Sum(data)
	icon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash[:]}}

	bartItemManager := newMockBARTItemManager(t)
	bartItemManager.EXPECT().BARTItem(mock.Anything, icon.Hash).Return(data, nil).Once()
	icons := NewBuddyIconNormaliser(bartItemManager, nil, nil, newMockSessionRetriever(t), slog.Default())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok := icons.NormalisedBuddyIcon(state.NewIdentScreenName("owner"), icon)
			assert.False(t, ok)
		}()
	}
	wg.Wait()
	icons.jobs.Wait()

	// a conforming icon is known as one
	_, ok := icons.NormalisedBuddyIcon(state.NewIdentScreenName("owner"), icon)
	assert.False(t, ok)
	icons.jobs.Wait()
}

func TestBuddyIconNormaliser_Announce(t *testing.T) {
	icon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("big icon")}}
	otherIcon := wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: []byte("another icon")}}
	notUploaded := icon
	notUploaded.Flags |= wire.BARTFlagsUnknown

	tests := []struct {
		name string
		// owner is the owner's session; nil when offline
		owner        *state.SessionInstance
		wantAnnounce bool
	}{
		{
			name:         "the owner still has the icon: their buddies are told",
			owner:        newTestInstance("owner", sessOptBuddyIcon(icon)),
			wantAnnounce: true,
		},
		{
			name: "the owner has gone offline",
		},
		{
			name:  "the owner has set another icon",
			owner: newTestInstance("owner", sessOptBuddyIcon(otherIcon)),
		},
		{
			name:  "the owner has cleared the icon",
			owner: newTestInstance("owner"),
		},
		{
			name:  "the owner's icon waits for its upload again",
			owner: newTestInstance("owner", sessOptBuddyIcon(notUploaded)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner := state.NewIdentScreenName("owner")
			sessionRetriever := newMockSessionRetriever(t)
			var sess *state.Session
			if tt.owner != nil {
				sess = tt.owner.Session()
			}
			sessionRetriever.EXPECT().RetrieveSession(owner).Return(sess)
			broadcaster := newMockbuddyBroadcaster(t)
			if tt.wantAnnounce {
				broadcaster.EXPECT().BroadcastBuddyArrived(mock.Anything, owner, sess.TLVUserInfo()).Return(nil)
			}

			icons := NewBuddyIconNormaliser(newMockBARTItemManager(t), nil, nil, sessionRetriever, slog.Default())
			icons.buddyBroadcaster = broadcaster
			icons.announce(context.Background(), owner, icon.Hash)
		})
	}
}

// fakeNormalisedBuddyIcons is a state.NormalisedBuddyIconFinder with a copy
// ready for each buddy icon hash it holds.
type fakeNormalisedBuddyIcons map[string]wire.BARTID

func (f fakeNormalisedBuddyIcons) NormalisedBuddyIcon(_ state.IdentScreenName, icon wire.BARTID) (wire.BARTID, bool) {
	normalised, ok := f[string(icon.Hash)]
	return normalised, ok
}

// sessOptNormalisedBuddyIcon makes normalised the icon the session is sent
// in place of the buddy icon icon.
func sessOptNormalisedBuddyIcon(icon wire.BARTID, normalised wire.BARTID) func(instance *state.SessionInstance) {
	return func(instance *state.SessionInstance) {
		instance.Session().SetNormalisedBuddyIcons(fakeNormalisedBuddyIcons{string(icon.Hash): normalised})
	}
}

// readTestdata returns the contents of the file name in testdata.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

// testPicture draws a w x h picture: a red disc on blue, or on nothing when
// transparent.
func testPicture(w, h int, transparent bool) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dx, dy := x-w/2, y-h/2
			switch {
			case dx*dx*h*h+dy*dy*w*w < w*w*h*h/9:
				img.SetNRGBA(x, y, color.NRGBA{R: 0xE0, G: 0x20, B: 0x20, A: 0xFF})
			case !transparent:
				img.SetNRGBA(x, y, color.NRGBA{R: 0x20, G: 0x40, B: 0xC0, A: 0xFF})
			}
		}
	}
	return img
}

// noisePicture draws a w x h picture of noise, which compresses badly.
func noisePicture(w, h int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	seed := uint32(1)
	for i := range img.Pix {
		seed = seed*1664525 + 1013904223
		img.Pix[i] = uint8(seed >> 24)
		if i%4 == 3 {
			img.Pix[i] = 0xFF
		}
	}
	return img
}

func encodeTestJPEG(t *testing.T, img image.Image, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}))
	return buf.Bytes()
}

func encodeTestPNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, png.Encode(&buf, img))
	return buf.Bytes()
}

func encodeTestGIF(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, gif.Encode(&buf, img, nil))
	return buf.Bytes()
}

// encodeTestBMP encodes img as a bottom-up 24-bit BMP.
func encodeTestBMP(img image.Image) []byte {
	b := img.Bounds()
	data := encodeTestBMPHeader(b.Dx(), b.Dy())
	stride := (24*b.Dx() + 31) / 32 * 4
	pixels := make([]byte, stride*b.Dy())
	for row := 0; row < b.Dy(); row++ {
		y := b.Max.Y - 1 - row
		for x := 0; x < b.Dx(); x++ {
			r, g, bl, _ := img.At(b.Min.X+x, y).RGBA()
			p := pixels[row*stride+x*3:]
			p[0], p[1], p[2] = uint8(bl>>8), uint8(g>>8), uint8(r>>8)
		}
	}
	return append(data, pixels...)
}

// encodeTestBMPHeader encodes the headers of a bottom-up 24-bit w x h BMP.
func encodeTestBMPHeader(w, h int) []byte {
	le := binary.LittleEndian
	header := make([]byte, 54)
	copy(header, "BM")
	le.PutUint32(header[2:], uint32(54+(24*w+31)/32*4*h))
	le.PutUint32(header[10:], 54)
	le.PutUint32(header[14:], 40)
	le.PutUint32(header[18:], uint32(w))
	le.PutUint32(header[22:], uint32(h))
	le.PutUint16(header[26:], 1)
	le.PutUint16(header[28:], 24)
	return header
}
