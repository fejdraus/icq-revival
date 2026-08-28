package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// blankIconGIF stands in for the blank placeholder the real BART service returns
// for the clear-icon hash; distinct from iconGIF so tests can tell them apart.
var blankIconGIF = []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xff}

// newExpressionsHandler builds a handler whose target user has the given icon,
// or no icon when id is nil. Its BART mock mirrors the real service: the
// clear-icon hash resolves to the blank placeholder, any other hash to iconGIF.
func newExpressionsHandler(id *wire.BARTID) *ExpressionsHandler {
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).Return(id, nil).Maybe()

	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything,
		mock.MatchedBy(func(q wire.SNAC_0x10_0x04_BARTDownloadQuery) bool { return q.HasClearIconHash() })).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: blankIconGIF}}, nil).Maybe()
	bartService.On("RetrieveItem", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: iconGIF}}, nil).Maybe()

	return NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, nil, nil, slog.Default())
}

func TestExpressionsHandler_Get_ServesIconBytes(t *testing.T) {
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, iconGIF, w.Body.Bytes())
	assert.Equal(t, "image/gif", w.Header().Get("Content-Type"))
	// The URL pins the icon hash, so it always resolves to the same image.
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
}

func TestExpressionsHandler_Get_IconWithoutHashIsNotCached(t *testing.T) {
	// Without a hash the URL keeps resolving to whatever the current icon is, so
	// caching it would pin a stale image.
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

func TestExpressionsHandler_Get_MissingIconServesPlaceholder(t *testing.T) {
	// A user with no icon still serves the blank placeholder for the hash-less
	// URL, so the client's <img> renders something and a cleared icon stops
	// showing the previous one rather than 404ing.
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, blankIconGIF, w.Body.Bytes())
	assert.Equal(t, "no-cache", w.Header().Get("Cache-Control"))
}

func TestExpressionsHandler_Get_BartIdServesRequestedHash(t *testing.T) {
	// Even though the user's *current* icon is hash B, a URL pinned to hash A must
	// serve A's bytes and cache immutably — otherwise a cached URL could later
	// resolve to a different image.
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).
		Return(bartID([]byte{0xbb}), nil).Maybe()

	bytesA := []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xa1}
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything,
		mock.MatchedBy(func(q wire.SNAC_0x10_0x04_BARTDownloadQuery) bool {
			return bytes.Equal(q.Hash, []byte{0xaa})
		})).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{Data: bytesA}}, nil).Once()

	h := NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, nil, nil, slog.Default())

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon&bartId=aa", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, bytesA, w.Body.Bytes())
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
	bartService.AssertExpectations(t)
}

func TestExpressionsHandler_Get_UnknownBartIdNotFound(t *testing.T) {
	iconRetriever := &MockBuddyIconRetriever{}
	iconRetriever.On("BuddyIconMetadata", mock.Anything, mock.Anything).
		Return(bartID([]byte{0xbb}), nil).Maybe()

	// An empty reply means the hash is not stored.
	bartService := &MockBARTService{}
	bartService.On("RetrieveItem", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x10_0x05_BARTDownloadReply{}}, nil).Once()

	h := NewExpressionsHandler(BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   bartService,
		Logger:        slog.Default(),
	}, nil, nil, slog.Default())

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&type=buddyIcon&bartId=abcdef", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestExpressionsHandler_Get_ListsBigBuddyIcon(t *testing.T) {
	// This is the shape the client scans for its large icon rendering.
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly", nil)
	r.Host = "api.example.com"
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var got struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				Expressions []struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"expressions"`
			} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	assert.Equal(t, 200, got.Response.StatusCode)
	assert.Len(t, got.Response.Data.Expressions, 1)
	assert.Equal(t, "bigBuddyIcon", got.Response.Data.Expressions[0].Type)
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead",
		got.Response.Data.Expressions[0].URL)
}

func TestExpressionsHandler_Get_ListsNothingWithoutIcon(t *testing.T) {
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"expressions":[]`)
}

func TestExpressionsHandler_Get_Redirect(t *testing.T) {
	h := newExpressionsHandler(bartID([]byte{0xde, 0xad}))

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&f=redirect", nil)
	r.Host = "api.example.com"
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t,
		"http://api.example.com/expressions/get?t=mikekelly&type=buddyIcon&bartId=dead",
		w.Header().Get("Location"))
}

func TestExpressionsHandler_Get_RedirectWithoutIcon(t *testing.T) {
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get?t=mikekelly&f=redirect", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestExpressionsHandler_Get_MissingTarget(t *testing.T) {
	h := newExpressionsHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/expressions/get", nil)
	w := httptest.NewRecorder()
	h.Get(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// MockBARTUploader is a mock implementation of BARTUploader.
type MockBARTUploader struct {
	mock.Mock
}

func (m *MockBARTUploader) UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x02_BARTUploadQuery) (wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

func newUploadSession() *state.WebAPISession {
	return &state.WebAPISession{
		AimSID:       "sid",
		ScreenName:   state.DisplayScreenName("testuser"),
		OSCARSession: state.NewSession().AddInstance(),
	}
}

// The Android client posts the raw JPEG with a Content-Type of
// application/x-www-form-urlencoded. The handler must read the body as bytes and
// must not let anything parse it as a form.
func TestExpressionsHandler_Upload_StoresAndPublishesIcon(t *testing.T) {
	image := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 'J', 'F', 'I', 'F'}
	hash := []byte{0xde, 0xad, 0xbe, 0xef}

	uploader := &MockBARTUploader{}
	uploader.On("UpsertItem", mock.Anything, mock.Anything,
		wire.SNACFrame{FoodGroup: wire.BART, SubGroup: wire.BARTUploadQuery},
		wire.SNAC_0x10_0x02_BARTUploadQuery{Type: wire.BARTTypesBuddyIcon, Data: image},
	).Return(wire.SNACMessage{
		Body: wire.SNAC_0x10_0x03_BARTUploadReply{
			Code: wire.BARTReplyCodesSuccess,
			ID: wire.BARTID{
				Type:     wire.BARTTypesBuddyIcon,
				BARTInfo: wire.BARTInfo{Flags: wire.BARTFlagsCustom, Hash: hash},
			},
		},
	}, nil).Once()

	fs := &MockFeedbagService{}
	fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{
			Items: []wire.FeedbagItem{
				// The root group, which lives at GroupID 0 / ItemID 0.
				{ClassID: wire.FeedbagClassIdGroup},
			},
		}}, nil).Once()

	var (
		upserted    []wire.FeedbagItem
		upsertFrame wire.SNACFrame
	)
	fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			upsertFrame = args.Get(2).(wire.SNACFrame)
			upserted = args.Get(3).([]wire.FeedbagItem)
		}).Return((*wire.SNACMessage)(nil), nil).Once()

	h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, uploader, fs, slog.Default())

	req := httptest.NewRequest(http.MethodPost,
		"/expressions/upload?f=json&aimsid=sid&type=buddyIcon", bytes.NewReader(image))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	h.Upload(rr, req, newUploadSession())

	assert.Equal(t, http.StatusOK, rr.Code)

	var got struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"response"`
	}
	assert.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.Equal(t, 200, got.Response.StatusCode)
	// type as 4 hex digits, then the content hash.
	assert.Equal(t, "0001deadbeef", got.Response.Data.ID)

	// The icon must be published to the feedbag, or expressions/get never sees it.
	assert.Len(t, upserted, 1)
	assert.Equal(t, wire.FeedbagClassIdBart, upserted[0].ClassID)
	assert.Equal(t, "1", upserted[0].Name)
	// A first icon must not land on the root group's (0, 0) row.
	assert.NotZero(t, upserted[0].ItemID)
	assert.Equal(t, uint16(wire.FeedbagInsertItem), upsertFrame.SubGroup)
	b, ok := upserted[0].Bytes(wire.FeedbagAttributesBartInfo)
	assert.True(t, ok)
	info := wire.BARTInfo{}
	assert.NoError(t, wire.UnmarshalBE(&info, bytes.NewBuffer(b)))
	assert.Equal(t, hash, info.Hash)

	uploader.AssertExpectations(t)
	fs.AssertExpectations(t)
}

// An existing icon is replaced in place rather than added alongside.
func TestExpressionsHandler_Upload_ReusesExistingFeedbagItem(t *testing.T) {
	uploader := &MockBARTUploader{}
	uploader.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{
			Body: wire.SNAC_0x10_0x03_BARTUploadReply{
				Code: wire.BARTReplyCodesSuccess,
				ID:   wire.BARTID{Type: wire.BARTTypesBuddyIcon, BARTInfo: wire.BARTInfo{Hash: []byte{0x01}}},
			},
		}, nil).Once()

	fs := &MockFeedbagService{}
	fs.On("Query", mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{Body: wire.SNAC_0x13_0x06_FeedbagReply{
			Items: []wire.FeedbagItem{
				{GroupID: 7, ItemID: 9, ClassID: wire.FeedbagClassIdBart, Name: "1"},
			},
		}}, nil).Once()

	var (
		upserted    []wire.FeedbagItem
		upsertFrame wire.SNACFrame
	)
	fs.On("UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			upsertFrame = args.Get(2).(wire.SNACFrame)
			upserted = args.Get(3).([]wire.FeedbagItem)
		}).
		Return((*wire.SNACMessage)(nil), nil).Once()

	h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, uploader, fs, slog.Default())
	req := httptest.NewRequest(http.MethodPost,
		"/expressions/upload?type=buddyIcon", bytes.NewReader([]byte{0x01, 0x02}))
	rr := httptest.NewRecorder()

	h.Upload(rr, req, newUploadSession())

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Len(t, upserted, 1)
	assert.Equal(t, uint16(7), upserted[0].GroupID)
	assert.Equal(t, uint16(9), upserted[0].ItemID)
	// Other instances are relayed this frame verbatim, so replacing an icon has
	// to go out as an update of an item they already hold, not an insert.
	assert.Equal(t, uint16(wire.FeedbagUpdateItem), upsertFrame.SubGroup)
}

func TestExpressionsHandler_Upload_RejectsBadRequests(t *testing.T) {
	cases := []struct {
		name string
		url  string
		body []byte
	}{
		{"missing type", "/expressions/upload?f=json", []byte{0x01}},
		{"unsupported type", "/expressions/upload?type=wallpaper", []byte{0x01}},
		{"empty body", "/expressions/upload?type=buddyIcon", nil},
		{"oversized body", "/expressions/upload?type=buddyIcon", make([]byte, bartUploadMaxBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uploader := &MockBARTUploader{}
			fs := &MockFeedbagService{}
			h := NewExpressionsHandler(BuddyIconSource{Logger: slog.Default()}, uploader, fs, slog.Default())

			req := httptest.NewRequest(http.MethodPost, tc.url, bytes.NewReader(tc.body))
			rr := httptest.NewRecorder()
			h.Upload(rr, req, newUploadSession())

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			// Nothing may be stored or published when the request is rejected.
			uploader.AssertNotCalled(t, "UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			fs.AssertNotCalled(t, "UpsertItem", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
