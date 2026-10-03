package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
)

func TestGetE2EDevicesHandler(t *testing.T) {
	sn := state.NewIdentScreenName("100001")
	user := &state.User{IdentScreenName: sn}
	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	key := func(b byte) []byte { return []byte(strings.Repeat(string(rune(b)), 32)) }

	tt := []struct {
		name       string
		setup      func(users *mockUserManager, e2e *mockE2EDeviceManager)
		statusCode int
		want       string
	}{
		{
			name: "user not found",
			setup: func(users *mockUserManager, _ *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(nil, nil)
			},
			statusCode: http.StatusNotFound,
			want:       `{"message":"user not found"}`,
		},
		{
			name: "no key published",
			setup: func(users *mockUserManager, e2e *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(user, nil)
				e2e.EXPECT().E2EAccount(mock.Anything, sn).Return(nil, nil)
				e2e.EXPECT().E2EDevices(mock.Anything, sn).Return(nil, nil)
			},
			statusCode: http.StatusOK,
			want:       `{"screen_name":"100001","account_key":null,"account_updated_at":null,"devices":[]}`,
		},
		{
			name: "devices, one revoked",
			setup: func(users *mockUserManager, e2e *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(user, nil)
				e2e.EXPECT().E2EAccount(mock.Anything, sn).Return(&state.E2EAccount{Key: key('A'), CreatedAt: t0, UpdatedAt: t0}, nil)
				e2e.EXPECT().E2EDevices(mock.Anything, sn).Return([]state.E2EDevice{
					{DeviceID: 1, Curve25519Key: key('B'), Ed25519Key: key('C'), CreatedAt: t0, LastSeenAt: t0},
					{DeviceID: 2, Curve25519Key: key('D'), Ed25519Key: key('E'), CreatedAt: t0, LastSeenAt: t0, RevokedAt: t0},
				}, nil)
			},
			statusCode: http.StatusOK,
			want: `{"screen_name":"100001","account_key":"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE","account_updated_at":"2026-09-30T12:00:00Z","devices":[` +
				`{"device_id":1,"curve25519_key":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","ed25519_key":"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M","created_at":"2026-09-30T12:00:00Z","last_seen_at":"2026-09-30T12:00:00Z","revoked_at":null},` +
				`{"device_id":2,"curve25519_key":"REREREREREREREREREREREREREREREREREREREREREQ","ed25519_key":"RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUU","created_at":"2026-09-30T12:00:00Z","last_seen_at":"2026-09-30T12:00:00Z","revoked_at":"2026-09-30T12:00:00Z"}]}`,
		},
		{
			name: "store error",
			setup: func(users *mockUserManager, e2e *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(user, nil)
				e2e.EXPECT().E2EAccount(mock.Anything, sn).Return(nil, io.EOF)
			},
			statusCode: http.StatusInternalServerError,
			want:       `{"message":"internal server error"}`,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			users := newMockUserManager(t)
			e2e := newMockE2EDeviceManager(t)
			tc.setup(users, e2e)

			req := httptest.NewRequest(http.MethodGet, "/user/100001/e2e/devices", nil)
			req.SetPathValue("screenname", "100001")
			rec := httptest.NewRecorder()
			getE2EDevicesHandler(rec, req, users, e2e, slog.Default())

			assert.Equal(t, tc.statusCode, rec.Code)
			assert.JSONEq(t, tc.want, rec.Body.String())
		})
	}
}

func TestDeleteE2EDeviceHandler(t *testing.T) {
	sn := state.NewIdentScreenName("100001")
	user := &state.User{IdentScreenName: sn}

	tt := []struct {
		name       string
		deviceID   string
		setup      func(users *mockUserManager, e2e *mockE2EDeviceManager)
		statusCode int
		want       string
	}{
		{
			name:       "invalid device id",
			deviceID:   "0",
			setup:      func(*mockUserManager, *mockE2EDeviceManager) {},
			statusCode: http.StatusBadRequest,
			want:       `{"message":"invalid device id"}`,
		},
		{
			name:     "user not found",
			deviceID: "7",
			setup: func(users *mockUserManager, _ *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(nil, nil)
			},
			statusCode: http.StatusNotFound,
			want:       `{"message":"user not found"}`,
		},
		{
			name:     "device not found",
			deviceID: "7",
			setup: func(users *mockUserManager, e2e *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(user, nil)
				e2e.EXPECT().E2ERevokeDevice(mock.Anything, sn, uint32(7), state.E2ERecovery("revoked by the operator (management API)"), mock.Anything).Return(state.ErrE2EDeviceNotFound)
			},
			statusCode: http.StatusNotFound,
			want:       `{"message":"device not found"}`,
		},
		{
			name:     "store error",
			deviceID: "7",
			setup: func(users *mockUserManager, e2e *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(user, nil)
				e2e.EXPECT().E2ERevokeDevice(mock.Anything, sn, uint32(7), state.E2ERecovery("revoked by the operator (management API)"), mock.Anything).Return(io.EOF)
			},
			statusCode: http.StatusInternalServerError,
			want:       `{"message":"internal server error"}`,
		},
		{
			name:     "revoked",
			deviceID: "7",
			setup: func(users *mockUserManager, e2e *mockE2EDeviceManager) {
				users.EXPECT().User(mock.Anything, sn).Return(user, nil)
				e2e.EXPECT().E2ERevokeDevice(mock.Anything, sn, uint32(7), state.E2ERecovery("revoked by the operator (management API)"), mock.Anything).Return(nil)
			},
			statusCode: http.StatusNoContent,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			users := newMockUserManager(t)
			e2e := newMockE2EDeviceManager(t)
			tc.setup(users, e2e)

			req := httptest.NewRequest(http.MethodDelete, "/user/100001/e2e/devices/"+tc.deviceID, nil)
			req.SetPathValue("screenname", "100001")
			req.SetPathValue("device_id", tc.deviceID)
			rec := httptest.NewRecorder()
			deleteE2EDeviceHandler(rec, req, users, e2e, slog.Default())

			assert.Equal(t, tc.statusCode, rec.Code)
			if tc.want != "" {
				assert.JSONEq(t, tc.want, rec.Body.String())
			}
		})
	}
}
