package icq_legacy

import (
	"encoding/binary"
	"log/slog"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

// presenceFields are the direct-connection and status fields a legacy
// client reads from a USER_ONLINE or USER_STATUS packet.
type presenceFields struct {
	IP         uint32
	Port       uint32
	InternalIP uint32
	DCType     uint8
	DCVersion  uint32
	Status     uint32
}

// parseOnlinePacket reads a USER_ONLINE packet as the given version sends it.
func parseOnlinePacket(t *testing.T, version uint16, p []byte) presenceFields {
	t.Helper()
	switch version {
	case ICQLegacyVersionV2:
		// header(6) + UIN(4) + IP(4) + PORT(2) + REAL_IP(4) + DCVER(2) + X1(1) + STATUS(2)
		assert.Equal(t, ICQLegacySrvUserOnline, binary.LittleEndian.Uint16(p[2:4]))
		return presenceFields{
			IP:         binary.LittleEndian.Uint32(p[10:14]),
			Port:       uint32(binary.LittleEndian.Uint16(p[14:16])),
			InternalIP: binary.LittleEndian.Uint32(p[16:20]),
			Status:     uint32(binary.LittleEndian.Uint16(p[23:25])),
		}
	case ICQLegacyVersionV3, ICQLegacyVersionV4:
		// header(16) + UIN(4) + IP(4) + PORT(4) + INT_IP(4) + DC_TYPE(1) + STATUS(4) + DCVER(2)
		assert.Equal(t, ICQLegacySrvUserOnline, binary.LittleEndian.Uint16(p[2:4]))
		return presenceFields{
			IP:         binary.LittleEndian.Uint32(p[20:24]),
			Port:       binary.LittleEndian.Uint32(p[24:28]),
			InternalIP: binary.LittleEndian.Uint32(p[28:32]),
			DCType:     p[32],
			Status:     binary.LittleEndian.Uint32(p[33:37]),
			DCVersion:  uint32(binary.LittleEndian.Uint16(p[37:39])),
		}
	default:
		// V5 data: UIN(4) + IP(4) + PORT(4) + INT_IP(4) + DC_TYPE(1) + STATUS(4) + DCVER(4)
		assert.Equal(t, ICQLegacySrvUserOnline, v5ServerCommand(p))
		d := v5ServerPacketData(p)
		return presenceFields{
			IP:         binary.LittleEndian.Uint32(d[4:8]),
			Port:       binary.LittleEndian.Uint32(d[8:12]),
			InternalIP: binary.LittleEndian.Uint32(d[12:16]),
			DCType:     d[16],
			Status:     binary.LittleEndian.Uint32(d[17:21]),
			DCVersion:  binary.LittleEndian.Uint32(d[21:25]),
		}
	}
}

// parseStatusPacket reads the status from a USER_STATUS packet.
func parseStatusPacket(t *testing.T, version uint16, p []byte) uint32 {
	t.Helper()
	switch version {
	case ICQLegacyVersionV2:
		assert.Equal(t, ICQLegacySrvUserStatus, binary.LittleEndian.Uint16(p[2:4]))
		return binary.LittleEndian.Uint32(p[10:14])
	case ICQLegacyVersionV3, ICQLegacyVersionV4:
		assert.Equal(t, ICQLegacySrvUserStatus, binary.LittleEndian.Uint16(p[2:4]))
		return binary.LittleEndian.Uint32(p[20:24])
	default:
		assert.Equal(t, ICQLegacySrvUserStatus, v5ServerCommand(p))
		return binary.LittleEndian.Uint32(v5ServerPacketData(p)[4:8])
	}
}

// newTestBridge wires a LegacyMessageBridge to real version handlers that
// share sessions and the given sender.
func newTestBridge(t *testing.T, sessions *LegacySessionManager, sender PacketSender) *LegacyMessageBridge {
	t.Helper()
	logger := slog.Default()
	svc := newMockLegacyService(t)
	v1 := NewV1Handler(sessions, svc, sender, logger)
	v2 := NewV2Handler(sessions, svc, sender, NewV2PacketBuilder(), logger)
	v3 := NewV3Handler(sessions, svc, sender, NewV3PacketBuilder(sessions, nil), logger)
	v4 := NewV4Handler(sessions, svc, sender, NewV4PacketBuilder(sessions, nil), logger)
	v5 := NewV5Handler(sessions, svc, sender, NewV5PacketBuilder(sessions, nil), logger)
	cfg := config.ICQLegacyConfig{SupportedVersions: []int{2, 3, 4, 5}}
	dispatcher := NewProtocolDispatcher(v1, v2, v3, v4, v5, cfg, logger)
	return NewLegacyMessageBridge(sessions, dispatcher, nil, logger)
}

func buddyArrivedMsg(uin uint32, oscarStatus uint32) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
		Body: wire.SNAC_0x03_0x0B_BuddyArrived{
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: strconv.FormatUint(uint64(uin), 10),
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{wire.NewTLVBE(wire.OServiceUserInfoStatus, oscarStatus)},
				},
			},
		},
	}
}

// TestLegacyMessageBridge_handleBuddyArrived_directConnection checks that a
// legacy client is told a contact signed on over OSCAR takes no direct
// connections (zero IP, port, DC type and version, DC-disabled status flag,
// no DC-auth flag), while a contact signed on over the legacy protocol keeps
// its real values, in both the USER_ONLINE and USER_STATUS packets of every
// protocol version.
func TestLegacyMessageBridge_handleBuddyArrived_directConnection(t *testing.T) {
	const (
		recipientUIN = uint32(100001)
		contactUIN   = uint32(100002)
		tcpPort      = uint32(5190)
		internalIP   = uint32(0x0A000002)
		dcType       = uint8(0x04) // DC_NORMAL
		// Away with "direct connection needs authorization", as ICQ 7.2 sends.
		oscarStatus = wire.OServiceUserStatusAway | wire.OServiceUserStatusDirectRequireAuth
	)
	oscarSide := ICQLegacyStatusAway | ICQLegacyStatusFlagDCDisabled
	legacySide := ICQLegacyStatusAway | ICQLegacyStatusFlagDCAuth

	legacyContact := sessionWithDirectConn(contactUIN, tcpPort, internalIP, dcType)
	legacyExtIP := legacyContact.GetExternalIP()

	tests := []struct {
		name          string
		version       uint16
		legacyContact bool
		wantOnline    presenceFields
		wantStatus    uint32
	}{
		{
			name:       "V2 recipient, OSCAR contact",
			version:    ICQLegacyVersionV2,
			wantOnline: presenceFields{Status: ICQLegacyStatusAway},
			wantStatus: oscarSide,
		},
		{
			name:       "V3 recipient, OSCAR contact",
			version:    ICQLegacyVersionV3,
			wantOnline: presenceFields{Status: oscarSide},
			wantStatus: oscarSide,
		},
		{
			name:          "V3 recipient, legacy contact",
			version:       ICQLegacyVersionV3,
			legacyContact: true,
			wantOnline:    presenceFields{Status: legacySide},
			wantStatus:    legacySide,
		},
		{
			name:       "V4 recipient, OSCAR contact",
			version:    ICQLegacyVersionV4,
			wantOnline: presenceFields{Status: oscarSide},
			wantStatus: oscarSide,
		},
		{
			name:          "V4 recipient, legacy contact",
			version:       ICQLegacyVersionV4,
			legacyContact: true,
			wantOnline:    presenceFields{Status: legacySide},
			wantStatus:    legacySide,
		},
		{
			name:       "V5 recipient, OSCAR contact",
			version:    ICQLegacyVersionV5,
			wantOnline: presenceFields{DCType: ICQLegacyDCTypeIndirect, Status: oscarSide},
			wantStatus: oscarSide,
		},
		{
			name:          "V5 recipient, legacy contact",
			version:       ICQLegacyVersionV5,
			legacyContact: true,
			wantOnline: presenceFields{
				IP:         legacyExtIP,
				Port:       tcpPort,
				InternalIP: internalIP,
				DCType:     dcType,
				DCVersion:  5,
				Status:     legacySide,
			},
			wantStatus: legacySide,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := newTestV5SessionManager()
			if tt.legacyContact {
				registerSession(sessions, legacyContact)
			}
			recipient := sessionWithInstance(recipientUIN)
			recipient.Version = tt.version
			recipient.SetContactList([]uint32{contactUIN})

			var sent [][]byte
			sender := newMockPacketSender(t)
			sender.EXPECT().SendToSession(recipient, mock.AnythingOfType("[]uint8")).
				Run(func(_ *LegacySession, p []byte) { sent = append(sent, p) }).
				Return(nil).Times(2)

			bridge := newTestBridge(t, sessions, sender)
			// The first arrival is USER_ONLINE, the next one USER_STATUS.
			bridge.handleBuddyArrived(recipient, buddyArrivedMsg(contactUIN, oscarStatus))
			bridge.handleBuddyArrived(recipient, buddyArrivedMsg(contactUIN, oscarStatus))

			if !assert.Len(t, sent, 2) {
				return
			}
			assert.Equal(t, tt.wantOnline, parseOnlinePacket(t, tt.version, sent[0]))
			assert.Equal(t, tt.wantStatus, parseStatusPacket(t, tt.version, sent[1]))
		})
	}
}

func TestStatusWithoutDirectConnection(t *testing.T) {
	tests := []struct {
		name   string
		status uint32
		want   uint32
	}{
		{
			name:   "online",
			status: ICQLegacyStatusOnline,
			want:   ICQLegacyStatusFlagDCDisabled,
		},
		{
			name:   "DC auth and contacts-only flags are dropped, others kept",
			status: ICQLegacyStatusOccupied | ICQLegacyStatusFlagWebAware | ICQLegacyStatusFlagDCAuth | ICQLegacyStatusFlagDCCont,
			want:   ICQLegacyStatusOccupied | ICQLegacyStatusFlagWebAware | ICQLegacyStatusFlagDCDisabled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, statusWithoutDirectConnection(tt.status))
		})
	}
}
