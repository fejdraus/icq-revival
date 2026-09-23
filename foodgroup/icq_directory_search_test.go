package foodgroup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestDirectorySearchCriteria(t *testing.T) {
	tlvs := wire.TLVList{
		wire.NewTLVBE(wire.ICQDirTagUID, "100002"),
		wire.NewTLVBE(wire.ICQDirTagFirstName, "Ivan"),
		wire.NewTLVBE(wire.ICQDirTagNickname, ""),
	}

	c := directorySearchCriteria(tlvs)

	assert.NotNil(t, c.UIN)
	assert.Equal(t, uint32(100002), *c.UIN)

	assert.NotNil(t, c.FirstName)
	assert.Equal(t, "Ivan", *c.FirstName)

	assert.Nil(t, c.LastName, "what the client did not send is not a criterion")
	assert.Nil(t, c.NickName, "an empty value is not a criterion either, or the result set collapses")
}

// In a search hit the country sits differently than in a profile: four bytes
// straight in the home address TLV, with no record list around it. The test
// pins that difference down - it is what the client requires, not a typo.
func TestDirectorySearchHit(t *testing.T) {
	user := state.User{IdentScreenName: state.NewIdentScreenName("100001")}
	user.ICQInfo.Basic.Nickname = "Leto"
	user.ICQInfo.Basic.FirstName = "Paul"
	user.ICQInfo.Basic.CountryCode = 380
	user.ICQInfo.More.Gender = 2
	user.ICQInfo.Permissions.AuthRequired = true

	item, err := directorySearchHit(user)
	assert.NoError(t, err)

	tlvs := decodeDirectoryItem(t, item)

	uid, ok := tlvs.String(wire.ICQDirTagUID)
	assert.True(t, ok)
	assert.Equal(t, "100001", uid)

	nick, ok := tlvs.String(wire.ICQDirTagNickname)
	assert.True(t, ok)
	assert.Equal(t, "Leto", nick)

	gender, ok := tlvs.Uint8(wire.ICQDirTagGender)
	assert.True(t, ok)
	assert.Equal(t, wire.ICQDirGenderMale, gender)

	auth, ok := tlvs.Uint8(wire.ICQDirTagAuthOptional)
	assert.True(t, ok)
	assert.Equal(t, uint8(0), auth, "authorization is required, so the \"not required\" tag is zero")

	blob, ok := tlvs.Bytes(wire.ICQDirTagHomeAddress)
	assert.True(t, ok)

	chain := wire.TLVRestBlock{}
	assert.NoError(t, wire.UnmarshalBE(&chain, bytes.NewBuffer(blob)))
	country, ok := chain.Bytes(wire.ICQDirAddrCountry)
	assert.True(t, ok)
	assert.Len(t, country, 4, "the client reads the country of a search hit as four bytes")
	assert.Equal(t, uint32(380), binary.BigEndian.Uint32(country))
}

// dirRecords is the other side of appendDirRecords. The test checks that a
// record list survives the round trip, so that saving a profile receives
// exactly what the server is able to send.
func TestDirRecordsRoundTrip(t *testing.T) {
	user := state.User{}
	user.ICQInfo.Basic.Phone = "+380441234567"
	user.ICQInfo.Basic.CellPhone = "+380671234567"
	user.ICQInfo.Work.Phone = "+380441111111"

	tlvs := wire.TLVList{}
	assert.NoError(t, appendDirRecords(&tlvs, wire.ICQDirTagPhones, directoryPhones(user)))

	recs := dirRecords(tlvs, wire.ICQDirTagPhones)
	assert.Len(t, recs, 3)

	got := map[uint16]string{}
	for _, rec := range recs {
		kind, ok := rec.Uint16BE(wire.ICQDirPhoneType)
		assert.True(t, ok)
		number, ok := rec.String(wire.ICQDirPhoneNumber)
		assert.True(t, ok)
		got[kind] = number
	}
	assert.Equal(t, "+380441234567", got[wire.ICQDirPhoneTypeHome])
	assert.Equal(t, "+380671234567", got[wire.ICQDirPhoneTypeCellular])
	assert.Equal(t, "+380441111111", got[wire.ICQDirPhoneTypeWork])
}

func TestDirRecordsMalformed(t *testing.T) {
	tests := []struct {
		name  string
		given []byte
	}{
		{name: "empty", given: nil},
		{name: "count only", given: []byte{0x00, 0x02}},
		{name: "record longer than the remainder", given: []byte{0x00, 0x01, 0xFF, 0xFF, 0x01}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlvs := wire.TLVList{wire.NewTLVBE(wire.ICQDirTagPhones, tt.given)}
			// Malformed input must not break the parse, only yield fewer records.
			assert.NotPanics(t, func() { dirRecords(tlvs, wire.ICQDirTagPhones) })
		})
	}
}
