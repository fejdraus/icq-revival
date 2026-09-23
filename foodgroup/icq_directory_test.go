package foodgroup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// decodeDirectoryItem parses a profile back the way a client does.
func decodeDirectoryItem(t *testing.T, item []byte) wire.TLVList {
	t.Helper()
	chain := wire.TLVRestBlock{}
	assert.NoError(t, wire.UnmarshalBE(&chain, bytes.NewBuffer(item)))
	return chain.TLVList
}

// decodeDirectoryRecords parses a nested record list.
func decodeDirectoryRecords(t *testing.T, blob []byte) []wire.TLVList {
	t.Helper()
	buf := bytes.NewBuffer(blob)

	var count uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &count))

	out := make([]wire.TLVList, 0, count)
	for i := 0; i < int(count); i++ {
		var size uint16
		assert.NoError(t, binary.Read(buf, binary.BigEndian, &size))
		chain := wire.TLVRestBlock{}
		assert.NoError(t, wire.UnmarshalBE(&chain, bytes.NewBuffer(buf.Next(int(size)))))
		out = append(out, chain.TLVList)
	}
	return out
}

func TestDirectoryProfile(t *testing.T) {
	user := state.User{
		ICQInfo: state.ICQInfo{
			Basic: state.ICQBasicInfo{
				FirstName:                 "Ivan",
				LastName:                  "Petrov",
				Nickname:                  "Fejd",
				EmailAddress:              "fejd@example.org",
				City:                      "Kyiv",
				State:                     "Kyiv Oblast",
				Address:                   "1 Khreshchatyk St",
				ZIPCode:                   "01001",
				CountryCode:               380,
				Phone:                     "+380441234567",
				CellPhone:                 "+380671234567",
				Fax:                       "+380441234568",
				GMTOffset:                 8,
				OriginallyFromCity:        "Lviv",
				OriginallyFromCountryCode: 380,
			},
			More: state.ICQMoreInfo{
				Gender:       2,
				HomePageAddr: "https://example.org",
				BirthYear:    1980,
				BirthMonth:   6,
				BirthDay:     15,
				Lang1:        49,
			},
			Work: state.ICQWorkInfo{
				Company:  "Open OSCAR",
				Position: "Support",
				City:     "Kyiv",
				Phone:    "+380441111111",
			},
			Notes:       state.ICQUserNotes{Notes: "живу на власному сервері — №1"}, // non-ASCII on purpose
			Interests:   state.ICQInterests{Count: 1, Code1: 100, Keyword1: "retro"},
			Permissions: state.ICQPermissions{AuthRequired: false, WebAware: true, AllowSpam: false},
		},
	}

	item, err := directoryProfile(user, "100002")
	assert.NoError(t, err)

	tlvs := decodeDirectoryItem(t, item)

	t.Run("plain fields", func(t *testing.T) {
		for _, tt := range []struct {
			tag  uint16
			want string
		}{
			{wire.ICQDirTagUID, "100002"},
			{wire.ICQDirTagFirstName, "Ivan"},
			{wire.ICQDirTagLastName, "Petrov"},
			{wire.ICQDirTagNickname, "Fejd"},
			{wire.ICQDirTagEmail, "fejd@example.org"},
			{wire.ICQDirTagHomepage, "https://example.org"},
			{wire.ICQDirTagAbout, "живу на власному сервері — №1"}, // the non-ASCII fixture
		} {
			got, ok := tlvs.String(tt.tag)
			assert.True(t, ok, "tag %#04x", tt.tag)
			assert.Equal(t, tt.want, got, "tag %#04x", tt.tag)
		}
	})

	t.Run("gender is converted to the directory form", func(t *testing.T) {
		got, ok := tlvs.Uint8(wire.ICQDirTagGender)
		assert.True(t, ok)
		assert.Equal(t, wire.ICQDirGenderMale, got)
	})

	t.Run("permissions", func(t *testing.T) {
		// The tag means "authorization not required", the inverse of what is stored.
		auth, ok := tlvs.Uint8(wire.ICQDirTagAuthOptional)
		assert.True(t, ok)
		assert.Equal(t, uint8(1), auth)

		webAware, ok := tlvs.Uint8(wire.ICQDirTagWebAware)
		assert.True(t, ok)
		assert.Equal(t, uint8(1), webAware)

		spam, ok := tlvs.Uint8(wire.ICQDirTagAllowSpam)
		assert.True(t, ok)
		assert.Equal(t, uint8(0), spam)
	})

	t.Run("home address", func(t *testing.T) {
		blob, ok := tlvs.Bytes(wire.ICQDirTagHomeAddress)
		assert.True(t, ok)
		recs := decodeDirectoryRecords(t, blob)
		assert.Len(t, recs, 1)

		city, ok := recs[0].String(wire.ICQDirAddrCity)
		assert.True(t, ok)
		assert.Equal(t, "Kyiv", city)

		// The country is four bytes: QIP 2012 does not read a two-byte one at
		// all, while Miranda and ICQ 6 accept any length.
		country, ok := recs[0].Bytes(wire.ICQDirAddrCountry)
		assert.True(t, ok)
		assert.Len(t, country, 4)
		assert.Equal(t, uint32(380), binary.BigEndian.Uint32(country))
	})

	t.Run("phones go as separate records carrying a kind", func(t *testing.T) {
		blob, ok := tlvs.Bytes(wire.ICQDirTagPhones)
		assert.True(t, ok)
		recs := decodeDirectoryRecords(t, blob)
		assert.Len(t, recs, 4, "home, work, cellular and fax")

		got := map[uint16]string{}
		for _, rec := range recs {
			kind, ok := rec.Uint16BE(wire.ICQDirPhoneType)
			assert.True(t, ok)
			number, ok := rec.String(wire.ICQDirPhoneNumber)
			assert.True(t, ok)
			got[kind] = number
		}
		assert.Equal(t, "+380441234567", got[wire.ICQDirPhoneTypeHome])
		assert.Equal(t, "+380441111111", got[wire.ICQDirPhoneTypeWork])
		assert.Equal(t, "+380671234567", got[wire.ICQDirPhoneTypeCellular])
		assert.Equal(t, "+380441234568", got[wire.ICQDirPhoneTypeFax])
	})

	t.Run("place of work", func(t *testing.T) {
		blob, ok := tlvs.Bytes(wire.ICQDirTagCompany)
		assert.True(t, ok)
		recs := decodeDirectoryRecords(t, blob)
		assert.Len(t, recs, 1)

		company, ok := recs[0].String(wire.ICQDirWorkCompany)
		assert.True(t, ok)
		assert.Equal(t, "Open OSCAR", company)
	})

	t.Run("interests", func(t *testing.T) {
		blob, ok := tlvs.Bytes(wire.ICQDirTagInterests)
		assert.True(t, ok)
		recs := decodeDirectoryRecords(t, blob)
		assert.Len(t, recs, 1)

		text, ok := recs[0].String(wire.ICQDirInterestText)
		assert.True(t, ok)
		assert.Equal(t, "retro", text)

		// The interest category is two bytes, the length the client itself sends;
		// QIP 2012 does not read a four-byte one. The country is the other way
		// round.
		cat, ok := recs[0].Bytes(wire.ICQDirInterestCat)
		assert.True(t, ok)
		assert.Len(t, cat, 2)
		assert.Equal(t, uint16(100), binary.BigEndian.Uint16(cat))
	})
}

// An empty profile must not produce empty fields: a client would wipe what it
// has already stored with them.
// The primary address goes out exactly once, in a tag of its own. Were it also
// placed in the list of extras, a client would show it twice: Miranda renders
// such a repeat as a second row labelled "2".
func TestDirectoryProfileEmailNotDuplicated(t *testing.T) {
	user := state.User{}
	user.ICQInfo.Basic.EmailAddress = "fejd@example.org"

	item, err := directoryProfile(user, "100002")
	assert.NoError(t, err)

	tlvs := decodeDirectoryItem(t, item)
	email, ok := tlvs.String(wire.ICQDirTagEmail)
	assert.True(t, ok)
	assert.Equal(t, "fejd@example.org", email)
	assert.False(t, tlvs.HasTag(wire.ICQDirTagEmails), "the list of extra addresses must not repeat the primary one")
}

func TestDirectoryProfileEmpty(t *testing.T) {
	item, err := directoryProfile(state.User{}, "100002")
	assert.NoError(t, err)

	tlvs := decodeDirectoryItem(t, item)

	for _, tag := range []uint16{
		wire.ICQDirTagFirstName,
		wire.ICQDirTagLastName,
		wire.ICQDirTagNickname,
		wire.ICQDirTagEmail,
		wire.ICQDirTagAbout,
		wire.ICQDirTagHomepage,
		wire.ICQDirTagGender,
		wire.ICQDirTagBirthDate,
		wire.ICQDirTagHomeAddress,
		wire.ICQDirTagPhones,
		wire.ICQDirTagEmails,
		wire.ICQDirTagCompany,
		wire.ICQDirTagInterests,
	} {
		assert.False(t, tlvs.HasTag(tag), "tag %#04x must not be sent empty", tag)
	}

	// The number and the permissions are always sent: a client identifies the
	// record by them.
	assert.True(t, tlvs.HasTag(wire.ICQDirTagUID))
	assert.True(t, tlvs.HasTag(wire.ICQDirTagAuthOptional))
}

func TestDirectoryGender(t *testing.T) {
	tests := []struct {
		name  string
		given uint16
		want  uint8
	}{
		{name: "unspecified", given: 0, want: wire.ICQDirGenderUnknown},
		{name: "female", given: 1, want: wire.ICQDirGenderFemale},
		{name: "male", given: 2, want: wire.ICQDirGenderMale},
		{name: "garbage", given: 77, want: wire.ICQDirGenderUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, directoryGender(tt.given))
		})
	}
}
