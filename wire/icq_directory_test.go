package wire

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mirandaDirectoryRequest builds a directory request exactly the way
// Miranda (stdpackets.cpp, packServIcqDirectoryHeader + icq_sendGetInfoServ).
// Testing against it also checks that our parser agrees with a live client.
func mirandaDirectoryRequest(subType uint16, uin string, token []byte) []byte {
	return mirandaDirectoryRequestBlock(subType, ICQDirectoryBlockInfo, uin, token)
}

// mirandaDirectoryRequestBlock is the same but with an explicit block tag: a
// profile lookup and a search share a sub-command and differ only by it.
func mirandaDirectoryRequestBlock(subType uint16, block uint16, uin string, token []byte) []byte {
	body := &bytes.Buffer{}

	// The nested SNAC header with the extra version block.
	for _, v := range []uint16{ICQDirectorySNACFamily, subType, 0x8000, 0, 0, 6, 1, 2, ICQDirectorySNACVersion} {
		_ = binary.Write(body, binary.BigEndian, v)
	}
	_ = binary.Write(body, binary.BigEndian, uint16(0))      // filler
	_ = binary.Write(body, binary.BigEndian, uint16(0x04E4)) // code page
	_ = binary.Write(body, binary.BigEndian, uint32(2))

	data := &bytes.Buffer{}
	if token != nil {
		_ = MarshalBE(TLV{Tag: ICQDirTagPrivacyToken, Value: token}, data)
	}
	_ = MarshalBE(TLV{Tag: ICQDirTagUID, Value: []byte(uin)}, data)

	_ = binary.Write(body, binary.BigEndian, block)
	_ = binary.Write(body, binary.BigEndian, uint32(1))
	_ = binary.Write(body, binary.BigEndian, uint16(data.Len()))
	body.Write(data.Bytes())

	out := &bytes.Buffer{}
	_ = binary.Write(out, binary.LittleEndian, uint16(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func TestUnmarshalICQDirectoryRequest(t *testing.T) {
	tests := []struct {
		name        string
		given       []byte
		wantSubType uint16
		wantBlock   uint16
		wantUID     string
		wantErr     bool
	}{
		{
			name:        "profile lookup for a buddy",
			given:       mirandaDirectoryRequest(ICQDirectoryQueryInfo, "100002", nil),
			wantSubType: ICQDirectoryQueryInfo,
			wantUID:     "100002",
		},
		{
			name:        "lookup carrying a privacy token",
			given:       mirandaDirectoryRequest(ICQDirectoryQueryInfo, "100003", make([]byte, 16)),
			wantSubType: ICQDirectoryQueryInfo,
			wantUID:     "100003",
		},
		{
			name:        "lookup for several users",
			given:       mirandaDirectoryRequest(ICQDirectoryQueryMultiInfo, "100004", nil),
			wantSubType: ICQDirectoryQueryMultiInfo,
			wantUID:     "100004",
		},
		{
			name:        "a search uses the same sub-command but another block",
			given:       mirandaDirectoryRequestBlock(ICQDirectoryQueryInfo, ICQDirectoryBlockSearch, "100005", nil),
			wantSubType: ICQDirectoryQueryInfo,
			wantBlock:   ICQDirectoryBlockSearch,
			wantUID:     "100005",
		},
		{
			name:    "truncated request",
			given:   mirandaDirectoryRequest(ICQDirectoryQueryInfo, "100002", nil)[:6],
			wantErr: true,
		},
		{
			name:    "foreign family in the nested header",
			given:   append([]byte{0x14, 0x00, 0x05, 0xBA}, make([]byte, 0x14)...),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalICQDirectoryRequest(bytes.NewBuffer(tt.given))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantSubType, got.SubType)
			if tt.wantBlock != 0 {
				assert.Equal(t, tt.wantBlock, got.Block)
			} else {
				assert.Equal(t, ICQDirectoryBlockInfo, got.Block)
			}

			uid, ok := got.UID()
			assert.True(t, ok)
			assert.Equal(t, tt.wantUID, uid)
		})
	}
}

// TestICQDirectoryPayload checks a reply the way the client reads it
// (fam_15icqserver.cpp, handleDirectoryQueryResponse): length, nested header,
// result byte, filler, counters and the item.
func TestICQDirectoryPayload(t *testing.T) {
	item := &bytes.Buffer{}
	assert.NoError(t, MarshalBE(TLVRestBlock{TLVList: TLVList{
		NewTLVBE(ICQDirTagUID, "100002"),
		NewTLVBE(ICQDirTagNickname, "Fejd"),
	}}, item))

	payload, err := ICQDirectoryPayload(ICQDirectoryQueryInfoAck, ICQDirectoryResultOK, item.Bytes(), 1, 1, false, true)
	assert.NoError(t, err)

	buf := bytes.NewBuffer(payload)

	var declaredLen uint16
	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &declaredLen))
	assert.Equal(t, buf.Len(), int(declaredLen), "the declared length must match the remainder")

	var family, subType, flags, seq, cmd, extraLen uint16
	for _, p := range []*uint16{&family, &subType, &flags, &seq, &cmd, &extraLen} {
		assert.NoError(t, binary.Read(buf, binary.BigEndian, p))
	}
	assert.Equal(t, ICQDirectorySNACFamily, family)
	assert.Equal(t, ICQDirectoryQueryInfoAck, subType)
	assert.Equal(t, uint16(0x8000), flags&0x8000, "the extra block bit is mandatory")
	assert.Zero(t, flags&0x0001, "the more-to-come bit must be clear: a single-packet reply")
	assert.Equal(t, uint16(6), extraLen)
	buf.Next(int(extraLen))

	result, err := buf.ReadByte()
	assert.NoError(t, err)
	assert.Equal(t, ICQDirectoryResultOK, result)

	var errMsgLen uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &errMsgLen))
	assert.Zero(t, errMsgLen)

	buf.Next(16) // filler, the client skips it

	var itemCount uint32
	var pageCount, blockCount, itemLen uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &pageCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &blockCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemLen))
	assert.Equal(t, uint32(1), itemCount)
	assert.Equal(t, uint16(1), blockCount, "the client accepts only one block")
	assert.Equal(t, item.Len(), int(itemLen))
	assert.Equal(t, buf.Len(), int(itemLen), "exactly the item is left after the counters")

	chain := TLVRestBlock{}
	assert.NoError(t, UnmarshalBE(&chain, buf))
	nick, ok := chain.String(ICQDirTagNickname)
	assert.True(t, ok)
	assert.Equal(t, "Fejd", nick)
}

func TestICQDirRecordList(t *testing.T) {
	recs := []ICQDirRecord{
		{TLVList: TLVList{NewTLVBE(ICQDirPhoneNumber, "+1234"), NewTLVBE(ICQDirPhoneType, ICQDirPhoneTypeHome)}},
		{TLVList: TLVList{NewTLVBE(ICQDirPhoneNumber, "+5678"), NewTLVBE(ICQDirPhoneType, ICQDirPhoneTypeWork)}},
	}

	blob, err := ICQDirRecordList(recs)
	assert.NoError(t, err)

	buf := bytes.NewBuffer(blob)
	var count uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &count))
	assert.Equal(t, uint16(2), count)

	for i, want := range []string{"+1234", "+5678"} {
		var size uint16
		assert.NoError(t, binary.Read(buf, binary.BigEndian, &size), "record %d", i)
		chain := TLVRestBlock{}
		assert.NoError(t, UnmarshalBE(&chain, bytes.NewBuffer(buf.Next(int(size)))))
		number, ok := chain.String(ICQDirPhoneNumber)
		assert.True(t, ok)
		assert.Equal(t, want, number)
	}
	assert.Zero(t, buf.Len(), "no spare bytes may be left in the record list")
}

func TestICQDirDate(t *testing.T) {
	tests := []struct {
		name  string
		year  uint16
		month uint8
		day   uint8
		want  float64
		ok    bool
	}{
		{name: "the epoch", year: 1900, month: 1, day: 1, want: 0, ok: true},
		{name: "the next day", year: 1900, month: 1, day: 2, want: 1, ok: true},
		{name: "an ordinary date", year: 1980, month: 6, day: 15, want: 29385, ok: true},
		{name: "no year", year: 0, month: 6, day: 15, ok: false},
		{name: "no month", year: 1980, month: 0, day: 15, ok: false},
		{name: "before the epoch", year: 1899, month: 1, day: 1, ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ICQDirDate(tt.year, tt.month, tt.day)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Less(t, math.Abs(got-tt.want), 0.5)
			}
		})
	}
}

// mirandaDirectorySearch builds a search request the way the client does
// (stdpackets.cpp, sendDirectorySearchPacket): block tag 0x02, then a two-byte
// page number and count - unlike a profile lookup, which carries a four-byte
// count in that place.
func mirandaDirectorySearch(page uint16, tlvs TLVList) []byte {
	body := &bytes.Buffer{}
	for _, v := range []uint16{ICQDirectorySNACFamily, ICQDirectoryQueryInfo, 0x8000, 0, 0, 6, 1, 2, ICQDirectorySNACVersion} {
		_ = binary.Write(body, binary.BigEndian, v)
	}
	_ = binary.Write(body, binary.BigEndian, uint16(0))
	_ = binary.Write(body, binary.BigEndian, uint16(0x04E4))
	_ = binary.Write(body, binary.BigEndian, uint32(2))

	data := &bytes.Buffer{}
	_ = MarshalBE(TLVRestBlock{TLVList: tlvs}, data)

	_ = binary.Write(body, binary.BigEndian, ICQDirectoryBlockSearch)
	_ = binary.Write(body, binary.BigEndian, page)
	_ = binary.Write(body, binary.BigEndian, uint16(1))
	_ = binary.Write(body, binary.BigEndian, uint16(data.Len()))
	body.Write(data.Bytes())

	out := &bytes.Buffer{}
	_ = binary.Write(out, binary.LittleEndian, uint16(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// mirandaDirectoryUpdate builds an upload of one's own profile
// (icq_changeUserDirectoryInfoServ): the data length follows the block tag
// directly, with no count in between.
func mirandaDirectoryUpdate(tlvs TLVList) []byte {
	body := &bytes.Buffer{}
	for _, v := range []uint16{ICQDirectorySNACFamily, ICQDirectorySetInfo, 0x8000, 0, 0, 6, 1, 2, ICQDirectorySNACVersion} {
		_ = binary.Write(body, binary.BigEndian, v)
	}
	_ = binary.Write(body, binary.BigEndian, uint16(0))
	_ = binary.Write(body, binary.BigEndian, uint16(0x04E4))
	_ = binary.Write(body, binary.BigEndian, uint32(2))

	data := &bytes.Buffer{}
	_ = MarshalBE(TLVRestBlock{TLVList: tlvs}, data)

	_ = binary.Write(body, binary.BigEndian, ICQDirectoryBlockInfo)
	_ = binary.Write(body, binary.BigEndian, uint16(data.Len()))
	body.Write(data.Bytes())

	out := &bytes.Buffer{}
	_ = binary.Write(out, binary.LittleEndian, uint16(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func TestUnmarshalICQDirectorySearch(t *testing.T) {
	given := mirandaDirectorySearch(3, TLVList{
		NewTLVBE(ICQDirTagFirstName, "Paul"),
		NewTLVBE(ICQDirTagNickname, "Leto"),
	})

	got, err := UnmarshalICQDirectoryRequest(bytes.NewBuffer(given))
	assert.NoError(t, err)
	assert.Equal(t, ICQDirectoryQueryInfo, got.SubType)
	assert.Equal(t, ICQDirectoryBlockSearch, got.Block)
	assert.Equal(t, uint16(3), got.Page)
	assert.True(t, got.IsSearch(), "a search must be told apart from a profile lookup")

	nick, ok := got.TLVs.String(ICQDirTagNickname)
	assert.True(t, ok)
	assert.Equal(t, "Leto", nick)
}

func TestUnmarshalICQDirectoryUpdate(t *testing.T) {
	given := mirandaDirectoryUpdate(TLVList{
		NewTLVBE(ICQDirTagNickname, "Fejd"),
		// Non-ASCII on purpose: strings travel as UTF-8 with neither a length
		// prefix nor a trailing NUL, so only the TLV bounds delimit them. The
		// fixture mixes two-byte letters with three-byte punctuation.
		NewTLVBE(ICQDirTagAbout, "живу на власному сервері — №1"),
	})

	got, err := UnmarshalICQDirectoryRequest(bytes.NewBuffer(given))
	assert.NoError(t, err)
	assert.Equal(t, ICQDirectorySetInfo, got.SubType)
	assert.False(t, got.IsSearch(), "saving a profile is not a search")

	about, ok := got.TLVs.String(ICQDirTagAbout)
	assert.True(t, ok)
	assert.Equal(t, "живу на власному сервері — №1", about)
}

// An empty result set and the intermediate packets are the two cases where the
// client decides whether to keep waiting.
func TestICQDirectoryPayloadCounts(t *testing.T) {
	t.Run("nothing found", func(t *testing.T) {
		payload, err := ICQDirectoryPayload(ICQDirectoryQueryInfoAck, ICQDirectoryResultOK, nil, 0, 1, false, true)
		assert.NoError(t, err)

		_, _, blockCount, itemLen := directoryCounters(t, payload)
		assert.Zero(t, blockCount, "a zero block count reads as \"not found\" to the client")
		assert.Zero(t, itemLen)
	})

	t.Run("more to come", func(t *testing.T) {
		payload, err := ICQDirectoryPayload(ICQDirectoryQueryInfoAck, ICQDirectoryResultOK, []byte{0, 1, 0, 0}, 5, 1, true, true)
		assert.NoError(t, err)

		flags, itemCount, blockCount, _ := directoryCounters(t, payload)
		assert.NotZero(t, flags&0x0001, "without this bit the client closes the request on the first packet")
		assert.Equal(t, uint32(5), itemCount)
		assert.Equal(t, uint16(1), blockCount)
	})
}

// directoryCounters pulls the flags and counters out of a prepared block.
func directoryCounters(t *testing.T, payload []byte) (flags uint16, itemCount uint32, blockCount uint16, itemLen uint16) {
	t.Helper()

	buf := bytes.NewBuffer(payload)
	var declaredLen uint16
	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &declaredLen))

	var family, subType, seq, cmd, extraLen uint16
	for _, p := range []*uint16{&family, &subType, &flags, &seq, &cmd, &extraLen} {
		assert.NoError(t, binary.Read(buf, binary.BigEndian, p))
	}
	buf.Next(int(extraLen))

	_, err := buf.ReadByte() // result byte
	assert.NoError(t, err)

	var errMsgLen uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &errMsgLen))
	buf.Next(16)

	var pageCount uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &pageCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &blockCount))
	if blockCount > 0 {
		assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemLen))
	}
	return flags, itemCount, blockCount, itemLen
}

// The bytes were captured from a live QIP 2012 (build 11.2.0.11) asking for a
// buddy's details. The layout matches Miranda's in every place but one: the
// nested SNAC carries the meta request subtype (0x0FA0) instead of the directory
// command (0x0002). Until the server tolerated that, QIP was refused and left
// every details tab empty.
func TestUnmarshalICQDirectoryRequestQIP(t *testing.T) {
	packet := []byte{
		0x24, 0x00, // length of the rest, little-endian
		0x05, 0xb9, // family
		0x0f, 0xa0, // subtype: the meta request instead of the command
		0x00, 0x00, // flags
		0x00, 0x00, 0x00, 0x00, // request id
		0x00, 0x00, // filler
		0x04, 0xe3, // code page (1251)
		0x00, 0x00, 0x00, 0x02, // constant
		0x00, 0x03, // block tag: profile
		0x00, 0x00, 0x00, 0x01, // item count
		0x00, 0x0a, // data length
		0x00, 0x32, 0x00, 0x06, '1', '0', '0', '0', '0', '1',
	}

	req, err := UnmarshalICQDirectoryRequest(bytes.NewBuffer(packet))
	assert.NoError(t, err)
	assert.Equal(t, ICQDirectoryQueryInfo, req.SubType, "the subtype must be normalized to the lookup command")
	assert.Equal(t, ICQDirectoryBlockInfo, req.Block)
	assert.False(t, req.IsSearch())

	uid, ok := req.UID()
	assert.True(t, ok)
	assert.Equal(t, "100001", uid)
}

// The reply header mirrors the client's convention: the version block is there
// only when one was sent. QIP 2012 sends a request without it and parses a reply
// the same way - the extra eight bytes shift its whole parse and the profile
// silently disappears. Miranda, on the contrary, always sends the tag.
func TestICQDirectoryPayloadVersionBlock(t *testing.T) {
	tests := []struct {
		name      string
		versioned bool
		wantFlags uint16
		wantLen   int // length of the nested header
	}{
		{name: "tag sent, tag returned", versioned: true, wantFlags: 0x8000, wantLen: 18},
		{name: "no tag sent, none in the reply", versioned: false, wantFlags: 0x0000, wantLen: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := ICQDirectoryPayload(ICQDirectoryQueryInfoAck, ICQDirectoryResultOK, nil, 0, 1, false, tt.versioned)
			assert.NoError(t, err)

			body := payload[2:] // past the little-endian length
			assert.Equal(t, ICQDirectorySNACFamily, binary.BigEndian.Uint16(body[0:2]))
			assert.Equal(t, ICQDirectoryQueryInfoAck, binary.BigEndian.Uint16(body[2:4]))
			assert.Equal(t, tt.wantFlags, binary.BigEndian.Uint16(body[4:6]))

			// The result byte follows the header directly, so its position shows
			// whether the parse is shifted.
			assert.Equal(t, ICQDirectoryResultOK, body[tt.wantLen])
		})
	}
}

// The reply layout for QIP 2012: exactly 25 bytes from the start of the body to
// the item count, then the block count and the item length right after it. It
// has no page count - QIP would take it for the length. The offsets come from
// its parser (InfICQ.dll).
func TestICQDirectoryPayloadQIPLayout(t *testing.T) {
	item := []byte{0x00, 0x32, 0x00, 0x02, '4', '2'}

	payload, err := ICQDirectoryPayload(ICQDirectoryQueryInfoAck, ICQDirectoryResultOK, item, 1, 1, false, false)
	assert.NoError(t, err)

	assert.Equal(t, len(payload)-2, int(binary.LittleEndian.Uint16(payload[0:2])),
		"the length up front does not count itself")

	// QIP drops 25 bytes from the start of the body, that length included.
	assert.Equal(t, uint32(1), binary.BigEndian.Uint32(payload[25:29]), "item count")
	assert.Equal(t, uint16(1), binary.BigEndian.Uint16(payload[29:31]), "block count")
	assert.Equal(t, uint16(len(item)), binary.BigEndian.Uint16(payload[31:33]), "item length")
	assert.Equal(t, item, payload[33:33+len(item)])

	// An item count of one is the very pattern QIP looks for on its fallback
	// path.
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, payload[25:29])
}

// Miranda's layout does not shift because of that: the same record, but with a
// page count and sixteen unidentified bytes.
func TestICQDirectoryPayloadMirandaLayout(t *testing.T) {
	item := []byte{0x00, 0x32, 0x00, 0x02, '4', '2'}

	payload, err := ICQDirectoryPayload(ICQDirectoryQueryInfoAck, ICQDirectoryResultOK, item, 1, 3, false, true)
	assert.NoError(t, err)

	// length 2 + SNAC 10 + version block 8 + result 1 + error length 2 + 16
	const itemCountAt = 39
	assert.Equal(t, uint32(1), binary.BigEndian.Uint32(payload[itemCountAt:itemCountAt+4]), "item count")
	assert.Equal(t, uint16(3), binary.BigEndian.Uint16(payload[itemCountAt+4:itemCountAt+6]), "page count")
	assert.Equal(t, uint16(1), binary.BigEndian.Uint16(payload[itemCountAt+6:itemCountAt+8]), "block count")
	assert.Equal(t, uint16(len(item)), binary.BigEndian.Uint16(payload[itemCountAt+8:itemCountAt+10]), "item length")
	assert.Equal(t, item, payload[itemCountAt+10:itemCountAt+10+len(item)])
}
