package foodgroup

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// TestDirectoryReplyOnTheWire builds a reply with the same code the server uses
// and takes it apart the way a client does: first the meta message envelope
// (fam_15icqserver.cpp, handleExtensionMetaResponse), then the directory block
// (handleDirectoryQueryResponse). It catches layout mismatches that checking the
// pieces separately cannot see.
func TestDirectoryReplyOnTheWire(t *testing.T) {
	const (
		selfUIN = uint32(100002)
		seq     = uint16(0x1234)
	)

	item, err := directoryProfile(userWithNickname("Leto"), "100001")
	assert.NoError(t, err)

	payload, err := wire.ICQDirectoryPayload(wire.ICQDirectoryQueryInfoAck, wire.ICQDirectoryResultOK, item, 1, 1, false, true)
	assert.NoError(t, err)

	snac := replySNAC(wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x0FAA_DBQueryMetaReplyDirectory{
			ICQMetadata: wire.ICQMetadata{
				UIN:     selfUIN,
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyDirectoryResponse,
			Success:    wire.ICQStatusCodeOK,
			Payload:    payload,
		},
	}, 42, 0)

	// This is how the reply goes out on the wire.
	raw := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(snac.Body, raw))

	block := wire.TLVRestBlock{}
	assert.NoError(t, wire.UnmarshalBE(&block, raw))
	md, ok := block.Bytes(wire.ICQTLVTagsMetadata)
	assert.True(t, ok, "the metadata tag must be present")

	buf := bytes.NewBuffer(md)

	// The meta message header, little-endian throughout.
	var chunkSize uint16
	var uin uint32
	var reqType, gotSeq, replySubType uint16
	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &chunkSize))
	assert.Equal(t, buf.Len(), int(chunkSize), "the declared chunk size must match the remainder")

	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &uin))
	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &reqType))
	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &gotSeq))
	assert.Equal(t, selfUIN, uin)
	assert.Equal(t, wire.ICQDBQueryMetaReply, reqType)
	assert.Equal(t, seq, gotSeq, "the client matches a reply to its request by this field")

	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &replySubType))
	// Only for this subtype does the client send the acknowledgement that stops
	// the spinner in the details window.
	assert.Equal(t, wire.ICQDBQueryMetaReplyDirectoryResponse, replySubType)

	result, err := buf.ReadByte()
	assert.NoError(t, err)
	assert.Equal(t, wire.ICQStatusCodeOK, result, "otherwise the client drops the reply unread")

	// Next comes the directory block, which the client parses in its own branch.
	var declaredLen uint16
	assert.NoError(t, binary.Read(buf, binary.LittleEndian, &declaredLen))
	assert.Equal(t, buf.Len(), int(declaredLen))

	var family, subType, flags, snacSeq, cmd, extraLen uint16
	for _, p := range []*uint16{&family, &subType, &flags, &snacSeq, &cmd, &extraLen} {
		assert.NoError(t, binary.Read(buf, binary.BigEndian, p))
	}
	assert.Equal(t, wire.ICQDirectorySNACFamily, family)
	assert.Equal(t, uint16(6), extraLen)
	buf.Next(int(extraLen))

	dirResult, err := buf.ReadByte()
	assert.NoError(t, err)
	assert.Equal(t, wire.ICQDirectoryResultOK, dirResult)

	var errMsgLen uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &errMsgLen))
	assert.Zero(t, errMsgLen)

	// The client's checks on the remaining length; both have to hold.
	assert.Greater(t, buf.Len(), 0x16, "the client drops a reply whose remainder is not above 0x16")
	buf.Next(16)

	var itemCount uint32
	var pageCount, blockCount, itemLen uint16
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &pageCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &blockCount))
	assert.NoError(t, binary.Read(buf, binary.BigEndian, &itemLen))
	assert.Equal(t, uint16(1), blockCount)
	assert.Equal(t, buf.Len(), int(itemLen), "the client compares the remainder with the item length")

	chain := wire.TLVRestBlock{}
	assert.NoError(t, wire.UnmarshalBE(&chain, buf))
	uid, ok := chain.String(wire.ICQDirTagUID)
	assert.True(t, ok, "without the number the client cannot tell who this is about")
	assert.Equal(t, "100001", uid)
}

func userWithNickname(nick string) state.User {
	u := state.User{}
	u.ICQInfo.Basic.Nickname = nick
	return u
}
