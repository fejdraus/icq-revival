package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Encoding of the ICQ "directory" protocol - the one clients from ICQ 6 onwards
// use to ask for profiles (Miranda calls it MDir). The classic meta protocol of
// ICQ 99-2003 lives next door in snacs.go and stays in service: the client
// picks the dialect, so the server has to understand both.
//
// Three differences matter to the codec: fields live in TLVs instead of a flat
// fixed-order structure; strings are UTF-8 with no length prefix and no
// trailing NUL; numbers are big-endian while the meta message envelope around
// them stays little-endian.

const (
	// ICQDirectorySNACFamily is the family of the nested SNAC header that a
	// directory request and reply carry inside the meta message.
	ICQDirectorySNACFamily uint16 = 0x05B9

	// ICQDirectorySNACVersion goes into TLV(1) of the nested header's extra
	// block.
	ICQDirectorySNACVersion uint16 = 0x0002
)

// Sub-commands of a directory request (the nested SNAC subtype).
const (
	ICQDirectoryQueryInfo      uint16 = 0x0002
	ICQDirectoryQueryMultiInfo uint16 = 0x0006
	ICQDirectoryQueryInfoAck   uint16 = 0x0009
	ICQDirectorySetInfo        uint16 = 0x0003
	ICQDirectorySetInfoAck     uint16 = 0x000A
)

// The block tag in the request body. A profile lookup and a search share the
// same sub-command, and only this number tells them apart: the client sends
// 0x03 when asking about one person and 0x02 when searching (stdpackets.cpp,
// icq_sendGetInfoServ versus sendDirectorySearchPacket).
const (
	ICQDirectoryBlockSearch uint16 = 0x0002
	ICQDirectoryBlockInfo   uint16 = 0x0003
)

// Meta reply subtypes of the directory protocol.
const (
	ICQDBQueryMetaReplyDirectoryData      uint16 = 0x0FAA
	ICQDBQueryMetaReplyDirectoryResponse  uint16 = 0x0FB4
	ICQDBQueryMetaReplyDirectoryUpdateAck uint16 = 0x0FDC
)

// The result byte inside the directory block. Clients accept only 1 and 4.
const (
	ICQDirectoryResultOK      uint8 = 0x01
	ICQDirectoryResultOKOwner uint8 = 0x04
)

// Top-level TLV tags of a profile.
const (
	ICQDirTagUID          uint16 = 0x0032
	ICQDirTagPrivacyToken uint16 = 0x003C
	ICQDirTagEmail        uint16 = 0x0050
	ICQDirTagPendingEmail uint16 = 0x0055
	ICQDirTagFirstName    uint16 = 0x0064
	ICQDirTagLastName     uint16 = 0x006E
	ICQDirTagNickname     uint16 = 0x0078
	ICQDirTagGender       uint16 = 0x0082
	ICQDirTagEmails       uint16 = 0x008C
	ICQDirTagHomeAddress  uint16 = 0x0096
	ICQDirTagOrigin       uint16 = 0x00A0
	ICQDirTagLang1        uint16 = 0x00AA
	ICQDirTagLang2        uint16 = 0x00B4
	ICQDirTagLang3        uint16 = 0x00BE
	ICQDirTagPhones       uint16 = 0x00C8
	ICQDirTagHomepage     uint16 = 0x00FA
	ICQDirTagEducation    uint16 = 0x010E
	ICQDirTagCompany      uint16 = 0x0118
	ICQDirTagInterests    uint16 = 0x0122
	ICQDirTagMaritalState uint16 = 0x012C
	ICQDirTagTimezone     uint16 = 0x017C
	ICQDirTagAbout        uint16 = 0x0186
	ICQDirTagAuthOptional uint16 = 0x019A
	ICQDirTagBirthDate    uint16 = 0x01A4
	ICQDirTagCodePage     uint16 = 0x01C2
	ICQDirTagInfoTime     uint16 = 0x01CC
	ICQDirTagAllowSpam    uint16 = 0x01EA
	ICQDirTagPrivacyLevel uint16 = 0x01F9
	ICQDirTagWebAware     uint16 = 0x0212
	ICQDirTagStatusNote   uint16 = 0x0226
	ICQDirTagOnlineOnly   uint16 = 0x0136
)

// Tags inside the nested records. Numbering restarts in every record, so the
// same value means different things depending on the record it appears in.
const (
	// Home address and place of origin.
	ICQDirAddrStreet  uint16 = 0x0064
	ICQDirAddrCity    uint16 = 0x006E
	ICQDirAddrState   uint16 = 0x0078
	ICQDirAddrZIP     uint16 = 0x0082
	ICQDirAddrCountry uint16 = 0x008C

	// Phone: number and kind.
	ICQDirPhoneNumber uint16 = 0x0064
	ICQDirPhoneType   uint16 = 0x006E

	// An e-mail address in the address list.
	ICQDirEmailAddress uint16 = 0x0064

	// Place of work.
	ICQDirWorkPosition   uint16 = 0x0064
	ICQDirWorkCompany    uint16 = 0x006E
	ICQDirWorkHomepage   uint16 = 0x0078
	ICQDirWorkDepartment uint16 = 0x007D
	ICQDirWorkIndustry   uint16 = 0x0082
	ICQDirWorkStreet     uint16 = 0x00AA
	ICQDirWorkCity       uint16 = 0x00B4
	ICQDirWorkState      uint16 = 0x00BE
	ICQDirWorkZIP        uint16 = 0x00C8
	ICQDirWorkCountry    uint16 = 0x00D2

	// Education.
	ICQDirStudyLevel     uint16 = 0x0064
	ICQDirStudyInstitute uint16 = 0x006E
	ICQDirStudyDegree    uint16 = 0x0078
	ICQDirStudyYear      uint16 = 0x008C

	// Interest.
	ICQDirInterestText uint16 = 0x0064
	ICQDirInterestCat  uint16 = 0x006E
)

// Phone kinds inside the ICQDirTagPhones record.
const (
	// Numbering starts at one, not zero: that is how Miranda reads it
	// (fam_15icqserver.cpp, getRecordByTLV(0x6E, 1..5)) and how QIP sends it.
	// Off by one, the home phone arrived as the work phone, the cellular as the
	// fax and the fax as the work fax.
	ICQDirPhoneTypeHome     uint16 = 1
	ICQDirPhoneTypeWork     uint16 = 2
	ICQDirPhoneTypeCellular uint16 = 3
	ICQDirPhoneTypeFax      uint16 = 4
	ICQDirPhoneTypeWorkFax  uint16 = 5
)

// Gender in the ICQDirTagGender tag. The classic protocol encodes the same
// values differently, so both directions need translating.
const (
	ICQDirGenderUnknown uint8 = 0
	ICQDirGenderFemale  uint8 = 1
	ICQDirGenderMale    uint8 = 2
)

// icqDirEpoch is where dates start in the directory protocol. A date travels as
// a float: the integer part counts days, the fraction is the time of day.
var icqDirEpoch = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)

// ICQDirDate converts a date into the number the client expects.
func ICQDirDate(year uint16, month uint8, day uint8) (float64, bool) {
	if year == 0 || month == 0 || day == 0 {
		return 0, false
	}
	t := time.Date(int(year), time.Month(month), int(day), 0, 0, 0, 0, time.UTC)
	days := t.Sub(icqDirEpoch).Hours() / 24
	if days < 0 {
		return 0, false
	}
	return days, true
}

// ICQDirDateParse is the reverse: it turns the number sent by the client into
// year, month and day.
func ICQDirDateParse(days float64) (uint16, uint8, uint8, bool) {
	if days <= 0 || days > 200000 {
		return 0, 0, 0, false
	}
	t := icqDirEpoch.Add(time.Duration(days * 24 * float64(time.Hour)))
	return uint16(t.Year()), uint8(t.Month()), uint8(t.Day()), true
}

// ICQDirRecord is one nested record: an address, a workplace, a phone and so on.
type ICQDirRecord struct {
	TLVList
}

// ICQDirRecordList encodes a list of nested records: a count, then every record
// preceded by its own length.
func ICQDirRecordList(records []ICQDirRecord) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.BigEndian, uint16(len(records))); err != nil {
		return nil, err
	}
	for _, rec := range records {
		body := &bytes.Buffer{}
		if err := MarshalBE(TLVRestBlock{TLVList: rec.TLVList}, body); err != nil {
			return nil, err
		}
		if body.Len() > math.MaxUint16 {
			return nil, errors.New("directory record too long")
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(body.Len())); err != nil {
			return nil, err
		}
		if _, err := buf.Write(body.Bytes()); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// ICQ_0x07DA_0x0FAA_DBQueryMetaReplyDirectory is the meta reply of the directory
// protocol. The body is prepared up front: it mixes both byte orders, which the
// struct-tag marshaller cannot express.
type ICQ_0x07DA_0x0FAA_DBQueryMetaReplyDirectory struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	Payload    []byte
}

// ICQDirectoryPayload wraps a reply into the directory envelope: length, nested
// SNAC header, result byte and the counters.
//
// A client parses exactly one record per packet (fam_15icqserver.cpp compares
// the block count against one), so several hits are sent as separate packets
// with the more-to-come flag raised on all but the last. An empty item means
// "nothing found" and leaves the block count at zero.
//
// The sixteen zero bytes after the error message length are skipped unread by
// the client ("unknown stuff"), but leaving them out shifts its parse, so the
// space is reserved.
func ICQDirectoryPayload(subType uint16, result uint8, item []byte, totalItems uint32, pages uint16, more bool, versioned bool) ([]byte, error) {
	if len(item) > math.MaxUint16 {
		return nil, errors.New("directory item too long")
	}

	body := &bytes.Buffer{}
	if err := writeICQDirectoryHeader(body, subType, more, versioned); err != nil {
		return nil, err
	}

	if err := binary.Write(body, binary.BigEndian, result); err != nil {
		return nil, err
	}
	if err := binary.Write(body, binary.BigEndian, uint16(0)); err != nil { // error message length
		return nil, err
	}
	// What follows works around a defect in QIP 2012; it is not a second
	// dialect of the protocol.
	//
	// The standard layout is sixteen unidentified bytes, the item count, the
	// page count, the block count and the item length. That is how Miranda
	// reads it (fam_15icqserver.cpp, handleDirectoryQueryResponse) and what
	// ICQ 6 itself expects - verified against the live client: it asks for a
	// profile with the version tag and parses such a reply correctly.
	//
	// QIP 2012 (InfICQ.dll, the parser at 0x4B25D4) reads it differently: it
	// drops exactly 25 bytes from the start of the body - the length, the
	// nested SNAC, the result byte and ten unidentified bytes - then takes the
	// item count and the block count. It has no page count at all: it treats
	// the next word as the item length. In a standard reply that word is the
	// block count, that is one, and the profile silently disappears - no
	// error, no log line. Its fallback path, which locates the block by
	// searching for the pattern "item count equals one", is off the same way.
	//
	// There is nothing else to tell it apart by: it reports no client name at
	// all (Miranda and ICQ 6 send "ICQ Client"), while the version tag is
	// written and parsed by the same code on the far side. So the signal stays
	// the same: send the tag and get the standard reply, omit it and get the
	// short one.
	unknownLen := 10
	if versioned {
		unknownLen = 16
	}
	if _, err := body.Write(make([]byte, unknownLen)); err != nil {
		return nil, err
	}
	if err := binary.Write(body, binary.BigEndian, totalItems); err != nil {
		return nil, err
	}
	if versioned {
		if err := binary.Write(body, binary.BigEndian, pages); err != nil {
			return nil, err
		}
	}

	blockCount := uint16(0)
	if len(item) > 0 {
		blockCount = 1
	}
	if err := binary.Write(body, binary.BigEndian, blockCount); err != nil {
		return nil, err
	}
	if blockCount > 0 {
		if err := binary.Write(body, binary.BigEndian, uint16(len(item))); err != nil {
			return nil, err
		}
		if _, err := body.Write(item); err != nil {
			return nil, err
		}
	}

	if body.Len() > math.MaxUint16 {
		return nil, errors.New("directory payload too long")
	}

	out := &bytes.Buffer{}
	if err := binary.Write(out, binary.LittleEndian, uint16(body.Len())); err != nil {
		return nil, err
	}
	if _, err := out.Write(body.Bytes()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ICQDirectoryUpdateAck builds the acknowledgement of a profile save. The
// optional tail with a timestamp and a privacy token is left out: the client
// reads it only when the remainder is exactly 0x18 bytes, and discards an empty
// token anyway.
// writeICQDirectoryHeader writes the nested SNAC header of a reply.
//
// The version block behind the header is written only when the client sent one.
// Miranda and ICQ 6 always send it and expect it back; QIP 2012 neither sends
// nor expects it, and the extra eight bytes shift its whole parse.
func writeICQDirectoryHeader(body *bytes.Buffer, subType uint16, more bool, versioned bool) error {
	flags := uint16(0)
	if versioned {
		flags |= 0x8000
	}
	if more {
		// The client keeps the request open while this bit is set both in the
		// SNAC itself and here: one of the two is not enough.
		flags |= 0x0001
	}

	header := []uint16{
		ICQDirectorySNACFamily,
		subType,
		flags,
		0, // sequence number
		0, // command
	}
	if versioned {
		header = append(header,
			6, // length of the extra block
			1, // TLV(1): version
			2, // value length
			ICQDirectorySNACVersion,
		)
	}

	for _, v := range header {
		if err := binary.Write(body, binary.BigEndian, v); err != nil {
			return err
		}
	}
	return nil
}

func ICQDirectoryUpdateAck(result uint8, versioned bool) ([]byte, error) {
	body := &bytes.Buffer{}
	if err := writeICQDirectoryHeader(body, ICQDirectorySetInfoAck, false, versioned); err != nil {
		return nil, err
	}
	if err := binary.Write(body, binary.BigEndian, result); err != nil {
		return nil, err
	}
	if err := binary.Write(body, binary.BigEndian, uint16(0)); err != nil {
		return nil, err
	}

	out := &bytes.Buffer{}
	if err := binary.Write(out, binary.LittleEndian, uint16(body.Len())); err != nil {
		return nil, err
	}
	if _, err := out.Write(body.Bytes()); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ICQDirectoryRequest is a parsed directory request.
type ICQDirectoryRequest struct {
	// SubType is the sub-command from the nested SNAC header: a profile lookup
	// or a save of the user's own profile.
	SubType uint16
	// Block tells a profile lookup from a search; they share a sub-command.
	Block uint16
	// Page is the result page number, search only.
	Page uint16
	// Versioned means the request header had the 0x8000 bit and the version
	// block behind it. The reply mirrors what the client chose: whoever does not
	// send this extension usually cannot parse it either.
	Versioned bool
	// TLVs is the request body: the number in ICQDirTagUID for a lookup, the
	// criteria for a search, the whole profile for a save.
	TLVs TLVList
}

// UID returns the number being asked about. It travels as a string, not a number.
func (r ICQDirectoryRequest) UID() (string, bool) {
	b, ok := r.TLVs.Bytes(ICQDirTagUID)
	if !ok {
		return "", false
	}
	return string(bytes.TrimRight(b, "\x00")), true
}

// IsSearch reports whether this is a search rather than one person's profile.
func (r ICQDirectoryRequest) IsSearch() bool {
	return r.SubType != ICQDirectorySetInfo && r.Block == ICQDirectoryBlockSearch
}

// UnmarshalICQDirectoryRequest parses the body of a directory request, the part
// that follows the subtype in the meta message.
//
// The body is laid out differently for the three kinds of request, told apart
// by the sub-command and the block tag: a lookup carries a four-byte count, a
// search a two-byte page number and count, a save the data length right away
// (stdpackets.cpp: icq_sendGetInfoServ,
// sendDirectorySearchPacket, icq_changeUserDirectoryInfoServ).
func UnmarshalICQDirectoryRequest(r *bytes.Buffer) (ICQDirectoryRequest, error) {
	var req ICQDirectoryRequest

	var payloadLen uint16
	if err := binary.Read(r, binary.LittleEndian, &payloadLen); err != nil {
		return req, fmt.Errorf("reading directory payload length: %w", err)
	}
	if int(payloadLen) > r.Len() {
		return req, fmt.Errorf("directory payload length %d exceeds %d bytes available", payloadLen, r.Len())
	}
	body := bytes.NewBuffer(r.Next(int(payloadLen)))

	var family, flags, seq, cmd uint16
	for _, p := range []*uint16{&family, &req.SubType, &flags, &seq, &cmd} {
		if err := binary.Read(body, binary.BigEndian, p); err != nil {
			return req, fmt.Errorf("reading directory SNAC header: %w", err)
		}
	}
	if family != ICQDirectorySNACFamily {
		return req, fmt.Errorf("unexpected directory SNAC family %#04x", family)
	}

	// QIP 2012 puts the meta request subtype into the nested SNAC instead of the
	// directory command, although the request is already identified by it from
	// the outside. Normalize it to the command: otherwise a profile lookup would
	// look unknown and be refused.
	switch req.SubType {
	case ICQDBQueryMetaReqDirectoryQuery:
		req.SubType = ICQDirectoryQueryInfo
	case ICQDBQueryMetaReqDirectoryUpdate:
		req.SubType = ICQDirectorySetInfo
	}

	// The extra block behind the header is present only with the 0x8000 bit.
	req.Versioned = flags&0x8000 != 0
	if req.Versioned {
		var extraLen uint16
		if err := binary.Read(body, binary.BigEndian, &extraLen); err != nil {
			return req, fmt.Errorf("reading directory SNAC extras length: %w", err)
		}
		if int(extraLen) > body.Len() {
			return req, errors.New("directory SNAC extras length exceeds payload")
		}
		body.Next(int(extraLen))
	}

	// Filler, code page and a constant. The client always writes them whatever
	// the request is (packServIcqDirectoryHeader), and the server ignores them.
	if body.Len() < 8 {
		return req, errors.New("directory request truncated before body")
	}
	body.Next(8)

	if err := binary.Read(body, binary.BigEndian, &req.Block); err != nil {
		return req, fmt.Errorf("reading directory block tag: %w", err)
	}

	switch {
	case req.SubType == ICQDirectorySetInfo:
		// The data length follows the block tag directly.
	case req.Block == ICQDirectoryBlockSearch:
		var count uint16
		if err := binary.Read(body, binary.BigEndian, &req.Page); err != nil {
			return req, fmt.Errorf("reading directory page: %w", err)
		}
		if err := binary.Read(body, binary.BigEndian, &count); err != nil {
			return req, fmt.Errorf("reading directory block count: %w", err)
		}
	default:
		var count uint32
		if err := binary.Read(body, binary.BigEndian, &count); err != nil {
			return req, fmt.Errorf("reading directory block count: %w", err)
		}
	}

	var dataLen uint16
	if err := binary.Read(body, binary.BigEndian, &dataLen); err != nil {
		return req, fmt.Errorf("reading directory data length: %w", err)
	}
	if int(dataLen) > body.Len() {
		return req, fmt.Errorf("directory data length %d exceeds %d bytes available", dataLen, body.Len())
	}

	tlvs := TLVRestBlock{}
	if err := UnmarshalBE(&tlvs, bytes.NewBuffer(body.Next(int(dataLen)))); err != nil {
		return req, fmt.Errorf("reading directory TLVs: %w", err)
	}
	req.TLVs = tlvs.TLVList

	return req, nil
}
