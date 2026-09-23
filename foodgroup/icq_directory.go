package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"strconv"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// Handling of the ICQ "directory" protocol, the one used by clients from ICQ 6
// onwards. The classic meta protocol lives in icq.go and stays in service: the
// client picks the dialect, not the server.
//
// Three actions travel under two meta request subtypes: a profile lookup and a
// search both use ICQDirectoryQueryInfo and differ only by the block tag, while
// saving one's own profile uses ICQDirectorySetInfo.

// DirectoryQuery answers a directory profile lookup or search.
func (s *ICQService) DirectoryQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, req wire.ICQDirectoryRequest, seq uint16) error {
	switch req.SubType {
	case wire.ICQDirectoryQueryInfo, wire.ICQDirectoryQueryMultiInfo:
	default:
		return s.directoryError(ctx, instance, inFrame.RequestID, seq, req)
	}

	if req.IsSearch() {
		return s.directorySearch(ctx, instance, inFrame, req, seq)
	}

	uid, ok := req.UID()
	if !ok {
		return s.directoryError(ctx, instance, inFrame.RequestID, seq, req)
	}

	uin, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return s.directoryError(ctx, instance, inFrame.RequestID, seq, req)
	}

	user, err := s.userFinder.FindByUIN(ctx, uint32(uin))
	if err != nil {
		return s.directoryError(ctx, instance, inFrame.RequestID, seq, req)
	}

	// The client tells its own profile from someone else's by the result byte:
	// its own is stored as account state, another's as buddy details.
	result := wire.ICQDirectoryResultOK
	if uint32(uin) == instance.UIN() {
		result = wire.ICQDirectoryResultOKOwner
	}

	item, err := directoryProfile(user, uid)
	if err != nil {
		return err
	}

	s.logger.DebugContext(ctx, "directory query answered",
		"requester", instance.UIN(),
		"client", instance.ClientID(),
		"target", uid,
		"result", result,
		"versioned", req.Versioned,
		"item_bytes", len(item))

	payload, err := wire.ICQDirectoryPayload(wire.ICQDirectoryQueryInfoAck, result, item, 1, 1, false, req.Versioned)
	if err != nil {
		return err
	}
	return s.directoryReply(ctx, instance, payload, inFrame.RequestID, seq, 0)
}

// DirectoryUpdate stores a profile sent by a client the directory way.
//
// Miranda takes this path regardless of its "Legacy fix" setting: it never
// uploads a profile the classic way.
func (s *ICQService) DirectoryUpdate(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, req wire.ICQDirectoryRequest, seq uint16) error {
	result := wire.ICQDirectoryResultOK
	if err := s.applyDirectoryProfile(ctx, instance, req.TLVs); err != nil {
		s.logger.ErrorContext(ctx, "directory update failed", "requester", instance.UIN(), "err", err.Error())
		result = 0
	} else {
		s.logger.DebugContext(ctx, "directory update applied", "requester", instance.UIN(), "fields", len(req.TLVs))
	}

	payload, err := wire.ICQDirectoryUpdateAck(result, req.Versioned)
	if err != nil {
		return err
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x0FAA_DBQueryMetaReplyDirectory{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyDirectoryUpdateAck,
			Success:    wire.ICQStatusCodeOK,
			Payload:    payload,
		},
	}
	return s.reply(ctx, instance, msg, inFrame.RequestID, 0)
}

// directorySearch answers a directory search.
//
// A client parses exactly one hit per packet, so every hit is sent on its own.
// The more-to-come flag must be set both in the SNAC and inside the directory
// block - the client checks both, and closes the search on the last packet.
func (s *ICQService) directorySearch(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, req wire.ICQDirectoryRequest, seq uint16) error {
	users, err := s.userFinder.SearchICQUsers(ctx, directorySearchCriteria(req.TLVs))
	if err != nil {
		s.logger.ErrorContext(ctx, "directory search failed", "requester", instance.UIN(), "err", err.Error())
		return s.directoryError(ctx, instance, inFrame.RequestID, seq, req)
	}

	s.logger.DebugContext(ctx, "directory search answered",
		"requester", instance.UIN(),
		"client", instance.ClientID(),
		"page", req.Page,
		"versioned", req.Versioned,
		"found", len(users))

	if len(users) == 0 {
		// An empty result is one packet with a zero block count. The client closes
		// the search on it; without it the client would wait forever.
		payload, err := wire.ICQDirectoryPayload(wire.ICQDirectoryQueryInfoAck, wire.ICQDirectoryResultOK, nil, 0, 1, false, req.Versioned)
		if err != nil {
			return err
		}
		return s.directoryReply(ctx, instance, payload, inFrame.RequestID, seq, 0)
	}

	total := uint32(len(users))
	for i, user := range users {
		last := i == len(users)-1

		item, err := directorySearchHit(user)
		if err != nil {
			return err
		}

		payload, err := wire.ICQDirectoryPayload(wire.ICQDirectoryQueryInfoAck, wire.ICQDirectoryResultOK, item, total, 1, !last, req.Versioned)
		if err != nil {
			return err
		}

		var snacFlags uint16
		if !last {
			snacFlags = wire.SNACFlagsMoreToCome
		}
		if err := s.directoryReply(ctx, instance, payload, inFrame.RequestID, seq, snacFlags); err != nil {
			return err
		}
	}
	return nil
}

// directoryReply sends a prepared directory block.
//
// The subtype is "response", not "data": clients parse both, but the
// acknowledgement that stops the spinner in the details window and closes a
// search is sent only for "response" (fam_15icqserver.cpp, the
// META_DIRECTORY_RESPONSE branches). On "data" the window hangs silently
// forever - there is no timeout. So "data" is used only for the intermediate
// packets of a result set.
func (s *ICQService) directoryReply(ctx context.Context, instance *state.SessionInstance, payload []byte, requestID uint32, seq uint16, snacFlags uint16) error {
	subType := wire.ICQDBQueryMetaReplyDirectoryResponse
	if snacFlags&wire.SNACFlagsMoreToCome != 0 {
		subType = wire.ICQDBQueryMetaReplyDirectoryData
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x0FAA_DBQueryMetaReplyDirectory{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: subType,
			Success:    wire.ICQStatusCodeOK,
			Payload:    payload,
		},
	}
	return s.reply(ctx, instance, msg, requestID, snacFlags)
}

// directoryError answers with a refusal in the directory envelope. Without it
// the client would wait for an answer forever: it has no timeout.
func (s *ICQService) directoryError(ctx context.Context, instance *state.SessionInstance, requestID uint32, seq uint16, req wire.ICQDirectoryRequest) error {
	s.logger.DebugContext(ctx, "directory query refused", "requester", instance.UIN(), "sub_type", req.SubType)

	payload, err := wire.ICQDirectoryPayload(req.SubType, 0, nil, 0, 0, false, req.Versioned)
	if err != nil {
		return err
	}
	return s.directoryReply(ctx, instance, payload, requestID, seq, 0)
}

// directorySearchCriteria converts the search conditions into the ones the
// store uses. The tags are the same as in a profile.
func directorySearchCriteria(tlvs wire.TLVList) state.ICQUserSearchCriteria {
	var c state.ICQUserSearchCriteria

	if uid, ok := tlvs.String(wire.ICQDirTagUID); ok && uid != "" {
		if uin, err := strconv.ParseUint(uid, 10, 32); err == nil {
			v := uint32(uin)
			c.UIN = &v
		}
	}
	for _, f := range []struct {
		tag uint16
		dst **string
	}{
		{wire.ICQDirTagFirstName, &c.FirstName},
		{wire.ICQDirTagLastName, &c.LastName},
		{wire.ICQDirTagNickname, &c.NickName},
		{wire.ICQDirTagEmail, &c.Email},
	} {
		if v, ok := tlvs.String(f.tag); ok && v != "" {
			val := v
			*f.dst = &val
		}
	}
	return c
}

// directorySearchHit builds one search hit.
//
// The layout differs from a profile: the client reads the country as four bytes
// straight from the home address TLV, with no record list around it
// (fam_15icqserver.cpp, parseDirectorySearchData).
func directorySearchHit(user state.User) ([]byte, error) {
	basic := user.ICQInfo.Basic
	more := user.ICQInfo.More

	tlvs := wire.TLVList{}
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTagUID, user.IdentScreenName.String()))

	appendDirString(&tlvs, wire.ICQDirTagFirstName, basic.FirstName)
	appendDirString(&tlvs, wire.ICQDirTagLastName, basic.LastName)
	appendDirString(&tlvs, wire.ICQDirTagNickname, basic.Nickname)
	appendDirString(&tlvs, wire.ICQDirTagEmail, basic.EmailAddress)

	if gender := directoryGender(more.Gender); gender != wire.ICQDirGenderUnknown {
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTagGender, gender))
	}
	if days, ok := wire.ICQDirDate(more.BirthYear, more.BirthMonth, more.BirthDay); ok {
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTagBirthDate, dirDateBytes(days)))
	}

	authOptional := uint8(0)
	if !user.ICQInfo.Permissions.AuthRequired {
		authOptional = 1
	}
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTagAuthOptional, authOptional))

	if basic.CountryCode != 0 {
		addr := wire.TLVList{}
		addr.Append(wire.NewTLVBE(wire.ICQDirAddrCountry, uint32(basic.CountryCode)))
		blob := &bytes.Buffer{}
		if err := wire.MarshalBE(wire.TLVRestBlock{TLVList: addr}, blob); err != nil {
			return nil, err
		}
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTagHomeAddress, blob.Bytes()))
	}

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(wire.TLVRestBlock{TLVList: tlvs}, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// applyDirectoryProfile stores a profile that was sent in. Sections missing
// from the message are left untouched: a client sends only what is filled in.
func (s *ICQService) applyDirectoryProfile(ctx context.Context, instance *state.SessionInstance, tlvs wire.TLVList) error {
	name := instance.IdentScreenName()

	user, err := s.userFinder.FindByUIN(ctx, instance.UIN())
	if err != nil {
		return err
	}

	basic := user.ICQInfo.Basic
	more := user.ICQInfo.More
	work := user.ICQInfo.Work
	perms := user.ICQInfo.Permissions

	takeString(tlvs, wire.ICQDirTagFirstName, &basic.FirstName)
	takeString(tlvs, wire.ICQDirTagLastName, &basic.LastName)
	takeString(tlvs, wire.ICQDirTagNickname, &basic.Nickname)
	takeString(tlvs, wire.ICQDirTagEmail, &basic.EmailAddress)
	takeString(tlvs, wire.ICQDirTagHomepage, &more.HomePageAddr)

	if v, ok := tlvs.Uint8(wire.ICQDirTagGender); ok {
		switch v {
		case wire.ICQDirGenderFemale:
			more.Gender = 1
		case wire.ICQDirGenderMale:
			more.Gender = 2
		default:
			more.Gender = 0
		}
	}
	if b, ok := tlvs.Bytes(wire.ICQDirTagBirthDate); ok && len(b) == 8 {
		days := math.Float64frombits(binary.BigEndian.Uint64(b))
		if y, m, d, ok := wire.ICQDirDateParse(days); ok {
			more.BirthYear, more.BirthMonth, more.BirthDay = y, m, d
		}
	}
	// Languages arrive as two bytes, not one: reading the first byte yielded
	// zero and the spoken languages were lost. Miranda reads them with the same
	// getNumber that understands 1, 2 and 4 bytes.
	takeLang(tlvs, wire.ICQDirTagLang1, &more.Lang1)
	takeLang(tlvs, wire.ICQDirTagLang2, &more.Lang2)
	takeLang(tlvs, wire.ICQDirTagLang3, &more.Lang3)
	takeLang(tlvs, wire.ICQDirTagMaritalState, &more.MaritalStatus)
	takeByte(tlvs, wire.ICQDirTagTimezone, &basic.GMTOffset)

	// The tag means "authorization not required", the inverse of what is stored.
	if v, ok := tlvs.Uint8(wire.ICQDirTagAuthOptional); ok {
		perms.AuthRequired = v == 0
	}
	if v, ok := tlvs.Uint8(wire.ICQDirTagWebAware); ok {
		perms.WebAware = v != 0
	}
	if v, ok := tlvs.Uint8(wire.ICQDirTagAllowSpam); ok {
		perms.AllowSpam = v != 0
	}

	if rec, ok := firstDirRecord(tlvs, wire.ICQDirTagHomeAddress); ok {
		takeString(rec, wire.ICQDirAddrStreet, &basic.Address)
		takeString(rec, wire.ICQDirAddrCity, &basic.City)
		takeString(rec, wire.ICQDirAddrState, &basic.State)
		takeString(rec, wire.ICQDirAddrZIP, &basic.ZIPCode)
		takeCode(rec, wire.ICQDirAddrCountry, &basic.CountryCode)
	}
	if rec, ok := firstDirRecord(tlvs, wire.ICQDirTagOrigin); ok {
		takeString(rec, wire.ICQDirAddrCity, &basic.OriginallyFromCity)
		takeString(rec, wire.ICQDirAddrState, &basic.OriginallyFromState)
		takeCode(rec, wire.ICQDirAddrCountry, &basic.OriginallyFromCountryCode)
	}
	if rec, ok := firstDirRecord(tlvs, wire.ICQDirTagCompany); ok {
		takeString(rec, wire.ICQDirWorkPosition, &work.Position)
		takeString(rec, wire.ICQDirWorkCompany, &work.Company)
		takeString(rec, wire.ICQDirWorkDepartment, &work.Department)
		takeString(rec, wire.ICQDirWorkHomepage, &work.WebPage)
		// A zero here does not wipe what is already stored: the directory dialect
		// has no occupation field at all - it carries an industry in that place -
		// and clients that do keep an occupation send it only in the classic
		// request (tag 0x01CC). QIP sends both requests in a row, and the zero
		// industry from the second one erased the occupation saved by the first.
		// Miranda marks the very same spot in its code as "Lost In Conversion".
		var industry uint16
		takeCode(rec, wire.ICQDirWorkIndustry, &industry)
		if industry != 0 {
			work.OccupationCode = industry
		}
		takeString(rec, wire.ICQDirWorkStreet, &work.Address)
		takeString(rec, wire.ICQDirWorkCity, &work.City)
		takeString(rec, wire.ICQDirWorkState, &work.State)
		takeString(rec, wire.ICQDirWorkZIP, &work.ZIPCode)
		takeCode(rec, wire.ICQDirWorkCountry, &work.CountryCode)
	}

	// Phones arrive as a single list with a kind on every entry, but are stored
	// in separate fields. The list is sent whole, so it replaces all five
	// fields: otherwise a number erased in the client stays in the profile
	// forever.
	if tlvs.HasTag(wire.ICQDirTagPhones) {
		basic.Phone, basic.CellPhone, basic.Fax = "", "", ""
		work.Phone, work.Fax = "", ""
	}
	for _, rec := range dirRecords(tlvs, wire.ICQDirTagPhones) {
		number, _ := rec.String(wire.ICQDirPhoneNumber)
		kind, _ := rec.Uint16BE(wire.ICQDirPhoneType)
		switch kind {
		case wire.ICQDirPhoneTypeHome:
			basic.Phone = number
		case wire.ICQDirPhoneTypeWork:
			work.Phone = number
		case wire.ICQDirPhoneTypeCellular:
			basic.CellPhone = number
		case wire.ICQDirPhoneTypeFax:
			basic.Fax = number
		case wire.ICQDirPhoneTypeWorkFax:
			work.Fax = number
		}
	}

	if err := s.userUpdater.SetBasicInfo(ctx, name, basic); err != nil {
		return err
	}
	if err := s.userUpdater.SetMoreInfo(ctx, name, more); err != nil {
		return err
	}
	if err := s.userUpdater.SetWorkInfo(ctx, name, work); err != nil {
		return err
	}
	if err := s.userUpdater.SetPermissions(ctx, name, perms); err != nil {
		return err
	}

	if about, ok := tlvs.String(wire.ICQDirTagAbout); ok {
		if err := s.userUpdater.SetUserNotes(ctx, name, state.ICQUserNotes{Notes: about}); err != nil {
			return err
		}
	}

	if recs := dirRecords(tlvs, wire.ICQDirTagInterests); len(recs) > 0 {
		var in state.ICQInterests
		dst := []struct {
			code    *uint16
			keyword *string
		}{
			{&in.Code1, &in.Keyword1},
			{&in.Code2, &in.Keyword2},
			{&in.Code3, &in.Keyword3},
			{&in.Code4, &in.Keyword4},
		}
		for i, rec := range recs {
			if i >= len(dst) {
				break
			}
			if v, ok := rec.String(wire.ICQDirInterestText); ok {
				*dst[i].keyword = v
			}
			takeCode(rec, wire.ICQDirInterestCat, dst[i].code)
			in.Count++
		}
		if err := s.userUpdater.SetInterests(ctx, name, in); err != nil {
			return err
		}
	}

	return nil
}

// dirRecords parses a nested record list: a count, then every record preceded
// by its own length.
func dirRecords(tlvs wire.TLVList, tag uint16) []wire.TLVList {
	blob, ok := tlvs.Bytes(tag)
	if !ok || len(blob) < 2 {
		return nil
	}

	buf := bytes.NewBuffer(blob)
	var count uint16
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return nil
	}

	var out []wire.TLVList
	for i := 0; i < int(count); i++ {
		var size uint16
		if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
			return out
		}
		if int(size) > buf.Len() {
			return out
		}
		chain := wire.TLVRestBlock{}
		if err := wire.UnmarshalBE(&chain, bytes.NewBuffer(buf.Next(int(size)))); err != nil {
			return out
		}
		out = append(out, chain.TLVList)
	}
	return out
}

func firstDirRecord(tlvs wire.TLVList, tag uint16) (wire.TLVList, bool) {
	recs := dirRecords(tlvs, tag)
	if len(recs) == 0 {
		return nil, false
	}
	return recs[0], true
}

func takeString(tlvs wire.TLVList, tag uint16, dst *string) {
	if v, ok := tlvs.String(tag); ok {
		*dst = v
	}
}

// takeLang reads a language code whatever length it arrives in.
func takeLang(tlvs wire.TLVList, tag uint16, dst *uint8) {
	var v uint16
	takeCode(tlvs, tag, &v)
	if v != 0 {
		*dst = uint8(v)
	}
}

func takeByte(tlvs wire.TLVList, tag uint16, dst *uint8) {
	if v, ok := tlvs.Uint8(tag); ok {
		*dst = v
	}
}

// takeCode reads a numeric code from a record: a country, an industry, an
// interest category.
//
// Clients disagree on the length: Miranda and ICQ 6 write two bytes, QIP 2012
// writes four. Reading the first two bytes of a four-byte value gives zeros,
// which is how both the country and the occupation went missing.
func takeCode(tlvs wire.TLVList, tag uint16, dst *uint16) {
	b, ok := tlvs.Bytes(tag)
	if !ok {
		return
	}
	switch len(b) {
	case 1:
		*dst = uint16(b[0])
	case 2:
		*dst = binary.BigEndian.Uint16(b)
	case 4:
		*dst = uint16(binary.BigEndian.Uint32(b))
	}
}

// directoryProfile lays a profile out into the directory protocol tags.
func directoryProfile(user state.User, uid string) ([]byte, error) {
	basic := user.ICQInfo.Basic
	more := user.ICQInfo.More
	work := user.ICQInfo.Work

	tlvs := wire.TLVList{}
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTagUID, uid))

	appendDirString(&tlvs, wire.ICQDirTagFirstName, basic.FirstName)
	appendDirString(&tlvs, wire.ICQDirTagLastName, basic.LastName)
	appendDirString(&tlvs, wire.ICQDirTagNickname, basic.Nickname)
	appendDirString(&tlvs, wire.ICQDirTagAbout, user.ICQInfo.Notes.Notes)
	appendDirString(&tlvs, wire.ICQDirTagHomepage, more.HomePageAddr)

	// The primary e-mail goes in a tag of its own rather than in the list: that
	// is the one the client shows and the only one it treats as verified.
	appendDirString(&tlvs, wire.ICQDirTagEmail, basic.EmailAddress)

	if gender := directoryGender(more.Gender); gender != wire.ICQDirGenderUnknown {
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTagGender, gender))
	}
	if days, ok := wire.ICQDirDate(more.BirthYear, more.BirthMonth, more.BirthDay); ok {
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTagBirthDate, dirDateBytes(days)))
	}

	// Two bytes, the length the client itself sends them in.
	appendDirWord(&tlvs, wire.ICQDirTagLang1, uint16(more.Lang1))
	appendDirWord(&tlvs, wire.ICQDirTagLang2, uint16(more.Lang2))
	appendDirWord(&tlvs, wire.ICQDirTagLang3, uint16(more.Lang3))
	appendDirWord(&tlvs, wire.ICQDirTagMaritalState, uint16(more.MaritalStatus))
	appendDirByte(&tlvs, wire.ICQDirTagTimezone, basic.GMTOffset)

	// The tag means "authorization not required", the inverse of what is stored.
	authOptional := uint8(0)
	if !user.ICQInfo.Permissions.AuthRequired {
		authOptional = 1
	}
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTagAuthOptional, authOptional))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTagWebAware, boolByte(user.ICQInfo.Permissions.WebAware)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTagAllowSpam, boolByte(user.ICQInfo.Permissions.AllowSpam)))

	if err := appendDirRecords(&tlvs, wire.ICQDirTagHomeAddress, directoryAddress(user)); err != nil {
		return nil, err
	}
	if err := appendDirRecords(&tlvs, wire.ICQDirTagOrigin, directoryOrigin(user)); err != nil {
		return nil, err
	}
	if err := appendDirRecords(&tlvs, wire.ICQDirTagPhones, directoryPhones(user)); err != nil {
		return nil, err
	}
	if err := appendDirRecords(&tlvs, wire.ICQDirTagEmails, directoryEmails(user)); err != nil {
		return nil, err
	}
	if err := appendDirRecords(&tlvs, wire.ICQDirTagCompany, directoryCompany(work)); err != nil {
		return nil, err
	}
	if err := appendDirRecords(&tlvs, wire.ICQDirTagInterests, directoryInterests(user)); err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(wire.TLVRestBlock{TLVList: tlvs}, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dirDateBytes encodes a date: the client expects a float holding the number of
// days since the epoch.
func dirDateBytes(days float64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], math.Float64bits(days))
	return buf[:]
}

// appendDirRecords adds a nested record list. An empty list is not sent at all:
// it would wipe the data the client already has.
func appendDirRecords(tlvs *wire.TLVList, tag uint16, records []wire.ICQDirRecord) error {
	if len(records) == 0 {
		return nil
	}
	blob, err := wire.ICQDirRecordList(records)
	if err != nil {
		return err
	}
	tlvs.Append(wire.NewTLVBE(tag, blob))
	return nil
}

func directoryAddress(user state.User) []wire.ICQDirRecord {
	basic := user.ICQInfo.Basic
	rec := wire.TLVList{}
	appendDirString(&rec, wire.ICQDirAddrStreet, basic.Address)
	appendDirString(&rec, wire.ICQDirAddrCity, basic.City)
	appendDirString(&rec, wire.ICQDirAddrState, basic.State)
	appendDirString(&rec, wire.ICQDirAddrZIP, basic.ZIPCode)
	appendDirCode(&rec, wire.ICQDirAddrCountry, basic.CountryCode)
	if len(rec) == 0 {
		return nil
	}
	return []wire.ICQDirRecord{{TLVList: rec}}
}

func directoryOrigin(user state.User) []wire.ICQDirRecord {
	basic := user.ICQInfo.Basic
	rec := wire.TLVList{}
	appendDirString(&rec, wire.ICQDirAddrCity, basic.OriginallyFromCity)
	appendDirString(&rec, wire.ICQDirAddrState, basic.OriginallyFromState)
	appendDirCode(&rec, wire.ICQDirAddrCountry, basic.OriginallyFromCountryCode)
	if len(rec) == 0 {
		return nil
	}
	return []wire.ICQDirRecord{{TLVList: rec}}
}

func directoryPhones(user state.User) []wire.ICQDirRecord {
	basic := user.ICQInfo.Basic
	work := user.ICQInfo.Work

	var out []wire.ICQDirRecord
	for _, p := range []struct {
		number string
		kind   uint16
	}{
		{basic.Phone, wire.ICQDirPhoneTypeHome},
		{work.Phone, wire.ICQDirPhoneTypeWork},
		{basic.CellPhone, wire.ICQDirPhoneTypeCellular},
		{basic.Fax, wire.ICQDirPhoneTypeFax},
		{work.Fax, wire.ICQDirPhoneTypeWorkFax},
	} {
		if p.number == "" {
			continue
		}
		rec := wire.TLVList{}
		rec.Append(wire.NewTLVBE(wire.ICQDirPhoneNumber, p.number))
		rec.Append(wire.NewTLVBE(wire.ICQDirPhoneType, p.kind))
		out = append(out, wire.ICQDirRecord{TLVList: rec})
	}
	return out
}

// directoryEmails returns the extra addresses, the ones beyond the primary.
//
// The primary goes out in the ICQDirTagEmail tag of its own and must not be
// repeated here: the client would show the same address twice, the second time
// in the list of extras (Miranda labels that row "2"). The profile holds no
// more than one address for now, so the list is always empty.
func directoryEmails(state.User) []wire.ICQDirRecord {
	return nil
}

func directoryCompany(work state.ICQWorkInfo) []wire.ICQDirRecord {
	rec := wire.TLVList{}
	appendDirString(&rec, wire.ICQDirWorkPosition, work.Position)
	appendDirString(&rec, wire.ICQDirWorkCompany, work.Company)
	appendDirString(&rec, wire.ICQDirWorkDepartment, work.Department)
	appendDirString(&rec, wire.ICQDirWorkHomepage, work.WebPage)
	appendDirWord(&rec, wire.ICQDirWorkIndustry, work.OccupationCode)
	appendDirString(&rec, wire.ICQDirWorkStreet, work.Address)
	appendDirString(&rec, wire.ICQDirWorkCity, work.City)
	appendDirString(&rec, wire.ICQDirWorkState, work.State)
	appendDirString(&rec, wire.ICQDirWorkZIP, work.ZIPCode)
	appendDirCode(&rec, wire.ICQDirWorkCountry, work.CountryCode)
	if len(rec) == 0 {
		return nil
	}
	return []wire.ICQDirRecord{{TLVList: rec}}
}

func directoryInterests(user state.User) []wire.ICQDirRecord {
	in := user.ICQInfo.Interests

	var out []wire.ICQDirRecord
	for _, it := range []struct {
		code    uint16
		keyword string
	}{
		{in.Code1, in.Keyword1},
		{in.Code2, in.Keyword2},
		{in.Code3, in.Keyword3},
		{in.Code4, in.Keyword4},
	} {
		if it.keyword == "" && it.code == 0 {
			continue
		}
		rec := wire.TLVList{}
		rec.Append(wire.NewTLVBE(wire.ICQDirInterestText, it.keyword))
		rec.Append(wire.NewTLVBE(wire.ICQDirInterestCat, it.code))
		out = append(out, wire.ICQDirRecord{TLVList: rec})
	}
	return out
}

// directoryGender converts gender from the stored form into the directory one.
// The two protocols use different values, so a translation is unavoidable.
func directoryGender(gender uint16) uint8 {
	switch gender {
	case 1:
		return wire.ICQDirGenderFemale
	case 2:
		return wire.ICQDirGenderMale
	default:
		return wire.ICQDirGenderUnknown
	}
}

// Empty fields are not sent at all: the client tells "no value" from "empty
// string" and in the latter case wipes what it has already stored.
func appendDirString(tlvs *wire.TLVList, tag uint16, value string) {
	if value == "" {
		return
	}
	tlvs.Append(wire.NewTLVBE(tag, value))
}

func appendDirByte(tlvs *wire.TLVList, tag uint16, value uint8) {
	if value == 0 {
		return
	}
	tlvs.Append(wire.NewTLVBE(tag, value))
}

// appendDirCode writes a country code as four bytes.
//
// The length of every numeric field has to mirror the client: QIP 2012 sends a
// country as four bytes and does not read a two-byte one at all, while it sends
// the industry, the languages and the interest category as two bytes and does
// not read four-byte ones either. Miranda and ICQ 6 accept any length: the
// getNumber in their parser understands 1, 2 and 4 bytes (tlv.cpp). Our reading
// side tolerates any length, see takeCode.
func appendDirCode(tlvs *wire.TLVList, tag uint16, value uint16) {
	if value == 0 {
		return
	}
	tlvs.Append(wire.NewTLVBE(tag, uint32(value)))
}

func appendDirWord(tlvs *wire.TLVList, tag uint16, value uint16) {
	if value == 0 {
		return
	}
	tlvs.Append(wire.NewTLVBE(tag, value))
}

func boolByte(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}
