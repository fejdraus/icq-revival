package foodgroup

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// A tZer is a short Flash movie ICQ plays over the message window. Its body is
// a document such as
//
//	<tzerRoot id="cantH" url="http://.../canthearu.swf"
//	    thumb="http://.../canthearu.png" name=" Вас не чути" freeData=""/>
//
// with the name in the sender's language. The ICQ generations send it in two
// forms, and neither reads the other's:
//
//   - ICQ 6.5 (and Miranda NG with the ICQ Revival plugin) sends an ICQ
//     plugin message: a channel 2 proposal with CapICQCh2Extended whose
//     service data (TLV 0x2711) names the tZer plugin and its "Send Tzer"
//     function, followed by the document in UTF-8. See tzerPluginSvcData.
//   - ICQ 7.2 sends a channel 1 IM with a fragment 0x10 holding CapICQTZers
//     between the features fragment and the text fragment; the text is the
//     document in UCS-2BE. See tzerIMFragments.
//
// tzerForRecipient turns one form into the other, or into a line of text for
// a client that plays no tZers at all.
var (
	// tzerPluginGUID is the GUID of the tZer plugin, as it is written in the
	// service data: {4FA6F34C-09B7-FD48-9208-7E857AE07330}.
	tzerPluginGUID = []byte{
		0x4F, 0xA6, 0xF3, 0x4C, 0x09, 0xB7, 0xFD, 0x48,
		0x92, 0x08, 0x7E, 0x85, 0x7A, 0xE0, 0x73, 0x30,
	}
	// tzerFunction is the name of the plugin function that sends a tZer.
	tzerFunction = []byte("Send Tzer")
	// tzerName finds the name of the tZer in its document.
	tzerName = regexp.MustCompile(`(?s)<tzerRoot\b[^>]*?\bname="([^"]*)"`)
)

const (
	// tzerFragmentID is the ID of the channel 1 fragment by which ICQ 7.2
	// marks an IM as a tZer; its payload is CapICQTZers.
	tzerFragmentID uint8 = 0x10
	// tzerIMLanguage is the language field ICQ 7.2 writes in the text
	// fragment of a tZer. Its meaning is unknown; it is copied as sent.
	tzerIMLanguage uint16 = 0x002D
	// tzerPluginSeq is the sequence number ICQ 6.5 wrote in both headers of
	// the plugin message it sent.
	tzerPluginSeq uint16 = 0x0064
)

// tzerForm is the form a tZer travels in.
type tzerForm int

const (
	// tzerNone is a message that is not a tZer.
	tzerNone tzerForm = iota
	// tzerPlugin is a channel 2 ICQ plugin message, as ICQ 6.5 sends it.
	tzerPlugin
	// tzerIM is a channel 1 IM with the tZer fragment, as ICQ 7.2 sends it.
	tzerIM
)

// tzerInIM reports whether recip plays tZers only in the form ICQ 7.2 sends
// them, a channel 1 IM. ICQ 7.2 announces CapICQTZers but not
// CapICQCh2Extended, the ICQ server relay capability: it takes no ICQ type-2
// (channel 2) messages at all, which is why it drops the plugin form without
// a trace. ICQ 6.5 and Miranda announce both. The missing capability is the
// very reason the plugin form can't reach the client, so it is a better test
// than capabilities that merely happen to differ between the versions, such as
// CapSmartCaps or CapICQ6HTML.
func tzerInIM(recip *state.Session) bool {
	return recip.HasCap(wire.CapICQTZers) && !recip.HasCap(wire.CapICQCh2Extended)
}

// tzerForRecipient returns the channel and the message data TLV in which the
// message msg is delivered to recip when msg is a tZer that recip can't take
// as it is:
//
//   - to a client that plays no tZers: a channel 1 IM "tZer: <name>";
//   - to ICQ 7.2 (see tzerInIM): the channel 1 IM it sends itself;
//   - to ICQ 6.5 and Miranda: the channel 2 plugin message ICQ 6.5 sends.
//
// ok is false when msg is not a tZer or goes as it is. The returned TLV
// replaces all of msg's TLVs.
func tzerForRecipient(msg wire.SNAC_0x04_0x06_ICBMChannelMsgToHost, recip *state.Session) (channel uint16, tlv wire.TLV, ok bool, err error) {
	form, doc := parseTzer(msg)
	if form == tzerNone {
		return 0, wire.TLV{}, false, nil
	}

	switch {
	case !recip.HasCap(wire.CapICQTZers):
		frags, err := textFragments(tzerText(doc))
		if err != nil {
			return 0, wire.TLV{}, false, fmt.Errorf("textFragments: %w", err)
		}
		return wire.ICBMChannelIM, wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags), true, nil
	case doc == "":
		// nothing to rebuild the tZer from
		return 0, wire.TLV{}, false, nil
	case form == tzerPlugin && tzerInIM(recip):
		frags, err := tzerIMFragments(doc)
		if err != nil {
			return 0, wire.TLV{}, false, fmt.Errorf("tzerIMFragments: %w", err)
		}
		return wire.ICBMChannelIM, wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags), true, nil
	case form == tzerIM && !tzerInIM(recip):
		frag := wire.ICBMCh2Fragment{
			Type:       wire.ICBMRdvMessagePropose,
			Capability: wire.CapICQCh2Extended,
		}
		binary.BigEndian.PutUint64(frag.Cookie[:], msg.Cookie)
		frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)))
		frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequestHostChk, []byte{}))
		frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, tzerPluginSvcData(doc)))
		buf := bytes.Buffer{}
		if err := wire.MarshalBE(frag, &buf); err != nil {
			return 0, wire.TLV{}, false, fmt.Errorf("wire.MarshalBE: %w", err)
		}
		return wire.ICBMChannelRendezvous, wire.NewTLVBE(wire.ICBMTLVData, buf.Bytes()), true, nil
	default:
		return 0, wire.TLV{}, false, nil
	}
}

// parseTzer reports whether msg is a tZer, in which form, and returns its
// document in UTF-8. The document is empty when a plugin message names the
// tZer function but its body can't be read.
func parseTzer(msg wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (tzerForm, string) {
	switch msg.ChannelID {
	case wire.ICBMChannelRendezvous:
		doc, ok := parseTzerPlugin(msg)
		if !ok {
			return tzerNone, ""
		}
		return tzerPlugin, doc
	case wire.ICBMChannelIM:
		doc, ok := parseTzerIM(msg)
		if !ok {
			return tzerNone, ""
		}
		return tzerIM, doc
	default:
		return tzerNone, ""
	}
}

// parseTzerPlugin reads the channel 2 form of a tZer; see tzerPluginSvcData.
func parseTzerPlugin(msg wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (string, bool) {
	b, ok := msg.Bytes(wire.ICBMTLVData)
	if !ok {
		return "", false
	}
	frag := wire.ICBMCh2Fragment{}
	if err := wire.UnmarshalBE(&frag, bytes.NewReader(b)); err != nil {
		return "", false
	}
	if frag.Type != wire.ICBMRdvMessagePropose || frag.Capability != wire.CapICQCh2Extended {
		return "", false
	}
	svc, ok := frag.Bytes(wire.ICBMRdvTLVTagsSvcData)
	if !ok {
		return "", false
	}
	// the plugin's GUID and then, a few bytes on, its function's name
	at := bytes.Index(svc, tzerPluginGUID)
	if at < 2 || !bytes.Contains(svc[at:], tzerFunction) {
		return "", false
	}
	// The plugin header's length precedes the GUID; after the header come
	// the length of the rest and the length of the document.
	pos := at + int(binary.LittleEndian.Uint16(svc[at-2:]))
	if pos+8 > len(svc) {
		return "", true
	}
	docLen := int(binary.LittleEndian.Uint32(svc[pos+4:]))
	pos += 8
	if docLen > len(svc)-pos {
		return "", true
	}
	return string(svc[pos : pos+docLen]), true
}

// parseTzerIM reads the channel 1 form of a tZer; see tzerIMFragments.
func parseTzerIM(msg wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (string, bool) {
	b, ok := msg.Bytes(wire.ICBMTLVAOLIMData)
	if !ok {
		return "", false
	}
	var frags []wire.ICBMCh1Fragment
	if err := wire.UnmarshalBE(&frags, bytes.NewReader(b)); err != nil {
		return "", false
	}
	isTzer := false
	var text []byte
	charset := wire.ICBMMessageEncodingASCII
	for _, frag := range frags {
		switch frag.ID {
		case tzerFragmentID:
			isTzer = bytes.Equal(frag.Payload, wire.CapICQTZers[:])
		case 1: // the message text
			m := wire.ICBMCh1Message{}
			if err := wire.UnmarshalBE(&m, bytes.NewReader(frag.Payload)); err != nil {
				return "", false
			}
			text, charset = m.Text, m.Charset
		}
	}
	if !isTzer {
		return "", false
	}
	switch charset {
	case wire.ICBMMessageEncodingUnicode:
		units := make([]uint16, len(text)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(text[2*i:])
		}
		return string(utf16.Decode(units)), true
	case wire.ICBMMessageEncodingLatin1:
		runes := make([]rune, len(text))
		for i, c := range text {
			runes[i] = rune(c)
		}
		return string(runes), true
	default:
		return string(text), true
	}
}

// tzerText returns the text a tZer with the document doc is sent in to a
// client that plays no tZers: "tZer: <name>", or "tZer" when it has no name.
func tzerText(doc string) string {
	m := tzerName.FindStringSubmatch(doc)
	if m == nil {
		return "tZer"
	}
	name := strings.TrimSpace(html.UnescapeString(m[1]))
	if name == "" {
		return "tZer"
	}
	return "tZer: " + name
}

// tzerPluginSvcData returns the service data (TLV 0x2711) of a tZer with the
// document doc, byte for byte as ICQ 6.5 writes it (all little-endian):
//
//	1B 00           length of the first header
//	09 00           protocol version
//	00 x16          plugin GUID (none)
//	00 00           unknown
//	00 00 00 00     client capability flags
//	00              unknown
//	64 00           sequence
//	0E 00           length of the second header
//	64 00           sequence
//	00 x12          unknown
//	1A 00           message type (plugin), flags
//	00 00 01 00     status, priority
//	00 00           the message text: none
//	30 00           length of the plugin header
//	GUID            the tZer plugin
//	00 00           function ID
//	09 00 00 00     "Send Tzer"
//	00 x17          unknown
//	len+4 (dword)   length of the rest
//	len (dword)     the document, in UTF-8
func tzerPluginSvcData(doc string) []byte {
	b := &bytes.Buffer{}
	le16 := func(v uint16) { b.Write(binary.LittleEndian.AppendUint16(nil, v)) }
	le32 := func(v uint32) { b.Write(binary.LittleEndian.AppendUint32(nil, v)) }

	le16(0x1B)
	le16(9)
	b.Write(make([]byte, 16+2+4+1))
	le16(tzerPluginSeq)
	le16(0x0E)
	le16(tzerPluginSeq)
	b.Write(make([]byte, 12))
	b.Write([]byte{0x1A, 0x00})
	le16(0)
	le16(1)
	le16(0)

	le16(uint16(len(tzerPluginGUID) + 2 + 4 + len(tzerFunction) + 17))
	b.Write(tzerPluginGUID)
	le16(0)
	le32(uint32(len(tzerFunction)))
	b.Write(tzerFunction)
	b.Write(make([]byte, 17))

	le32(uint32(len(doc) + 4))
	le32(uint32(len(doc)))
	b.WriteString(doc)
	return b.Bytes()
}

// tzerIMFragments returns the fragments of a channel 1 tZer with the
// document doc, as ICQ 7.2 writes them:
//
//	05 01 00 01 01               features: text
//	10 01 00 10 <CapICQTZers>    the tZer mark
//	01 01 <len> 00 02 00 2D ...  the document in UCS-2BE
func tzerIMFragments(doc string) ([]wire.ICBMCh1Fragment, error) {
	units := utf16.Encode([]rune(doc))
	msg := wire.ICBMCh1Message{
		Charset:  wire.ICBMMessageEncodingUnicode,
		Language: tzerIMLanguage,
		Text:     make([]byte, 2*len(units)),
	}
	for i, u := range units {
		binary.BigEndian.PutUint16(msg.Text[2*i:], u)
	}
	msgBuf := bytes.Buffer{}
	if err := wire.MarshalBE(msg, &msgBuf); err != nil {
		return nil, err
	}
	return []wire.ICBMCh1Fragment{
		{ID: 5, Version: 1, Payload: []byte{1}},
		{ID: tzerFragmentID, Version: 1, Payload: wire.CapICQTZers[:]},
		{ID: 1, Version: 1, Payload: msgBuf.Bytes()},
	}, nil
}

// textFragments returns the fragments of a channel 1 message whose text is
// text: in ASCII when it is ASCII, otherwise in UCS-2, which every ICQ and AIM
// client reads.
func textFragments(text string) ([]wire.ICBMCh1Fragment, error) {
	ascii := true
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return wire.ICBMFragmentList(text)
	}

	units := utf16.Encode([]rune(text))
	msg := wire.ICBMCh1Message{
		Charset: wire.ICBMMessageEncodingUnicode,
		Text:    make([]byte, 2*len(units)),
	}
	for i, u := range units {
		binary.BigEndian.PutUint16(msg.Text[2*i:], u)
	}
	msgBuf := bytes.Buffer{}
	if err := wire.MarshalBE(msg, &msgBuf); err != nil {
		return nil, err
	}
	return []wire.ICBMCh1Fragment{
		{ID: 5, Version: 1, Payload: []byte{1, 1, 2}}, // capabilities: text
		{ID: 1, Version: 1, Payload: msgBuf.Bytes()},  // the message text
	}, nil
}
