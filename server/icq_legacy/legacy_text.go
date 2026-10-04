package icq_legacy

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/mk6i/open-oscar-server/foodgroup"
	"github.com/mk6i/open-oscar-server/wire"
)

// legacyText converts text between the legacy UDP clients (V2-V5, ICQ 95 to
// 99b) and the rest of the server.
//
// Those clients know no Unicode: they send and expect the bytes of the code
// page Windows runs them in - the same classic code page the OSCAR classic
// dialect (ICQ 99 to 2003) is configured with. The server keeps text as UTF-8
// and OSCAR clients send it as UCS-2, UTF-8 or HTML, so the legacy side is
// converted at its edge: what it sends becomes UTF-8, what it gets becomes
// plain text in its code page.
//
// The FE-separated fields of ICQ messages (URL, authorization, contacts) are
// converted one by one: 0xFE is no UTF-8 byte, so a whole message never reads
// as UTF-8.
//
// With no code page configured the bytes pass through as before; text from
// UCS-2 then goes out as Latin-1.
type legacyText struct {
	cp foodgroup.ClassicText
}

// toLegacy turns a UTF-8 text from the server into the legacy client's code
// page, field by field. Text that is not UTF-8 is already in a code page and
// stays as it is. A character the code page lacks becomes '?'.
func (t legacyText) toLegacy(s string) string {
	return mapFields(s, t.encode)
}

// fromLegacy turns a text a legacy client sent into UTF-8, field by field.
// Without a code page it stays as sent.
func (t legacyText) fromLegacy(s string) string {
	return mapFields(s, t.cp.In)
}

// messageToLegacy returns the text of an ICQ message for a legacy client:
// the markup of an HTML reader's message taken out, line breaks as CRLF and
// the text in the client's code page.
func (t legacyText) messageToLegacy(s string) string {
	if !utf8.ValidString(s) {
		// already a code page's bytes
		return crlf(s)
	}
	return t.encode(crlf(foodgroup.PlainText(s)))
}

// icbmToLegacy returns the text of an OSCAR channel 1 message for a legacy
// client, read in the charset the message names.
func (t legacyText) icbmToLegacy(msg wire.ICBMCh1Message) string {
	return t.encode(crlf(foodgroup.PlainText(t.cp.ICBMText(msg))))
}

// encode turns UTF-8 into the legacy client's code page, or into Latin-1
// when none is configured, as the bridge did before code pages.
func (t legacyText) encode(s string) string {
	if t.cp.Converts() {
		return t.cp.Out(s)
	}
	return utf8ToLatin1(s)
}

// icbmFromLegacy returns the ICBM payload to send OSCAR clients a plain text
// message a legacy client wrote: channel 1, in UCS-2 unless it is ASCII, so
// ICQ 6 and 7 and every other OSCAR client read it. It returns false when no
// code page is configured: the text cannot be read then and goes as sent.
func (t legacyText) icbmFromLegacy(text string) ([]byte, bool) {
	if !t.cp.Converts() {
		return nil, false
	}
	frags, err := foodgroup.ICBMTextFragments(t.cp.In(text))
	if err != nil {
		return nil, false
	}
	b, err := wire.MarshalICBMFragmentList(frags)
	if err != nil {
		return nil, false
	}
	return b, true
}

// icbmPayloadToLegacy returns the text of a channel 1 message - the value of
// its TLV 0x0002, a list of ICBM fragments - for a legacy client.
func (t legacyText) icbmPayloadToLegacy(payload []byte) (string, bool) {
	var frags []wire.ICBMCh1Fragment
	if err := wire.UnmarshalBE(&frags, bytes.NewBuffer(payload)); err != nil {
		return "", false
	}
	for _, frag := range frags {
		if frag.ID != 1 { // 1 = message text
			continue
		}
		msg := wire.ICBMCh1Message{}
		if err := wire.UnmarshalBE(&msg, bytes.NewBuffer(frag.Payload)); err != nil {
			return "", false
		}
		return t.icbmToLegacy(msg), true
	}
	return "", false
}

// ch4ToLegacy returns the text of an OSCAR channel 4 (ICQ) message for a
// legacy client: a plain message like any other, the FE-separated fields of
// the others (URL, authorization, contacts) one by one.
func (t legacyText) ch4ToLegacy(msg wire.ICBMCh4Message) string {
	if uint16(msg.MessageType) == ICQLegacyMsgText {
		return t.messageToLegacy(msg.Message)
	}
	return t.toLegacy(msg.Message)
}

// mapFields applies conv to each 0xFE-separated field of s.
func mapFields(s string, conv func(string) string) string {
	if !strings.Contains(s, "\xFE") {
		return conv(s)
	}
	parts := strings.Split(s, "\xFE")
	for i, p := range parts {
		parts[i] = conv(p)
	}
	return strings.Join(parts, "\xFE")
}

// crlf writes every line break as CRLF, the way the Windows clients show
// them.
func crlf(s string) string {
	if !strings.Contains(s, "\n") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}
