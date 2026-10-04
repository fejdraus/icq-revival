package foodgroup

import (
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/mk6i/open-oscar-server/wire"
)

// Converts reports whether t converts text at all: false when no code page is
// configured and the classic clients' bytes pass through unchanged.
func (t ClassicText) Converts() bool {
	return t.enc != nil
}

// ICBMText returns the text of a channel 1 message as UTF-8, read in the
// charset the message names: UCS-2BE (0x0002) is decoded; ASCII (0x0000) and
// Latin-1 (0x0003) are what classic clients fill with the bytes of their code
// page, so text there that is not already UTF-8 is read in the classic code
// page, or as Latin-1 when none is configured.
func (t ClassicText) ICBMText(msg wire.ICBMCh1Message) string {
	if msg.Charset == wire.ICBMMessageEncodingUnicode {
		return decodeUTF16BE(msg.Text)
	}
	s := string(msg.Text)
	if utf8.ValidString(s) {
		return s
	}
	if t.enc != nil {
		return t.In(s)
	}
	return latin1ToUTF8(s)
}

// PlainText returns s, UTF-8, with its HTML markup taken out the way a client
// that reads no HTML is sent it: tags dropped, entities decoded, <BR> as a
// line break. Text with no tag in it comes back as it is, so a plain "a < b"
// keeps its sign.
func PlainText(s string) string {
	if !hasMarkup(s) {
		return s
	}
	return string(stripHTML([]byte(s)))
}

// ICBMTextFragments returns the fragments of a channel 1 message whose text
// is text, UTF-8: in ASCII when it is ASCII, otherwise in UCS-2, which every
// ICQ and AIM client reads.
func ICBMTextFragments(text string) ([]wire.ICBMCh1Fragment, error) {
	return textFragments(text)
}

// hasMarkup reports whether s holds something that looks like an HTML tag:
// '<' followed by a letter, '/' or '!'.
func hasMarkup(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		c := s[i+1]
		if c == '/' || c == '!' || (c|0x20 >= 'a' && c|0x20 <= 'z') {
			return true
		}
	}
	return false
}

// decodeUTF16BE turns UTF-16BE bytes into UTF-8, dropping NUL characters.
func decodeUTF16BE(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if u := binary.BigEndian.Uint16(b[i:]); u != 0 {
			units = append(units, u)
		}
	}
	return string(utf16.Decode(units))
}

// encodeUTF16BE turns UTF-8 into UTF-16BE bytes.
func encodeUTF16BE(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.BigEndian.PutUint16(b[2*i:], u)
	}
	return b
}

// latin1ToUTF8 reads each byte of s as the Latin-1 character of that value.
func latin1ToUTF8(s string) string {
	runes := make([]rune, len(s))
	for i := 0; i < len(s); i++ {
		runes[i] = rune(s[i])
	}
	return string(runes)
}
