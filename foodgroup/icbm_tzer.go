package foodgroup

import (
	"bytes"
	"encoding/binary"
	"html"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// A tZer, the short Flash movie ICQ 6 plays over the message window, travels
// as an ICQ plugin message: a channel 2 proposal with CapICQCh2Extended whose
// service data (TLV 0x2711) names the tZer plugin and its "Send Tzer"
// function, followed by a document such as
//
//	<tzerRoot id="cantH" url="http://.../canthearu.swf"
//	    thumb="http://.../canthearu.png" name=" Вас не чути" freeData=""/>
//
// with the name in UTF-8, in the sender's language.
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

// tzerText reports whether the channel 2 message inBody is a tZer the
// recipient recip can't play and, if it is, returns the text it is sent in
// its place: "tZer: <name>". Clients that announce CapICQTZers (ICQ 5.1 and
// later, and Miranda NG with the ICQ Revival plugin) get the tZer itself;
// everyone else would show nothing at all.
func tzerText(inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost, recip *state.Session) (string, bool) {
	if inBody.ChannelID != wire.ICBMChannelRendezvous || recip.HasCap(wire.CapICQTZers) {
		return "", false
	}
	b, ok := inBody.Bytes(wire.ICBMTLVData)
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
	if at < 0 || !bytes.Contains(svc[at:], tzerFunction) {
		return "", false
	}
	m := tzerName.FindSubmatch(svc[at:])
	if m == nil {
		return "tZer", true
	}
	name := strings.TrimSpace(html.UnescapeString(string(m[1])))
	if name == "" {
		return "tZer", true
	}
	return "tZer: " + name, true
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
