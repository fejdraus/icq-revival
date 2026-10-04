package foodgroup

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/charmap"

	"github.com/mk6i/open-oscar-server/wire"
)

// win1251 returns s, UTF-8, in the bytes of windows-1251.
func win1251(t *testing.T, s string) string {
	t.Helper()
	out, err := charmap.Windows1251.NewEncoder().String(s)
	require.NoError(t, err)
	return out
}

func TestClassicText_ICBMText(t *testing.T) {
	tests := []struct {
		name     string
		codePage string
		msg      func(t *testing.T) wire.ICBMCh1Message
		want     string
	}{
		{
			name:     "UCS-2 is decoded",
			codePage: "windows-1251",
			msg: func(t *testing.T) wire.ICBMCh1Message {
				return wire.ICBMCh1Message{Charset: wire.ICBMMessageEncodingUnicode, Text: encodeUTF16BE("Привет")}
			},
			want: "Привет",
		},
		{
			name:     "ASCII charset holding the code page",
			codePage: "windows-1251",
			msg: func(t *testing.T) wire.ICBMCh1Message {
				return wire.ICBMCh1Message{Charset: wire.ICBMMessageEncodingASCII, Text: []byte(win1251(t, "Привет"))}
			},
			want: "Привет",
		},
		{
			name:     "Latin-1 charset holding the code page",
			codePage: "windows-1251",
			msg: func(t *testing.T) wire.ICBMCh1Message {
				return wire.ICBMCh1Message{Charset: wire.ICBMMessageEncodingLatin1, Text: []byte(win1251(t, "Привет"))}
			},
			want: "Привет",
		},
		{
			name:     "UTF-8 stays",
			codePage: "windows-1251",
			msg: func(t *testing.T) wire.ICBMCh1Message {
				return wire.ICBMCh1Message{Charset: wire.ICBMMessageEncodingASCII, Text: []byte("Привет")}
			},
			want: "Привет",
		},
		{
			name: "no code page reads Latin-1",
			msg: func(t *testing.T) wire.ICBMCh1Message {
				return wire.ICBMCh1Message{Charset: wire.ICBMMessageEncodingLatin1, Text: []byte("caf\xe9")}
			},
			want: "café",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := NewClassicText(tt.codePage)
			require.NoError(t, err)
			assert.Equal(t, tt.want, ct.ICBMText(tt.msg(t)))
		})
	}
}

func TestPlainText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "ICQ 7 message",
			in:   `<HTML><BODY dir="ltr"><B><FONT color="#000000" size="2" face="Arial">Привет</FONT></B></BODY></HTML>`,
			want: "Привет",
		},
		{
			name: "entities, line breaks, nested tags",
			in:   `<HTML><B>a &amp; b<BR>c &lt;d&gt;<FONT><I>е</I></FONT></B></HTML>`,
			want: "a & b\nc <d>е",
		},
		{
			name: "plain text with a sign stays",
			in:   "a < b & c",
			want: "a < b & c",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, PlainText(tt.in))
		})
	}
}

// TestStripHTMLFromICBMTLV_UCS2 checks that a UCS-2 message - ICQ 7 sends its
// HTML so - reaches a client that reads no HTML as plain text, still UCS-2.
func TestStripHTMLFromICBMTLV_UCS2(t *testing.T) {
	msg := wire.ICBMCh1Message{
		Charset: wire.ICBMMessageEncodingUnicode,
		Text:    encodeUTF16BE(`<HTML><BODY dir="ltr"><B>Привет<BR>мир</B></BODY></HTML>`),
	}
	msgBuf := bytes.Buffer{}
	require.NoError(t, wire.MarshalBE(msg, &msgBuf))
	payload, err := wire.MarshalICBMFragmentList([]wire.ICBMCh1Fragment{
		{ID: 5, Version: 1, Payload: []byte{1, 1, 2}},
		{ID: 1, Version: 1, Payload: msgBuf.Bytes()},
	})
	require.NoError(t, err)

	got, err := stripHTMLFromICBMTLV(wire.NewTLVBE(wire.ICBMTLVAOLIMData, payload))
	require.NoError(t, err)

	var frags []wire.ICBMCh1Fragment
	require.NoError(t, wire.UnmarshalBE(&frags, bytes.NewReader(got.Value)))
	out := wire.ICBMCh1Message{}
	require.NoError(t, wire.UnmarshalBE(&out, bytes.NewReader(frags[1].Payload)))
	assert.Equal(t, wire.ICBMMessageEncodingUnicode, out.Charset)
	assert.Equal(t, "Привет\nмир", decodeUTF16BE(out.Text))
}
