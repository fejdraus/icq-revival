package foodgroup

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"

	"github.com/mk6i/open-oscar-server/state"
)

// ClassicText converts the text of the classic ICQ dialect - the 0x07D0
// requests of ICQ 99 to 2003, flat blocks of strings - to and from what the
// server keeps.
//
// Those clients know no Unicode: they send and expect the bytes of the code
// page Windows runs them in, and the protocol does not say which. The newer
// clients (the ICQ 6 directory, the registration page) send UTF-8, and the
// database holds whatever each sent. So the classic side is converted at
// its edge: what it sends becomes UTF-8, what it gets becomes its code page.
//
// A text that is already valid UTF-8 is taken as it is. Cyrillic, Greek and
// the other single-byte code pages almost never form valid UTF-8, so this
// tells the two apart; plain ASCII is the same in both.
//
// The legacy UDP clients (ICQ 95 to 99b, server/icq_legacy) write in the
// same code page and are converted with it too.
type ClassicText struct {
	enc encoding.Encoding // nil: bytes pass through unchanged
}

// NewClassicText returns the converter for a code page named as in the
// WHATWG encoding list, e.g. "windows-1251". An empty name converts nothing.
func NewClassicText(codePage string) (ClassicText, error) {
	if codePage == "" {
		return ClassicText{}, nil
	}
	enc, err := htmlindex.Get(codePage)
	if err != nil {
		return ClassicText{}, fmt.Errorf("unknown code page %q: %w", codePage, err)
	}
	return ClassicText{enc: enc}, nil
}

// In turns a text from a classic client into UTF-8.
func (t ClassicText) In(s string) string {
	if t.enc == nil || utf8.ValidString(s) {
		return s
	}
	out, err := t.enc.NewDecoder().String(s)
	if err != nil {
		return s
	}
	return out
}

// Out turns UTF-8 into the classic client's code page. A character the code
// page lacks becomes '?'.
func (t ClassicText) Out(s string) string {
	if t.enc == nil || !utf8.ValidString(s) || isASCIIText(s) {
		return s
	}
	var b strings.Builder
	e := t.enc.NewEncoder()
	for _, r := range s {
		if enc, err := e.String(string(r)); err == nil {
			b.WriteString(enc)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

// InAll converts every string field of *v from the client, through nested
// structs and slices.
func (t ClassicText) InAll(v any) {
	if t.enc != nil {
		walkStrings(reflect.ValueOf(v).Elem(), t.In)
	}
}

// OutAll returns a copy of v, a struct, with every string field converted for
// the client.
func (t ClassicText) OutAll(v any) any {
	if t.enc == nil || v == nil {
		return v
	}
	src := reflect.ValueOf(v)
	cp := reflect.New(src.Type()).Elem()
	cp.Set(src)
	walkStrings(cp, t.Out)
	return cp.Interface()
}

func walkStrings(v reflect.Value, conv func(string) string) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(conv(v.String()))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			walkStrings(v.Field(i), conv)
		}
	case reflect.Slice:
		// A copy, so the caller's slice is left as it was.
		if v.CanSet() && v.Len() > 0 && v.Type().Elem().Kind() != reflect.Uint8 {
			cp := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
			reflect.Copy(cp, v)
			for i := 0; i < cp.Len(); i++ {
				walkStrings(cp.Index(i), conv)
			}
			v.Set(cp)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStrings(v.Index(i), conv)
		}
	case reflect.Pointer:
		// Only a pointer to a string: the search criteria are made of them.
		if !v.IsNil() && v.Elem().Kind() == reflect.String {
			walkStrings(v.Elem(), conv)
		}
	}
}

func isASCIIText(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

// classicZIP is a ZIP code as a classic client can show it. ICQ 2003b takes
// only a number from 1 to 99999 - a US ZIP code - and refuses to open the
// page of the details with anything else ("The field Zip is out of range").
// A code it cannot show, such as a six-digit postcode typed in ICQ 6, goes
// out empty.
func classicZIP(zip string) string {
	n, err := strconv.Atoi(strings.TrimSpace(zip))
	if err != nil || n < 1 || n > 99999 {
		return ""
	}
	return zip
}

// keptZIP is the ZIP code to save from a classic client. It sends back empty
// the code it was given empty because it could not show it; that stored code
// stays rather than being wiped by the next save.
func (s *ICQService) keptZIP(ctx context.Context, instance *state.SessionInstance, sent string, stored func(state.User) string) string {
	if sent != "" {
		return sent
	}
	u, err := s.userFinder.FindByUIN(ctx, instance.UIN())
	if err != nil {
		return sent
	}
	if old := stored(u); old != "" && classicZIP(old) == "" {
		return old
	}
	return sent
}
