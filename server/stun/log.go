package stun

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// requestLog writes one INFO line for each message a client sends the
// server that looks like STUN or TURN: its type, method and class, and the
// type and length of each attribute - never their contents. It exists to see
// exactly what a client asks for, such as the TURN requests ICQ 6.5 sends
// before a call.
//
// It writes at most requestLogBurst lines at once and requestLogRate lines a
// second after that, so that a client in a loop cannot fill the log; lines
// left out are counted in the next one written.
type requestLog struct {
	logger  *slog.Logger
	limiter *rate.Limiter

	mu      sync.Mutex
	skipped int
}

const (
	requestLogRate  = 5
	requestLogBurst = 50
)

func newRequestLog(logger *slog.Logger) *requestLog {
	return &requestLog{
		logger:  logger,
		limiter: rate.NewLimiter(rate.Every(time.Second/requestLogRate), requestLogBurst),
	}
}

// log writes msg, which came from from, if the limit allows.
func (l *requestLog) log(msg []byte, from *net.UDPAddr) {
	l.mu.Lock()
	if !l.limiter.Allow() {
		l.skipped++
		l.mu.Unlock()
		return
	}
	skipped := l.skipped
	l.skipped = 0
	l.mu.Unlock()

	args := append([]any{"from", from.String()}, describe(msg)...)
	if skipped > 0 {
		args = append(args, "skipped", skipped)
	}
	l.logger.Info("STUN/TURN message", args...)
}

// describe returns log attributes that tell what msg is without showing any
// of its contents.
func describe(msg []byte) []any {
	if len(msg) < headerLen || msg[0]&0xC0 != 0 {
		return []any{"kind", "not STUN", "len", len(msg)}
	}
	typ := binary.BigEndian.Uint16(msg[0:2])
	length := int(binary.BigEndian.Uint16(msg[2:4]))
	modern := binary.BigEndian.Uint32(msg[4:8]) == magicCookie
	args := []any{
		"type", fmt.Sprintf("0x%04x", typ),
		"len", len(msg),
		"body", length,
		"id", map[bool]string{true: "rfc5389", false: "classic"}[modern],
	}
	if headerLen+length != len(msg) {
		return append(args, "kind", "length does not match the packet")
	}
	body := msg[headerLen:]
	attrs, ok := walk(body, !modern)
	if !ok {
		// a classic message whose attributes are padded all the same
		attrs, ok = walk(body, false)
	}
	var list []string
	for _, a := range attrs {
		list = append(list, fmt.Sprintf("0x%04x/%d", a.typ, len(a.value)))
	}
	if !ok {
		list = append(list, "malformed")
	}
	old := isAOLTURN(attrs)
	return append(args,
		"method", methodName(typ&^0x0110, old),
		"class", className(typ&0x0110),
		"dialect", map[bool]string{true: "draft TURN", false: "STUN/RFC TURN"}[old],
		"attrs", strings.Join(list, " "))
}

func className(class uint16) string {
	switch class {
	case classRequest:
		return "request"
	case classSuccess:
		return "success"
	case classErrorResponse:
		return "error"
	default:
		return "indication"
	}
}

// methodName names a method. The TURN of the old drafts that ICQ 6.5 speaks
// and the TURN of RFC 5766 give the same numbers different meanings, so the
// name depends on which one the message is in.
func methodName(method uint16, draftTURN bool) string {
	switch method {
	case methodBinding:
		return "Binding"
	case 0x0002:
		return "SharedSecret"
	case 0x0003:
		return "Allocate"
	}
	if draftTURN {
		switch method {
		case 0x0004:
			return "Send"
		case 0x0005:
			return "Data"
		case 0x0006:
			return "SetActiveDestination"
		case 0x0007:
			return "ConnectionStatus"
		case 0x0009:
			return "CloseBinding"
		}
	} else {
		switch method {
		case 0x0004:
			return "Refresh"
		case 0x0006:
			return "Send"
		case 0x0007:
			return "Data"
		case 0x0008:
			return "CreatePermission"
		case 0x0009:
			return "ChannelBind"
		}
	}
	return fmt.Sprintf("0x%03x", method)
}
