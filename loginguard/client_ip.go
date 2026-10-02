package loginguard

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// WithClientIP returns ctx carrying the address a sign-in comes from, which
// the auth service counts failures against. ip may carry a port.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIP returns the address WithClientIP put in ctx, or "" when there is
// none.
func ClientIP(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}

// ParsePrefixes parses a list of CIDR prefixes or bare addresses.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is neither an address nor a CIDR prefix", s)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// RequestClientIP returns the address of the client behind r. That is the
// socket's peer, unless the peer is one of the trusted proxies: then it is the
// address the proxy names in X-Real-IP, or failing that the last address in
// X-Forwarded-For that is not itself a trusted proxy. Headers from anyone else
// are ignored, since a client can write them.
func RequestClientIP(r *http.Request, trusted []netip.Prefix) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if !inPrefixes(peer.Addr(), trusted) {
		return peer.Addr().Unmap().String()
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if addr, err := netip.ParseAddr(v); err == nil {
			return addr.Unmap().String()
		}
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !inPrefixes(addr, trusted) {
			return addr.Unmap().String()
		}
	}
	return peer.Addr().Unmap().String()
}

// ClientIPMiddleware puts the RequestClientIP of every request in its context.
func ClientIPMiddleware(trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithClientIP(r.Context(), RequestClientIP(r, trusted))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func inPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
