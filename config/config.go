package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/loginguard"
)

var (
	// Simple error for duplicate listener definitions
	errDuplicateListener = errors.New("duplicate listener definition")
	// Simple error for missing BOS listeners
	errNoBOSListeners = errors.New("at least one BOS listener is required")
)

// Custom error types for URI-related errors
type uriFormatError struct {
	URI string
	Err error
}

func (e uriFormatError) Error() string {
	return fmt.Sprintf("invalid listener URI %q: %v. Valid format: SCHEME://HOST:PORT (e.g., LOCAL://0.0.0.0:5190)", e.URI, e.Err)
}

type Build struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func validateAllowedOrigin(origin string) error {
	const format = "Valid format: SCHEME://HOST[:PORT] with at most one * (e.g., https://example.com, http://localhost:*)"

	reject := func(reason string) error {
		return fmt.Errorf("invalid web API allowed origin %q: %s. %s", origin, reason, format)
	}

	if strings.Count(origin, "*") > 1 {
		return reject("only one wildcard is allowed per origin")
	}

	scheme, host, ok := cutOriginScheme(origin)
	if !ok {
		return reject("scheme must be http or https, and cannot itself be a wildcard")
	}

	if host == "" {
		return reject("missing host")
	}

	// An origin is a scheme, host and port and nothing else.
	if strings.ContainsAny(host, "/?#@") {
		return reject("must not have a trailing slash, path, query, fragment or userinfo")
	}

	// A browser omits the port when it is the default for the scheme, so an
	// entry that spells it out can never match.
	if (scheme == "http" && strings.HasSuffix(host, ":80")) ||
		(scheme == "https" && strings.HasSuffix(host, ":443")) {
		return fmt.Errorf("invalid web API allowed origin %q: a browser omits the default port, so this would never match. Use %q", origin, origin[:strings.LastIndex(origin, ":")])
	}

	return nil
}

// cutOriginScheme splits an origin into its scheme and the rest.
func cutOriginScheme(origin string) (scheme string, rest string, ok bool) {
	lower := strings.ToLower(origin)
	for _, s := range []string{"http", "https"} {
		if prefix := s + "://"; strings.HasPrefix(lower, prefix) {
			return s, origin[len(prefix):], true
		}
	}
	return "", "", false
}

// ListenerGroup is a set of related BOS endpoints: one plaintext, and
// optionally one for SSL clients. Both listen in plaintext — a load balancer
// terminates TLS and forwards decrypted traffic to the SSL endpoint. Pairing
// them lets a redirect hand a client the sibling endpoint's advertised host,
// so a session can upgrade to SSL or downgrade to plaintext on reconnect.
//
// A group may also have a TLS 1.3 endpoint that this server terminates itself
// (see Endpoint.Transport).
type ListenerGroup struct {
	// Name is the URI scheme the group was parsed from, e.g. "LOCAL".
	Name                   string
	BOSListenAddress       string
	BOSListenAddressSSL    string
	BOSAdvertisedHostPlain string
	BOSAdvertisedHostSSL   string
	KerberosListenAddress  string
	// BOSListenAddressTLS is the socket on which this server terminates TLS
	// 1.3 itself. Empty when the group has no such endpoint.
	BOSListenAddressTLS string
	// BOSAdvertisedHostTLS is the host every client that connected over TLS
	// 1.3 is sent to.
	BOSAdvertisedHostTLS string
}

// HasSSL reports whether clients can reach this group over SSL. Config
// validation guarantees such a group also has an SSL listen address.
func (g ListenerGroup) HasSSL() bool {
	return g.BOSAdvertisedHostSSL != ""
}

// PlainEndpoint returns the group's plaintext BOS socket.
func (g ListenerGroup) PlainEndpoint() Endpoint {
	return Endpoint{Group: g, ListenAddress: g.BOSListenAddress}
}

// SSLEndpoint returns the socket that receives decrypted traffic from the
// group's SSL terminator. ok is false when SSL is not enabled for the group.
func (g ListenerGroup) SSLEndpoint() (ep Endpoint, ok bool) {
	if !g.HasSSL() {
		return Endpoint{}, false
	}
	return Endpoint{Group: g, ListenAddress: g.BOSListenAddressSSL, IsSSL: true}, true
}

// HasTLS reports whether the group has a TLS 1.3 endpoint that this server
// terminates itself. Config validation guarantees such a group also has an
// advertised TLS host.
func (g ListenerGroup) HasTLS() bool {
	return g.BOSListenAddressTLS != ""
}

// TLSEndpoint returns the socket on which this server terminates TLS 1.3
// itself. ok is false when the group has none.
func (g ListenerGroup) TLSEndpoint() (ep Endpoint, ok bool) {
	if !g.HasTLS() {
		return Endpoint{}, false
	}
	return Endpoint{Group: g, ListenAddress: g.BOSListenAddressTLS, Transport: TransportTLS13}, true
}

// Endpoints returns every BOS socket the group binds.
func (g ListenerGroup) Endpoints() []Endpoint {
	eps := []Endpoint{g.PlainEndpoint()}
	if ssl, ok := g.SSLEndpoint(); ok {
		eps = append(eps, ssl)
	}
	if tls, ok := g.TLSEndpoint(); ok {
		eps = append(eps, tls)
	}
	return eps
}

// Transport says how a connection reaches the server on an endpoint.
type Transport uint8

const (
	// TransportPlain is a plain TCP socket. It also covers the decrypted
	// traffic of an external SSL terminator (Endpoint.IsSSL), whose TLS the
	// server never sees.
	TransportPlain Transport = iota
	// TransportTLS13 is TLS 1.3 terminated by this server itself, so the TLS
	// version and the exporter (RFC 9266 tls-exporter) are known to it.
	TransportTLS13
)

// String returns the name of the transport, for logs.
func (t Transport) String() string {
	if t == TransportTLS13 {
		return "TLS13"
	}
	return "plain"
}

// Endpoint is a single BOS socket. IsSSL means traffic arrives from an SSL
// terminator, so clients that connect here stay on the SSL path. Transport is
// TransportTLS13 on the endpoint where this server terminates TLS itself.
type Endpoint struct {
	Group         ListenerGroup
	ListenAddress string
	IsSSL         bool
	Transport     Transport
}

// AdvertisedHost returns the BOS host clients on this endpoint reconnect to.
func (e Endpoint) AdvertisedHost() string {
	switch {
	case e.Transport == TransportTLS13:
		return e.Group.BOSAdvertisedHostTLS
	case e.IsSSL:
		return e.Group.BOSAdvertisedHostSSL
	default:
		return e.Group.BOSAdvertisedHostPlain
	}
}

// LoginRedirect returns the BOS host a client that signed in on this endpoint
// is sent to, and whether the client must negotiate SSL with that host itself.
// wantsSSL is whether the client asked for SSL.
//
// The SSL terminator's endpoint keeps its clients on the SSL host whatever
// they asked. The TLS 1.3 endpoint always sends its clients to the TLS host,
// so the BOS port the client reports is the one it is really on. Only a
// client that asked for SSL is told to negotiate it: a client whose TLS is
// added from outside (the E2E add-on) asks for nothing and must keep speaking
// plain FLAP, which the add-on wraps.
func (e Endpoint) LoginRedirect(wantsSSL bool) (host string, clientSSL bool) {
	switch {
	case e.Transport == TransportTLS13:
		return e.Group.BOSAdvertisedHostTLS, wantsSSL
	case e.IsSSL:
		return e.Group.BOSAdvertisedHostSSL, true
	default:
		return e.Group.BOSAdvertisedHostPlain, false
	}
}

// ServiceRedirect returns the host a client on this endpoint is sent to for
// another service, and whether the client must negotiate SSL with that host
// itself. wantsSSL is whether the client asked for SSL in its service request.
//
// A client on the TLS 1.3 endpoint gets the TLS host, told to negotiate SSL
// only when it asked (see LoginRedirect). Elsewhere, a client that did not ask
// gets the plain host, and one that asked gets the SSL host, or the plain host
// when the group has no SSL, for the client to decide whether to go on
// without it.
func (e Endpoint) ServiceRedirect(wantsSSL bool) (host string, clientSSL bool) {
	switch {
	case e.Transport == TransportTLS13:
		return e.Group.BOSAdvertisedHostTLS, wantsSSL
	case !wantsSSL:
		return e.Group.BOSAdvertisedHostPlain, false
	case e.Group.HasSSL():
		return e.Group.BOSAdvertisedHostSSL, true
	default:
		return e.Group.BOSAdvertisedHostPlain, false
	}
}

//go:generate go run ../cmd/config_generator unix settings.env basic
//go:generate go run ../cmd/config_generator unix ssl/settings.env ssl
type Config struct {
	BOSListeners            []string `envconfig:"OSCAR_LISTENERS" required:"true" basic:"LOCAL://0.0.0.0:5190" ssl:"LOCAL://0.0.0.0:5190" description:"Network listeners for core OSCAR services. For multi-homed servers, allows users to connect from multiple networks. For example, you can allow both LAN and Internet clients to connect to the same server using different connection settings.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Listener names and ports must be unique\n\t- Listener names are user-defined\n\t- Each listener needs a listener in OSCAR_ADVERTISED_LISTENERS_PLAIN\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:5190\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:5190,LAN://192.168.1.10:5191"`
	BOSAdvertisedHostsPlain []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_PLAIN" required:"true" basic:"LOCAL://127.0.0.1:5190" ssl:"LOCAL://ras.dev:5190" description:"Hostnames published by the server that clients connect to for accessing various OSCAR services. These hostnames are NOT the bind addresses. For multi-homed use servers, allows clients to connect using separate hostnames per network.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Each listener config must correspond to a config in OSCAR_LISTENERS\n\t- Clients MUST be able to connect to these hostnames\n\nExamples:\n\t// Local LAN config, server behind NAT\n\tLAN://192.168.1.10:5190\n\t// Separate Internet and LAN config\n\tWAN://aim.example.com:5190,LAN://192.168.1.10:5191"`
	BOSListenersSSL         []string `envconfig:"OSCAR_LISTENERS_SSL" required:"false" basic:"" ssl:"LOCAL://0.0.0.0:5191" description:"Network listeners for core OSCAR services that receive decrypted traffic from an SSL terminator such as nginx. Clients that connect through these listeners are redirected to the hostnames in OSCAR_ADVERTISED_LISTENERS_SSL, keeping them on the SSL path for the rest of the session.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Listener names and ports must be unique\n\t- Each listener needs a listener in OSCAR_LISTENERS and OSCAR_ADVERTISED_LISTENERS_SSL\n\t- A listener without a matching OSCAR_ADVERTISED_LISTENERS_SSL entry is not started\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:5191\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:5191,LAN://192.168.1.10:5192"`
	BOSAdvertisedHostsSSL   []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_SSL" required:"false" basic:"" ssl:"LOCAL://ras.dev:5193" description:"Same as OSCAR_ADVERTISED_LISTENERS_PLAIN, except the hostname is for the server that terminates SSL. Each listener defined here must have a matching listener in OSCAR_LISTENERS_SSL for the terminator to forward decrypted traffic to."`
	BOSListenersTLS         []string `envconfig:"OSCAR_LISTENERS_TLS" required:"false" basic:"" ssl:"LOCAL://0.0.0.0:5194" description:"Network listeners on which this server terminates TLS 1.3 itself, with the certificate in TLS_CERT_FILE and TLS_KEY_FILE. TLS 1.2 and older are refused. ALPN picks the protocol on the one port: 'oscar' or none is OSCAR, 'http/1.1' is the WebAPI (only when ENABLE_WEBAPI=1). The E2E add-on for ICQ 6.5 and 7.2 wraps the client's server connections in TLS to this port.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Listener names and ports must be unique\n\t- Each listener needs a listener in OSCAR_LISTENERS and OSCAR_ADVERTISED_LISTENERS_TLS\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:5194"`
	BOSAdvertisedHostsTLS   []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_TLS" required:"false" basic:"" ssl:"LOCAL://ras.dev:5194" description:"Same as OSCAR_ADVERTISED_LISTENERS_PLAIN, for the listeners in OSCAR_LISTENERS_TLS. Every client that connected over TLS 1.3 is sent here, in the sign-in reply and in every service redirect; only one that asked for SSL is told to negotiate SSL itself (the E2E add-on wraps the client's plain FLAP in TLS). The host name must be one the certificate is issued to.\n\nExamples:\n\tLAN://icq.example.com:5194"`
	TLSCertFile             string   `envconfig:"TLS_CERT_FILE" required:"false" basic:"" ssl:"certs/server.pem" description:"PEM certificate chain served on OSCAR_LISTENERS_TLS, such as a Let's Encrypt fullchain.pem. The file is read again when it changes, so a renewed certificate is served without a restart. Required when OSCAR_LISTENERS_TLS is set.\n\nExamples:\n\t/certs/ts-cert.pem"`
	TLSKeyFile              string   `envconfig:"TLS_KEY_FILE" required:"false" basic:"" ssl:"certs/server.pem" description:"PEM private key of TLS_CERT_FILE. Read again when it changes. Required when OSCAR_LISTENERS_TLS is set.\n\nExamples:\n\t/certs/ts-key.pem"`
	KerberosListeners       []string `envconfig:"KERBEROS_LISTENERS" required:"false" basic:"" ssl:"LOCAL://0.0.0.0:1088" description:"Network listeners for Kerberos authentication. See OSCAR_LISTENERS doc for more details.\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:1088\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:1088,LAN://192.168.1.10:1087"`
	TOCListeners            []string `envconfig:"TOC_LISTENERS" required:"true" basic:"0.0.0.0:9898" ssl:"0.0.0.0:9898" description:"Network listeners for TOC protocol service.\n\nFormat: Comma-separated list of hostname:port pairs.\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:9898\n\t// Multiple listeners\n\t0.0.0.0:9898,192.168.1.10:9899"`
	APIListener             string   `envconfig:"API_LISTENER" required:"true" basic:"127.0.0.1:8080" ssl:"127.0.0.1:8080" description:"Network listener for management API binds to. Only 1 listener can be specified. (Default 127.0.0.1 restricts to same machine only)."`
	WebAPIListeners         []string `envconfig:"WEBAPI_LISTENERS" required:"false" basic:"0.0.0.0:8081" ssl:"0.0.0.0:8081" description:"Network listeners for WebAPI. See OSCAR_LISTENERS doc for more details.\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:8081\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:8081,LAN://192.168.1.10:8082"`
	WebAPIAllowedOrigins    []string `envconfig:"WEBAPI_ALLOWED_ORIGINS" required:"false" basic:"http://localhost:*" ssl:"http://localhost:*" description:"Origins allowed to call the WebAPI from a browser (CORS). A browser blocks a cross-origin response whose origin is not listed here, so the client serving the web app must appear in this list.\n\nFormat:\n\t- Comma-separated list of [SCHEME]://[HOSTNAME]:[PORT]\n\t- An origin is the scheme, host and port together: a client served from another port needs its own entry\n\t- Omit the port when it is the scheme default, the way a browser writes it: https://aim.example.com, not https://aim.example.com:443\n\t- No trailing slash, path, query or fragment\n\t- An entry may contain one wildcard (*) standing in for 0 or more characters, in the host or the port: https://*.example.com, http://localhost:* . Only one wildcard per entry, the scheme cannot be wildcarded, and matching one costs a little more per request\n\t- A lone * allows any origin, which is also what an unset or empty value means\n\nExamples:\n\t// Single origin\n\thttps://ras.dev\n\t// Web app on a separate port, plus the API host itself\n\thttp://localhost:8000,https://ras.dev\n\t// Any origin (development only)\n\t*"`

	DBPath                 string `envconfig:"DB_PATH" required:"true" basic:"oscar.sqlite" ssl:"oscar.sqlite" description:"The path to the SQLite database file. The file and DB schema are auto-created if they doesn't exist."`
	DisableAuth            bool   `envconfig:"DISABLE_AUTH" required:"true" basic:"true" ssl:"true" description:"Disable password check and auto-create new users at login time. Useful for quickly creating new accounts during development without having to register new users via the management API."`
	DisableMultiLoginNotif bool   `envconfig:"DISABLE_MULTI_LOGIN_NOTIF" required:"false" basic:"true" ssl:"true" description:"Disable notification sent when another client signs in with the same screen name."`
	LogLevel               string `envconfig:"LOG_LEVEL" required:"true" basic:"info" ssl:"info" description:"Set logging granularity. Possible values: 'trace', 'debug', 'info', 'warn', 'error'."`
	ICQClassicCodePage     string `envconfig:"ICQ_CLASSIC_CODEPAGE" required:"false" default:"windows-1251" basic:"windows-1251" ssl:"windows-1251" description:"Code page of the text that classic ICQ clients (ICQ 99 to 2003) send and expect in profiles and searches, and the legacy UDP clients (ICQ 95 to 99b) in messages too. They know no Unicode and the protocol does not name the code page, so the server keeps their text as UTF-8 and sends it back to them in this one. Names as in the WHATWG encoding list; empty passes their bytes through unchanged.\n\nExamples:\n\t// Cyrillic\n\twindows-1251\n\t// Western European\n\twindows-1252"`
	STUNListener           string `envconfig:"STUN_LISTENER" required:"false" basic:"0.0.0.0:3478" ssl:"0.0.0.0:3478" default:"0.0.0.0:3478" description:"UDP address of the STUN server. ICQ 6 asks STUN for its public address before a voice or video call; the ICQ 6.5 patch points the client here in place of turn.oscar.aol.com, which no longer exists. Clients reach it on UDP 3478, the port the client has built in. Empty turns it off.\n\nFormat: HOST:PORT\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:3478"`
	LegacyWebURL           string `envconfig:"LEGACY_WEB_URL" required:"false" default:"" basic:"http://127.0.0.1:8101" ssl:"http://127.0.0.1:8101" description:"Base address of the legacy web service (the ICQ 6 pages and the animated avatar gallery), as this server reaches it. Clients that cannot play Flash avatars are shown a still picture of a gallery avatar in its place, which the server downloads from LEGACY_WEB_URL/icq/avatars/NAME-still.jpg. Empty turns the still pictures off.\n\nExamples:\n\t// legacy web on the same host\n\thttp://127.0.0.1:8101"`

	// TURN relay of the STUN server
	TURN TURNConfig

	// Key directory of the end-to-end encryption add-on
	E2E E2EConfig

	// ICQ Legacy Protocol Configuration
	ICQLegacy ICQLegacyConfig

	// Throttling of failed sign-ins
	LoginGuard LoginGuardConfig
}

// LoginGuardConfig holds the limits on failed sign-ins, shared by every
// sign-in path: OSCAR (FLAP, BUCP), Kerberos, TOC, the WebAPI and legacy ICQ.
type LoginGuardConfig struct {
	AccountFailures  int           `envconfig:"LOGIN_GUARD_ACCOUNT_FAILURES" required:"false" default:"5" basic:"5" ssl:"5" description:"Failed sign-ins an account gets before it is paused. Each further failure doubles the pause, from LOGIN_GUARD_ACCOUNT_BASE_DELAY up to LOGIN_GUARD_ACCOUNT_MAX_DELAY. While paused, a sign-in is answered with the protocol's own 'rate limited, try later' error without the password being checked; an account that does not exist is treated the same. A sign-in that succeeds forgets the account's failures. 0 turns the account limit off."`
	AccountBaseDelay time.Duration `envconfig:"LOGIN_GUARD_ACCOUNT_BASE_DELAY" required:"false" default:"1s" basic:"1s" ssl:"1s" description:"The first pause of an account that used up LOGIN_GUARD_ACCOUNT_FAILURES."`
	AccountMaxDelay  time.Duration `envconfig:"LOGIN_GUARD_ACCOUNT_MAX_DELAY" required:"false" default:"15m" basic:"15m" ssl:"15m" description:"The longest pause of an account. An account that has not failed for this long after its pause ended starts over."`
	IPFailures       int           `envconfig:"LOGIN_GUARD_IP_FAILURES" required:"false" default:"30" basic:"30" ssl:"30" description:"Failed sign-ins one client address gets per LOGIN_GUARD_IP_WINDOW, on any accounts; then it earns one attempt back every LOGIN_GUARD_IP_WINDOW / LOGIN_GUARD_IP_FAILURES. An IPv6 address counts as its /64. 0 turns the address limit off."`
	IPWindow         time.Duration `envconfig:"LOGIN_GUARD_IP_WINDOW" required:"false" default:"10m" basic:"10m" ssl:"10m" description:"The period LOGIN_GUARD_IP_FAILURES is spread over."`
	KnownAddressTTL  time.Duration `envconfig:"LOGIN_GUARD_KNOWN_ADDRESS_TTL" required:"false" default:"720h" basic:"720h" ssl:"720h" description:"How long an address an account signed in from is remembered as the owner's. Failures from such an address are counted on their own, so someone guessing the password from elsewhere does not pause the owner. Kept in memory only. 0 turns this off."`
	TrustedProxies   []string      `envconfig:"LOGIN_GUARD_TRUSTED_PROXIES" required:"false" default:"127.0.0.0/8,::1/128" basic:"127.0.0.0/8,::1/128" ssl:"127.0.0.0/8,::1/128,172.16.0.0/12" description:"Addresses of the reverse proxies (such as nginx in front of Kerberos and the WebAPI) whose X-Real-IP or X-Forwarded-For header names the client of an HTTP sign-in. A request from anywhere else is counted under its own socket address, and its headers are ignored. A proxy in another container must be listed, or all of its clients share one address budget.\n\nFormat: comma-separated addresses or CIDR prefixes\n\nExamples:\n\t// nginx on the same host\n\t127.0.0.0/8,::1/128\n\t// nginx in a Docker bridge network\n\t127.0.0.0/8,::1/128,172.16.0.0/12"`
}

// TURNConfig holds the settings of the TURN relay that the STUN server runs
// for ICQ 6.5 voice and video calls.
type TURNConfig struct {
	Enabled     bool          `envconfig:"TURN_ENABLED" required:"false" default:"false" basic:"false" ssl:"false" description:"Make the STUN server a TURN relay as well. ICQ 6.5 asks the STUN host for a relayed address before a voice or video call, in the TURN of an early draft, and offers it to its peer as one more way to reach it; the call goes through the relay only when the two clients cannot reach each other directly, as between two symmetric NATs or through a VPN. Only clients signed in to this server from the same IP address get an allocation. Needs STUN_LISTENER, TURN_PUBLIC_IP, and TURN_RELAY_PORTS open to the Internet for UDP."`
	PublicIP    string        `envconfig:"TURN_PUBLIC_IP" required:"false" basic:"127.0.0.1" ssl:"ras.dev" description:"The server's IPv4 address on the Internet, or a host name that resolves to it: clients are told their relayed ports are on this address. Resolved once, at startup.\n\nExamples:\n\t// an address\n\t192.0.2.1\n\t// a host name\n\ticq.example.com"`
	RelayPorts  string        `envconfig:"TURN_RELAY_PORTS" required:"false" default:"49160-49199" basic:"49160-49199" ssl:"49160-49199" description:"UDP ports of relayed addresses, as FIRST-LAST. Each allocation takes one, and a call takes up to four per client relayed (audio and video, RTP and RTCP), so the size of the range caps how many allocations there are at once. They must be open to the Internet for UDP.\n\nExamples:\n\t49160-49199"`
	MaxPerIP    int           `envconfig:"TURN_MAX_ALLOCATIONS_PER_IP" required:"false" default:"8" basic:"8" ssl:"8" description:"Most allocations the clients behind one IP address may hold at once. A client in a video call holds four."`
	Kbps        int           `envconfig:"TURN_RELAY_KBPS" required:"false" default:"2000" basic:"2000" ssl:"2000" description:"Most kilobits a second one allocation relays, both ways together; what is over it is dropped. An ICQ 6.5 audio stream needs under 100, a video stream a few hundred."`
	IdleTimeout time.Duration `envconfig:"TURN_IDLE_TIMEOUT" required:"false" default:"5m" basic:"5m" ssl:"5m" description:"Close an allocation that has relayed nothing for this long, even if the client keeps refreshing it."`
}

// E2EConfig holds the settings of the key directory that the end-to-end
// encryption add-on for ICQ 6.5 and 7.2 publishes its public keys to. The
// directory is served by the WebAPI under /e2e/v1/; see
// docs/e2e/KEY-DIRECTORY-API.md.
type E2EConfig struct {
	TokenTTL       time.Duration `envconfig:"E2E_TOKEN_TTL" required:"false" default:"12h" basic:"12h" ssl:"12h" description:"Lifetime of the key directory token handed to a client when it signs in over BOS. A token also dies with the session it was issued to; a client refreshes it before it expires."`
	MaxDevices     int           `envconfig:"E2E_MAX_DEVICES" required:"false" default:"10" basic:"10" ssl:"10" description:"Most devices that are not revoked an account may have in the key directory."`
	MaxOneTimeKeys int           `envconfig:"E2E_MAX_ONE_TIME_KEYS" required:"false" default:"100" basic:"100" ssl:"100" description:"Most one-time keys the key directory holds for one device."`
	KTOrigin       string        `envconfig:"E2E_KT_ORIGIN" required:"false" default:"open-oscar-server/e2e-kt" basic:"open-oscar-server/e2e-kt" ssl:"open-oscar-server/e2e-kt" description:"Name of the key transparency log, the first line of its signed checkpoints. Make it unique to this server, such as icq.example.org/e2e-kt, and keep it: clients pin the log key under this name. No spaces or plus signs."`
	KTAuditors     []string      `envconfig:"E2E_KT_AUDITORS" required:"false" basic:"" ssl:"" description:"Verifier keys of the auditors of the key transparency log, comma-separated: name+id+base64 key, as e2e-kt-auditor -print-key prints it. Only their cosignatures are accepted and handed to clients."`
	LinkTTL        time.Duration `envconfig:"E2E_LINK_TTL" required:"false" default:"10m" basic:"10m" ssl:"10m" description:"How long a device-link request waits for one of the account's devices to answer before it is dropped."`
}

// PortRange returns the first and last relay port of TURN_RELAY_PORTS.
func (c TURNConfig) PortRange() (first, last uint16, err error) {
	lo, hi, ok := strings.Cut(strings.TrimSpace(c.RelayPorts), "-")
	if !ok {
		return 0, 0, fmt.Errorf("invalid TURN relay ports %q. Valid format: FIRST-LAST (e.g., 49160-49199)", c.RelayPorts)
	}
	a, errA := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	b, errB := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if errA != nil || errB != nil || a == 0 || a > b {
		return 0, 0, fmt.Errorf("invalid TURN relay ports %q. Valid format: FIRST-LAST (e.g., 49160-49199)", c.RelayPorts)
	}
	return uint16(a), uint16(b), nil
}

// validate checks the settings of an enabled relay.
func (c TURNConfig) validate(stunListener string) error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(stunListener) == "" {
		return fmt.Errorf("TURN_ENABLED needs STUN_LISTENER: the relay runs in the STUN server")
	}
	if strings.TrimSpace(c.PublicIP) == "" {
		return fmt.Errorf("TURN_ENABLED needs TURN_PUBLIC_IP, the address clients are told to reach relayed ports on")
	}
	if _, _, err := c.PortRange(); err != nil {
		return err
	}
	if c.MaxPerIP < 1 {
		return fmt.Errorf("TURN_MAX_ALLOCATIONS_PER_IP must be at least 1")
	}
	if c.Kbps < 64 {
		return fmt.Errorf("TURN_RELAY_KBPS must be at least 64")
	}
	if c.IdleTimeout <= 0 {
		return fmt.Errorf("TURN_IDLE_TIMEOUT must be positive")
	}
	return nil
}

// ICQLegacyConfig holds configuration for legacy ICQ protocol support (v2-v5)
type ICQLegacyConfig struct {
	Enabled            bool          `envconfig:"ICQ_LEGACY_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable legacy ICQ protocol support (v2-v5). Allows vintage ICQ clients to connect."`
	UDPListener        string        `envconfig:"ICQ_LEGACY_UDP_LISTENER" required:"false" basic:"0.0.0.0:4000" ssl:"0.0.0.0:4000" description:"UDP listener address for legacy ICQ protocols.\n\nFormat: HOST:PORT\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:4000\n\t// Specific interface\n\t192.168.1.10:4000"`
	SupportedVersions  []int         `envconfig:"ICQ_LEGACY_VERSIONS" required:"false" basic:"2,3,4,5" ssl:"2,3,4,5" description:"Comma-separated list of supported ICQ protocol versions. Valid values: 1, 2, 3, 4, 5 (V1 is experimental)."`
	SessionTimeout     time.Duration `envconfig:"ICQ_LEGACY_SESSION_TIMEOUT" required:"false" basic:"120s" ssl:"120s" description:"Session timeout for legacy ICQ connections. Sessions are cleaned up after this duration of inactivity."`
	KeepAliveInterval  time.Duration `envconfig:"ICQ_LEGACY_KEEPALIVE_INTERVAL" required:"false" basic:"120s" ssl:"120s" description:"Expected keep-alive interval from clients. Used for timeout calculations."`
	AutoRegistration   bool          `envconfig:"ICQ_LEGACY_AUTO_REGISTRATION" required:"false" basic:"false" ssl:"false" description:"Allow automatic user registration from legacy clients. When enabled, new UINs can be created via the legacy protocol."`
	DepartmentsEnabled bool          `envconfig:"ICQ_LEGACY_DEPARTMENTS_ENABLED" required:"false" basic:"false" ssl:"false" description:"Enable department listing feature (groupware functionality)."`
	BroadcastEnabled   bool          `envconfig:"ICQ_LEGACY_BROADCAST_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable broadcast message functionality."`
	WWPEnabled         bool          `envconfig:"ICQ_LEGACY_WWP_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable Web Pager (WWP) message support."`
	DirectConnections  []int         `envconfig:"ICQ_LEGACY_DIRECT_CONNECTIONS" required:"false" basic:"5" ssl:"5" description:"Comma-separated list of protocol versions that send real connection info (IP, port) in user online notifications. Disabled for privacy and interoperability. Required for peer-to-peer features (file transfer, direct chat). Example: 5 or 3,4,5"`
}

// DefaultICQLegacyConfig returns the default configuration for ICQ legacy protocol
func DefaultICQLegacyConfig() ICQLegacyConfig {
	return ICQLegacyConfig{
		Enabled:            true,
		UDPListener:        "0.0.0.0:4000",
		SupportedVersions:  []int{2, 3, 4, 5},
		SessionTimeout:     120 * time.Second,
		KeepAliveInterval:  120 * time.Second,
		AutoRegistration:   false,
		DepartmentsEnabled: false,
		BroadcastEnabled:   true,
		WWPEnabled:         true,
	}
}

// SupportsVersion checks if a specific protocol version is enabled
func (c *ICQLegacyConfig) SupportsVersion(version int) bool {
	for _, v := range c.SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// DirectConnectionEnabled checks if direct connections are enabled for a specific protocol version
func (c *ICQLegacyConfig) DirectConnectionEnabled(version int) bool {
	for _, v := range c.DirectConnections {
		if v == version {
			return true
		}
	}
	return false
}

func (c *Config) ParseListenersCfg() ([]ListenerGroup, error) {
	// Helper function to parse and validate a single URI
	parseURI := func(uriStr string) (*url.URL, error) {
		uriStr = strings.TrimSpace(uriStr)
		if uriStr == "" {
			return nil, nil
		}

		u, err := url.Parse(uriStr)
		if err != nil {
			return nil, uriFormatError{URI: uriStr, Err: err}
		}
		switch {
		case u.Scheme == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing scheme")}
		case u.Hostname() == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing host")}
		case u.Port() == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing port")}
		}

		return u, nil
	}

	m := make(map[string]*ListenerGroup)

	// Parse BOS listeners
	for _, uriStr := range c.BOSListeners {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSListenAddress != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSListenAddress = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse SSL BOS listeners
	for _, uriStr := range c.BOSListenersSSL {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSListenAddressSSL != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSListenAddressSSL = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse plaintext BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsPlain {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSAdvertisedHostPlain != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSAdvertisedHostPlain = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse SSL BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsSSL {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSAdvertisedHostSSL != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSAdvertisedHostSSL = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse TLS BOS listeners
	for _, uriStr := range c.BOSListenersTLS {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSListenAddressTLS != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSListenAddressTLS = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse TLS BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsTLS {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSAdvertisedHostTLS != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSAdvertisedHostTLS = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse Kerberos listeners
	for _, uriStr := range c.KerberosListeners {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].KerberosListenAddress != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].KerberosListenAddress = net.JoinHostPort(u.Hostname(), u.Port())
	}

	ret := make([]ListenerGroup, 0, len(m))

	for k, v := range m {
		switch {
		case v.BOSAdvertisedHostPlain == "":
			return nil, fmt.Errorf("missing BOS advertise address for listener `%s://`", k)
		case v.BOSListenAddress == "":
			return nil, fmt.Errorf("missing BOS listen address for listener `%s://`", k)
		case v.HasSSL() && v.BOSListenAddressSSL == "":
			return nil, fmt.Errorf("missing SSL BOS listen address for listener `%s://`", k)
		case v.BOSAdvertisedHostTLS != "" && v.BOSListenAddressTLS == "":
			return nil, fmt.Errorf("missing TLS BOS listen address (OSCAR_LISTENERS_TLS) for listener `%s://`", k)
		case v.BOSListenAddressTLS != "" && v.BOSAdvertisedHostTLS == "":
			return nil, fmt.Errorf("missing TLS BOS advertise address (OSCAR_ADVERTISED_LISTENERS_TLS) for listener `%s://`", k)
		}
		v.Name = k
		ret = append(ret, *v)
	}

	if len(ret) == 0 {
		return nil, errNoBOSListeners
	}

	// The groups come out of a map, in an order that changes from run to run.
	// Sorting them by name keeps the result, and the collision error below,
	// the same every time.
	slices.SortFunc(ret, func(a, b ListenerGroup) int {
		return strings.Compare(a.Name, b.Name)
	})

	// Catch sockets that collide across lists or groups, which would otherwise
	// surface at bind time as a bare "address already in use".
	seen := make(map[string]string, len(ret)*3)
	for _, l := range ret {
		for _, socket := range []struct{ envVar, addr string }{
			{"OSCAR_LISTENERS", l.BOSListenAddress},
			{"OSCAR_LISTENERS_SSL", l.BOSListenAddressSSL},
			{"OSCAR_LISTENERS_TLS", l.BOSListenAddressTLS},
			{"KERBEROS_LISTENERS", l.KerberosListenAddress},
		} {
			if socket.addr == "" {
				continue
			}
			src := fmt.Sprintf("%s `%s://`", socket.envVar, l.Name)
			if prev, ok := seen[socket.addr]; ok {
				return nil, fmt.Errorf("listen address %s is configured for both %s and %s", socket.addr, prev, src)
			}
			seen[socket.addr] = src
		}
	}

	return ret, nil
}

func (c *Config) Validate() error {
	// Validate TOCListeners (format: hostname:port pairs)
	for _, listener := range c.TOCListeners {
		listener = strings.TrimSpace(listener)
		if listener == "" {
			continue
		}

		host, port, err := net.SplitHostPort(listener)
		if err != nil {
			return fmt.Errorf("invalid TOC listener %q: %v. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener, err)
		}

		if host == "" {
			return fmt.Errorf("invalid TOC listener %q: missing host. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener)
		}

		if port == "" {
			return fmt.Errorf("invalid TOC listener %q: missing port. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener)
		}
	}

	// Validate APIListener (format: hostname:port pair, no scheme)
	apiListener := strings.TrimSpace(c.APIListener)
	if apiListener == "" {
		return fmt.Errorf("APIListener is required and cannot be empty")
	}

	host, port, err := net.SplitHostPort(apiListener)
	if err != nil {
		return fmt.Errorf("invalid API listener %q: %v. Valid format: HOST:PORT (e.g., 127.0.0.1:8080)", c.APIListener, err)
	}

	if host == "" {
		return fmt.Errorf("invalid API listener %q: missing host. Valid format: HOST:PORT (e.g., 127.0.0.1:8080)", c.APIListener)
	}

	if port == "" {
		return fmt.Errorf("invalid API listener %q: missing port. Valid format: HOST:PORT (e.g., 127.0.0.1:8080)", c.APIListener)
	}

	// Validate WebAPIListeners (format: hostname:port pairs, no scheme)
	for _, listener := range c.WebAPIListeners {
		listener = strings.TrimSpace(listener)
		if listener == "" {
			continue
		}

		host, port, err := net.SplitHostPort(listener)
		if err != nil {
			return fmt.Errorf("invalid web API listener %q: %v. Valid format: HOST:PORT (e.g., 0.0.0.0:8081)", listener, err)
		}

		if host == "" {
			return fmt.Errorf("invalid web API listener %q: missing host. Valid format: HOST:PORT (e.g., 0.0.0.0:8081)", listener)
		}

		if port == "" {
			return fmt.Errorf("invalid web API listener %q: missing port. Valid format: HOST:PORT (e.g., 0.0.0.0:8081)", listener)
		}
	}

	// Validate WebAPIAllowedOrigins (format: scheme://host[:port], or * for any).
	// An empty list is valid and means any origin is allowed.
	for _, origin := range c.WebAPIAllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" || origin == "*" {
			continue
		}
		if err := validateAllowedOrigin(origin); err != nil {
			return err
		}
	}

	if err := c.validateTLS(); err != nil {
		return err
	}

	if err := c.LoginGuard.validate(); err != nil {
		return err
	}

	return c.TURN.validate(c.STUNListener)
}

// validate checks that the sign-in limits make sense.
func (c LoginGuardConfig) validate() error {
	if c.AccountFailures < 0 || c.IPFailures < 0 {
		return errors.New("LOGIN_GUARD_ACCOUNT_FAILURES and LOGIN_GUARD_IP_FAILURES cannot be negative")
	}
	if c.AccountFailures > 0 && (c.AccountBaseDelay <= 0 || c.AccountMaxDelay < c.AccountBaseDelay) {
		return errors.New("LOGIN_GUARD_ACCOUNT_BASE_DELAY must be positive and no longer than LOGIN_GUARD_ACCOUNT_MAX_DELAY")
	}
	if c.IPFailures > 0 && c.IPWindow <= 0 {
		return errors.New("LOGIN_GUARD_IP_WINDOW must be positive")
	}
	if c.KnownAddressTTL < 0 {
		return errors.New("LOGIN_GUARD_KNOWN_ADDRESS_TTL cannot be negative")
	}
	if _, err := loginguard.ParsePrefixes(c.TrustedProxies); err != nil {
		return fmt.Errorf("invalid LOGIN_GUARD_TRUSTED_PROXIES: %w", err)
	}
	return nil
}

// Guard returns the limits as the login guard takes them.
func (c LoginGuardConfig) Guard() loginguard.Config {
	return loginguard.Config{
		AccountFreeFailures: c.AccountFailures,
		AccountBaseDelay:    c.AccountBaseDelay,
		AccountMaxDelay:     c.AccountMaxDelay,
		IPMaxFailures:       c.IPFailures,
		IPWindow:            c.IPWindow,
		KnownAddressTTL:     c.KnownAddressTTL,
	}
}

// HasTLSListeners reports whether OSCAR_LISTENERS_TLS names a listener.
func (c *Config) HasTLSListeners() bool {
	return slices.ContainsFunc(c.BOSListenersTLS, func(s string) bool {
		return strings.TrimSpace(s) != ""
	})
}

// validateTLS checks that a TLS listener has a certificate to serve.
func (c *Config) validateTLS() error {
	if !c.HasTLSListeners() {
		return nil
	}
	if strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "" {
		return errors.New("OSCAR_LISTENERS_TLS needs TLS_CERT_FILE and TLS_KEY_FILE, the certificate the TLS listener serves")
	}
	return nil
}
