package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseListenersCfg_TLS(t *testing.T) {
	cases := []struct {
		name        string
		cfg         Config
		want        []ListenerGroup
		errContains string
	}{
		{
			name: "TLS listener with its advertised host",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSListenersSSL:         []string{"LAN://127.0.0.1:5191"},
				BOSAdvertisedHostsSSL:   []string{"LAN://icq.example.org:3143"},
				BOSListenersTLS:         []string{"LAN://0.0.0.0:5194"},
				BOSAdvertisedHostsTLS:   []string{"LAN://icq.example.org:5194"},
			},
			want: []ListenerGroup{
				{
					Name:                   "lan",
					BOSListenAddress:       "0.0.0.0:5190",
					BOSListenAddressSSL:    "127.0.0.1:5191",
					BOSAdvertisedHostPlain: "icq.example.org:5190",
					BOSAdvertisedHostSSL:   "icq.example.org:3143",
					BOSListenAddressTLS:    "0.0.0.0:5194",
					BOSAdvertisedHostTLS:   "icq.example.org:5194",
				},
			},
		},
		{
			name: "TLS listener without an advertised host",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSListenersTLS:         []string{"LAN://0.0.0.0:5194"},
			},
			errContains: "missing TLS BOS advertise address",
		},
		{
			name: "advertised TLS host without a listener",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSAdvertisedHostsTLS:   []string{"LAN://icq.example.org:5194"},
			},
			errContains: "missing TLS BOS listen address",
		},
		{
			name: "TLS listener without a plain BOS listener in its group",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSListenersTLS:         []string{"WAN://0.0.0.0:5194"},
				BOSAdvertisedHostsTLS:   []string{"WAN://icq.example.org:5194"},
			},
			errContains: "missing BOS advertise address for listener `wan://`",
		},
		{
			name: "TLS listener on the plain listener's socket",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSListenersTLS:         []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsTLS:   []string{"LAN://icq.example.org:5190"},
			},
			errContains: "listen address 0.0.0.0:5190 is configured for both OSCAR_LISTENERS `lan://` and OSCAR_LISTENERS_TLS `lan://`",
		},
		{
			name: "duplicate TLS listener",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSListenersTLS:         []string{"LAN://0.0.0.0:5194", "LAN://0.0.0.0:5195"},
				BOSAdvertisedHostsTLS:   []string{"LAN://icq.example.org:5194"},
			},
			errContains: "duplicate listener definition",
		},
		{
			name: "TLS listener missing its port",
			cfg: Config{
				BOSListeners:            []string{"LAN://0.0.0.0:5190"},
				BOSAdvertisedHostsPlain: []string{"LAN://icq.example.org:5190"},
				BOSListenersTLS:         []string{"LAN://0.0.0.0"},
				BOSAdvertisedHostsTLS:   []string{"LAN://icq.example.org:5194"},
			},
			errContains: "missing port",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.cfg.ParseListenersCfg()
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestConfigValidate_TLS(t *testing.T) {
	base := func() Config {
		return Config{APIListener: "127.0.0.1:8080"}
	}
	cases := []struct {
		name        string
		mutate      func(c *Config)
		errContains string
	}{
		{
			name:   "no TLS listener needs no certificate",
			mutate: func(*Config) {},
		},
		{
			name: "TLS listener with certificate and key",
			mutate: func(c *Config) {
				c.BOSListenersTLS = []string{"LAN://0.0.0.0:5194"}
				c.TLSCertFile = "/certs/ts-cert.pem"
				c.TLSKeyFile = "/certs/ts-key.pem"
			},
		},
		{
			name: "TLS listener without a certificate",
			mutate: func(c *Config) {
				c.BOSListenersTLS = []string{"LAN://0.0.0.0:5194"}
				c.TLSKeyFile = "/certs/ts-key.pem"
			},
			errContains: "OSCAR_LISTENERS_TLS needs TLS_CERT_FILE and TLS_KEY_FILE",
		},
		{
			name: "TLS listener without a key",
			mutate: func(c *Config) {
				c.BOSListenersTLS = []string{"LAN://0.0.0.0:5194"}
				c.TLSCertFile = "/certs/ts-cert.pem"
			},
			errContains: "OSCAR_LISTENERS_TLS needs TLS_CERT_FILE and TLS_KEY_FILE",
		},
		{
			name: "blank TLS listener entry is no listener",
			mutate: func(c *Config) {
				c.BOSListenersTLS = []string{" "}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := c.Validate()
			if tc.errContains != "" {
				assert.ErrorContains(t, err, tc.errContains)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestEndpoint_Redirects(t *testing.T) {
	group := ListenerGroup{
		BOSListenAddress:       "0.0.0.0:5190",
		BOSListenAddressSSL:    "127.0.0.1:5191",
		BOSAdvertisedHostPlain: "icq.example.org:5190",
		BOSAdvertisedHostSSL:   "icq.example.org:3143",
		BOSListenAddressTLS:    "0.0.0.0:5194",
		BOSAdvertisedHostTLS:   "icq.example.org:5194",
	}
	plain := group.PlainEndpoint()
	ssl, _ := group.SSLEndpoint()
	tlsEP, ok := group.TLSEndpoint()
	assert.True(t, ok)

	noSSLGroup := group
	noSSLGroup.BOSListenAddressSSL, noSSLGroup.BOSAdvertisedHostSSL = "", ""
	noSSLTLS, ok := noSSLGroup.TLSEndpoint()
	assert.True(t, ok)

	cases := []struct {
		name          string
		endpoint      Endpoint
		wantsSSL      bool
		wantLogin     string
		wantLoginSSL  bool
		wantService   string
		wantServiceOK bool
	}{
		{
			name:        "plain endpoint, no SSL asked",
			endpoint:    plain,
			wantLogin:   "icq.example.org:5190",
			wantService: "icq.example.org:5190",
		},
		{
			name:          "plain endpoint, SSL asked: login stays plain, service goes to the SSL host",
			endpoint:      plain,
			wantsSSL:      true,
			wantLogin:     "icq.example.org:5190",
			wantService:   "icq.example.org:3143",
			wantServiceOK: true,
		},
		{
			name:         "SSL terminator endpoint keeps its clients on the SSL host",
			endpoint:     ssl,
			wantLogin:    "icq.example.org:3143",
			wantLoginSSL: true,
			wantService:  "icq.example.org:5190",
		},
		{
			name:        "TLS endpoint, no SSL asked: the TLS host, client not told to negotiate SSL",
			endpoint:    tlsEP,
			wantLogin:   "icq.example.org:5194",
			wantService: "icq.example.org:5194",
		},
		{
			name:        "TLS endpoint in a group without SSL, no SSL asked: still the TLS host",
			endpoint:    noSSLTLS,
			wantLogin:   "icq.example.org:5194",
			wantService: "icq.example.org:5194",
		},
		{
			name:          "TLS endpoint in a group without SSL, SSL asked: the TLS host",
			endpoint:      noSSLTLS,
			wantsSSL:      true,
			wantLogin:     "icq.example.org:5194",
			wantLoginSSL:  true,
			wantService:   "icq.example.org:5194",
			wantServiceOK: true,
		},
		{
			name:          "TLS endpoint, SSL asked: the TLS host",
			endpoint:      tlsEP,
			wantsSSL:      true,
			wantLogin:     "icq.example.org:5194",
			wantLoginSSL:  true,
			wantService:   "icq.example.org:5194",
			wantServiceOK: true,
		},
		{
			name:        "plain endpoint without SSL in the group, SSL asked: plain host",
			endpoint:    noSSLGroup.PlainEndpoint(),
			wantsSSL:    true,
			wantLogin:   "icq.example.org:5190",
			wantService: "icq.example.org:5190",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, secure := tc.endpoint.LoginRedirect(tc.wantsSSL)
			assert.Equal(t, tc.wantLogin, host)
			assert.Equal(t, tc.wantLoginSSL, secure)

			host, secure = tc.endpoint.ServiceRedirect(tc.wantsSSL)
			assert.Equal(t, tc.wantService, host)
			assert.Equal(t, tc.wantServiceOK, secure)
		})
	}
}

func TestListenerGroup_TLSEndpoint(t *testing.T) {
	cases := []struct {
		name          string
		group         ListenerGroup
		wantEndpoints int
		wantTLS       bool
	}{
		{
			name:          "plain only",
			group:         ListenerGroup{BOSListenAddress: ":5190", BOSAdvertisedHostPlain: "h:5190"},
			wantEndpoints: 1,
		},
		{
			name: "plain, SSL and TLS",
			group: ListenerGroup{
				BOSListenAddress: ":5190", BOSAdvertisedHostPlain: "h:5190",
				BOSListenAddressSSL: ":5191", BOSAdvertisedHostSSL: "h:3143",
				BOSListenAddressTLS: ":5194", BOSAdvertisedHostTLS: "h:5194",
			},
			wantEndpoints: 3,
			wantTLS:       true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eps := tc.group.Endpoints()
			assert.Len(t, eps, tc.wantEndpoints)
			ep, ok := tc.group.TLSEndpoint()
			assert.Equal(t, tc.wantTLS, ok)
			if ok {
				assert.Equal(t, TransportTLS13, ep.Transport)
				assert.False(t, ep.IsSSL)
				assert.Equal(t, ":5194", ep.ListenAddress)
				assert.Equal(t, "h:5194", ep.AdvertisedHost())
				assert.Equal(t, "TLS13", ep.Transport.String())
				assert.Contains(t, eps, ep)
			}
		})
	}
}
