package config

import (
	"os"
	"testing"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
)

func TestTURNConfigPortRange(t *testing.T) {
	tests := []struct {
		name      string
		ports     string
		wantFirst uint16
		wantLast  uint16
		wantErr   bool
	}{
		{name: "a range", ports: "49160-49199", wantFirst: 49160, wantLast: 49199},
		{name: "one port", ports: "49160-49160", wantFirst: 49160, wantLast: 49160},
		{name: "spaces around", ports: " 49160 - 49199 ", wantFirst: 49160, wantLast: 49199},
		{name: "backwards", ports: "49199-49160", wantErr: true},
		{name: "a single number", ports: "49160", wantErr: true},
		{name: "port 0", ports: "0-10", wantErr: true},
		{name: "past 65535", ports: "65000-70000", wantErr: true},
		{name: "not numbers", ports: "a-b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, last, err := TURNConfig{RelayPorts: tt.ports}.PortRange()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantFirst, first)
			assert.Equal(t, tt.wantLast, last)
		})
	}
}

func TestConfigValidateTURN(t *testing.T) {
	enabled := TURNConfig{Enabled: true, PublicIP: "192.0.2.1", RelayPorts: "49160-49199", MaxPerIP: 8, Kbps: 2000, IdleTimeout: 5 * time.Minute}
	tests := []struct {
		name        string
		stun        string
		turn        func(c *TURNConfig)
		errContains string
	}{
		{name: "an enabled relay", stun: "0.0.0.0:3478"},
		{name: "a disabled relay needs nothing", stun: "", turn: func(c *TURNConfig) { *c = TURNConfig{} }},
		{name: "no STUN server", stun: "", errContains: "STUN_LISTENER"},
		{name: "no public address", stun: "0.0.0.0:3478", turn: func(c *TURNConfig) { c.PublicIP = "" }, errContains: "TURN_PUBLIC_IP"},
		{name: "bad ports", stun: "0.0.0.0:3478", turn: func(c *TURNConfig) { c.RelayPorts = "1" }, errContains: "relay ports"},
		{name: "no allocations per address", stun: "0.0.0.0:3478", turn: func(c *TURNConfig) { c.MaxPerIP = 0 }, errContains: "TURN_MAX_ALLOCATIONS_PER_IP"},
		{name: "too little bandwidth", stun: "0.0.0.0:3478", turn: func(c *TURNConfig) { c.Kbps = 10 }, errContains: "TURN_RELAY_KBPS"},
		{name: "no idle timeout", stun: "0.0.0.0:3478", turn: func(c *TURNConfig) { c.IdleTimeout = 0 }, errContains: "TURN_IDLE_TIMEOUT"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{APIListener: "127.0.0.1:8080", STUNListener: tt.stun, TURN: enabled}
			if tt.turn != nil {
				tt.turn(&c.TURN)
			}
			err := c.Validate()
			if tt.errContains == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.errContains)
		})
	}
}

func TestTURNConfigFromEnv(t *testing.T) {
	for _, v := range []string{"TURN_ENABLED", "TURN_PUBLIC_IP", "TURN_RELAY_PORTS", "TURN_MAX_ALLOCATIONS_PER_IP", "TURN_RELAY_KBPS", "TURN_IDLE_TIMEOUT"} {
		t.Setenv(v, "") // restored after the test
		assert.NoError(t, os.Unsetenv(v))
	}
	t.Setenv("TURN_ENABLED", "true")
	t.Setenv("TURN_PUBLIC_IP", "icq.example.com")

	var c TURNConfig
	assert.NoError(t, envconfig.Process("", &c))
	assert.Equal(t, TURNConfig{Enabled: true, PublicIP: "icq.example.com", RelayPorts: "49160-49199",
		MaxPerIP: 8, Kbps: 2000, IdleTimeout: 5 * time.Minute}, c)
}
