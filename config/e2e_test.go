package config

import (
	"os"
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/assert"
)

// E2E_KT_AUDITORS takes several auditors' verifier keys, comma-separated; a
// key's base64 may hold plus signs and slashes, which the list keeps.
func TestE2EConfigAuditorsFromEnv(t *testing.T) {
	for _, v := range []string{"E2E_TOKEN_TTL", "E2E_MAX_DEVICES", "E2E_MAX_ONE_TIME_KEYS", "E2E_KT_ORIGIN", "E2E_KT_AUDITORS", "E2E_LINK_TTL"} {
		t.Setenv(v, "") // restored after the test
		assert.NoError(t, os.Unsetenv(v))
	}
	keys := []string{
		"a.example.net/icq+21aa4075+BFICDtUSzx6N2RdRPWK479HEgQ0502Q7ExO26fmhIBGh",
		"b.example.net/icq+eab1b5d6+BAE7giifet59i6DIHYzEzvXAP3emEDXyr5XZIS5fhMGL",
		"c.example.net/icq+0badf00d+BA+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	t.Setenv("E2E_KT_AUDITORS", keys[0]+","+keys[1]+","+keys[2])

	var c E2EConfig
	assert.NoError(t, envconfig.Process("", &c))
	assert.Equal(t, keys, c.KTAuditors)
}
