package util

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadConfig error: %q", err)
	}
	want := "Google Endpoint Verification"
	if config.CertConfigs.MacOSKeychain.Issuer != want {
		t.Errorf("Expected issuer is %q, got: %q", want, config.CertConfigs.MacOSKeychain.Issuer)
	}
}
