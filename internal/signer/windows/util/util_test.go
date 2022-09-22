package util

import (
	"testing"
)

func TestLoadCertInfo(t *testing.T) {
	config, err := LoadConfig("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadConfig error: %q", err)
	}
	want := "enterprise_v1_corp_client"
	if config.CertInfo.Issuer != want {
		t.Errorf("Expected issuer is %q, got: %q", want, config.CertInfo.Issuer)
	}
	want = "MY"
	if config.CertInfo.Store != want {
		t.Errorf("Expected store is %q, got: %q", want, config.CertInfo.Store)
	}
	want = "current_user"
	if config.CertInfo.Provider != want {
		t.Errorf("Expected provider is %q, got: %q", want, config.CertInfo.Provider)
	}
}
