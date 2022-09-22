package util

import (
	"testing"
)

func TestLoadCertInfo(t *testing.T) {
	certInfo, err := LoadCertInfo("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadCertInfo error: %q", err)
	}
	want := "Google Endpoint Verification"
	if certInfo.Issuer != want {
		t.Errorf("Expected issuer is %q, got: %q", want, certInfo.Issuer)
	}
}
