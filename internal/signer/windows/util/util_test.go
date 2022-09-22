package util

import (
	"testing"
)

func TestLoadCertInfo(t *testing.T) {
	certInfo, err := LoadCertInfo("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadCertInfo error: %q", err)
	}
	want := "enterprise_v1_corp_client"
	if certInfo.Issuer != want {
		t.Errorf("Expected issuer is %q, got: %q", want, certInfo.Issuer)
	}
	want = "MY"
	if certInfo.Store != want {
		t.Errorf("Expected store is %q, got: %q", want, certInfo.Store)
	}
	want = "current_user"
	if certInfo.Provider != want {
		t.Errorf("Expected provider is %q, got: %q", want, certInfo.Provider)
	}
}
