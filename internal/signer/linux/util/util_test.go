package util

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./test_data/enterprise_certificate_config.json")
	if err != nil {
		t.Fatalf("LoadConfig error: %q", err)
	}
	want := "0x1739427"
	if config.CertInfo.Slot != want {
		t.Errorf("Expected slot is %q, got: %q", want, config.CertInfo.Slot)
	}
	want = "gecc"
	if config.CertInfo.Label != want {
		t.Errorf("Expected label is %q, got: %q", want, config.CertInfo.Label)
	}
	want = "pkcs11_module.so"
	if config.Libs.PKCS11Module != want {
		t.Errorf("Expected pkcs11_module is %q, got: %q", want, config.Libs.PKCS11Module)
	}
}

func TestParseHexString(t *testing.T) {
	got, err := ParseHexString("0x1739427")
	if err != nil {
		t.Fatalf("ParseHexString error: %q", err)
	}
	want := uint32(0x1739427)
	if got != want {
		t.Errorf("Expected result is %q, got: %q", want, got)
	}
}
