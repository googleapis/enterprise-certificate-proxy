package util

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./test_data/certificate_config.json")
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}
	want := "0x1739427"
	if config.CertConfigs.PKCS11.Slot != want {
		t.Errorf("Expected slot is %v, got: %v", want, config.CertConfigs.PKCS11.Slot)
	}
	want = "gecc"
	if config.CertConfigs.PKCS11.Label != want {
		t.Errorf("Expected label is %v, got: %v", want, config.CertConfigs.PKCS11.Label)
	}
	want = "pkcs11_module.so"
	if config.CertConfigs.PKCS11.PKCS11Module != want {
		t.Errorf("Expected pkcs11_module is %v, got: %v", want, config.CertConfigs.PKCS11.PKCS11Module)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	_, err := LoadConfig("./test_data/certificate_config_missing.json")
	if err == nil {
		t.Error("Expected error but got nil")
	}
}

func TestParseHexString(t *testing.T) {
	got, err := ParseHexString("0x1739427")
	if err != nil {
		t.Fatalf("ParseHexString error: %v", err)
	}
	want := uint32(0x1739427)
	if got != want {
		t.Errorf("Expected result is %v, got: %v", want, got)
	}
}

func TestParseHexStringFailure(t *testing.T) {
	_, err := ParseHexString("abcdefgh")
	if err == nil {
		t.Error("Expected error but got nil")
	}
}
