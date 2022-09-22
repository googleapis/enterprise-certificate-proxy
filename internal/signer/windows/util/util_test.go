package util

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadConfig error: %q", err)
	}
	want := "enterprise_v1_corp_client"
	if config.CertConfigs.WindowsMyStoreConfig.Issuer != want {
		t.Errorf("Expected issuer is %q, got: %q", want, config.CertConfigs.WindowsMyStoreConfig.Issuer)
	}
	want = "MY"
	if config.CertConfigs.WindowsMyStoreConfig.Store != want {
		t.Errorf("Expected store is %q, got: %q", want, config.CertConfigs.WindowsMyStoreConfig.Store)
	}
	want = "current_user"
	if config.CertConfigs.WindowsMyStoreConfig.Provider != want {
		t.Errorf("Expected provider is %q, got: %q", want, config.CertConfigs.WindowsMyStoreConfig.Provider)
	}
}
