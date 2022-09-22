package util

import (
	"testing"
)

func TestLoadSignerBinaryPath(t *testing.T) {
	path, err := LoadSignerBinaryPath("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadSignerBinaryPath error: %q", err)
	}
	want := "C:/Program Files (x86)/Google/Endpoint Verification/signer.exe"
	if path != want {
		t.Errorf("Expected path is %q, got: %q", want, path)
	}
}
