//go:build windows
// +build windows

package ncrypt

import (
	"testing"
)

func TestCredProviderNotSupported(t *testing.T) {
	_, err := Cred("issuer", "store", "unsupported_provider")
	if err == nil {
		t.Errorf("Expected error, but got nil.")
	}
	want := "provider must be local_machine or current_user"
	if err.Error() != want {
		t.Errorf("Expected error is %q, got: %q", want, err.Error())
	}
}
