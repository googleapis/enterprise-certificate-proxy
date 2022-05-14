//go:build darwin && cgo
// +build darwin,cgo

package keychain

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"unsafe"
)

type signerOpts crypto.Hash

func (s signerOpts) HashFunc() crypto.Hash {
	return crypto.Hash(s)
}

func TestKeychainError(t *testing.T) {
	tests := []struct {
		e    keychainError
		want string
	}{
		{e: keychainError(0), want: "No error."},
		{e: keychainError(-4), want: "Function or operation not implemented."},
	}

	for i, test := range tests {
		if got := test.e.Error(); got != test.want {
			t.Errorf("test %d: %#v.Error() = %q, want %q", i, test.e, got, test.want)
		}
	}
}

func TestBytesToCFDataRoundTrip(t *testing.T) {
	want := []byte("an arbitrary and yet coherent byte slice!")
	d := bytesToCFData(want)
	defer cfRelease(unsafe.Pointer(d))
	if got := cfDataToBytes(d); !bytes.Equal(got, want) {
		t.Errorf("bytesToCFData -> cfDataToBytes\ngot  %x\nwant %x", got, want)
	}
}
