// Copyright 2022 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// The tests in this file launches a mock signer binary "signer.go".
package client

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestClient_Cred_Success(t *testing.T) {
	_, err := Cred("testdata/enterprise_certificate_config.json")
	if err != nil {
		t.Errorf("Cred: got %v, want nil err", err)
	}
}

func TestClient_Cred_ConfigMissing(t *testing.T) {
	_, err := Cred("missing.json")
	if got, want := err, os.ErrNotExist; !errors.Is(got, want) {
		t.Errorf("Cred: with missing config; got %v, want %v err", got, want)
	}
}

func TestClient_Public(t *testing.T) {
	key, err := Cred("testdata/enterprise_certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if key.Public() == nil {
		t.Error("Public: got nil, want non-nil Public Key")
	}
}

func TestClient_CertificateChain(t *testing.T) {
	key, err := Cred("testdata/enterprise_certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if key.CertificateChain() == nil {
		t.Error("CertificateChain: got nil, want non-nil Certificate Chain")
	}
}

func TestClient_Sign(t *testing.T) {
	key, err := Cred("testdata/enterprise_certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := key.Sign(nil, []byte("testDigest"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := signed, []byte("testDigest"); !bytes.Equal(got, want) {
		t.Errorf("Sign: got %c, want %c", got, want)
	}
}

func TestClient_Close(t *testing.T) {
	key, err := Cred("testdata/enterprise_certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	err = key.Close()
	if err != nil {
		t.Errorf("Close: got %v, want nil err", err)
	}
}
