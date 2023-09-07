// Copyright 2022 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The tests in this file launches a mock signer binary "signer.go".
package client

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestClient_Cred_Success(t *testing.T) {
	_, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Errorf("Cred: got %v, want nil err", err)
	}
}

func TestClient_Cred_ConfigMissing(t *testing.T) {
	_, err := Cred("missing.json")
	if got, want := err, ErrCredUnavailable; !errors.Is(got, want) {
		t.Errorf("Cred: with missing config; got %v, want %v err", got, want)
	}
}

func TestClient_Cred_BinaryPathMissing(t *testing.T) {
	_, err := Cred("testdata/certificate_config_missing_path.json")
	if got, want := err, ErrCredUnavailable; !errors.Is(got, want) {
		t.Errorf("Cred: with missing ECP path; got %v, want %v err", got, want)
	}
}

func TestClient_Cred_EnvOverride_ExplicitConfig(t *testing.T) {
	configFilePath := "testdata/certificate_config.json"
	os.Setenv("GOOGLE_API_CERTIFICATE_CONFIG", "testdata/certificate_config_missing_path.json")
	_, err := Cred(configFilePath)
	if err != nil {
		t.Errorf("Cred: with explicit config and set env var; got %v, want %v err", err, nil)
	}
}

func TestClient_Cred_EnvOverride_EmptyConfig(t *testing.T) {
	configFilePath := ""
	os.Setenv("GOOGLE_API_CERTIFICATE_CONFIG", "testdata/certificate_config_broken.json")
	_, err := Cred(configFilePath)
	var serr *json.SyntaxError
	if got, want := err, &serr; !errors.As(got, want) {
		t.Errorf("Cred: with empty config and set env var; got %v, want %v err", got, want)
	}
}

func TestClient_Public(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if key.Public() == nil {
		t.Error("Public: got nil, want non-nil Public Key")
	}
}

func TestClient_CertificateChain(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if key.CertificateChain() == nil {
		t.Error("CertificateChain: got nil, want non-nil Certificate Chain")
	}
}

func TestClient_Sign(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
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

func TestClient_Sign_HashSizeMismatch(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.Sign(nil, []byte("testDigest"), crypto.SHA256)
	if got, want := err.Error(), "Digest length of 10 bytes does not match Hash function size of 32 bytes"; got != want {
		t.Errorf("Sign: got err %v, want err %v", got, want)
	}
}

func TestClient_Close(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	err = key.Close()
	if err != nil {
		t.Errorf("Close: got %v, want nil err", err)
	}
}

func TestClient_Encrypt(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("Plain text to encrypt")
	_, err = key.Encrypt(message)
	if err != nil {
		t.Errorf("Encrypt: got %v, want nil err", err)
	}
}

func TestClient_Decrypt(t *testing.T) {
	key, err := Cred("testdata/certificate_config.json")
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("Plain text to encrypt")
	encryptedData, err := key.Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt: got %v, want nil err", err)
	}
	decryptedData, err := key.Decrypt(encryptedData)
	if err != nil {
		t.Fatalf("Decrypt: got %v, want nil err", err)
	}
	decryptedData = bytes.Trim(decryptedData, "\x00")
	if string(decryptedData) != string(message) {
		t.Errorf("Decrypt: got %v, want %v", string(decryptedData), string(message))
	}
}
