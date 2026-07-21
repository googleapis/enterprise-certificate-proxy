// Copyright 2023 Google LLC.
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

package linux

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"testing"

	"github.com/googleapis/enterprise-certificate-proxy/internal/testflags"
)

func getTestParams() (string, string, string, string) {
	module := *testflags.TestModule
	if module == "" {
		module = "/usr/local/lib/softhsm/libsofthsm2.so"
	}
	label := *testflags.TestLabel
	if label == "" {
		label = "Demo Object"
	}
	pin := *testflags.TestUserPin
	if pin == "" {
		pin = "0000"
	}
	slot := *testflags.TestSlot
	return module, slot, label, pin
}

func makeTestSecureKey(t *testing.T) *SecureKey {
	module, slot, label, pin := getTestParams()
	if _, err := os.Stat(module); os.IsNotExist(err) {
		t.Skipf("Skipping test: PKCS11 module not found at %s", module)
	}
	sk, err := NewSecureKey(module, slot, label, pin)
	if err != nil {
		t.Skipf("Skipping test: failed to initialize secure key: %v", err)
	}
	return sk
}

func TestEncrypt(t *testing.T) {
	sk := makeTestSecureKey(t)
	defer sk.Close()

	publicKey := sk.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestEncrypt: EC keys not yet supported for Encrypt")
	}

	message := "Plain text to encrypt"
	bMessage := []byte(message)
	//Softhsm only supports SHA1
	_, err := sk.Encrypt(nil, bMessage, crypto.SHA1)
	if err != nil {
		t.Errorf("Client Encrypt error: %q", err)
	}
}

func TestDecrypt(t *testing.T) {
	sk := makeTestSecureKey(t)
	defer sk.Close()

	publicKey := sk.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestDecrypt: EC keys not yet supported for Decrypt")
	}

	message := "Plain text to encrypt"
	bMessage := []byte(message)
	//Softhsm only supports SHA1
	cipher, err := sk.Encrypt(nil, bMessage, crypto.SHA1)
	if err != nil {
		t.Errorf("Client Encrypt error: %q", err)
		return
	}
	decrypted, err := sk.Decrypt(nil, cipher, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("Client Decrypt error: %v", err)
	}
	decrypted = bytes.Trim(decrypted, "\x00")
	if string(decrypted) != message {
		t.Errorf("Client Decrypt error: expected %q, got %q", message, string(decrypted))
	}
}
