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

package darwin

import (
	"bytes"
	"testing"

	"github.com/googleapis/enterprise-certificate-proxy/internal/signer/darwin/keychain"
)

const TEST_CREDENTIALS = "TestIssuer"

func TestClientEncrypt(t *testing.T) {
	secureKey, err := keychain.Cred(TEST_CREDENTIALS)
	if err != nil {
		t.Errorf("Cred: got %v, want nil err", err)
		return
	}
	plaintext := []byte("Plain text to encrypt")
	_, err = secureKey.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Client API encryption: got %v, want nil err", err)
		return
	}
}

func TestClientDecrypt(t *testing.T) {
	secureKey, err := keychain.Cred(TEST_CREDENTIALS)
	if err != nil {
		t.Errorf("Cred: got %v, want nil err", err)
		return
	}
	byteSlice := []byte("Plain text to encrypt")
	ciphertext, _ := secureKey.Encrypt(byteSlice)
	plaintext, err := secureKey.Decrypt(ciphertext)
	if err != nil {
		t.Errorf("Client API decryption: got %v, want nil err", err)
		return
	}
	if !bytes.Equal(byteSlice, plaintext) {
		t.Errorf("Decryption message does not match original: got %v, want %v", plaintext, byteSlice)
	}
}
