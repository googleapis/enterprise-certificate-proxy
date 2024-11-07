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
	"crypto"
	"crypto/rsa"
	"testing"
)

const testIssuer = "TestIssuer"

func TestClientEncrypt(t *testing.T) {
	secureKey, err := NewSecureKey(testIssuer)
	if err != nil {
		t.Errorf("Cred: got %v, want nil err", err)
		return
	}
	plaintext := []byte("Plain text to encrypt")
	_, err = secureKey.Encrypt(nil, plaintext, crypto.SHA256)
	if err != nil {
		t.Errorf("Client API encryption: got %v, want nil err", err)
		return
	}
}

func TestImportPKCS12Cred(t *testing.T) {
	credPath := "../testdata/testcred.p12"
	password := "1234"
	err := ImportPKCS12Cred(credPath, password)
	if err != nil {
		t.Errorf("ImportPKCS12Cred: got %v, want nil err", err)
		return
	}
}
