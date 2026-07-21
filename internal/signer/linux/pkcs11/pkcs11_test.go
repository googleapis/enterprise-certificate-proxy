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

package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"sync"
	"testing"

	"github.com/googleapis/enterprise-certificate-proxy/internal/testflags"
)

func makeTestKey(t testing.TB) *Key {
	module := *testflags.TestModule
	if module == "" {
		module = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(module); os.IsNotExist(err) {
		t.Skipf("Skipping test: PKCS11 module not found at %s", module)
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
	key, err := Cred(module, slot, label, pin)
	if err != nil {
		t.Skipf("Skipping test: failed to initialize PKCS11 module: %v", err)
	}
	return key
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

func TestCredLinux(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()
}

func BenchmarkEncryptRSA(b *testing.B) {
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	key := makeTestKey(b)
	defer key.Close()
	b.Run("encryptRSA Crypto", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, errEncrypt := key.encryptRSA(bMsg, crypto.SHA256)
			if errEncrypt != nil {
				b.Errorf("EncryptRSA error: %q", errEncrypt)
				return
			}
		}
	})
}

func TestEncrypt(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()
	publicKey := key.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestEncrypt: EC keys not yet supported for Encrypt")
	}
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	_, err := key.Encrypt(bMsg, crypto.SHA1)
	if err != nil {
		t.Errorf("Encrypt error: %q", err)
	}
}

func TestDecrypt(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()
	publicKey := key.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestDecrypt: EC keys not yet supported for Decrypt")
	}
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	// Softhsm only supports SHA1
	ciphertext, err := key.Encrypt(bMsg, crypto.SHA1)
	if err != nil {
		t.Errorf("Encrypt error: %q", err)
	}
	decrypted, err := key.Decrypt(ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	decrypted = bytes.Trim(decrypted, "\x00")
	if string(decrypted) != msg {
		t.Errorf("Decrypt error: expected %q, got %q", msg, string(decrypted))
	}
}

func TestConcurrentSign(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()

	// Use a 32-byte digest for SHA256 signing
	digest := make([]byte, 32)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := key.Sign(nil, digest, crypto.SHA256)
			if err != nil {
				t.Errorf("Sign error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentDecrypt(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()

	publicKey := key.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestConcurrentDecrypt: EC keys not yet supported for Decrypt")
	}

	msg := []byte("Plain text to encrypt")
	ciphertext, err := key.Encrypt(msg, crypto.SHA1)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decrypted, err := key.Decrypt(ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
			if err != nil {
				t.Errorf("Decrypt error: %v", err)
				return
			}
			decrypted = bytes.Trim(decrypted, "\x00")
			if string(decrypted) != string(msg) {
				t.Errorf("Decrypt mismatch: expected %q, got %q", msg, decrypted)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentSignAndDecrypt(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()

	publicKey := key.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestConcurrentSignAndDecrypt: EC keys not yet supported for Encrypt/Decrypt")
	}

	msg := make([]byte, 32) // 32-byte digest/payload
	ciphertext, err := key.Encrypt(msg, crypto.SHA1)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := key.Sign(nil, msg, crypto.SHA256)
			if err != nil {
				t.Errorf("Sign error: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_, err := key.Decrypt(ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
			if err != nil {
				t.Errorf("Decrypt error: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestConcurrentHashAccess(t *testing.T) {
	key := makeTestKey(t)
	defer key.Close()

	publicKey := key.Public()
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		t.Skip("Skipping TestConcurrentHashAccess: EC keys not yet supported for Encrypt")
	}

	msg := []byte("Some plaintext message")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		// Request A: SHA256 Encrypt
		go func() {
			defer wg.Done()
			_, err := key.Encrypt(msg, crypto.SHA256)
			if err != nil {
				t.Errorf("SHA256 Encrypt error: %v", err)
			}
		}()
		// Request B: SHA1 Encrypt
		go func() {
			defer wg.Done()
			_, err := key.Encrypt(msg, crypto.SHA1)
			if err != nil {
				t.Errorf("SHA1 Encrypt error: %v", err)
			}
		}()
	}
	wg.Wait()
}
