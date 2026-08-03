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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"
)

func makeTestKey(t testing.TB) *Key {
	module := os.Getenv("ECP_TEST_MODULE")
	if module == "" {
		module = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(module); os.IsNotExist(err) {
		t.Skipf("Skipping test: PKCS11 module not found at %s. Set ECP_TEST_MODULE env var to configure.", module)
	}
	label := os.Getenv("ECP_TEST_LABEL")
	if label == "" {
		label = "Demo Object"
	}
	pin := os.Getenv("ECP_TEST_USER_PIN")
	if pin == "" {
		pin = "0000"
	}
	slot := os.Getenv("ECP_TEST_SLOT")
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

func TestBuildChain(t *testing.T) {
	// Create mock certificates using Go standard library
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// 1. Create a root CA cert
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("Failed to parse root certificate: %v", err)
	}

	// 2. Create an intermediate CA cert (signed by Root)
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate certificate: %v", err)
	}

	// 3. Create a leaf cert (signed by Intermediate)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "Leaf Cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	// Test case: Leaf + Intermediate + Root CA available in the candidates pool
	candidates := []*x509.Certificate{intermediateCert, rootCert}
	chain := buildChain(leafCert, candidates)

	if len(chain) != 3 {
		t.Fatalf("Expected chain length of 3, got: %d", len(chain))
	}
	if !bytes.Equal(chain[0], leafCert.Raw) {
		t.Error("First certificate in chain should be the leaf certificate")
	}
	if !bytes.Equal(chain[1], intermediateCert.Raw) {
		t.Error("Second certificate in chain should be the intermediate certificate")
	}
	if !bytes.Equal(chain[2], rootCert.Raw) {
		t.Error("Third certificate in chain should be the root certificate")
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
