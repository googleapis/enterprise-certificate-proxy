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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"math/big"
	"testing"
	"time"
)

const (
	testModule  = "/usr/lib/softhsm/libsofthsm2.so"
	testLabel   = "Demo Object"
	testUserPin = "0000"
)

var testSlot = flag.String("testSlot", "", "libsofthsm2 slot location")

func makeTestKey() (*Key, error) {
	key, err := Cred(testModule, *testSlot, testLabel, testUserPin)
	return key, err
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
	key, err := makeTestKey()
	if err != nil {
		t.Errorf("Cred error: %q", err)
	}
	defer key.Close()
}

func BenchmarkEncryptRSA(b *testing.B) {
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	key, errCred := makeTestKey()
	if errCred != nil {
		b.Errorf("Cred error: %q", errCred)
		return
	}
	defer key.Close()
	b.Run("encryptRSA Crypto", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, errEncrypt := key.encryptRSA(bMsg)
			if errEncrypt != nil {
				b.Errorf("EncryptRSA error: %q", errEncrypt)
				return
			}
		}
	})
}

func TestEncrypt(t *testing.T) {
	key, errCred := makeTestKey()
	if errCred != nil {
		t.Errorf("Cred error: %q", errCred)
		return
	}
	defer key.Close()
	msg := "Plain text to encrypt"
	bMsg := []byte(msg)
	_, err := key.Encrypt(bMsg, crypto.SHA1)
	if err != nil {
		t.Errorf("Encrypt error: %q", err)
	}
}

func TestDecrypt(t *testing.T) {
	key, errCred := makeTestKey()
	if errCred != nil {
		t.Errorf("Cred error: %q", errCred)
		return
	}
	defer key.Close()
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
