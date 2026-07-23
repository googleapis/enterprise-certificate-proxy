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

// pkcs11 provides helpers for working with certificates via PKCS#11 APIs
// provided by go-pkcs11
package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"github.com/google/go-pkcs11/pkcs11"
)

// ParseHexString parses hexadecimal string into uint32
func ParseHexString(str string) (i uint32, err error) {
	stripped := strings.ReplaceAll(str, "0x", "")
	resultUint64, err := strconv.ParseUint(stripped, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(resultUint64), nil
}

// Cred returns a Key wrapping the first valid certificate in the pkcs11 module
// matching a given slot and label.
func Cred(pkcs11Module string, slotUint32Str string, label string, userPin string) (*Key, error) {
	module, err := pkcs11.Open(pkcs11Module)
	if err != nil {
		return nil, err
	}
	slotUint32, err := ParseHexString(slotUint32Str)
	if err != nil {
		return nil, err
	}
	kslot, err := module.Slot(slotUint32, pkcs11.Options{PIN: userPin})
	if err != nil {
		return nil, err
	}

	certs, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassCertificate, Label: label})
	if err != nil {
		return nil, err
	}

	if len(certs) < 1 {
		return nil, fmt.Errorf("no certificate object was found with label %s", label)
	}

	cert, err := certs[0].Certificate()
	if err != nil {
		return nil, err
	}
	leafX509, err := cert.X509()
	if err != nil {
		return nil, err
	}

	// Fetch all certificate objects to resolve intermediate and root certificates
	allCertObjs, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassCertificate})
	if err != nil {
		return nil, err
	}

	var candidates []*x509.Certificate
	for _, cObj := range allCertObjs {
		c, err := cObj.Certificate()
		if err != nil {
			continue
		}
		x, err := c.X509()
		if err != nil {
			continue
		}
		candidates = append(candidates, x)
	}

	// Build the chain starting with the leaf certificate
	kchain := buildChain(leafX509, candidates)

	pubKeys, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassPublicKey, Label: label})
	if err != nil {
		return nil, err
	}

	if len(pubKeys) < 1 {
		return nil, fmt.Errorf("no public key object was found with label %s", label)
	}

	pubKey, err := pubKeys[0].PublicKey()
	if err != nil {
		return nil, err
	}

	privkeys, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassPrivateKey, Label: label})
	if err != nil {
		return nil, err
	}

	if len(privkeys) < 1 {
		return nil, fmt.Errorf("no private key object was found with label %s", label)
	}

	privKey, err := privkeys[0].PrivateKey(pubKey)
	if err != nil {
		return nil, err
	}
	ksigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("PrivateKey does not implement crypto.Signer")
	}
	kdecrypter, _ := privKey.(crypto.Decrypter)
	defaultHash := crypto.SHA256
	return &Key{
		slot:      kslot,
		signer:    ksigner,
		chain:     kchain,
		privKey:   privKey,
		label:     label,
		module:    *module,
		hash:      defaultHash,
		decrypter: kdecrypter,
	}, nil
}

// Key is a wrapper around the pkcs11 module and uses it to
// implement signing-related methods.
type Key struct {
	slot      *pkcs11.Slot
	signer    crypto.Signer
	chain     [][]byte
	privKey   crypto.PrivateKey
	label     string
	module    pkcs11.Module
	hash      crypto.Hash
	decrypter crypto.Decrypter
}

// CertificateChain returns the credential as a raw X509 cert chain. This
// contains the public key.
func (k *Key) CertificateChain() [][]byte {
	return k.chain
}

// Close releases resources held by the credential.
func (k *Key) Close() {
	_ = k.slot.Close()
	_ = k.module.Close()
}

// Public returns the corresponding public key for this Key.
func (k *Key) Public() crypto.PublicKey {
	return k.signer.Public()
}

// Sign signs a message.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.signer.Sign(nil, digest, opts)
}

// Encrypt encrypts a plaintext message digest using the public key. Here, we use standard golang API.
func (k *Key) Encrypt(plaintext []byte, opts any) ([]byte, error) {
	if hash, ok := opts.(crypto.Hash); ok {
		k.hash = hash
	} else {
		return nil, fmt.Errorf("unsupported encrypt opts: %v", opts)
	}
	publicKey := k.Public()
	_, ok := publicKey.(*rsa.PublicKey)
	if ok {
		return k.encryptRSA(plaintext)
	}
	_, ok = publicKey.(*ecdsa.PublicKey)
	if ok {
		// TODO: Implement encryption for ec keys - https://github.com/googleapis/enterprise-certificate-proxy/issues/95
		return nil, errors.New("encrypt error: EC keys not yet supported")
	}
	return nil, errors.New("encrypt error: Unsupported key type")
}

// Decrypt decrypts a ciphertext message digest using the private key. Here, we pass off the decryption to pkcs11 library.
func (k *Key) Decrypt(msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if oaepOpts, ok := opts.(*rsa.OAEPOptions); ok {
		k.hash = oaepOpts.Hash
	} else {
		return nil, fmt.Errorf("unsupported DecrypterOpts: %v", opts)
	}
	if k.decrypter == nil {
		return nil, fmt.Errorf("decrypt error: Decrypter is nil")
	}
	publicKey := k.Public()
	_, ok := publicKey.(*rsa.PublicKey)
	if ok {
		return k.decryptRSAWithPKCS11(msg)
	}
	_, ok = publicKey.(*ecdsa.PublicKey)
	if ok {
		// TODO: Implement decryption for ec keys - https://github.com/googleapis/enterprise-certificate-proxy/issues/95
		return nil, errors.New("decrypt error: EC keys not yet supported")
	}
	return nil, errors.New("decrypt error: Unsupported key type")
}

func (k *Key) encryptRSA(data []byte) ([]byte, error) {
	publicKey := k.Public()
	rsaPubKey := publicKey.(*rsa.PublicKey)
	hash, err := cryptoHashToHash(k.hash)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptOAEP(hash, rand.Reader, rsaPubKey, data, nil)
}

func (k *Key) decryptRSAWithPKCS11(encryptedData []byte) ([]byte, error) {
	opts := &rsa.OAEPOptions{Hash: k.hash}
	return k.decrypter.Decrypt(nil, encryptedData, opts)
}

func cryptoHashToHash(hash crypto.Hash) (hash.Hash, error) {
	switch hash {
	case crypto.SHA256:
		return sha256.New(), nil
	case crypto.SHA1:
		return sha1.New(), nil
	default:
		return nil, errors.New("hash conversion error: Unsupported hash")
	}
}


// buildChain builds a certificate chain starting from the leaf certificate, using candidates found in the token.
func buildChain(leaf *x509.Certificate, candidates []*x509.Certificate) [][]byte {
	var kchain [][]byte
	current := leaf
	kchain = append(kchain, current.Raw)

	// Prevent infinite loops (e.g. self-signed root)
	visited := make(map[string]bool)
	visited[string(current.Raw)] = true

	for {
		// If current is self-signed (root), we stop
		if bytes.Equal(current.RawSubject, current.RawIssuer) {
			break
		}

		// Look for current is issuer in the candidate pool
		var foundIssuer *x509.Certificate
		for _, cand := range candidates {
			if bytes.Equal(cand.RawSubject, current.RawIssuer) {
				if !visited[string(cand.Raw)] {
					foundIssuer = cand
					break
				}
			}
		}

		if foundIssuer == nil {
			break // Issuer not found
		}

		current = foundIssuer
		kchain = append(kchain, current.Raw)
		visited[string(current.Raw)] = true
	}

	return kchain
}
