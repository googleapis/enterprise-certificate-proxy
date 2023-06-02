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

//go:build darwin && cgo
// +build darwin,cgo

// Package darwin contains a darwin-specific client for accessing the signer APIs directly,
// bypassing the RPC-mechanims of the universal client.
package darwin

import (
	"crypto"
	"github.com/googleapis/enterprise-certificate-proxy/internal/signer/darwin/keychain"
	"io"
)

// SecureKey is a public wrapper for the internal keychain implementation.
type SecureKey struct {
	key *keychain.Key
}

// CertificateChain returns the credential as a raw X509 cert chain. This contains the public key.
func (sk *SecureKey) CertificateChain() [][]byte {
	return sk.key.CertificateChain()
}

// Public returns the public key for this SecureKey.
func (sk *SecureKey) Public() crypto.PublicKey {
	return sk.key.Public()
}

// Sign signs a message digest, using the specified signer options.
func (sk *SecureKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signed []byte, err error) {
	return sk.key.Sign(nil, digest, opts)
}

// Close frees up resources associated with the underlying key.
func (sk *SecureKey) Close() {
	sk.key.Close()
}

// Cred gets the first Credential (filtering on issuer) corresponding to
// available certificate and private key pairs (i.e. identities) available in
// the Keychain. This includes both the current login keychain for the user,
// and the system keychain.
func NewSecureKey(issuerCN string) (*SecureKey, error) {
	k, err := keychain.Cred(issuerCN)
	return &SecureKey{key: k}, err
}
