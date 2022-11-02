// Cert_util provides helpers for working with certificates via PKCS11

package util

import (
	"crypto"
	"errors"
	"io"

	"github.com/google/go-pkcs11/pkcs11"
)

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

	certs, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassCertificate, Label: label})
	if err != nil {
		return nil, err
	}
	cert, err := certs[0].Certificate()
	if err != nil {
		return nil, err
	}
	x509, err := cert.X509()
	if err != nil {
		return nil, err
	}
	var kchain [][]byte
	kchain = append(kchain, x509.Raw)

	pubKeys, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassPublicKey, Label: label})
	if err != nil {
		return nil, err
	}
	pubKey, err := pubKeys[0].PublicKey()
	if err != nil {
		return nil, err
	}

	privkeys, err := kslot.Objects(pkcs11.Filter{Class: pkcs11.ClassPrivateKey, Label: label})
	if err != nil {
		return nil, err
	}
	privKey, err := privkeys[0].PrivateKey(pubKey)
	if err != nil {
		return nil, err
	}
	ksigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("PrivateKey does not implement crypto.Signer")
	}

	return &Key{
		slot:   kslot,
		signer: ksigner,
		chain:  kchain,
	}, nil
}

// Key is a wrapper around the pkcs11 module and uses it to
// implement signing-related methods.
type Key struct {
	slot   *pkcs11.Slot
	signer crypto.Signer
	chain  [][]byte
}

// CertificateChain returns the credential as a raw X509 cert chain. This
// contains the public key.
func (k *Key) CertificateChain() [][]byte {
	return k.chain
}

// Close releases resources held by the credential.
func (k *Key) Close() {
	k.slot.Close()
}

// Public returns the corresponding public key for this Key.
func (k *Key) Public() crypto.PublicKey {
	return k.signer.Public()
}

// Sign signs a message.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.signer.Sign(nil, digest, opts)
}
