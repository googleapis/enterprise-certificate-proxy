// Signer.go is a net/rpc server that listens on stdin/stdout, exposing
// methods that perform device certificate signing for Windows OS using ncrypt utils.
// This server is intended to be launched as a subprocess by the signer client,
// and should not be launched manually as a stand-alone process.
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"io"
	"log"
	"net/rpc"
	"os"
	"signer/ncrypt"
	"signer/util"
	"time"
)

func init() {
	gob.Register(crypto.SHA1)
	gob.Register(crypto.SHA224)
	gob.Register(crypto.SHA256)
	gob.Register(crypto.SHA384)
	gob.Register(crypto.SHA512)
	gob.Register(&rsa.PSSOptions{})
}

// SignArgs contains arguments to a crypto Signer.Sign method.
type SignArgs struct {
	Digest []byte            // The content to sign.
	Opts   crypto.SignerOpts // Options for signing, such as Hash identifier.
}

// A EnterpriseCertSigner exports RPC methods for signing.
type EnterpriseCertSigner struct {
	key *ncrypt.Key
}

// A Transport wraps a pair of unidirectional streams as an io.ReadWriteCloser.
type Transport struct {
	io.ReadCloser
	io.WriteCloser
}

// Close closes t's underlying ReadCloser and WriteCloser.
func (t *Transport) Close() error {
	rerr := t.ReadCloser.Close()
	werr := t.WriteCloser.Close()
	if rerr != nil {
		return rerr
	}
	return werr
}

// CertificateChain returns the credential as a raw X509 cert chain. This
// contains the public key.
func (k *EnterpriseCertSigner) CertificateChain(ignored struct{}, certificateChain *[][]byte) error {
	*certificateChain = k.key.CertificateChain()
	return nil
}

// Public returns the corresponding public key for this Key, in ASN.1 DER form.
func (k *EnterpriseCertSigner) Public(ignored struct{}, publicKey *[]byte) (err error) {
	*publicKey, err = x509.MarshalPKIXPublicKey(k.key.Public())
	return
}

// Sign signs a message by encrypting a message digest.
func (k *EnterpriseCertSigner) Sign(args SignArgs, resp *[]byte) (err error) {
	var opts crypto.SignerOpts
	if args.Opts != nil {
		opts = args.Opts
	} else {
		opts = args.Hash
	}
	*resp, err = k.key.Sign(nil, args.Digest, opts)
	return
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Signer is not meant to be invoked manually, exiting...")
	}
	configFilePath := os.Args[1]
	certInfo, err := util.LoadCertInfo(configFilePath)

	enterpriseCertSigner := new(EnterpriseCertSigner)
	enterpriseCertSigner.key, err = ncrypt.Cred(certInfo.Issuer, certInfo.Store, certInfo.Provider)
	if err != nil {
		log.Fatalf("Failed to initialize enterprise cert signer using ncrypt: %v", err)
	}

	if err := rpc.Register(enterpriseCertSigner); err != nil {
		log.Fatalf("Failed to register enterprise cert signer with net/rpc: %v", err)
	}

	// If the parent process dies, we should exit. This prevents zombie
	// rpcservers sticking around when uplink restarts.
	// We can detect this by periodically checking if the PID of the parent
	// process is 1 (https://stackoverflow.com/a/2035683).
	go func() {
		for {
			if os.Getppid() == 1 {
				log.Fatalln("Enterprise cert signer's parent process died, exiting...")
			}
			time.Sleep(time.Second)
		}
	}()

	rpc.ServeConn(&Transport{os.Stdin, os.Stdout})
}
