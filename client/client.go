// Client is a cross-platform client for the signer binary (a.k.a."EnterpriseCertSigner").
// The signer binary is OS-specific, but exposes a standard set of APIs for the client to use.
package client

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"fmt"
	"io"
	"net/rpc"
	"os"
	"os/exec"

	"github.com/enterprise-certificate-proxy/client/util"
)

const signAPI = "EnterpriseCertSigner.Sign"
const certificateChainAPI = "EnterpriseCertSigner.CertificateChain"
const publicKeyAPI = "EnterpriseCertSigner.Public"

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

func init() {
	gob.Register(crypto.SHA256)
	gob.Register(&rsa.PSSOptions{})
}

// SignArgs contains arguments to a crypto Signer.Sign method.
type SignArgs struct {
	Digest []byte
	Hash   crypto.Hash
	Opts   crypto.SignerOpts
}

// Key implements credential.Credential by holding the executed signer subprocess.
type Key struct {
	cmd       *exec.Cmd
	client    *rpc.Client
	publicKey crypto.PublicKey
	chain     [][]byte
}

// CertificateChain returns the credential as a raw X509 cert chain. This contains the public key.
func (k *Key) CertificateChain() [][]byte {
	return k.chain
}

// Close closes the RPC connection and kills the signer process.
func (k *Key) Close() error {
	if err := k.client.Close(); err != nil {
		return fmt.Errorf("Closing RPC connection: %w", err)
	}
	if err := k.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("Killing signer process: %w", err)
	}
	return k.cmd.Wait()
}

// Public gets the public key for this Key.
func (k *Key) Public() crypto.PublicKey {
	return k.publicKey
}

// Sign signs a message by encrypting a message digest.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signed []byte, err error) {
	err = k.client.Call(signAPI, SignArgs{Digest: digest, Hash: opts.HashFunc(), Opts: opts}, &signed)
	return
}

// Cred spawns a signer subprocess.
// The signer binary location is specified by a well-known metadata file.
func Cred() (*Key, error) {
	metadataFilePath := util.GetMetadataFilePath()
	enterpriseCertSignerPath, err := util.LoadSignerBinaryPath(metadataFilePath)
	if err != nil {
		return nil, err
	}
	k := &Key{
		cmd: exec.Command(enterpriseCertSignerPath, metadataFilePath),
	}

	k.cmd.Stderr = os.Stderr

	kin, err := k.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	kout, err := k.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	k.client = rpc.NewClient(&Transport{kout, kin})

	if err := k.cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting enterprise cert signer subprocess: %w", err)
	}

	if err := k.client.Call(certificateChainAPI, struct{}{}, &k.chain); err != nil {
		return nil, fmt.Errorf("CertificateChain RPC: %w", err)
	}

	var publicKeyBytes []byte
	if err := k.client.Call(publicKeyAPI, struct{}{}, &publicKeyBytes); err != nil {
		return nil, fmt.Errorf("Public RPC: %w", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key from enterprise cert signer: %w", err)
	}

	var ok bool
	k.publicKey, ok = publicKey.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("enterprise cert signer returned invalid public key type: %T", publicKey)
	}

	return k, nil
}
