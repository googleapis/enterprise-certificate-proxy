// This package is intended to be compiled into a C shared library for
// use by non-Golang clients to perform certificate and signing operations.
//
// The shared library exports language-specific wrappers around the Golang
// client APIs.
//
// Example compilation command:
// go build -buildmode=c-shared -o signer.dylib main.go
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"log"
	"unsafe"

	"github.com/googleapis/enterprise-certificate-proxy/client"
)

func getCertPem(configFilePath string) []byte {
	key, err := client.Cred(configFilePath)
	if err != nil {
		log.Printf("Could not create client using config %s: %v", configFilePath, err)
		return nil
	}
	defer key.Close()

	certChain := key.CertificateChain()
	certChainPem := []byte{}
	for i := 0; i < len(certChain); i++ {
		certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certChain[i]})
		certChainPem = append(certChainPem, certPem...)
	}
	return certChainPem
}

//export GetCertPemForPython
//
// GetCertPemForPython reads the contents of the certificate specified by configFilePath,
// storing the result inside a certHolder byte array of size certHolderLen.
//
// We must call it twice to get the cert. First time use nil for certHolder to get
// the cert length. Second time we pre-create an array in Python of the cert length and
// call this function again to load the cert into the array.
func GetCertPemForPython(configFilePath *C.char, certHolder *byte, certHolderLen int) int {
	pemBytes := getCertPem(C.GoString(configFilePath))
	if certHolder != nil {
		cert := unsafe.Slice(certHolder, certHolderLen)
		copy(cert, pemBytes)
	}
	return len(pemBytes)
}

//export SignForPython
//
// SignForPython signs a message digest of length digestLen using a certificate private key
// specified by configFilePath, storing the result inside a sigHolder byte array of size sigHolderLen.
func SignForPython(configFilePath *C.char, digest *byte, digestLen int, sigHolder *byte, sigHolderLen int) int {
	// First create a handle around the specified certificate and private key.
	key, err := client.Cred(C.GoString(configFilePath))
	if err != nil {
		log.Printf("Could not create client using config %s: %v", C.GoString(configFilePath), err)
		return 0
	}
	defer key.Close()

	var isRsa bool
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		isRsa = false
		log.Print("the key is ecdsa key")
		break
	case *rsa.PublicKey:
		isRsa = true
		log.Print("the key is rsa key")
		break
	default:
		log.Printf("unsupported key type")
		return 0
	}

	// Compute the signature
	digestSlice := unsafe.Slice(digest, digestLen)
	var signature []byte
	var signErr error
	if isRsa {
		// For RSA key, we need to create the padding and flags for RSASSA-SHA256
		opts := rsa.PSSOptions{
			SaltLength: digestLen,
			Hash:       crypto.SHA256,
		}

		signature, signErr = key.Sign(nil, digestSlice, &opts)
	} else {
		signature, signErr = key.Sign(nil, digestSlice, crypto.SHA256)
	}
	if signErr != nil {
		log.Printf("failed to sign hash: %v", signErr)
		return 0
	}

	// Create a Go buffer around the output buffer and copy the signature into the buffer
	outBytes := unsafe.Slice(sigHolder, sigHolderLen)
	for i := 0; i < len(signature); i++ {
		outBytes[i] = signature[i]
	}
	return len(signature)
}

func main() {}
