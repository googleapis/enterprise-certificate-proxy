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
	"unsafe"

	"github.com/googleapis/enterprise-certificate-proxy/client"
        "github.com/googleapis/enterprise-certificate-proxy/utils"
)

// Version is generally set by the build command. Releases of ECP must have a specific version set.
// The version can be set when running `go build` like so `-ldflags="-X=main.Version=$CURRENT_TAG" `.
var Version = "dev"

func getCertPem(configFilePath string) []byte {
	key, err := client.Cred(configFilePath)
	if err != nil {
		utils.Debugf("Could not create client using config %s: %v", configFilePath, err)
		return nil
	}
	defer func() {
		if err = key.Close(); err != nil {
			utils.Debugf("Failed to clean up key. %v", err)
		}
	}()

	certChain := key.CertificateChain()
	certChainPem := []byte{}
	for i := 0; i < len(certChain); i++ {
		certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certChain[i]})
		certChainPem = append(certChainPem, certPem...)
	}
	return certChainPem
}

// ECPVersion returns ECP's version number.
//
//export ECPVersion
func ECPVersion() *C.char {
	return C.CString(Version)
}

// GetCertPem reads the contents of the certificate specified by configFilePath,
// storing the result inside a certHolder byte array of size certHolderLen.
//
// We must call it twice to get the cert. First time use nil for certHolder to get
// the cert length. Second time we pre-create an array of the cert length and
// call this function again to load the cert into the array.
//
//export GetCertPem
func GetCertPem(configFilePath *C.char, certHolder *byte, certHolderLen int) int {
	pemBytes := getCertPem(C.GoString(configFilePath))
	if certHolder != nil {
		cert := unsafe.Slice(certHolder, certHolderLen)
		copy(cert, pemBytes)
	}
	return len(pemBytes)
}

// GetCertPemForPython reads the contents of the certificate specified by configFilePath,
// storing the result inside a certHolder byte array of size certHolderLen.
//
// We must call it twice to get the cert. First time use nil for certHolder to get
// the cert length. Second time we pre-create an array in Python of the cert length and
// call this function again to load the cert into the array.
//
// Deprecated: This API is deprecated in favor of GetCertPem and will be removed in future versions.
//
//export GetCertPemForPython
func GetCertPemForPython(configFilePath *C.char, certHolder *byte, certHolderLen int) int {
	return GetCertPem(configFilePath, certHolder, certHolderLen)
}

// Sign signs a message digest of length digestLen using a certificate private key
// specified by configFilePath, storing the result inside a sigHolder byte array of size sigHolderLen.
//
//export Sign
func Sign(configFilePath *C.char, digest *byte, digestLen int, sigHolder *byte, sigHolderLen int) int {
	// First create a handle around the specified certificate and private key.
	key, err := client.Cred(C.GoString(configFilePath))
	if err != nil {
		utils.Debugf("Could not create client using config %s: %v", C.GoString(configFilePath), err)
		return 0
	}
	defer func() {
		if err = key.Close(); err != nil {
			utils.Debugf("Failed to clean up key. %v", err)
		}
	}()
	var isRsa bool
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		isRsa = false
		utils.Debugf("the key is ecdsa key")
	case *rsa.PublicKey:
		isRsa = true
		utils.Debugf("the key is rsa key")
	default:
		utils.Debugf("unsupported key type")
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
		utils.Errorf("failed to sign hash: %v", signErr)
		return 0
	}
	if sigHolderLen < len(signature) {
		utils.Debugf("The sigHolder buffer size %d is smaller than the signature size %d", sigHolderLen, len(signature))
		return 0
	}

	// Create a Go buffer around the output buffer and copy the signature into the buffer
	outBytes := unsafe.Slice(sigHolder, sigHolderLen)
	copy(outBytes, signature)
	return len(signature)
}

// SignForPython signs a message digest of length digestLen using a certificate private key
// specified by configFilePath, storing the result inside a sigHolder byte array of size sigHolderLen.
//
// Deprecated: This API is deprecated in favor of Sign and will be removed in future versions.
//
//export SignForPython
func SignForPython(configFilePath *C.char, digest *byte, digestLen int, sigHolder *byte, sigHolderLen int) int {
	return Sign(configFilePath, digest, digestLen, sigHolder, sigHolderLen)
}

// GetKeyType returns a string representing ECP's key type.
// The key is derived from the ECP configuration.
//
//export GetKeyType
func GetKeyType(configFilePath *C.char) *C.char {
	key, err := client.Cred(C.GoString(configFilePath))
	if err != nil {
		utils.Debugf("Could not create client using config %s: %v", C.GoString(configFilePath), err)
		return C.CString("unknown")
	}
	defer func() {
		if err = key.Close(); err != nil {
			utils.Debugf("Failed to clean up key. %v", err)
		}
	}()
	switch key.Public().(type) {
	case *ecdsa.PublicKey:
		return C.CString("EC")
	case *rsa.PublicKey:
		return C.CString("RSA")
	default:
		return C.CString("unknown")
	}
}

func main() {}
