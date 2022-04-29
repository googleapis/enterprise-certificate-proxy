// Package util provides helper functions for the client.
package util

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
)

const metadataFileName = ".secureConnect/context_aware_metadata.json"

// Metadata represents the secureConnect metadata JSON file.
type Metadata struct {
	EnterpriseCert EnterpriseCert `json:"enterprise_cert"`
}

// EnterpriseCert section contains parameters for initializing signer.
type EnterpriseCert struct {
	Libs Libs `json:"libs"`
}

// Libs specifies the locations of helper libraries.
type Libs struct {
	SignerBinary string `json:"signer_binary"`
}

// LoadSignerBinaryPath retrieves the path of the signer binary from the metadata file.
func LoadSignerBinaryPath(metadataFileName string) (path string, err error) {
	jsonFile, err := os.Open(metadataFileName)
	if err != nil {
		return "", err
	}

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return "", err
	}
	var metadata Metadata
	err = json.Unmarshal(byteValue, &metadata)
	if err != nil {
		return "", err
	}
	signerBinaryPath := metadata.EnterpriseCert.Libs.SignerBinary
	if signerBinaryPath == "" {
		return "", errors.New("Signer binary path is missing.")
	}
	return signerBinaryPath, nil
}

func guessUnixHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// GetMetadataFilePath returns the path of the well-known secureConnect metadata JSON file.
func GetMetadataFilePath() (path string) {
	return filepath.Join(guessUnixHomeDir(), metadataFileName)
}
