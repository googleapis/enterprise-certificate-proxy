// Package util provides helper functions for the signer.
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// ParseHexString parses string into uint32
func ParseHexString(str string) (i uint32, err error) {
	stripped := strings.Replace(str, "0x", "", -1)
	resultUint64, err := strconv.ParseUint(stripped, 16, 32)
	if err != nil {
		return 0, err
	}
	return uint32(resultUint64), nil
}

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
	CertInfo CertInfo `json:"cert_info"`
	Libs     Libs     `json:"libs"`
}

// CertInfo contains parameters describing the certificate to use.
type CertInfo struct {
	Slot  string `json:"slot"`  // The hexadecimal representation of the uint36 slot ID. (ex:0x1739427)
	Label string `json:"label"` // The token label (ex: gecc)
}

// Libs contains the path to helper libs
type Libs struct {
	PKCS11Module string `json:"pkcs11_module"` // The path to the pkcs11 module (shared lib)
}

// LoadConfig retrieves the ECP config file.
func LoadConfig(configFilePath string) (config EnterpriseCertificateConfig, err error) {
	jsonFile, err := os.Open(configFilePath)
	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}
	return config, nil

}
