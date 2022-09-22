// Package util provides helper functions for the signer.
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// ParseHexString parses hexadecimal string into uint32
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
	CertConfigs CertConfigs `json:"cert_configs"`
}

// Container for various ECP Configs.
type CertConfigs struct {
	Pkcs11Config Pkcs11Config `json:"pkcs11"`
}

// Pkcs11Config contains parameters describing the certificate to use.
type Pkcs11Config struct {
	Slot         string `json:"slot"`        // The hexadecimal representation of the uint36 slot ID. (ex:0x1739427)
	Label        string `json:"label"`       // The token label (ex: gecc)
	PKCS11Module string `json:"module_path"` // The path to the pkcs11 module (shared lib)
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

	var ecpConfig EnterpriseCertificateConfig
	err = json.Unmarshal(byteValue, &ecpConfig)

	if err != nil { return EnterpriseCertificateConfig{}, err
	}

	return ecpConfig, nil
}
