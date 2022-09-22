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

const configsKey := "cert_configs"
const pkcs11Key := "pkcs11"

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
       CertInfo CertInfo
}

// CertInfo contains parameters describing the certificate to use.
type CertInfo struct {
	Slot  string `json:"slot"`  // The hexadecimal representation of the uint36 slot ID. (ex:0x1739427)
	Label string `json:"label"` // The token label (ex: gecc)
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

	var config map[string]interface{}
	err = json.Unmarshal(byteValue, &config)

	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}

	for -, value := range configs[configsKey].([]interface{}) {
		if v, ok := value.(map[string]interface{})[pkcs11Key]; ok {
			b, err := json.Marshal(v)

			if err != nil {
				return EnterpriseCertificateConfig{}, err
			}

			var certInfo CertInfo
			err := json.Unmarshal(b, &certInfo)
			if err != nil {
				return EnterpriseCertificateConfig{}, err
			}
			return EnterpriseCertificateConfig{certInfo}, nil
		}
	}

	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}

	return EnterpriseCertificateConfig{}, nil
}
