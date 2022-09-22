// Package util provides helper functions for the signer.
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

const configsKey := "cert_configs"
const macosKey := "macos_keychain"

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
	CertInfo CertInfo
}

// CertInfo contains parameters describing the certificate to use.
type CertInfo struct {
	Issuer string `json:"issuer"`
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

	var ecpConfig map[string]interface{}
	err = json.Unmarshal(byteValue, &ecpConfig)

	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}

	for _, value := range ecpConfig[configsKey].([]interface{}) {
		if v, ok := value.(map[string]interface{})[macosKey]; ok {
			b, err := json.Marshal(v)

			if err != nil {
				return EnterpriseCertificateConfig{}, err
			}

			var certInfo CertInfo
			err = json.Unmarshal(b, &certInfo)
			if err != nil {
				return EnterpriseCertificateConfig{}, err
			}
			return EnterpriseCertificateConfig{certInfo}, nil
		}
	}

	return EnterpriseCertificateConfig{}, nil
}
