// Package util provides helper functions for the signer.
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

const configsKey := "cert_configs"
const winMyStoreKey := "windows_my_store"

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
	CertInfo CertInfo
}

// CertInfo contains parameters describing the certificate to use.
type CertInfo struct {
	Issuer   string `json:"issuer"`
	Store    string `json:"store"`
	Provider string `json:"provider"`
}

// LoadCertInfo retrieves the certificate info from the config file.
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
		if v, ok := value.(map[string]interface{})[winMyStoreKey]; ok {
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
