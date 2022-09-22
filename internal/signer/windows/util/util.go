// Package util provides helper functions for the signer.
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
	CertConfigs CertConfigs `json:"cert_configs"`
}

// Container for various ECP Configs.
type CertConfigs struct {
	WindowsMyStoreConfig WindowsMyStoreConfig `json:"windows_my_store"`
}

// WindowsMyStoreConfig contains parameters describing the certificate to use.
type WindowsMyStoreConfig struct {
	Issuer   string `json:"issuer"`
	Store    string `json:"store"`
	Provider string `json:"provider"`
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

	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}

	return ecpConfig, nil
}
