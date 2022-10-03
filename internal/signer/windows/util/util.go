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

// CertConfigs is a container for various ECP Configs.
type CertConfigs struct {
	WindowsStore WindowsStore `json:"windows_store"`
}

// WindowsStore contains parameters describing the certificate to use.
type WindowsStore struct {
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
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return EnterpriseCertificateConfig{}, err
	}
	return config, nil

}
