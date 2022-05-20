// Package util provides helper functions for the signer.
package util

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
	CertInfo CertInfo `json:"cert_info"`
}

// CertInfo contains parameters describing the certificate to use.
type CertInfo struct {
	Issuer   string `json:"issuer"`
	Store    string `json:"store"`
	Provider string `json:"provider"`
}

// LoadCertInfo retrieves the certificate info from the config file.
func LoadCertInfo(configFilePath string) (certInfo CertInfo, err error) {
	jsonFile, err := os.Open(configFilePath)
	if err != nil {
		return CertInfo{}, err
	}

	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return CertInfo{}, err
	}
	var config EnterpriseCertificateConfig
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return CertInfo{}, err
	}
	return config.CertInfo, nil

}
