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

// CertConfigs is a container for various ECP Configs.
type CertConfigs struct {
	PKCS11 PKCS11 `json:"pkcs11"`
}

// PKCS11 contains parameters describing the certificate to use.
type PKCS11 struct {
	Slot         string `json:"slot"`     // The hexadecimal representation of the uint36 slot ID. (ex:0x1739427)
	Label        string `json:"label"`    // The token label (ex: gecc)
	PKCS11Module string `json:"module"`   // The path to the pkcs11 module (shared lib)
	UserPin      string `json:"user_pin"` // Optional user pin to unlock the PKCS #11 module. If it is not defined or empty C_Login will not be called.
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
