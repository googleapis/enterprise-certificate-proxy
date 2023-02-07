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

package util

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("./test_data/certificate_config.json")
	if err != nil {
		t.Errorf("LoadConfig error: %q", err)
	}
	want := "enterprise_v1_corp_client"
	if config.CertConfigs.WindowsStore.Issuer != want {
		t.Errorf("Expected issuer is %q, got: %q", want, config.CertConfigs.WindowsStore.Issuer)
	}
	want = "MY"
	if config.CertConfigs.WindowsStore.Store != want {
		t.Errorf("Expected store is %q, got: %q", want, config.CertConfigs.WindowsStore.Store)
	}
	want = "current_user"
	if config.CertConfigs.WindowsStore.Provider != want {
		t.Errorf("Expected provider is %q, got: %q", want, config.CertConfigs.WindowsStore.Provider)
	}
}
