// Copyright 2025 Google LLC
//
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

package logger

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	originalOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(originalOutput) // Reset log output after tests

	originalEnabled := loggingEnabled
	defer func() { loggingEnabled = originalEnabled }() // Reset state after tests

	tests := []struct {
		name     string
		enabled  bool
		logFunc  func()
		expected string
	}{
		{
			name:     "Info enabled",
			enabled:  true,
			logFunc:  func() { Info("test message") },
			expected: "[INFO] test message",
		},
		{
			name:     "Info disabled",
			enabled:  false,
			logFunc:  func() { Info("test message") },
			expected: "",
		},
		{
			name:     "Infof enabled",
			enabled:  true,
			logFunc:  func() { Infof("format %s", "message") },
			expected: "[INFO] format message",
		},
		{
			name:     "Infof disabled",
			enabled:  false,
			logFunc:  func() { Infof("format %s", "message") },
			expected: "",
		},
		{
			name:     "Error enabled",
			enabled:  true,
			logFunc:  func() { Error("test error") },
			expected: "[ERROR] test error",
		},
		{
			name:     "Error disabled",
			enabled:  false,
			logFunc:  func() { Error("test error") },
			expected: "",
		},
		{
			name:     "Errorf enabled",
			enabled:  true,
			logFunc:  func() { Errorf("format %s", "error") },
			expected: "[ERROR] format error",
		},
		{
			name:     "Errorf disabled",
			enabled:  false,
			logFunc:  func() { Errorf("format %s", "error") },
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			loggingEnabled = tt.enabled

			tt.logFunc()

			output := buf.String()
			if tt.expected == "" {
				if output != "" {
					t.Errorf("expected no output, got %q", output)
				}
			} else {
				if !strings.Contains(output, tt.expected) {
					t.Errorf("expected output to contain %q, got %q", tt.expected, output)
				}
			}
		})
	}
}

func TestInit(t *testing.T) {
	// Simple sanity test for init behavior. Since init() runs before tests,
	// test manually setting the env behaves properly.
	os.Setenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS", "1")
	defer os.Unsetenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS")
}
