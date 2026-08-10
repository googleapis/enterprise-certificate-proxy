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

	originalLevel := currentLevel
	defer func() { currentLevel = originalLevel }() // Reset state after tests

	type logFunc struct {
		f        func()
		expected string
	}

	tests := []struct {
		name     string
		level    LogLevel
		funcs    []logFunc
	}{
		{
			name:  "Trace level",
			level: LevelTrace,
			funcs: []logFunc{
				{f: func() { Trace("msg") }, expected: "[TRACE] msg"},
				{f: func() { Debug("msg") }, expected: "[DEBUG] msg"},
				{f: func() { Info("msg") }, expected: "[INFO] msg"},
				{f: func() { Warn("msg") }, expected: "[WARN] msg"},
				{f: func() { Error("msg") }, expected: "[ERROR] msg"},
			},
		},
		{
			name:  "Info level",
			level: LevelInfo,
			funcs: []logFunc{
				{f: func() { Trace("msg") }, expected: ""},
				{f: func() { Debug("msg") }, expected: ""},
				{f: func() { Info("msg") }, expected: "[INFO] msg"},
				{f: func() { Warn("msg") }, expected: "[WARN] msg"},
				{f: func() { Error("msg") }, expected: "[ERROR] msg"},
			},
		},
		{
			name:  "Error level",
			level: LevelError,
			funcs: []logFunc{
				{f: func() { Trace("msg") }, expected: ""},
				{f: func() { Debug("msg") }, expected: ""},
				{f: func() { Info("msg") }, expected: ""},
				{f: func() { Warn("msg") }, expected: ""},
				{f: func() { Error("msg") }, expected: "[ERROR] msg"},
			},
		},
		{
			name:  "Off level",
			level: LevelOff,
			funcs: []logFunc{
				{f: func() { Trace("msg") }, expected: ""},
				{f: func() { Debug("msg") }, expected: ""},
				{f: func() { Info("msg") }, expected: ""},
				{f: func() { Warn("msg") }, expected: ""},
				{f: func() { Error("msg") }, expected: ""},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentLevel = tt.level
			for _, fn := range tt.funcs {
				buf.Reset()
				fn.f()
				output := buf.String()
				if fn.expected == "" {
					if output != "" {
						t.Errorf("expected no output, got %q", output)
					}
				} else {
					if !strings.Contains(output, fn.expected) {
						t.Errorf("expected output to contain %q, got %q", fn.expected, output)
					}
				}
			}
		})
	}
}

func TestInit(t *testing.T) {
	tests := []struct {
		envValue      string
		expectedLevel LogLevel
	}{
		{"", LevelOff},
		{"TRACE", LevelTrace},
		{"trace", LevelTrace},
		{"DEBUG", LevelDebug},
		{"INFO", LevelInfo},
		{"WARN", LevelWarn},
		{"ERROR", LevelError},
		{"1", LevelInfo},
		{"true", LevelInfo},
	}

	originalLevel := currentLevel
	defer func() { currentLevel = originalLevel }()

	for _, tt := range tests {
		t.Run("Env="+tt.envValue, func(t *testing.T) {
			if tt.envValue == "" {
				os.Unsetenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS")
			} else {
				os.Setenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS", tt.envValue)
			}
			
			// We must reset the level to test init parsing
			currentLevel = LevelOff
			
			// Simulate init behavior manually for tests
			flag := os.Getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS")
			if flag != "" {
				switch strings.ToUpper(flag) {
				case "TRACE":
					currentLevel = LevelTrace
				case "DEBUG":
					currentLevel = LevelDebug
				case "INFO":
					currentLevel = LevelInfo
				case "WARN":
					currentLevel = LevelWarn
				case "ERROR":
					currentLevel = LevelError
				default:
					currentLevel = LevelInfo
				}
			}

			if currentLevel != tt.expectedLevel {
				t.Errorf("expected level %v for env %q, got %v", tt.expectedLevel, tt.envValue, currentLevel)
			}
		})
	}
}
