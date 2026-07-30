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

// Package logger provides a standardized logging utility across ECP.
package logger

import (
	"log"
	"os"
)

var (
	loggingEnabled bool
)

func init() {
	if os.Getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS") != "" {
		loggingEnabled = true
	}
}

// Info logs a message at Info level.
func Info(v ...any) {
	if !loggingEnabled {
		return
	}
	args := append([]any{"[INFO] "}, v...)
	log.Print(args...)
}

// Infof logs a formatted message at Info level.
func Infof(format string, v ...any) {
	if !loggingEnabled {
		return
	}
	log.Printf("[INFO] "+format, v...)
}

// Error logs a message at Error level.
func Error(v ...any) {
	if !loggingEnabled {
		return
	}
	args := append([]any{"[ERROR] "}, v...)
	log.Print(args...)
}

// Errorf logs a formatted message at Error level.
func Errorf(format string, v ...any) {
	if !loggingEnabled {
		return
	}
	log.Printf("[ERROR] "+format, v...)
}

// Fatal logs a message at Fatal level and exits.
func Fatal(v ...any) {
	args := append([]any{"[FATAL] "}, v...)
	log.Fatal(args...)
}

// Fatalf logs a formatted message at Fatal level and exits.
func Fatalf(format string, v ...any) {
	log.Fatalf("[FATAL] "+format, v...)
}
