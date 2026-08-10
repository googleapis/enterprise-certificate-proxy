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
	"strings"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	LevelTrace LogLevel = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
	LevelOff // Used to disable logging
)

var currentLevel LogLevel = LevelOff

func init() {
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
			// For backward compatibility, any other value enables at Info level.
			currentLevel = LevelInfo
		}
	}
}

// Trace logs a message at Trace level.
func Trace(v ...any) {
	if currentLevel > LevelTrace {
		return
	}
	args := append([]any{"[TRACE] "}, v...)
	log.Print(args...)
}

// Tracef logs a formatted message at Trace level.
func Tracef(format string, v ...any) {
	if currentLevel > LevelTrace {
		return
	}
	log.Printf("[TRACE] "+format, v...)
}

// Debug logs a message at Debug level.
func Debug(v ...any) {
	if currentLevel > LevelDebug {
		return
	}
	args := append([]any{"[DEBUG] "}, v...)
	log.Print(args...)
}

// Debugf logs a formatted message at Debug level.
func Debugf(format string, v ...any) {
	if currentLevel > LevelDebug {
		return
	}
	log.Printf("[DEBUG] "+format, v...)
}

// Info logs a message at Info level.
func Info(v ...any) {
	if currentLevel > LevelInfo {
		return
	}
	args := append([]any{"[INFO] "}, v...)
	log.Print(args...)
}

// Infof logs a formatted message at Info level.
func Infof(format string, v ...any) {
	if currentLevel > LevelInfo {
		return
	}
	log.Printf("[INFO] "+format, v...)
}

// Warn logs a message at Warn level.
func Warn(v ...any) {
	if currentLevel > LevelWarn {
		return
	}
	args := append([]any{"[WARN] "}, v...)
	log.Print(args...)
}

// Warnf logs a formatted message at Warn level.
func Warnf(format string, v ...any) {
	if currentLevel > LevelWarn {
		return
	}
	log.Printf("[WARN] "+format, v...)
}

// Error logs a message at Error level.
func Error(v ...any) {
	if currentLevel > LevelError {
		return
	}
	args := append([]any{"[ERROR] "}, v...)
	log.Print(args...)
}

// Errorf logs a formatted message at Error level.
func Errorf(format string, v ...any) {
	if currentLevel > LevelError {
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
