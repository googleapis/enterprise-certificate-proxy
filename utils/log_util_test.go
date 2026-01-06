package utils

import (
	"bytes"
        "os"
        "os/exec"
	"strings"
	"testing"
)

func TestLogFunctions(t *testing.T) {
	// 1. Setup: Redirect stdLogger output to a buffer
	var buf bytes.Buffer
	originalOutput := stdLogger.Writer()
	stdLogger.SetOutput(&buf)
	
	// Ensure we restore original output after the test
	defer stdLogger.SetOutput(originalOutput)

	// 2. Enable logging for this test
	isEcpLogEnabled = true

	tests := []struct {
		name     string
		logFunc  func(string, ...any)
		format   string
		args     []any
		contains string
	}{
		{
			name:     "Errorf formatting",
			logFunc:  Errorf,
			format:   "error occurred: %s",
			args:     []any{"timeout"},
			contains: "[ERROR] error occurred: timeout",
		},
		{
			name:     "Infof formatting",
			logFunc:  Infof,
			format:   "user %d logged in",
			args:     []any{123},
			contains: "[INFO] user 123 logged in",
		},
		{
			name:     "Debugf formatting",
			logFunc:  Debugf,
			format:   "metadata: %v",
			args:     []any{"some-data"},
			contains: "[DEBUG] metadata: some-data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.format, tt.args...)
			
			output := buf.String()
			if !strings.Contains(output, tt.contains) {
				t.Errorf("%s: expected output to contain %q, got %q", tt.name, tt.contains, output)
			}
		})
	}
}

func TestLoggingDisabled(t *testing.T) {
	var buf bytes.Buffer
	stdLogger.SetOutput(&buf)
	defer stdLogger.SetOutput(os.Stderr)

	// 1. Force disable
	isEcpLogEnabled = false

	// 2. Try to log
	Infof("This should not be seen")

	// 3. Verify buffer is empty
	if buf.Len() > 0 {
		t.Errorf("Expected no output when logging is disabled, got %q", buf.String())
	}
}

// TestFatalf verifies that the process would exit. 
// Testing os.Exit is typically done by running the test in a sub-process.
func TestFatalf(t *testing.T) {
	if os.Getenv("BE_CRASHER") == "1" {
		isEcpLogEnabled = true
		Fatalf("crashing...")
		return
	}

	// Re-run the test as a subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestFatalf")
	cmd.Env = append(os.Environ(), "BE_CRASHER=1")
	err := cmd.Run()

	// Check if it exited with status 1
	if err == nil {
		t.Fatalf("Expected process to exit with error, but it succeeded")
	}
}
