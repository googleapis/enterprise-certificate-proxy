package utils

import (
        "io"
        "log"
        "os"
)

var (
     // Use a dedicated logger to allow silencing the global 'log' package if needed.
     stdLogger = log.New(os.Stderr, "", log.LstdFlags)
     isEcpLogEnabled = false
)

func init() {
        env := os.Getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS")
        if env == "" {
                // If logging is disabled, silence the global log package to prevent 
                // logs from other packages.
                log.SetOutput(io.Discard)
                } else {
                       isEcpLogEnabled = true
                }
}
	
// Errorf logs an error message.
func Errorf(format string, v ...any) {
        if isEcpLogEnabled {
                stdLogger.Printf("[ERROR] "+format, v...)
        }
}

// Warnf logs a warning message.
func Warnf(format string, v ...any) {
        if isEcpLogEnabled {
                stdLogger.Printf("[WARN] "+format, v...)
        }
}

// Infof logs an info message.
func Infof(format string, v ...any) {
        if isEcpLogEnabled {
                stdLogger.Printf("[INFO] "+format, v...)
        }
}

// Debugf logs a debug message.
func Debugf(format string, v ...any) {
        if isEcpLogEnabled {
                stdLogger.Printf("[DEBUG] "+format, v...)
        }
}

// Debugln logs a debug message.
func Debugln(v ...any) {
        if isEcpLogEnabled {
                args := append([]any{"[DEBUG]"}, v...)
                stdLogger.Println(args...)
        }
}

// Fatalf logs a fatal message and exits.
func Fatalf(format string, v ...any) {
        if isEcpLogEnabled {
                stdLogger.Fatalf("[FATAL] "+format, v...)
                os.Exit(1)
        }
}

// Fatalln logs a fatal message and exits.
func Fatalln(v ...any) {
        if isEcpLogEnabled {
                stdLogger.Fatalln(append([]any{"[FATAL]"}, v...)...)
                os.Exit(1)
        }
}
