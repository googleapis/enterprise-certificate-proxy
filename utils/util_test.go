package utils_test

import (
	"testing"

	"os"

	"github.com/googleapis/enterprise-certificate-proxy/utils"
)

func TestEnabledLogging(t *testing.T) {
	os.Setenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS", "1")

	if !utils.EnableECPLogging() {
		t.Error("ECP Logging should be enabled if ENABLE_ENTERPRISE_CERTIFICATE_LOGS is set.")
	}
}

func TestDisabledLogging(t *testing.T) {
	os.Unsetenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS")

	if utils.EnableECPLogging() {
		t.Error("ECP Logging should be enabled if ENABLE_ENTERPRISE_CERTIFICATE_LOGS is set.")
	}
}
