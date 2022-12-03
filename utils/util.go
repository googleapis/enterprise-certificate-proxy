package utils

import (
	"io/ioutil"
	"log"
	"os"
)

// / If ECP Logging is enabled return true
// / Otherwise return false
func EnableECPLogging() bool {
	if os.Getenv("ENABLE_ENTERPRISE_CERTIFICATE_LOGS") != "" {
		return true
	}

	log.SetOutput(ioutil.Discard)
	return false
}
