#!/bin/bash

# Get the directory of the current script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the root directory (one level up from scripts/)
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd $ROOT_DIR
cd http_proxy
go mod tidy
go get .
go run main.go -port 8080 -enterprise_certificate_file_path "/google/src/cloud/neastin/neastin-auth/google3/experimental/users/neastin/gcloud-cba/gcloud-go-proxy-integration/certificate_config.json"
