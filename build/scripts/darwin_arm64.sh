#!/bin/bash

set -eu

# Create a folder to hold the binaries
rm -rf ./build/bin/darwin_amd64
mkdir -p ./build/bin/darwin_amd64

# Build the signer binary
cd ./internal/signer/darwin
CGO_ENABLED=1 GO111MODULE=on GOARCH=arm64 go build
mv signer ./../../../build/bin/darwin_amd64/ecp
cd ./../../..

# Build the signer library
CGO_ENABLED=1 GO111MODULE=on GOARCH=arm64 go build -buildmode=c-shared -o build/bin/darwin_amd64/libecp.dylib cshared/main.go
rm build/bin/darwin_amd64/libecp.h
