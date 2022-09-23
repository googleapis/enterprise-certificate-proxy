#!/bin/bash

# Create a folder to hold the binaries
rm -rf ./build/bin/linux_amd64
mkdir -p ./build/bin/linux_amd64

# Build the signer library
go build -buildmode=c-shared -o build/bin/linux_amd64/libecp.so cshared/main.go
rm build/bin/linux_amd64/libecp.h

# Build the signer binary
cd ./internal/signer/linux
go build
mv signer ./../../../build/bin/linux_amd64/ecp
cd ./../../..
