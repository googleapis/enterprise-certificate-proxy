#!/bin/bash

# Create a folder to hold the binaries
rm -rf ./build/bin/darwin_amd64
mkdir -p ./build/bin/darwin_amd64

# Build the signer binary
cd ./internal/signer/darwin
go build
mv signer ./../../../build/bin/darwin_amd64
cd ./../../..

# Build the signer library
go build -buildmode=c-shared -o build/bin/darwin_amd64/signer.dylib cshared/main.go
rm build/bin/darwin_amd64/signer.h
