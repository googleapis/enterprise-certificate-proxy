#!/bin/bash

# Create a folder to hold the binaries
rm -rf ./build/darwin_amd64
mkdir ./build/darwin_amd64

# Build the signer binary
cd ./internal/signer/darwin
go build
mv signer ./../../../build/darwin_amd64
cd ./../../..

# Build the signer library
go build -buildmode=c-shared -o build/darwin_amd64/signer.dylib cshared/main.go
rm build/darwin_amd64/signer.h
