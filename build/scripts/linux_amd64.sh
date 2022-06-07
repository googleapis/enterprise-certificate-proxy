#!/bin/bash

# Create a folder to hold the binaries
rm -rf ./build/linux_amd64
mkdir ./build/linux_amd64

# Build the signer library
go build -buildmode=c-shared -o build/linux_amd64/signer.so cshared/main.go
rm build/linux_amd64/signer.h

# (TODO) Build the signer binary