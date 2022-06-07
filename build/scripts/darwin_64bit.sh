#!/bin/bash

# Build the signer binary
cd ./internal/signer/darwin
go build
mv signer ./../../../build/darwin_64bit
cd ./../../..

# Build the signer library
go build -buildmode=c-shared -o build/darwin_64bit/signer.dylib cshared/main.go
rm build/darwin_64bit/signer.h