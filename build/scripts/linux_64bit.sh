#!/bin/bash

# Build the signer library
go build -buildmode=c-shared -o build/linux_64bit/signer.so cshared/main.go
rm build/linux_64bit/signer.h