#!/bin/bash

# Copyright 2022 Google LLC.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eux

CURRENT_TAG=$(cat version.txt)

# Create a folder to hold the binaries
rm -rf ./build/bin/linux_amd64
mkdir -p ./build/bin/linux_amd64

# Build the signer library
go build -buildmode=c-shared -ldflags="-X=main.Version=$CURRENT_TAG" -o build/bin/linux_amd64/libecp.so cshared/main.go
rm build/bin/linux_amd64/libecp.h

# Build the ECP HTTP Proxy binary
pushd http_proxy
go build
mv http_proxy ../build/bin/linux_amd64/ecp_http_proxy
popd

# Build the signer binary
cd ./internal/signer/linux
go build
mv linux ./../../../build/bin/linux_amd64/ecp
cd ./../../..
