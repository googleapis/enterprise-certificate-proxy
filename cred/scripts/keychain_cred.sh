#!/bin/bash

# Copyright 2023 Google LLC.
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

PASSWORD="1234"
WORK_DIR=$(mktemp -d)

pushd ${WORK_DIR}

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 5 -nodes -subj "/C=US/ST=WA/L=Kirkland/O=Temp/OU=CI/CN=TestIssuer/emailAddress=dev@example.com"
openssl pkcs12 -inkey key.pem -in cert.pem -export -out cred.p12 -passin pass:${PASSWORD} -passout pass:${PASSWORD}
security import cred.p12 -P ${PASSWORD} -A

popd