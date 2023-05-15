#!/bin/bash

# Copyright 2023 Google LLC.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Fail on any error.
set -eo pipefail

# Install zip
apt install zip -y

# Start the releasetool reporter
requirementsFile=$(realpath $(dirname "$0"))/requirements.txt
python3 -m pip install --require-hashes -r $requirementsFile
python3 -m releasetool publish-reporter-script > /tmp/publisher-script; source /tmp/publisher-script

# Move to the repository directory
cd github/enterprise-certificate-proxy/

# Create a directory for storing the zip of released artifact
# 'pkg/*' is being skipped because it wasn't a part of released artifact.
mkdir pkg && zip -r pkg/enterprise-certificate-proxy.zip . -x 'pkg/*' @

# Store the commit hash in a txt as an artifact.
echo -e $KOKORO_GITHUB_COMMIT >> pkg/commit.txt
