#!/bin/bash
# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

#!/bin/bash

# List of all projects for which integration test failed, if any.
failed=()

# Update status of the integration script. The first argument is
# the exit code for the integration run of a project and the second
# argument is the project name.
update_status(){
 if [ "$1" -ne 0 ]; then
    failed+=("$2")
 fi
}

# Print go version for debugging purposes. Expected to be go1.18.8.
go version

# Clone kubernetes to a dedicated directory.
dir="$GOPATH/src/kubernetes"
if [ -d "$dir" ]; then
  echo "Destination kubernetes already exists. Using the existing code."
else
  git clone https://github.com/kubernetes/kubernetes.git "${dir}"
fi

# Checkout kubernetes version v1.15.11 that
# is known to have vulnerabilities.
pushd "$dir" || exit
cd pkg || exit
git checkout tags/v1.15.11
govulncheck --json ./... &> k8s.txt
k8s k8s.txt
update_status $? "kubernetes(source)"
popd || exit

# Clone scanner to a dedicated directory.
dir="$GOPATH/src/scanner"
if [ -d "$dir" ]; then
  echo "Destination scanner already exists. Using the existing code."
else
  git clone https://github.com/stackrox/scanner.git "${dir}"
fi

pushd "$dir" || exit
# Use scanner at specific commit and tag version for reproducibility.
git checkout 29b8761da747
go build -trimpath -ldflags="-X github.com/stackrox/scanner/pkg/version.Version=2.26-29-g29b8761da7-dirty" -o image/scanner/bin/scanner ./cmd/clair
govulncheck -mode=binary --json ./image/scanner/bin/scanner &> scan.txt
stackrox-scanner scan.txt
update_status $? "stackrox-scanner(binary)"
popd || exit

if [ ${#failed[@]} -ne 0 ]; then
  echo "FAIL: integration run failed for the following projects: ${failed[*]}"
  exit 1
fi
echo PASS
