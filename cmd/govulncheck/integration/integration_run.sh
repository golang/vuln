#!/bin/bash
# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Clone kubernetes to a dedicated directory.
dir="$GOPATH/src/kubernetes"
if [ -d $dir ]; then
  echo "Destination kubernetes already exists. Using the existing code."
else
  git clone https://github.com/kubernetes/kubernetes.git "${dir}"
fi

# Checkout kubernetes version v1.15.11 that
# is known to have vulnerabilities.
pushd $dir
cd pkg
git checkout tags/v1.15.11
govulncheck --json ./... &> govulncheck.txt
k8s govulncheck.txt
exitcode=$?
popd

if [ ${exitcode} -ne 0 ]; then
  echo "FAIL: got exit code $exitcode, want 0"
  exit 1
fi
echo PASS
