#!/bin/bash
# Copyright 2022 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# Run integration_test.sh on kokoro.

# Fail on any error.
set -e

# Code under repo is checked out to ${KOKORO_ARTIFACTS_DIR}/git.
# The main directory name in this path is determined by the scm name specified
# in the job configuration, which in this case is "vuln".
cd "${KOKORO_ARTIFACTS_DIR}/git/vuln/cmd/govulncheck/integration"

# Run integration_test.sh
./integration_test.sh

