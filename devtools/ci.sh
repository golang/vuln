#!/usr/bin/env bash
# Copyright 2021 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# This script will be run by our Kokoro job, whose configuration
# can be found under go/kokoro in Google3's internal repo.
# It is run from the repo's root directory.

docker run -v $PWD:/vuln -w /vuln golang:1.17.3 ./all.bash
