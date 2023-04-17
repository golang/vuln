#!/usr/bin/env -S bash -e

# Copyright 2023 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

source devtools/lib.sh || { echo "Are you at repo root?"; exit 1; }

# Script for copying data from the v1 schema in vuln.go.dev for tests.

origin="https://vuln.go.dev"

go install golang.org/x/vulndb/cmd/indexdb@latest

# Copy files for unit tests.
copyFiles=(
  "ID/GO-2021-0159.json"
  "ID/GO-2022-0229.json"
  "ID/GO-2022-0463.json"
  "ID/GO-2022-0569.json"
  "ID/GO-2022-0572.json"
  "ID/GO-2021-0068.json"
  "ID/GO-2022-0475.json"
  "ID/GO-2022-0476.json"
  "ID/GO-2021-0240.json"
  "ID/GO-2021-0264.json"
  "ID/GO-2022-0273.json"
)

UNIT_OUT_DIR=$(pwd)/internal/client/testdata/vulndb-v1

for f in "${copyFiles[@]}"; do
  mkdir -p "$UNIT_OUT_DIR/$(dirname "$f")" && curl -L $origin/"$f" --output "$UNIT_OUT_DIR"/"$f"
done

unit_vulns="$UNIT_OUT_DIR/ID"
indexdb -out "$UNIT_OUT_DIR" -vulns "$unit_vulns"

# Copy files for integration tests.
copyFiles=(
  "ID/GO-2022-0969.json"
  "ID/GO-2020-0015.json"
  "ID/GO-2021-0113.json"
  "ID/GO-2021-0054.json"
  "ID/GO-2021-0059.json"
  "ID/GO-2021-0265.json"
)

INTEG_OUT_DIR=$(pwd)/cmd/govulncheck/testdata/vulndb-v1

for f in "${copyFiles[@]}"; do
  mkdir -p "$INTEG_OUT_DIR"/"$(dirname "$f")" && curl -L "$origin"/"$f" --output "$INTEG_OUT_DIR"/"$f"
done

integ_vulns="$INTEG_OUT_DIR/ID"
indexdb -out "$INTEG_OUT_DIR" -vulns "$integ_vulns"
