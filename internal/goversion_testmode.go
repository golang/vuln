// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build testmode
// +build testmode

package internal

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// GoVersion returns the current Go version obtained by go env GOVERSION.
//
// For debugging and testing purposes, undocumented environment variable
// TEST_GOVERSION can be used instead.
func GoVersion() string {
	if v := os.Getenv("TEST_GOVERSION"); v != "" {
		// Unlikely to happen in practice, mostly used for testing.
		return v
	}
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine go version; skipping stdlib scanning: %v\n", err)
		return ""
	}
	return string(bytes.TrimSpace(out))
}
