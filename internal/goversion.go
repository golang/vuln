// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !testmode
// +build !testmode

package internal

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// GoVersion returns the current Go version obtained by go env GOVERSION.
func GoVersion() string {
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to determine go version; skipping stdlib scanning: %v\n", err)
		return ""
	}
	return string(bytes.TrimSpace(out))
}
