// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testenv

import (
	"os/exec"
	"testing"
)

// NeedsGoEnv skips t if the current system can't get the environment with
// “go env” in a subprocess.
func NeedsGoEnv(t testing.TB) {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("skipping test: can't run go env")
	}
}
