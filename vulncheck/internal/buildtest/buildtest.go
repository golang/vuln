// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package buildtest provides support for running "go build"
// in tests.
package buildtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// GoBuild runs "go build" on dir using the additional environment
// variables in env. Each element of env should be of the form
// "VAR=VALUE".
// It returns the path to the resulting binary, and a function
// to call when finished with the binary.
func GoBuild(t *testing.T, dir string, env ...string) (binaryPath string, cleanup func()) {
	switch runtime.GOOS {
	case "android", "js", "ios":
		t.Skipf("skipping on OS without 'go build' %s", runtime.GOOS)
	}
	tmpDir, err := os.MkdirTemp("", "buildtest")
	if err != nil {
		t.Fatal(err)
	}
	binaryPath = filepath.Join(tmpDir, filepath.Base(dir))
	var exeSuffix string
	if runtime.GOOS == "windows" {
		exeSuffix = ".exe"
	}
	// Make sure we use the same version of go that is running this test.
	goCommandPath := filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix)
	if _, err := os.Stat(goCommandPath); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goCommandPath, "build", "-o", binaryPath)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return binaryPath, func() { os.RemoveAll(tmpDir) }
}
