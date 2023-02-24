// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/mod/modfile"
)

// excluded contains the set of modules that x/vuln should not depend on.
var excluded = map[string]bool{
	"golang.org/x/exp": true,
}

func Test(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	cmd := exec.Command(bash, "./checks.bash")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	dat, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	f, err := modfile.Parse("go.mod", dat, nil)
	if err != nil {
		t.Fatalf("modfile.Parse: %v", err)
	}
	for _, r := range f.Require {
		if excluded[r.Mod.Path] {
			t.Errorf("go.mod contains %q as a dependency, which should not happen", r.Mod.Path)
		}
	}
}
