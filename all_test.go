// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/vuln/internal/scan"
)

// excluded contains the set of modules that x/vuln should not depend on.
var excluded = map[string]bool{
	"golang.org/x/exp": true,
}

func TestBashChecks(t *testing.T) {
	skipIfShort(t)
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	var cmd *exec.Cmd
	if os.Getenv("GO_BUILDER_NAME") != "" {
		cmd = exec.Command(bash, "./checks.bash", "trybots")
	} else {
		cmd = exec.Command(bash, "./checks.bash")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestDependencies(t *testing.T) {
	dat, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	f, err := modfile.Parse("go.mod", dat, nil)
	if err != nil {
		t.Fatalf("modfile.Parse: %v", err)
	}
	for _, r := range f.Require {
		// This is used by staticcheck.
		if strings.HasPrefix(r.Mod.Path, "golang.org/x/exp/typeparams") {
			continue
		}
		for ex := range excluded {
			if strings.HasPrefix(r.Mod.Path, ex) {
				t.Errorf("go.mod contains %q as a dependency, which should not happen", r.Mod.Path)
			}
		}
	}
}

func TestGovulncheck(t *testing.T) {
	skipIfShort(t)
	skipIfTrybot(t)
	ctx := context.Background()
	err := scan.Command(ctx, "./...").Run()
	switch err := err.(type) {
	case nil:
	case interface{ ExitCode() int }:
		if err.ExitCode() != 0 {
			t.Error("govulncheck found problems")
		}
	default:
		t.Error(err)
	}
}

func TestStaticCheck(t *testing.T) {
	skipIfShort(t)
	skipIfTrybot(t)
	rungo(t, "run", "honnef.co/go/tools/cmd/staticcheck@v0.4.3", "./...")
}

func rungo(t *testing.T, args ...string) {
	cmd := exec.Command("go", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Log("\n" + string(output))
		t.Error("command had non zero exit code")
	}
}

func isTrybot() bool { return os.Getenv("GO_BUILDER_NAME") != "" }

func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping: short mode")
	}
}

func skipIfTrybot(t *testing.T) {
	if isTrybot() {
		t.Skip("skipping: trybot")
	}
}
