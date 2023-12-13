// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/vuln/internal/testenv"
	"golang.org/x/vuln/scan"
	"mvdan.cc/unparam/check"
)

// excluded contains the set of modules that x/vuln should not depend on.
var excluded = map[string]bool{
	"golang.org/x/exp": true,
}

var goHeader = regexp.MustCompile(`^// Copyright 20\d\d The Go Authors\. All rights reserved\.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file\.`)

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
	testenv.NeedsGoBuild(t)

	var o string
	out := bytes.NewBufferString(o)
	ctx := context.Background()

	cmd := scan.Command(ctx, "./...")
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}

	t.Logf("govulncheck finished with std out/err:\n%s", out.String())
	switch err := err.(type) {
	case nil:
		t.Log("govulncheck: no vulnerabilities detected")
	case interface{ ExitCode() int }:
		t.Errorf("govulncheck: unexpected exit code %d and error %v", err.ExitCode(), err)
	default:
		t.Errorf("govulncheck: abruptly failed with error %v", err)
	}
}

func TestStaticCheck(t *testing.T) {
	skipIfShort(t)
	rungo(t, "run", "honnef.co/go/tools/cmd/staticcheck@v0.4.3", "./...")
}

func TestUnparam(t *testing.T) {
	testenv.NeedsGoBuild(t)
	warns, err := check.UnusedParams(false, false, false, "./...")
	if err != nil {
		t.Fatalf("check.UnusedParams: %v", err)
	}
	for _, warn := range warns {
		t.Errorf(warn)
	}
}

func TestVet(t *testing.T) {
	rungo(t, "vet", "-all", "./...")
}

func TestMisspell(t *testing.T) {
	skipIfShort(t)
	rungo(t, "run", "github.com/client9/misspell/cmd/misspell@v0.3.4", "-error", ".")
}

func TestHeaders(t *testing.T) {
	sfs := os.DirFS(".")
	fs.WalkDir(sfs, ".", func(path string, d fs.DirEntry, _ error) error {
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := sfs.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if !goHeader.MatchReader(bufio.NewReader(f)) {
			t.Errorf("%v: incorrect go header", path)
		}
		return nil
	})
}

func rungo(t *testing.T, args ...string) {
	t.Helper()
	testenv.NeedsGoBuild(t)

	cmd := exec.Command("go", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Log("\n" + string(output))
		t.Error("command had non zero exit code")
	}
}

func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping: short mode")
	}
}
