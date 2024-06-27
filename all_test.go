// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.17 && !windows
// +build go1.17,!windows

package main

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/vuln/internal/testenv"
)

// excluded contains the set of modules that x/vuln should not depend on.
var excluded = map[string]bool{
	"golang.org/x/exp": true,
}

var goHeader = regexp.MustCompile(`^// Copyright 20\d\d The Go Authors\. All rights reserved\.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file\.`)

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
		for ex := range excluded {
			if strings.HasPrefix(r.Mod.Path, ex) {
				t.Errorf("go.mod contains %q as a dependency, which should not happen", r.Mod.Path)
			}
		}
	}
}

func TestVet(t *testing.T) {
	rungo(t, "vet", "-all", "./...")
}

func TestGoModTidy(t *testing.T) {
	rungo(t, "mod", "tidy")
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
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) && len(ee.Stderr) > 0 {
			t.Fatalf("%v: %v\n%s", cmd, err, ee.Stderr)
		}
		t.Fatalf("%v: %v\n%s", cmd, err, output)
	}
}
