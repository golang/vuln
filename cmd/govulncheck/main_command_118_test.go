// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Only run this on Go 1.18 or higher, because govulncheck can't
// run on binaries before 1.18.

//go:build go1.18
// +build go1.18

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/go-cmdtest"
	"golang.org/x/vuln/internal/buildtest"
	"golang.org/x/vuln/internal/web"
)

var update = flag.Bool("update", false, "update test files with results")

func TestCommand(t *testing.T) {
	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ts, err := cmdtest.Read("testdata")
	if err != nil {
		t.Fatal(err)
	}
	ts.DisableLogging = false
	// Define a command that runs govulncheck with our local DB. We can't use
	// cmdtest.Program for this because it doesn't let us set the environment,
	// and that is the only way to tell govulncheck about an alternative vuln
	// database.
	binary, cleanup := buildtest.GoBuild(t, ".", "testmode") // build govulncheck
	// Use Cleanup instead of defer, because when subtests are parallel, defer
	// runs too early.
	t.Cleanup(cleanup)

	ts.Commands["govulncheck"] = func(args []string, inputFile string) ([]byte, error) {
		cmd := exec.Command(binary, args...)
		if inputFile != "" {
			return nil, errors.New("input redirection makes no sense")
		}
		// We set GOVERSION to always get the same results regardless of the underlying Go build system.
		vulndbDir, err := filepath.Abs(filepath.Join(testDir, "testdata", "vulndb"))
		if err != nil {
			return nil, err
		}
		govulndbURI, err := web.URLFromFilePath(vulndbDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create GOVULNDB env var: %v", err)
		}
		// We set TEST_GOVERSION to always get the same results regardless of the underlying Go build system.
		cmd.Env = append(os.Environ(), "GOVULNDB="+govulndbURI.String(), "TEST_GOVERSION=go1.18")
		out, err := cmd.CombinedOutput()
		out = filterGoFilePaths(out)
		out = filterStdlibVersions(out)
		out = filterHeapGo(out)
		return out, err
	}

	// Build test module binaries.
	moduleDirs, err := filepath.Glob("testdata/modules/*")
	if err != nil {
		t.Fatal(err)
	}

	// skipBuild contains names of module directories
	// that should not be Go built. For instance, they
	// might contain expected build errors.
	skipBuild := map[string]bool{
		"nogomod": true,
		"nogosum": true,
	}

	os.Setenv("moddir", filepath.Join(testDir, "testdata", "modules"))
	for _, md := range moduleDirs {
		if skipBuild[filepath.Base(md)] {
			continue
		}

		binary, cleanup := buildtest.GoBuild(t, md, "")
		t.Cleanup(cleanup)
		// Set an environment variable to the path to the binary, so tests
		// can refer to it.
		varName := filepath.Base(md) + "_binary"
		os.Setenv(varName, binary)
	}
	if *update {
		ts.Run(t, true)
	} else {
		ts.RunParallel(t, false)
	}
}

var (
	goFileRegexp        = regexp.MustCompile(`[^\s"]*\.go[\s":]`)
	stdlibVersionRegexp = regexp.MustCompile(`("Path": "stdlib",\s*"Version": ")v[^\s]+"`)
	heapGoRegexp        = regexp.MustCompile(`heap\.go:(\d+)`)
)

// filterGoFilePaths modifies paths to Go files by replacing their directory with "...".
// For example,/a/b/c.go becomes .../c.go .
// This makes it possible to compare govulncheck output across systems, because
// Go filenames include setup-specific paths.
func filterGoFilePaths(data []byte) []byte {
	return goFileRegexp.ReplaceAllFunc(data, func(b []byte) []byte {
		s := string(b)
		return []byte(fmt.Sprintf(`.../%s%c`, filepath.Base(s[:len(s)-1]), s[len(s)-1]))
	})
}

// filterStdlibVersions removes Go standard library versions from JSON output,
// since they depend on the system running the test. Some have different
// versions than others, and on some we are unable to extract a version from
// the binary so the version is empty.
func filterStdlibVersions(data []byte) []byte {
	return stdlibVersionRegexp.ReplaceAll(data, []byte(`${1}"`))
}

// There was a one-line change in container/heap/heap.go between 1.18
// and 1.19 that makes the stack traces different. Ignore it.
func filterHeapGo(data []byte) []byte {
	return heapGoRegexp.ReplaceAll(data, []byte(`N`))
}
