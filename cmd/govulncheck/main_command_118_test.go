// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Only run this on Go 1.18 or higher, because govulncheck can't
// run on binaries before 1.18.

//go:build go1.18
// +build go1.18

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	"github.com/google/go-cmdtest"
	"golang.org/x/vuln/internal/scan"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/internal/web"
)

var update = flag.Bool("update", false, "update test files with results")

func TestCommand(t *testing.T) {
	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	vulndbDir, err := filepath.Abs(filepath.Join(testDir, "testdata", "vulndb-v1"))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := testSuite("testdata", vulndbDir)
	if err != nil {
		t.Fatal(err)
	}

	moduleDirs, err := filepath.Glob("testdata/modules/*")
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("moddir", filepath.Join(testDir, "testdata", "modules"))
	for _, md := range moduleDirs {
		// Skip nogomod module. It has intended build issues.
		if filepath.Base(md) == "nogomod" {
			continue
		}
		// Also skip stripped binary. That is tested separately
		// in TestCommandStrip.
		if filepath.Base(md) == "strip" {
			continue
		}

		// Build test module binary.
		binary, cleanup := test.GoBuild(t, md, "", false)
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

func TestCommandStrip(t *testing.T) {
	if runtime.GOOS == "darwin" {
		// TODO(https://go.dev/issue/59732): investigate why
		t.Skip("binaries are not fully stripped on darwin")
	}
	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	vulndbDir, err := filepath.Abs(filepath.Join(testDir, "testdata", "vulndb-v1"))
	if err != nil {
		t.Fatal(err)
	}
	ts, err := testSuite("testdata/strip", vulndbDir)
	if err != nil {
		t.Fatal(err)
	}

	// Build strip test module binary.
	moduleDir, err := filepath.Abs("testdata/modules/strip")
	if err != nil {
		t.Fatal(err)
	}

	os.Setenv("moddir", filepath.Join(testDir, "testdata", "modules", "strip"))
	strip, stripCleanup := test.GoBuild(t, moduleDir, "", true)
	t.Cleanup(stripCleanup)
	varName := filepath.Base(moduleDir) + "_binary"
	os.Setenv(varName, strip)
	if *update {
		ts.Run(t, true)
	} else {
		ts.RunParallel(t, false)
	}
}

// testSuite creates a cmdtest suite from dir. It also defines
// a govulncheck command on the suite that runs govulncheck
// against vulnerability database available at vulndbDir.
func testSuite(dir, vulndbDir string) (*cmdtest.TestSuite, error) {
	ts, err := cmdtest.Read(dir)
	if err != nil {
		return nil, err
	}
	ts.DisableLogging = true
	ts.Commands["govulncheck"] = func(args []string, inputFile string) ([]byte, error) {
		govulndbURI, err := web.URLFromFilePath(vulndbDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create GOVULNDB env var: %v", err)
		}

		newargs := []string{"-db", govulndbURI.String()}
		hasDir := false
		for _, s := range args {
			if s == "-C" {
				hasDir = true
			}
		}
		if !hasDir {
			newargs = append(newargs, "-C", dir)
		}
		newargs = append(newargs, args...)
		buf := &bytes.Buffer{}
		cmd := scan.Command(context.Background(), newargs...)
		cmd.Stdout = buf
		cmd.Stderr = buf
		if inputFile != "" {
			//TODO: use as Stdin
			return nil, errors.New("input redirection makes no sense")
		}
		// We set GOVERSION to always get the same results regardless of the underlying Go build system.
		//TODO: when cmd supports Env:
		//cmd.Env = append(os.Environ(), "GOVERSION=go1.18")
		os.Setenv("GOVERSION", "go1.18")
		err = cmd.Run()
		switch e := err.(type) {
		case nil:
		case interface{ ExitCode() int }:
			err = &cmdtest.ExitCodeErr{Msg: err.Error(), Code: e.ExitCode()}
			if e.ExitCode() == 0 {
				err = nil
			}
		default:
			fmt.Fprintln(buf, err)
			err = &cmdtest.ExitCodeErr{Msg: err.Error(), Code: 1}
		}
		out := buf.Bytes()
		out = filterGoFilePaths(out)
		out = filterProgressNumbers(out)
		out = filterEnvironmentData(out)
		out = filterHeapGo(out)
		return out, err
	}
	return ts, nil
}

var (
	goFileRegexp                 = regexp.MustCompile(`[^\s"]*\.go[\s":]`)
	heapGoRegexp                 = regexp.MustCompile(`heap\.go:(\d+)`)
	progressRegexp               = regexp.MustCompile(`Scanning your code and (\d+) packages across (\d+)`)
	govulncheckRegexp            = regexp.MustCompile(`govulncheck@v(.*) with`)
	govulncheckBinaryErrorRegexp = regexp.MustCompile(`"([^"]*") is a file`)
	govulncheckJSONRegexp        = regexp.MustCompile(`"govulncheck@v(.*)",`)
	vulndbRegexp                 = regexp.MustCompile(`file:///(.*)/testdata/vulndb`)
	gorootRegexp                 = regexp.MustCompile(`package (.*) is not in GOROOT (.*)`)
	lastModifiedRegexp           = regexp.MustCompile(`modified (.*)\)`)
	goVersionRegexp              = regexp.MustCompile(`Using go1.[\.\d]*`)
	goVersionJSONRegexp          = regexp.MustCompile(`"go_version": "go[^\s"]*"`)
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

// There was a one-line change in container/heap/heap.go between 1.18
// and 1.19 that makes the stack traces different. Ignore it.
func filterHeapGo(data []byte) []byte {
	return heapGoRegexp.ReplaceAll(data, []byte(`N`))
}

func filterProgressNumbers(data []byte) []byte {
	return progressRegexp.ReplaceAll(data, []byte("Scanning your code and P packages across M"))
}

func filterEnvironmentData(data []byte) []byte {
	data = govulncheckRegexp.ReplaceAll(data, []byte("govulncheck@v0.0.0-00000000000-20000101010101 with"))
	data = govulncheckJSONRegexp.ReplaceAll(data, []byte("govulncheck@v0.0.0-00000000000-20000101010101"))
	data = govulncheckBinaryErrorRegexp.ReplaceAll(data, []byte("govulncheck: myfile is a file"))
	data = vulndbRegexp.ReplaceAll(data, []byte("testdata/vulndb"))
	data = gorootRegexp.ReplaceAll(data, []byte("package foo is not in GOROOT (/tmp/foo)"))
	data = goVersionRegexp.ReplaceAll(data, []byte(`Using go1.18`))
	data = goVersionJSONRegexp.ReplaceAll(data, []byte(`"go_version": "go1.18"`))
	return lastModifiedRegexp.ReplaceAll(data, []byte("modified 01 Jan 21 00:00 UTC)"))
}
