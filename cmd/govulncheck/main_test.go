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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/google/go-cmdtest"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/internal/web"
	"golang.org/x/vuln/scan"
)

var update = flag.Bool("update", false, "update test files with results")

// testCase models a group of tests in cmd/govulncheck testdata.
type testCase struct {
	dir       string   // subdirectory in testdata containing tests
	skipGOOS  []string // GOOS to skip, if any
	copy      bool     // copy the folder to isolate it
	skipBuild bool     // skip building the test case
	strip     bool     // indicates if binaries should be stripped
}

func (tc testCase) skip() bool {
	for _, sg := range tc.skipGOOS {
		if runtime.GOOS == sg {
			return true
		}
	}
	return false
}

// testCases contains the list of major groups of tests in
// cmd/govulncheck/testdata folder with information on how
// to run them.
var testCases = []testCase{
	{dir: "common"},
	{dir: "stdlib"},
	// Binaries are not stripped on darwin with go1.21 and earlier. See #61051.
	{dir: "strip", skipGOOS: []string{"darwin"}, strip: true},
	// nogomod case has code with no go.mod and does not compile,
	// so we need to copy it and skip building binaries.
	{dir: "nogomod", copy: true, skipBuild: true},
}

func TestCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that uses internet in short mode")
	}

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.dir, func(t *testing.T) {
			runTestCase(t, testDir, tc)
		})
	}
}

func runTestCase(t *testing.T, testDir string, tc testCase) {
	if tc.skip() {
		return
	}

	base := tc.dir
	testCaseDir := filepath.Join(testDir, "testdata", base)
	if tc.copy {
		testCaseDir = copyTestCase(testCaseDir, t)
	}
	vulndbDir := filepath.Join(testCaseDir, "vulndb-v1")
	modulesDir := filepath.Join(testCaseDir, "modules")
	testfilesDir := filepath.Join(testCaseDir, "testfiles")
	govulndbURI, err := web.URLFromFilePath(vulndbDir)
	if err != nil {
		t.Fatalf("failed to create vulndb url: %v", err)
	}
	fixups, err := loadFixups(filepath.Join(testCaseDir, "fixups.json"))
	if err != nil {
		t.Fatalf("failed to load fixups: %v", err)
	}

	moduleDirs, err := filepath.Glob(filepath.Join(modulesDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, md := range moduleDirs {
		if tc.skipBuild {
			continue
		}

		// Build test module binary.
		binary, cleanup := test.GoBuild(t, md, "", tc.strip)
		t.Cleanup(cleanup)
		// Set an environment variable to the path to the binary, so tests
		// can refer to it. The binary name is unique across all test cases.
		varName := tc.dir + "_" + filepath.Base(md) + "_binary"
		os.Setenv(varName, binary)
	}

	os.Setenv("moddir", modulesDir)
	os.Setenv("testdir", testfilesDir)
	runTestSuite(t, testfilesDir, govulndbURI.String(), fixups, *update)
}

// Limit the number of concurrent scans. Scanning is implemented using
// x/tools/go/ssa, which is known to be memory-hungry
// (see https://go.dev/issue/14113), and by default the testing package
// allows up to GOMAXPROCS parallel tests at a time.
//
// For now we arbitrarily limit to ⌈GOMAXPROCS/4⌉, on the theory that many Go
// developer and CI machines have at least 8 logical cores and we want most
// runs of the test to exercise at least a little concurrency. If that turns
// out to still be too high, we may consider reducing it further.
//
// Since all of the scans run in the same process, we need an especially low
// limit on 32-bit platforms: we may run out of virtual address space well
// before we run out of system RAM.
var (
	parallelLimiter     chan struct{}
	parallelLimiterInit sync.Once
)

// testSuite creates a cmdtest suite from testfilesDir. It also defines
// a govulncheck command on the suite that runs govulncheck against
// vulnerability database available at vulndbDir.
func runTestSuite(t *testing.T, testfilesDir string, vulndbDir string, fixups []fixup, update bool) {
	parallelLimiterInit.Do(func() {
		limit := (runtime.GOMAXPROCS(0) + 3) / 4
		if limit > 2 && unsafe.Sizeof(uintptr(0)) < 8 {
			limit = 2
		}
		parallelLimiter = make(chan struct{}, limit)
	})
	ts, err := cmdtest.Read(filepath.Join(testfilesDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	ts.DisableLogging = true

	govulncheckCmd := func(args []string, inputFile string) ([]byte, error) {
		parallelLimiter <- struct{}{}
		defer func() { <-parallelLimiter }()

		newargs := append([]string{"-db", vulndbDir}, args...)

		buf := &bytes.Buffer{}
		cmd := scan.Command(context.Background(), newargs...)
		cmd.Stdout = buf
		cmd.Stderr = buf
		if inputFile != "" {
			input, err := os.Open(filepath.Join(testfilesDir, inputFile))
			if err != nil {
				return nil, err
			}
			defer input.Close()
			cmd.Stdin = input
		}
		// We set GOVERSION to always get the same results regardless of the underlying Go build system.
		cmd.Env = append(os.Environ(), "GOVERSION=go1.18")
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		err := cmd.Wait()
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
		sorted := buf
		if err == nil && isJSONMode(args) {
			// parse, sort and reprint the output for test stability
			gather := test.NewMockHandler()
			if err := govulncheck.HandleJSON(buf, gather); err != nil {
				return nil, err
			}
			sorted = &bytes.Buffer{}
			h := govulncheck.NewJSONHandler(sorted)
			if err := gather.Write(h); err != nil {
				return nil, err
			}
		}
		out := sorted.Bytes()
		for _, fix := range fixups {
			out = fix.apply(out)
		}
		return out, err
	}
	ts.Commands["govulncheck"] = govulncheckCmd

	// govulncheck-cmp is like govulncheck except that the last argument is a file
	// whose contents are compared to the output of govulncheck. This command does
	// not output anything.
	ts.Commands["govulncheck-cmp"] = func(args []string, inputFile string) ([]byte, error) {
		l := len(args)
		if l == 0 {
			return nil, nil
		}
		cmpArg := args[l-1]
		gArgs := args[:l-1]

		out, err := govulncheckCmd(gArgs, inputFile)
		if err != nil {
			return nil, &cmdtest.ExitCodeErr{Msg: err.Error(), Code: 1}
		}
		got := string(out)

		file, err := os.ReadFile(cmpArg)
		if err != nil {
			return nil, &cmdtest.ExitCodeErr{Msg: err.Error(), Code: 1}
		}
		want := string(file)

		if diff := cmp.Diff(want, got); diff != "" {
			return nil, &cmdtest.ExitCodeErr{Msg: "govulncheck output not matching the file contents:\n" + diff, Code: 1}
		}
		return nil, nil
	}

	if update {
		ts.Run(t, true)
		return
	}
	ts.RunParallel(t, false)
}

func isJSONMode(args []string) bool {
	for _, arg := range args {
		if arg == "json" {
			return true
		}
	}
	return false
}
