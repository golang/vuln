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
	"regexp"
	"runtime"
	"sync"
	"testing"
	"unsafe"

	"github.com/google/go-cmdtest"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/internal/web"
	"golang.org/x/vuln/scan"
)

var update = flag.Bool("update", false, "update test files with results")

type fixup struct {
	pattern     string
	compiled    *regexp.Regexp
	replace     string
	replaceFunc func(b []byte) []byte
}

var fixups = []fixup{
	{
		// modifies paths to Go files by replacing their directory with "...".
		// For example,/a/b/c.go becomes .../c.go .
		// This makes it possible to compare govulncheck output across systems, because
		// Go filenames include setup-specific paths.
		pattern: `[^\s"]*\.go[\s":]`,
		replaceFunc: func(b []byte) []byte {
			s := string(b)
			return []byte(fmt.Sprintf(`.../%s%c`, filepath.Base(s[:len(s)-1]), s[len(s)-1]))
		},
	}, {
		// There was a one-line change in container/heap/heap.go between 1.18
		// and 1.19 that makes the stack traces different. Ignore it.
		pattern: `heap\.go:(\d+)`,
		replace: `N`,
	}, {
		pattern: `Scanning your code and (\d+) packages across (\d+)`,
		replace: `Scanning your code and P packages across M`,
	}, {
		pattern: `Scanner: govulncheck@v.*`,
		replace: `Scanner: govulncheck@v1.0.0`,
	}, {
		pattern: `"([^"]*") is a file`,
		replace: `govulncheck: myfile is a file`,
	}, {
		pattern: `"scanner_version": "[^"]*"`,
		replace: `"scanner_version": "v0.0.0-00000000000-20000101010101"`,
	}, {
		pattern: `file:///(.*)/testdata/vulndb`,
		replace: `testdata/vulndb`,
	}, {
		pattern: `package (.*) is not in (GOROOT|std) (.*)`,
		replace: `package foo is not in GOROOT (/tmp/foo)`,
	}, {
		pattern: `modified (.*)\)`,
		replace: `modified 01 Jan 21 00:00 UTC)`,
	}, {
		pattern: `Go: (go1.[\.\d]*|devel).*`,
		replace: `Go: go1.18`,
	}, {
		pattern: `"go_version": "go[^\s"]*"`,
		replace: `"go_version": "go1.18"`,
	},
}

func (f *fixup) init() {
	f.compiled = regexp.MustCompile(f.pattern)
}

func (f *fixup) apply(data []byte) []byte {
	if f.replaceFunc != nil {
		return f.compiled.ReplaceAllFunc(data, f.replaceFunc)
	}
	return f.compiled.ReplaceAll(data, []byte(f.replace))
}

func init() {
	for i := range fixups {
		fixups[i].init()
	}
}

func TestCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that uses internet in short mode")
	}

	testDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	vulndbDir, err := filepath.Abs(filepath.Join(testDir, "testdata", "vulndb-v1"))
	if err != nil {
		t.Fatal(err)
	}
	govulndbURI, err := web.URLFromFilePath(vulndbDir)
	if err != nil {
		t.Fatalf("failed to create make vulndb url: %v", err)
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

		// Build test module binary.
		binary, cleanup := test.GoBuild(t, md, "", filepath.Base(md) == "strip")
		t.Cleanup(cleanup)
		// Set an environment variable to the path to the binary, so tests
		// can refer to it.
		varName := filepath.Base(md) + "_binary"
		os.Setenv(varName, binary)
	}
	runTestSuite(t, filepath.Join(testDir, "testdata"), govulndbURI.String(), *update)
	if runtime.GOOS != "darwin" {
		// TODO(https://go.dev/issue/61051): binaries are not currently stripped on darwin.
		// This is expected to change in Go 1.22.
		runTestSuite(t, filepath.Join(testDir, "testdata/strip"), govulndbURI.String(), *update)
	}
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

// testSuite creates a cmdtest suite from dir. It also defines
// a govulncheck command on the suite that runs govulncheck
// against vulnerability database available at vulndbDir.
func runTestSuite(t *testing.T, dir string, govulndb string, update bool) {
	parallelLimiterInit.Do(func() {
		limit := (runtime.GOMAXPROCS(0) + 3) / 4
		if limit > 2 && unsafe.Sizeof(uintptr(0)) < 8 {
			limit = 2
		}
		parallelLimiter = make(chan struct{}, limit)
	})

	ts, err := cmdtest.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	ts.DisableLogging = true

	ts.Commands["govulncheck"] = func(args []string, inputFile string) ([]byte, error) {
		parallelLimiter <- struct{}{}
		defer func() { <-parallelLimiter }()

		newargs := append([]string{"-db", govulndb}, args...)

		buf := &bytes.Buffer{}
		cmd := scan.Command(context.Background(), newargs...)
		cmd.Stdout = buf
		cmd.Stderr = buf
		if inputFile != "" {
			input, err := os.Open(filepath.Join(dir, inputFile))
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
	if update {
		ts.Run(t, true)
		return
	}
	ts.RunParallel(t, false)
}

func isJSONMode(args []string) bool {
	for _, arg := range args {
		if arg == "-json" {
			return true
		}
	}
	return false
}
