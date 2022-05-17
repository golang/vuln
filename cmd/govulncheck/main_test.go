// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"golang.org/x/vuln/cmd/govulncheck/internal/govulncheck"
	"golang.org/x/vuln/internal/buildtest"
	"golang.org/x/vuln/osv"
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
	// Define a command that lets us cd into a module directory.
	// The modules for these tests live under testdata/modules.
	ts.Commands["cdmodule"] = func(args []string, inputFile string) ([]byte, error) {
		if len(args) != 1 {
			return nil, errors.New("need exactly 1 argument")
		}
		return nil, os.Chdir(filepath.Join(testDir, "testdata", "modules", args[0]))
	}
	// Define a command that runs govulncheck with our local DB. We can't use
	// cmdtest.Program for this because it doesn't let us set the environment,
	// and that is the only way to tell govulncheck about an alternative vuln
	// database.
	binary, cleanup := buildtest.GoBuild(t, ".") // build govulncheck
	defer cleanup()
	ts.Commands["govulncheck"] = func(args []string, inputFile string) ([]byte, error) {
		cmd := exec.Command(binary, args...)
		if inputFile != "" {
			return nil, errors.New("input redirection makes no sense")
		}
		cmd.Env = append(os.Environ(), "GOVULNDB=file://"+testDir+"/testdata/vulndb")
		out, err := cmd.CombinedOutput()
		out = filterGoFilePaths(out)
		return out, err
	}

	// Build test module binaries.
	moduleDirs, err := filepath.Glob("testdata/modules/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, md := range moduleDirs {
		binary, cleanup := buildtest.GoBuild(t, md)
		defer cleanup()
		// Set an environment variable to the path to the binary, so tests
		// can refer to it.
		varName := filepath.Base(md) + "_binary"
		os.Setenv(varName, binary)
	}
	ts.Run(t, *update)
}

var goFileRegexp = regexp.MustCompile(`[^\s"]*\.go[\s":]`)

// filterGoFilePaths  modifies paths to Go files by replacing their directory with "...".
// For example,/a/b/c.go becomes .../c.go .
// This makes it possible to compare govulncheck output across systems, because
// Go filenames include setup-specific paths.
func filterGoFilePaths(data []byte) []byte {
	return goFileRegexp.ReplaceAllFunc(data, func(b []byte) []byte {
		s := string(b)
		return []byte(fmt.Sprintf(`.../%s%c`, filepath.Base(s[1:len(s)-1]), s[len(s)-1]))
	})
}

func TestLatestFixed(t *testing.T) {
	for _, test := range []struct {
		name string
		in   []osv.Affected
		want string
	}{
		{"empty", nil, ""},
		{
			"no semver",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeGit,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
							},
						}},
				},
			},
			"",
		},
		{
			"one",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
							},
						}},
				},
			},
			"v1.2.3",
		},
		{
			"several",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
								{Introduced: "v1.5.0", Fixed: "v1.5.6"},
							},
						}},
				},
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.3.0", Fixed: "v1.4.1"},
							},
						}},
				},
			},
			"v1.5.6",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := govulncheck.LatestFixed(test.in)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
