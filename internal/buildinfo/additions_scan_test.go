// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package buildinfo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/internal/testenv"
)

// testAll executes testing function ft on all valid combinations
// of gooss and goarchs.
func testAll(t *testing.T, gooss, goarchs []string, ft func(*testing.T, string, string)) {
	// unsupported platforms for building Go binaries.
	var unsupported = map[string]bool{
		"darwin/386": true,
		"darwin/arm": true,
	}

	for _, g := range gooss {
		for _, a := range goarchs {
			goos := g
			goarch := a

			ga := goos + "/" + goarch
			if unsupported[ga] {
				continue
			}

			t.Run(ga, func(t *testing.T) {
				ft(t, goos, goarch)
			})
		}
	}
}

func TestExtractPackagesAndSymbols(t *testing.T) {
	testAll(t, []string{"linux", "darwin", "windows", "freebsd"}, []string{"amd64", "386", "arm", "arm64"},
		func(t *testing.T, goos, goarch string) {
			binary, done := test.GoBuild(t, "testdata", "", false, "GOOS", goos, "GOARCH", goarch)
			defer done()

			f, err := os.Open(binary)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			_, syms, _, err := ExtractPackagesAndSymbols(f)
			if err != nil {
				t.Fatal(err)
			}

			got := sortedSymbols("main", syms)
			want := []Symbol{
				{"main", "f"},
				{"main", "g"},
				{"main", "main"},
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("(-want,+got):%s", diff)
			}
		})
}

// sortedSymbols gets symbols for pkg and
// sorts them for testing purposes.
func sortedSymbols(pkg string, syms []Symbol) []Symbol {
	var s []Symbol
	for _, ps := range syms {
		if ps.Pkg == pkg {
			s = append(s, ps)
		}
	}
	sort.SliceStable(s, func(i, j int) bool { return s[i].Pkg+"."+s[i].Name < s[j].Pkg+"."+s[j].Name })
	return s
}

// Test58509 is supposed to test issue #58509 where a whole
// vulnerable function is deleted from the binary so we
// cannot detect its presence.
//
// Note: the issue is still not addressed and the test
// expectations are set to fail once it gets addressed.
func Test58509(t *testing.T) {
	testenv.NeedsGoBuild(t)

	vulnLib := `package bvuln

%s debug = true

func Vuln() {
	if debug {
		return
	}
	print("vuln")
}`

	for _, tc := range []struct {
		gl   string
		want bool
	}{
		{"const", false}, // TODO(https://go.dev/issue/58509): change expectations once issue is addressed
		{"var", true},
	} {
		tc := tc
		t.Run(tc.gl, func(t *testing.T) {
			e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
				{
					Name: "golang.org/entry",
					Files: map[string]interface{}{
						"main.go": `
			package main

			import (
				"golang.org/bmod/bvuln"
			)

			func main() {
				bvuln.Vuln()
			}
			`,
					}},
				{
					Name:  "golang.org/bmod@v0.5.0",
					Files: map[string]interface{}{"bvuln/bvuln.go": fmt.Sprintf(vulnLib, tc.gl)},
				},
			})
			defer e.Cleanup()

			cmd := exec.Command("go", "build", "-o", "entry")
			cmd.Dir = e.Config.Dir
			cmd.Env = e.Config.Env
			out, err := cmd.CombinedOutput()
			if err != nil || len(out) > 0 {
				t.Fatalf("failed to build the binary %v %v", err, string(out))
			}

			exe, err := os.Open(filepath.Join(e.Config.Dir, "entry"))
			if err != nil {
				t.Fatal(err)
			}
			defer exe.Close()

			_, syms, _, err := ExtractPackagesAndSymbols(exe)
			if err != nil {
				t.Fatal(err)
			}

			// effectively, Vuln is not optimized away from the program
			got := len(sortedSymbols("golang.org/bmod/bvuln", syms)) != 0
			if got != tc.want {
				t.Errorf("want %t; got %t", tc.want, got)
			}
		})
	}
}
