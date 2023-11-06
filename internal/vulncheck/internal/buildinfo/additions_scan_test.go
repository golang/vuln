// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package buildinfo

import (
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/test"
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

			got := mainSortedSymbols(syms)
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

// mainSortedSymbols gets symbols for "main" package and
// sorts them for testing purposes.
func mainSortedSymbols(syms []Symbol) []Symbol {
	var s []Symbol
	for _, ps := range syms {
		if ps.Pkg == "main" {
			s = append(s, ps)
		}
	}
	sort.SliceStable(s, func(i, j int) bool { return s[i].Pkg+"."+s[i].Name < s[j].Pkg+"."+s[j].Name })
	return s
}
