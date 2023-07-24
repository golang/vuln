// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package buildinfo

import (
	"os"
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
			got := syms["main"]
			want := []string{"f", "g", "main"}
			if !cmp.Equal(got, want) {
				t.Errorf("\ngot  %q\nwant %q", got, want)
			}
		})
}

// TestStrippedBinary checks that there is no symbol table for
// stripped binaries. This does not include darwin binaries.
// For more info, see #61051.
func TestStrippedBinary(t *testing.T) {
	// We exclude darwin as its stripped binaries seem to
	// preserve the symbol table. See TestStrippedDarwin.
	testAll(t, []string{"linux", "windows", "freebsd"}, []string{"amd64", "386", "arm", "arm64"},
		func(t *testing.T, goos, goarch string) {
			binary, done := test.GoBuild(t, "testdata", "", true, "GOOS", goos, "GOARCH", goarch)
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
			if syms != nil {
				t.Errorf("want empty symbol table; got %v symbols", len(syms))
			}
		})
}

// TestStrippedDarwin checks that the symbol table exists and
// is complete on darwin even in the presence of stripping.
// This test will become obsolete once #61051 is addressed.
func TestStrippedDarwin(t *testing.T) {
	t.Skip("to temporarily resolve #61511")
	testAll(t, []string{"darwin"}, []string{"amd64", "386", "arm", "arm64"},
		func(t *testing.T, goos, goarch string) {
			binary, done := test.GoBuild(t, "testdata", "", true, "GOOS", goos, "GOARCH", goarch)
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
			got := syms["main"]
			want := []string{"f", "g", "main"}
			if !cmp.Equal(got, want) {
				t.Errorf("\ngot  %q\nwant %q", got, want)
			}
		})
}
