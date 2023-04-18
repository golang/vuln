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

func TestExtractPackagesAndSymbols(t *testing.T) {
	unsupported := map[string]bool{
		"darwin/386": true,
		"darwin/arm": true,
	}

	for _, g := range []string{"linux", "darwin", "windows", "freebsd"} {
		for _, a := range []string{"amd64", "386", "arm", "arm64"} {
			goos := g
			goarch := a

			ga := goos + "/" + goarch
			if unsupported[ga] {
				continue
			}

			t.Run(ga, func(t *testing.T) {
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
	}
}

// TestStrippedBinary checks support for stripped binaries.
// Currently, just checks that there is no symbol table.
func TestStrippedBinary(t *testing.T) {
	binary, done := test.GoBuild(t, "testdata", "", true, "GOOS", "linux", "GOARCH", "amd64")
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
		t.Errorf("want empty symbol table; got %v", syms)
	}
}
