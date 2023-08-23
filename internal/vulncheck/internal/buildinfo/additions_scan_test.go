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
