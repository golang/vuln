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
	"golang.org/x/vuln/internal/buildtest"
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
				binary, done := buildtest.GoBuild(t, "testdata", "", "GOOS", goos, "GOARCH", goarch)
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
				want := []string{"main", "f", "g"}
				if !cmp.Equal(got, want) {
					t.Errorf("\ngot  %q\nwant %q", got, want)
				}
			})
		}
	}
}
