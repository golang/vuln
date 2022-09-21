// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package binscan

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/buildtest"
)

func TestExtractPackagesAndSymbols(t *testing.T) {
	for _, gg := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(gg, func(t *testing.T) {
			goos, goarch, _ := strings.Cut(gg, "/")
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
