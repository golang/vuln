// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.22
// +build go1.22

package buildinfo

import (
	"testing"

	"golang.org/x/vuln/internal/test"
)

// TestStrippedBinary checks that there is no symbol table for
// stripped binaries.
func TestStrippedBinary(t *testing.T) {
	testAll(t, []string{"linux", "windows", "freebsd", "darwin"}, []string{"amd64", "386", "arm", "arm64"},
		func(t *testing.T, goos, goarch string) {
			binary, done := test.GoBuild(t, "testdata/src", "", true, "GOOS", goos, "GOARCH", goarch)
			defer done()

			_, syms, _, err := ExtractPackagesAndSymbols(binary)
			if err != nil {
				t.Fatal(err)
			}
			if len(syms) != 0 {
				t.Errorf("want empty symbol table; got %v symbols", len(syms))
			}
		})
}
