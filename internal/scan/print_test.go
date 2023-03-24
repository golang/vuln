// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package scan_test

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/scan"
)

func TestPrinting(t *testing.T) {
	testdata := os.DirFS("testdata")
	inputs, err := fs.Glob(testdata, "*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range inputs {
		name := strings.TrimSuffix(input, ".json")
		t.Run(name, func(t *testing.T) {
			rawJSON, _ := fs.ReadFile(testdata, input)
			wantText, _ := fs.ReadFile(testdata, name+".txt")
			got := &strings.Builder{}
			testRunHandler(t, rawJSON, scan.NewTextHandler(got))
			if diff := cmp.Diff(string(wantText), got.String()); diff != "" {
				t.Errorf("Readable mismatch (-want, +got):\n%s", diff)
			}
			got.Reset()
			// this effectively tests that we can round trip the json
			testRunHandler(t, rawJSON, govulncheck.NewJSONHandler(got))
			if diff := cmp.Diff(string(rawJSON), got.String()); diff != "" {
				t.Errorf("JSON mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func testRunHandler(t *testing.T, rawJSON []byte, output govulncheck.Handler) {
	if err := govulncheck.HandleJSON(bytes.NewReader(rawJSON), output); err != nil {
		t.Fatal(err)
	}
	if err := output.Flush(); err != nil {
		t.Fatal(err)
	}
}
