// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package scan_test

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/scan"
)

var update = flag.Bool("update", false, "update test files with results")

func TestPrinting(t *testing.T) {
	testdata := os.DirFS("testdata")
	inputs, err := fs.Glob(testdata, "*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range inputs {
		name := strings.TrimSuffix(input, ".json")
		rawJSON, _ := fs.ReadFile(testdata, input)
		textfiles, err := fs.Glob(testdata, name+"*.txt")
		if err != nil {
			t.Fatal(err)
		}
		for _, textfile := range textfiles {
			textname := strings.TrimSuffix(textfile, ".txt")
			t.Run(textname, func(t *testing.T) {
				wantText, _ := fs.ReadFile(testdata, textfile)
				got := &bytes.Buffer{}
				handler := scan.NewTextHandler(got)
				handler.Show(strings.Split(textname, "_")[1:])
				testRunHandler(t, rawJSON, handler)
				if diff := cmp.Diff(string(wantText), got.String()); diff != "" {
					if *update {
						// write the output back to the file
						os.WriteFile(filepath.Join("testdata", textfile), got.Bytes(), 0644)
						return
					}
					t.Errorf("Readable mismatch (-want, +got):\n%s", diff)
				}
			})
		}
		t.Run(name+"_json", func(t *testing.T) {
			// this effectively tests that we can round trip the json
			got := &strings.Builder{}
			testRunHandler(t, rawJSON, govulncheck.NewJSONHandler(got))
			if diff := cmp.Diff(strings.TrimSpace(string(rawJSON)), strings.TrimSpace(got.String())); diff != "" {
				t.Errorf("JSON mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func testRunHandler(t *testing.T, rawJSON []byte, handler govulncheck.Handler) {
	if err := govulncheck.HandleJSON(bytes.NewReader(rawJSON), handler); err != nil {
		t.Fatal(err)
	}
	err := scan.Flush(handler)
	switch e := err.(type) {
	case nil:
	case interface{ ExitCode() int }:
		if e.ExitCode() != 0 && e.ExitCode() != 3 {
			// not success or vulnerabilities found
			t.Fatal(err)
		}
	default:
		t.Fatal(err)
	}
}
