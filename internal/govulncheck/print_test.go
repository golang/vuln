// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package govulncheck

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/osv"
)

func TestPlatforms(t *testing.T) {
	for _, test := range []struct {
		entry *osv.Entry
		want  string
	}{
		{
			entry: &osv.Entry{ID: "All"},
			want:  "",
		},
		{
			entry: &osv.Entry{
				ID: "one-import",
				Affected: []osv.Affected{{
					Package: osv.Package{Name: "golang.org/vmod"},
					Ranges:  osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							GOOS:   []string{"windows", "linux"},
							GOARCH: []string{"amd64", "wasm"},
						}},
					},
				}},
			},
			want: "linux/amd64, linux/wasm, windows/amd64, windows/wasm",
		},
		{
			entry: &osv.Entry{
				ID: "two-imports",
				Affected: []osv.Affected{{
					Package: osv.Package{Name: "golang.org/vmod"},
					Ranges:  osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{
							{
								GOOS:   []string{"windows"},
								GOARCH: []string{"amd64"},
							},
							{
								GOOS:   []string{"linux"},
								GOARCH: []string{"amd64"},
							},
						},
					},
				}},
			},
			want: "linux/amd64, windows/amd64",
		},
		{
			entry: &osv.Entry{
				ID: "two-os-only",
				Affected: []osv.Affected{{
					Package: osv.Package{Name: "golang.org/vmod"},
					Ranges:  osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{
							{
								GOOS: []string{"windows, linux"},
							},
						},
					},
				}},
			},
			want: "windows, linux",
		},
		{
			entry: &osv.Entry{
				ID: "one-arch-only",
				Affected: []osv.Affected{{
					Package: osv.Package{Name: "golang.org/vmod"},
					Ranges:  osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{
							{
								GOOS: []string{"amd64"},
							},
						},
					},
				}},
			},
			want: "amd64",
		},
	} {
		t.Run(test.entry.ID, func(t *testing.T) {
			got := platforms("golang.org/vmod", test.entry)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

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
			testRunHandler(t, rawJSON, NewTextHandler(got))
			if diff := cmp.Diff(string(wantText), got.String()); diff != "" {
				t.Errorf("Readable mismatch (-want, +got):\n%s", diff)
			}
			got.Reset()
			// this effectively tests that we can round trip the json
			testRunHandler(t, rawJSON, NewJSONHandler(got))
			if diff := cmp.Diff(string(rawJSON), got.String()); diff != "" {
				t.Errorf("JSON mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func testRunHandler(t *testing.T, rawJSON []byte, output Handler) {
	if err := HandleJSON(bytes.NewReader(rawJSON), output); err != nil {
		t.Fatal(err)
	}
	if err := output.Flush(); err != nil {
		t.Fatal(err)
	}
}
