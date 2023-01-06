// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
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
			got := platforms(test.entry)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestIndent(t *testing.T) {
	for _, test := range []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"short", "hello", 2, "  hello"},
		{"multi", "mulit\nline\nstring", 1, " mulit\n line\n string"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := indent(test.s, test.n)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
