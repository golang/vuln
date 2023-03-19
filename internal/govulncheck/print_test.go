// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package govulncheck

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/result"
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

// testVuln1 is a test third-party vulnerability.
var testVuln1 = &osv.Entry{
	ID:      "GO-0000-0001",
	Details: "Third-party vulnerability",
	Affected: []osv.Affected{{
		Package: osv.Package{Name: "golang.org/vmod"},
		EcosystemSpecific: osv.EcosystemSpecific{
			Imports: []osv.EcosystemSpecificImport{{
				GOOS: []string{"amd"},
			}},
		},
	}}}

// testVuln1 is a test stdlib vulnerability.
var testVuln2 = &osv.Entry{
	ID:      "GO-0000-0002",
	Details: "Stdlib vulnerability",
	Affected: []osv.Affected{{
		Package: osv.Package{Name: internal.GoStdModulePath},
	}}}

func TestPrintTextNoVulns(t *testing.T) {
	preamble := &result.Preamble{
		Analysis: result.AnalysisSource,
		Mode:     result.ModeCompact,
	}
	r := []*result.Vuln{
		{
			OSV: testVuln1,
			Modules: []*result.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
				},
			},
		},
	}
	testPrint(t, preamble, r, "no_vulns")
}
func TestPrintTextSource(t *testing.T) {
	preamble := &result.Preamble{
		Analysis: result.AnalysisSource,
		Mode:     result.ModeCompact,
	}
	r := []*result.Vuln{
		{
			OSV: testVuln1,
			Modules: []*result.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
					Packages: []*result.Package{
						{
							CallStacks: []result.CallStack{{Summary: "main calls vmod.Vuln"}},
						},
					},
				},
			},
		},
		{
			OSV: testVuln2,
			Modules: []*result.Module{
				{
					Path:         internal.GoStdModulePath,
					FoundVersion: "v0.0.1",
					Packages: []*result.Package{
						{
							Path: "net/http",
						},
					},
				},
			},
		}}

	testPrint(t, preamble, r, "source")
}
func TestPrintTextBinary(t *testing.T) {
	preamble := &result.Preamble{
		Analysis: result.AnalysisBinary,
		Mode:     result.ModeCompact,
	}
	r := []*result.Vuln{
		{
			OSV: testVuln1,
			Modules: []*result.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
					// We can omit package info since in binary mode
					// there are no call stacks and we don't show symbols.
				},
			},
		},
		{
			OSV: testVuln2,
			Modules: []*result.Module{
				{
					Path:         internal.GoStdModulePath,
					FoundVersion: "v0.0.1",
					Packages: []*result.Package{
						{
							Path: "net/http",
						},
					},
				},
			},
		}}
	testPrint(t, preamble, r, "binary")
}
func TestPrintTextMultiModuleAndStacks(t *testing.T) {
	preamble := &result.Preamble{
		Analysis: result.AnalysisSource,
		Mode:     result.ModeCompact,
	}
	r := []*result.Vuln{
		{
			OSV: testVuln1,
			Modules: []*result.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
					Packages: []*result.Package{
						{
							CallStacks: []result.CallStack{{Summary: "main calls vmod.Vuln"}, {Summary: "main calls vmod.VulnFoo"}},
						},
					},
				},
				{
					Path:         "golang.org/vmod1",
					FoundVersion: "v0.0.3",
					FixedVersion: "v0.0.4",
					Packages: []*result.Package{
						{
							CallStacks: []result.CallStack{{Summary: "Foo calls vmod1.Vuln"}},
						},
						{
							CallStacks: []result.CallStack{{Summary: "Bar calls vmod1.VulnFoo"}},
						},
					},
				},
			},
		}}

	testPrint(t, preamble, r, "multi_stacks")
}

func testPrint(t *testing.T, preamble *result.Preamble, vulns []*result.Vuln, name string) {
	testdata := os.DirFS("testdata")
	wantText, _ := fs.ReadFile(testdata, name+".txt")
	wantJSON, _ := fs.ReadFile(testdata, name+".json")
	got := &strings.Builder{}
	testRunHandler(t, preamble, vulns, NewTextHandler(got, preamble))
	if diff := cmp.Diff(string(wantText), got.String()); diff != "" {
		t.Errorf("Readable mismatch (-want, +got):\n%s", diff)
	}
	got.Reset()
	testRunHandler(t, preamble, vulns, NewJSONHandler(got))
	if diff := cmp.Diff(string(wantJSON), got.String()); diff != "" {
		t.Errorf("JSON mismatch (-want, +got):\n%s", diff)
	}
}

func testRunHandler(t *testing.T, preamble *result.Preamble, vulns []*result.Vuln, output Handler) {
	output.Preamble(preamble)
	for _, v := range vulns {
		if err := output.Vulnerability(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := output.Flush(); err != nil {
		t.Fatal(err)
	}
}
