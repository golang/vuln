// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/internal"
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
	r := &govulncheck.Result{Vulns: []*govulncheck.Vuln{
		{
			OSV: testVuln1,
			Modules: []*govulncheck.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
				},
			},
		},
	}}

	got := new(strings.Builder)
	if err := doPrintText(got, r, false, true); err != nil {
		t.Fatal(err)
	}
	want := `No vulnerabilities found.

=== Informational ===

Found 1 vulnerability in packages that you import, but there are no call
stacks leading to the use of this vulnerability. You may not need to
take any action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
for details.

Vulnerability #1: GO-0000-0001
  Third-party vulnerability
  More info: https://pkg.go.dev/vuln/GO-0000-0001
  Found in: golang.org/vmod@v0.0.1
  Fixed in: golang.org/vmod@v0.1.3
  Platforms: amd
`
	if diff := cmp.Diff(want, got.String()); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestPrintTextSource(t *testing.T) {
	r := &govulncheck.Result{Vulns: []*govulncheck.Vuln{
		{
			OSV: testVuln1,
			Modules: []*govulncheck.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
					Packages: []*govulncheck.Package{
						{
							CallStacks: []govulncheck.CallStack{{Summary: "main calls vmod.Vuln"}},
						},
					},
				},
			},
		},
		{
			OSV: testVuln2,
			Modules: []*govulncheck.Module{
				{
					Path:         internal.GoStdModulePath,
					FoundVersion: "v0.0.1",
					Packages: []*govulncheck.Package{
						{
							Path: "net/http",
						},
					},
				},
			},
		}}}

	got := new(strings.Builder)
	if err := doPrintText(got, r, false, true); err != nil {
		t.Fatal(err)
	}
	want := `Your code is affected by 1 vulnerability from 1 module.

Vulnerability #1: GO-0000-0001
  Third-party vulnerability

  More info: https://pkg.go.dev/vuln/GO-0000-0001

  Module: golang.org/vmod
    Found in: golang.org/vmod@v0.0.1
    Fixed in: golang.org/vmod@v0.1.3
    Platforms: amd

    Call stacks in your code:
      main calls vmod.Vuln

=== Informational ===

Found 1 vulnerability in packages that you import, but there are no call
stacks leading to the use of this vulnerability. You may not need to
take any action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
for details.

Vulnerability #1: GO-0000-0002
  Stdlib vulnerability
  More info: https://pkg.go.dev/vuln/GO-0000-0002
  Found in: net/http@v0.0.1
  Fixed in: N/A
`
	if diff := cmp.Diff(want, got.String()); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestPrintTextBinary(t *testing.T) {
	r := &govulncheck.Result{Vulns: []*govulncheck.Vuln{
		{
			OSV: testVuln1,
			Modules: []*govulncheck.Module{
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
			Modules: []*govulncheck.Module{
				{
					Path:         internal.GoStdModulePath,
					FoundVersion: "v0.0.1",
					Packages: []*govulncheck.Package{
						{
							Path: "net/http",
						},
					},
				},
			},
		}}}

	got := new(strings.Builder)
	if err := doPrintText(got, r, false, false); err != nil {
		t.Fatal(err)
	}
	want := `Your code is affected by 2 vulnerabilities from 1 module and the Go standard library.

Vulnerability #1: GO-0000-0001
  Third-party vulnerability

  More info: https://pkg.go.dev/vuln/GO-0000-0001

  Module: golang.org/vmod
    Found in: golang.org/vmod@v0.0.1
    Fixed in: golang.org/vmod@v0.1.3
    Platforms: amd

Vulnerability #2: GO-0000-0002
  Stdlib vulnerability

  More info: https://pkg.go.dev/vuln/GO-0000-0002

  Standard library
    Found in: net/http@v0.0.1
    Fixed in: N/A
`
	if diff := cmp.Diff(want, got.String()); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}

func TestPrintTextMultiModuleAndStacks(t *testing.T) {
	r := &govulncheck.Result{Vulns: []*govulncheck.Vuln{
		{
			OSV: testVuln1,
			Modules: []*govulncheck.Module{
				{
					Path:         "golang.org/vmod",
					FoundVersion: "v0.0.1",
					FixedVersion: "v0.1.3",
					Packages: []*govulncheck.Package{
						{
							CallStacks: []govulncheck.CallStack{{Summary: "main calls vmod.Vuln"}, {Summary: "main calls vmod.VulnFoo"}},
						},
					},
				},
				{
					Path:         "golang.org/vmod1",
					FoundVersion: "v0.0.3",
					FixedVersion: "v0.0.4",
					Packages: []*govulncheck.Package{
						{
							CallStacks: []govulncheck.CallStack{{Summary: "Foo calls vmod1.Vuln"}},
						},
						{
							CallStacks: []govulncheck.CallStack{{Summary: "Bar calls vmod1.VulnFoo"}},
						},
					},
				},
			},
		}}}

	got := new(strings.Builder)
	if err := doPrintText(got, r, false, true); err != nil {
		t.Fatal(err)
	}
	want := `Your code is affected by 1 vulnerability from 2 modules.

Vulnerability #1: GO-0000-0001
  Third-party vulnerability

  More info: https://pkg.go.dev/vuln/GO-0000-0001

  Module: golang.org/vmod
    Found in: golang.org/vmod@v0.0.1
    Fixed in: golang.org/vmod@v0.1.3
    Platforms: amd

    Call stacks in your code:
      main calls vmod.Vuln
      main calls vmod.VulnFoo

  Module: golang.org/vmod1
    Found in: golang.org/vmod1@v0.0.3
    Fixed in: golang.org/vmod1@v0.0.4

    Call stacks in your code:
      Foo calls vmod1.Vuln

      Bar calls vmod1.VulnFoo
`
	if diff := cmp.Diff(want, got.String()); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}
