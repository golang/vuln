// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"path"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/osv"
)

func TestFilterVulns(t *testing.T) {
	mv := moduleVulnerabilities{
		{
			mod: &Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{
					{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}},
					{Package: osv.Package{Name: "a.example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, // should be filtered out
					{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "0.9.0"}}}}},       // should be filtered out
				}},
				{ID: "b", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.1"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{Imports: []osv.EcosystemSpecificImport{{
						GOOS: []string{"windows", "linux"},
					}},
					}}}},
				{ID: "c", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.1"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"arm64", "amd64"},
					}},
					}}}},
				{ID: "d", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOOS: []string{"windows"},
					}},
				}}}},
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/b",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "e", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"arm64"},
					}},
				}}}},
				{ID: "f", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOOS: []string{"linux"},
					}},
				}}}},
				{ID: "g", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.1"}}}}}}},
				{ID: "h", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOOS: []string{"windows"}, GOARCH: []string{"amd64"},
					}},
				}}}},
			},
		},
		{
			mod: &Module{
				Path: "example.mod/c",
			},
			vulns: []*osv.Entry{
				{ID: "i", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/c"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.0"}}}}}}},
				{ID: "j", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/c"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "3.0.0"}}}}}}},
				{ID: "k"},
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/d",
				Version: "v1.2.0",
			},
			vulns: []*osv.Entry{
				{ID: "l", Affected: []osv.Affected{
					{Package: osv.Package{Name: "example.mod/d"}, EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							GOOS: []string{"windows"}, // should be filtered out
						}},
					}},
					{Package: osv.Package{Name: "example.mod/d"}, EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							GOOS: []string{"linux"},
						}},
					}},
				}},
			},
		},
	}

	expected := moduleVulnerabilities{
		{
			mod: &Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}}},
				{ID: "c", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"arm64", "amd64"},
					}},
				}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.1"}}}}}}},
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/b",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "f", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOOS: []string{"linux"},
					}},
				}}}},
				{ID: "g", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.1"}}}}}}},
			},
		},
		{
			mod: &Module{
				Path: "example.mod/c",
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/d",
				Version: "v1.2.0",
			},
			vulns: []*osv.Entry{
				{ID: "l", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/d"}, EcosystemSpecific: osv.EcosystemSpecific{
					Imports: []osv.EcosystemSpecificImport{{
						GOOS: []string{"linux"},
					}},
				}}}},
			},
		},
	}

	filtered := mv.filter("linux", "amd64")
	if diff := diffModuleVulnerabilities(expected, filtered); diff != "" {
		t.Fatalf("Filter returned unexpected results (-want,+got):\n%s", diff)
	}
}

func diffModuleVulnerabilities(a, b moduleVulnerabilities) string {
	return cmp.Diff(a, b, cmp.Exporter(func(t reflect.Type) bool {
		return reflect.TypeOf(moduleVulnerabilities{}) == t || reflect.TypeOf(modVulns{}) == t
	}))
}

func TestVulnsForPackage(t *testing.T) {
	mv := moduleVulnerabilities{
		{
			mod: &Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/a"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/a/b",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "b", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/a/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/d",
				Version: "v0.0.1",
			},
			vulns: []*osv.Entry{
				{ID: "d", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/d"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path: "example.mod/d",
						}},
					},
				}}},
			},
		},
	}

	filtered := mv.vulnsForPackage("example.mod/a/b/c")
	expected := []*osv.Entry{
		{ID: "b", Affected: []osv.Affected{{
			Package: osv.Package{Name: "example.mod/a/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Imports: []osv.EcosystemSpecificImport{{
					Path: "example.mod/a/b/c",
				}},
			},
		}}},
	}

	if !reflect.DeepEqual(filtered, expected) {
		t.Fatalf("VulnsForPackage returned unexpected results, got:\n%s\nwant:\n%s", vulnsToString(filtered), vulnsToString(expected))
	}
}

func TestVulnsForPackageReplaced(t *testing.T) {
	mv := moduleVulnerabilities{
		{
			mod: &Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/a"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			mod: &Module{
				Path: "example.mod/a/b",
				Replace: &Module{
					Path: "example.mod/b",
				},
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "c", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path: "example.mod/b/c",
						}},
					},
				}}},
			},
		},
	}

	filtered := mv.vulnsForPackage("example.mod/a/b/c")
	expected := []*osv.Entry{
		{ID: "c", Affected: []osv.Affected{{
			Package: osv.Package{Name: "example.mod/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Imports: []osv.EcosystemSpecificImport{{
					Path: "example.mod/b/c",
				}},
			},
		}}},
	}

	if !reflect.DeepEqual(filtered, expected) {
		t.Fatalf("VulnsForPackage returned unexpected results, got:\n%s\nwant:\n%s", vulnsToString(filtered), vulnsToString(expected))
	}
}

func TestVulnsForSymbol(t *testing.T) {
	mv := moduleVulnerabilities{
		{
			mod: &Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/a"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			mod: &Module{
				Path:    "example.mod/a/b",
				Version: "v1.0.0",
			},
			vulns: []*osv.Entry{
				{ID: "b", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/a/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path:    "example.mod/a/b/c",
							Symbols: []string{"a"},
						}},
					},
				}}},
				{ID: "c", Affected: []osv.Affected{{
					Package: osv.Package{Name: "example.mod/a/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Imports: []osv.EcosystemSpecificImport{{
							Path:    "example.mod/a/b/c",
							Symbols: []string{"b"},
						}},
					},
				}}},
			},
		},
	}

	filtered := mv.vulnsForSymbol("example.mod/a/b/c", "a")
	expected := []*osv.Entry{
		{ID: "b", Affected: []osv.Affected{{
			Package: osv.Package{Name: "example.mod/a/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Imports: []osv.EcosystemSpecificImport{{
					Path:    "example.mod/a/b/c",
					Symbols: []string{"a"},
				}},
			},
		}}},
	}

	if !reflect.DeepEqual(filtered, expected) {
		t.Fatalf("VulnsForPackage returned unexpected results, got:\n%s\nwant:\n%s", vulnsToString(filtered), vulnsToString(expected))
	}
}

func TestConvert(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import _ "golang.org/amod/avuln"
		`}},
		{
			Name: "golang.org/zmod@v0.0.0",
			Files: map[string]interface{}{"z/z.go": `
			package z
			`},
		},
		{
			Name: "golang.org/amod@v1.1.3",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			import _ "golang.org/wmod/w"
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln
			`},
		},
		{
			Name: "golang.org/wmod@v0.0.0",
			Files: map[string]interface{}{"w/w.go": `
			package w

			import _ "golang.org/bmod/bvuln"
			`},
		},
	})
	defer e.Cleanup()

	// Load x as entry package.
	pkgs, err := loadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}

	vpkgs := Convert(pkgs)

	wantPkgs := map[string][]string{
		"golang.org/amod/avuln": {"golang.org/wmod/w"},
		"golang.org/bmod/bvuln": nil,
		"golang.org/entry/x":    {"golang.org/amod/avuln"},
		"golang.org/wmod/w":     {"golang.org/bmod/bvuln"},
	}
	if got := pkgPathToImports(vpkgs); !reflect.DeepEqual(got, wantPkgs) {
		t.Errorf("want %v;got %v", wantPkgs, got)
	}

	wantMods := map[string]string{
		"golang.org/amod":  "v1.1.3",
		"golang.org/bmod":  "v0.5.0",
		"golang.org/entry": "",
		"golang.org/wmod":  "v0.0.0",
	}
	if got := modulePathToVersion(vpkgs); !reflect.DeepEqual(got, wantMods) {
		t.Errorf("want %v;got %v", wantMods, got)
	}
}
