// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/osv"
)

func TestFilterVulns(t *testing.T) {
	past := time.Now().Add(-3 * time.Hour)
	mv := moduleVulnerabilities{
		{
			Module: &packages.Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{
					{Module: osv.Module{Path: "example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}},
					{Module: osv.Module{Path: "a.example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}, // should be filtered out
					{Module: osv.Module{Path: "example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "0.9.0"}}}}},       // should be filtered out
				}},
				{ID: "b", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.1"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						GOOS: []string{"windows", "linux"},
					}},
					}}}},
				{ID: "c", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.1"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						GOARCH: []string{"arm64", "amd64"},
					}},
					}}}},
				{ID: "d", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/a"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOOS: []string{"windows"},
					}},
				}}}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/b",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "e", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOARCH: []string{"arm64"},
					}},
				}}}},
				{ID: "f", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOOS: []string{"linux"},
					}},
				}}}},
				{ID: "g", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.1"}}}}}}},
				{ID: "h", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOOS: []string{"windows"}, GOARCH: []string{"amd64"},
					}},
				}}}},
			},
		},
		{
			Module: &packages.Module{
				Path: "example.mod/c",
			},
			Vulns: []*osv.Entry{
				{ID: "i", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/c"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.0"}}}}}}},
				{ID: "j", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/c"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Fixed: "3.0.0"}}}}}}},
				{ID: "k"},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/d",
				Version: "v1.2.0",
			},
			Vulns: []*osv.Entry{
				{ID: "l", Affected: []osv.Affected{
					{Module: osv.Module{Path: "example.mod/d"}, EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							GOOS: []string{"windows"}, // should be filtered out
						}},
					}},
					{Module: osv.Module{Path: "example.mod/d"}, EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							GOOS: []string{"linux"},
						}},
					}},
				}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/w",
				Version: "v1.3.0",
			},
			Vulns: []*osv.Entry{
				{ID: "m", Withdrawn: &past, Affected: []osv.Affected{ // should be filtered out
					{Module: osv.Module{Path: "example.mod/w"}, EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							GOOS: []string{"linux"},
						}},
					}},
				}},
				{ID: "n", Affected: []osv.Affected{
					{Module: osv.Module{Path: "example.mod/w"}, EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							GOOS: []string{"linux"},
						}},
					}},
				}},
			},
		},
	}

	expected := moduleVulnerabilities{
		{
			Module: &packages.Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}}},
				{ID: "c", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/a"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOARCH: []string{"arm64", "amd64"},
					}},
				}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.0.0"}, {Fixed: "1.0.1"}}}}}}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/b",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "f", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOOS: []string{"linux"},
					}},
				}}}},
				{ID: "g", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOARCH: []string{"amd64"},
					}},
				}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "0.0.1"}, {Fixed: "2.0.1"}}}}}}},
			},
		},
		{
			Module: &packages.Module{
				Path: "example.mod/c",
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/d",
				Version: "v1.2.0",
			},
			Vulns: []*osv.Entry{
				{ID: "l", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/d"}, EcosystemSpecific: osv.EcosystemSpecific{
					Packages: []osv.Package{{
						GOOS: []string{"linux"},
					}},
				}}}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/w",
				Version: "v1.3.0",
			},
			Vulns: []*osv.Entry{
				{ID: "n", Affected: []osv.Affected{
					{Module: osv.Module{Path: "example.mod/w"}, EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							GOOS: []string{"linux"},
						}},
					}},
				}},
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
		return reflect.TypeOf(moduleVulnerabilities{}) == t || reflect.TypeOf(ModVulns{}) == t
	}))
}

func TestVulnsForPackage(t *testing.T) {
	mv := moduleVulnerabilities{
		{
			Module: &packages.Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/a"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/a/b",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "b", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/a/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/d",
				Version: "v0.0.1",
			},
			Vulns: []*osv.Entry{
				{ID: "d", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/d"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
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
			Module: osv.Module{Path: "example.mod/a/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Packages: []osv.Package{{
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
			Module: &packages.Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/a"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			Module: &packages.Module{
				Path: "example.mod/a/b",
				Replace: &packages.Module{
					Path: "example.mod/b",
				},
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "c", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
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
			Module: osv.Module{Path: "example.mod/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Packages: []osv.Package{{
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
			Module: &packages.Module{
				Path:    "example.mod/a",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/a"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path: "example.mod/a/b/c",
						}},
					},
				}}},
			},
		},
		{
			Module: &packages.Module{
				Path:    "example.mod/a/b",
				Version: "v1.0.0",
			},
			Vulns: []*osv.Entry{
				{ID: "b", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/a/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path:    "example.mod/a/b/c",
							Symbols: []string{"a"},
						}},
					},
				}}},
				{ID: "c", Affected: []osv.Affected{{
					Module: osv.Module{Path: "example.mod/a/b"},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
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
			Module: osv.Module{Path: "example.mod/a/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Packages: []osv.Package{{
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
	pkgs, err := loadTestPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}

	wantPkgs := map[string][]string{
		"golang.org/amod/avuln": {"golang.org/wmod/w"},
		"golang.org/bmod/bvuln": nil,
		"golang.org/entry/x":    {"golang.org/amod/avuln"},
		"golang.org/wmod/w":     {"golang.org/bmod/bvuln"},
	}
	if got := pkgPathToImports(pkgs); !reflect.DeepEqual(got, wantPkgs) {
		t.Errorf("want %v;got %v", wantPkgs, got)
	}

	wantMods := map[string]string{
		"golang.org/amod":  "v1.1.3",
		"golang.org/bmod":  "v0.5.0",
		"golang.org/entry": "",
		"golang.org/wmod":  "v0.0.0",
	}
	if got := modulePathToVersion(pkgs); !reflect.DeepEqual(got, wantMods) {
		t.Errorf("want %v;got %v", wantMods, got)
	}
}

func TestReceiver(t *testing.T) {
	tcs := []struct {
		name string
		fn   *FuncNode
		want string
	}{
		{
			name: "empty",
			fn: &FuncNode{
				RecvType: "",
				Package:  &packages.Package{PkgPath: "example.com/a/pkg"},
			},
			want: "",
		},
		{
			name: "pointer",
			fn: &FuncNode{
				RecvType: "*example.com/a/pkg.Atype",
				Package:  &packages.Package{PkgPath: "example.com/a/pkg"},
			},
			want: "*Atype",
		},
		{
			name: "not pointer",
			fn: &FuncNode{
				RecvType: "example.com/a/pkg.Atype",
				Package:  &packages.Package{PkgPath: "example.com/a/pkg"},
			},
			want: "Atype",
		},
		{
			name: "no prefix",
			fn: &FuncNode{
				RecvType: "Atype",
				Package:  &packages.Package{PkgPath: "example.com/a/pkg"},
			},
			want: "Atype",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.fn.Receiver()
			if got != tc.want {
				t.Errorf("*FuncNode.Receiver() = %s, want %s", got, tc.want)
			}
		})
	}
}
