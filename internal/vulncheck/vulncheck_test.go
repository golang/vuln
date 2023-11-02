// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/osv"
)

func TestFilterVulns(t *testing.T) {
	past := time.Now().Add(-3 * time.Hour)
	mv := []*ModVulns{
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

	want := affectingVulns{
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

	got := affectingVulnerabilities(mv, "linux", "amd64")
	if diff := cmp.Diff(want, got, cmp.Exporter(func(t reflect.Type) bool {
		return reflect.TypeOf(affectingVulns{}) == t || reflect.TypeOf(ModVulns{}) == t
	})); diff != "" {
		t.Errorf("(-want,+got):\n%s", diff)
	}
}

func TestVulnsForPackage(t *testing.T) {
	aff := affectingVulns{
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

	got := aff.ForPackage("example.mod/a/b/c")
	want := []*osv.Entry{
		{ID: "b", Affected: []osv.Affected{{
			Module: osv.Module{Path: "example.mod/a/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Packages: []osv.Package{{
					Path: "example.mod/a/b/c",
				}},
			},
		}}},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want,+got):\n%s", diff)
	}
}

func TestVulnsForPackageReplaced(t *testing.T) {
	aff := affectingVulns{
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

	got := aff.ForPackage("example.mod/a/b/c")
	want := []*osv.Entry{
		{ID: "c", Affected: []osv.Affected{{
			Module: osv.Module{Path: "example.mod/b"},
			EcosystemSpecific: osv.EcosystemSpecific{
				Packages: []osv.Package{{
					Path: "example.mod/b/c",
				}},
			},
		}}},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want,+got):\n%s", diff)
	}
}

func TestVulnsForSymbol(t *testing.T) {
	aff := affectingVulns{
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

	got := aff.ForSymbol("example.mod/a/b/c", "a")
	want := []*osv.Entry{
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

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("(-want,+got):\n%s", diff)
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
				t.Errorf("want %s; got %s", tc.want, got)
			}
		})
	}
}
