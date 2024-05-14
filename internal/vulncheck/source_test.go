// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"path"
	"reflect"
	"testing"

	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/test"
)

// TestCalls checks for call graph vuln slicing correctness.
// The inlined test code has the following call graph
//
//	        x.X
//	      /  |  \
//	     /  d.D1 avuln.VulnData.Vuln1
//	    /  /  |
//	   c.C1  d.internal.Vuln1
//	    |
//	  avuln.VulnData.Vuln2
//
//	       --------------------y.Y-------------------------------
//	      /           /              \         \         \       \
//	     /           /                \         \         \       \
//	    /           /                  \         \         \       \
//	  c.C4 c.vulnWrap.V.Vuln1(=nil)   c.C2   bvuln.Vuln   c.C3   c.C3$1
//	    |                                       | |
//	y.benign                                    e.E
//
// and this slice
//
//	        x.X
//	      /  |  \
//	     /  d.D1 avuln.VulnData.Vuln1
//	    /  /
//	   c.C1
//	    |
//	  avuln.VulnData.Vuln2
//
//	   y.Y
//	    |
//	bvuln.Vuln
//	   | |
//	   e.E
//
// related to avuln.VulnData.{Vuln1, Vuln2} and bvuln.Vuln vulnerabilities.
func TestCalls(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import (
				"golang.org/cmod/c"
				"golang.org/dmod/d"
			)

			func X(x bool) {
				if x {
					c.C1().Vuln1() // vuln use: Vuln1
				} else {
					d.D1() // no vuln use
				}
			}
			`,
				"y/y.go": `
			package y

			import (
				"golang.org/cmod/c"
			)

			func Y(y bool) {
				if y {
					c.C2()() // vuln use: bvuln.Vuln
				} else {
					c.C3()()
					w := c.C4(benign)
					w.V.Vuln1() // no vuln use: Vuln1 does not belong to vulnerable type
				}
			}

			func benign(i c.I) {}
		`}},
		{
			Name: "golang.org/cmod@v1.1.3",
			Files: map[string]interface{}{"c/c.go": `
			package c

			import (
				"golang.org/amod/avuln"
				"golang.org/bmod/bvuln"
			)

			type I interface {
				Vuln1()
			}

			func C1() I {
				v := avuln.VulnData{}
				v.Vuln2() // vuln use
				return v
			}

			func C2() func() {
				return bvuln.Vuln
			}

			func C3() func() {
				return func() {}
			}

			type vulnWrap struct {
				V I
			}

			func C4(f func(i I)) vulnWrap {
				f(avuln.VulnData{})
				return vulnWrap{}
			}
			`},
		},
		{
			Name: "golang.org/dmod@v0.5.0",
			Files: map[string]interface{}{"d/d.go": `
			package d

			import (
				"golang.org/cmod/c"
			)

			type internal struct{}

			func (i internal) Vuln1() {}

			func D1() {
				c.C1() // transitive vuln use
				var i c.I
				i = internal{}
				i.Vuln1() // no vuln use
			}
			`},
		},
		{
			Name: "golang.org/amod@v1.1.3",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			type VulnData struct {}
			func (v VulnData) Vuln1() {}
			func (v VulnData) Vuln2() {}
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			import (
				"golang.org/emod/e"
			)

			func Vuln() {
				e.E(Vuln)
			}
			`},
		},
		{
			Name: "golang.org/emod@v1.5.0",
			Files: map[string]interface{}{"e/e.go": `
			package e

			func E(f func()) {
				f()
			}
			`},
		},
	})
	defer e.Cleanup()

	// Load x and y as entry packages.
	graph := NewPackageGraph("go1.18")
	err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x"), path.Join(e.Temp(), "entry/y")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.TopPkgs()) != 2 {
		t.Fatal("failed to load x and y test packages")
	}

	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := source(context.Background(), test.NewMockHandler(), cfg, c, graph)
	if err != nil {
		t.Fatal(err)
	}

	// Check that we find the right number of vulnerabilities.
	// There should be three entries as there are three vulnerable
	// symbols in the two import-reachable OSVs.
	if len(result.Vulns) != 3 {
		t.Errorf("want 3 Vulns, got %d", len(result.Vulns))
	}

	// Check that call graph entry points are present.
	if got := len(result.EntryFunctions); got != 2 {
		t.Errorf("want 2 call graph entry points; got %v", got)
	}

	// Check that vulnerabilities are connected to the call graph.
	// For the test example, all vulns should have a call sink.
	for _, v := range result.Vulns {
		if v.CallSink == nil {
			t.Errorf("want CallSink !=0 for %v; got 0", v.Symbol)
		}
	}

	wantCalls := map[string][]string{
		"golang.org/entry/x.X":       {"golang.org/amod/avuln.VulnData.Vuln1", "golang.org/cmod/c.C1", "golang.org/dmod/d.D1"},
		"golang.org/cmod/c.C1":       {"golang.org/amod/avuln.VulnData.Vuln2"},
		"golang.org/dmod/d.D1":       {"golang.org/cmod/c.C1"},
		"golang.org/entry/y.Y":       {"golang.org/bmod/bvuln.Vuln"},
		"golang.org/bmod/bvuln.Vuln": {"golang.org/emod/e.E"},
		"golang.org/emod/e.E":        {"golang.org/bmod/bvuln.Vuln"},
	}

	if callStrMap := callGraphToStrMap(result); !reflect.DeepEqual(wantCalls, callStrMap) {
		t.Errorf("want %v call graph; got %v", wantCalls, callStrMap)
	}
}

func TestAllSymbolsVulnerable(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/vmod/vuln"

			func X() {
				vuln.V1()
			}`,
			},
		},
		{
			Name: "golang.org/vmod@v1.2.3",
			Files: map[string]interface{}{"vuln/vuln.go": `
			package vuln

			func V1() {}
			func V2() {}
			func v() {}
			type a struct{}
			func (x a) foo() {}
			func (x *a) bar() {}
			`},
		},
	})
	defer e.Cleanup()

	client, err := client.NewInMemoryClient(
		[]*osv.Entry{
			{
				ID: "V",
				Affected: []osv.Affected{{
					Module: osv.Module{Path: "golang.org/vmod"},
					Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
					EcosystemSpecific: osv.EcosystemSpecific{
						Packages: []osv.Package{{
							Path:    "golang.org/vmod/vuln",
							Symbols: []string{},
						}},
					},
				}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Load x as entry package.
	graph := NewPackageGraph("go1.18")
	err = graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.TopPkgs()) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := source(context.Background(), test.NewMockHandler(), cfg, client, graph)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Vulns) != 2 { // init and V1
		t.Errorf("want 2 Vulns, got %d", len(result.Vulns))
	}

	for _, v := range result.Vulns {
		if v.CallSink == nil {
			t.Errorf("expected a call sink for %s; got none", v.Symbol)
		}
	}
}

// TestNoSyntheticNodes checks that removing synthetic wrappers from
// call graph still produces correct results.
func TestNoSyntheticNodes(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/amod/avuln"

			type i interface {
				Vuln1()
			}

			func X() {
				v := &avuln.VulnData{}
				var x i = v // to force creatation of wrapper method *avuln.VulnData.Vuln1
				x.Vuln1()
			}`,
			},
		},
		{
			Name: "golang.org/amod@v1.1.3",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			type VulnData struct {}
			func (v VulnData) Vuln1() {}
			func (v VulnData) Vuln2() {}
			`},
		},
	})
	defer e.Cleanup()

	// Load x as entry package.
	graph := NewPackageGraph("go1.18")
	err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.TopPkgs()) != 1 {
		t.Fatal("failed to load x test package")
	}

	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := source(context.Background(), test.NewMockHandler(), cfg, c, graph)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Vulns) != 1 {
		t.Errorf("want 1 Vuln, got %d", len(result.Vulns))
	}

	vuln := result.Vulns[0]
	if vuln.Symbol != "VulnData.Vuln1" {
		t.Fatalf("expected VulnData.Vuln1 as called symbol; got %s", vuln.Symbol)
	}

	stack := sourceCallstacks(result)[vuln]
	// We don't want the call stack X -> *VulnData.Vuln1 (wrapper) -> VulnData.Vuln1.
	// We want X -> VulnData.Vuln1.
	if len(stack) != 2 {
		t.Errorf("want stack of length 2; got stack of length %v", len(stack))
	}
}

func TestRecursion(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/bmod/bvuln"


			func X() {
				y()
				bvuln.Vuln()
				z()
			}

			func y() {
				X()
			}

			func z() {}
			`,
			},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			func Vuln() {}
			`},
		},
	})
	defer e.Cleanup()

	// Load x as entry package.
	graph := NewPackageGraph("go1.18")
	err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.TopPkgs()) != 1 {
		t.Fatal("failed to load x test package")
	}

	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	result, err := source(context.Background(), test.NewMockHandler(), cfg, c, graph)
	if err != nil {
		t.Fatal(err)
	}

	wantCalls := map[string][]string{
		"golang.org/entry/x.X": {"golang.org/bmod/bvuln.Vuln", "golang.org/entry/x.y"},
		"golang.org/entry/x.y": {"golang.org/entry/x.X"},
	}

	if callStrMap := callGraphToStrMap(result); !reflect.DeepEqual(wantCalls, callStrMap) {
		t.Errorf("want %v call graph; got %v", wantCalls, callStrMap)
	}
}

func TestIssue57174(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/bmod/bvuln"

			func P(d [][3]int) {
				p(d)
			}

			func p[E interface{ [3]int | [4]int }](d []E) {
				c := d[0]
				if c[0] > 0 {
					bvuln.Vuln()
				}
			}
			`,
			},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			func Vuln() {}
			`},
		},
	})
	defer e.Cleanup()

	// Load x as entry package.
	graph := NewPackageGraph("go1.18")
	err := graph.LoadPackagesAndMods(e.Config, nil, []string{path.Join(e.Temp(), "entry/x")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.TopPkgs()) != 1 {
		t.Fatal("failed to load x test package")
	}

	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	cfg := &govulncheck.Config{ScanLevel: "symbol"}
	_, err = source(context.Background(), test.NewMockHandler(), cfg, c, graph)
	if err != nil {
		t.Fatal(err)
	}
}
