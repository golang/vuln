// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"os"
	"path"
	"reflect"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/osv"
)

// TestImports checks for imports graph correctness. The inlined
// test code has the following package imports graphs:
//
//	entry/x        entry/y
//	       \     /        \
//	     amod/avuln      zmod/z
//	         |
//	       wmod/w
//	         |
//	     bmod/bvuln
//
// Packages ending in "vuln" have some known vulnerabilities.
func TestImports(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/amod/avuln"

			func X() {
				avuln.VulnData{}.Vuln1()
			}
			`,
				"y/y.go": `
			package y

			import (
				"golang.org/amod/avuln"
				"golang.org/zmod/z"
			)

			func Y() {
				avuln.VulnData{}.Vuln2()
				z.Z()
			}
		`}},
		{
			Name: "golang.org/zmod@v0.0.0",
			Files: map[string]interface{}{"z/z.go": `
			package z

			import "archive/zip"

			func Z() {
				_, _ = zip.OpenReader("filename")
			}
			`},
		},
		{
			Name: "golang.org/amod@v1.1.3",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			import "golang.org/wmod/w"

			type VulnData struct {}
			func (v VulnData) Vuln1() { w.W() }
			func (v VulnData) Vuln2() {}
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"bvuln/bvuln.go": `
			package bvuln

			import _ "golang.org/cmod/c"

			func Vuln() {}
			`},
		},
		{
			Name: "golang.org/cmod@v0.3.0",
			Files: map[string]interface{}{"c/c.go": `
			package c
			`},
		},
		{
			Name: "golang.org/wmod@v0.0.0",
			Files: map[string]interface{}{"w/w.go": `
			package w

			import "golang.org/bmod/bvuln"

			func W() { bvuln.Vuln() }
			`},
		},
	})
	defer e.Cleanup()

	// Load x and y as entry packages.
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"), path.Join(e.Temp(), "entry/y"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatal("failed to load x and y test packages")
	}

	cfg := &Config{
		Client:          testClient,
		ImportsOnly:     true,
		SourceGoVersion: "go1.18",
	}

	result, err := Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Check that we find the right number of vulnerabilities.
	// There should be four entries as there are three vulnerable
	// symbols in the two import-reachable OSVs and one standard
	// library vulnerability.
	if len(result.Vulns) != 4 {
		t.Errorf("want 4 Vulns, got %d", len(result.Vulns))
	}

	// Check that vulnerabilities are connected to the imports graph.
	for _, v := range result.Vulns {
		if v.ImportSink == 0 {
			t.Errorf("want ImportSink !=0 for %v:%v; got %v", v.Symbol, v.PkgPath, v.ImportSink)
		}
	}

	// Check that the package entry points are collected.
	if got := len(result.Imports.Entries); got != 2 {
		t.Errorf("want 2 package entry points; got %v", got)
	}

	// The imports slice should include import chains:
	//   x -> avuln -> w -> bvuln
	//         |
	//   y ---- ------> z
	// That is, c package shoud not appear in the slice.
	wantImports := map[string][]string{
		"golang.org/entry/x":    {"golang.org/amod/avuln"},
		"golang.org/entry/y":    {"golang.org/amod/avuln", "golang.org/zmod/z"},
		"golang.org/amod/avuln": {"golang.org/wmod/w"},
		"golang.org/wmod/w":     {"golang.org/bmod/bvuln"},
		"golang.org/zmod/z":     {"archive/zip"},
	}

	if igStrMap := impGraphToStrMap(result.Imports); !reflect.DeepEqual(wantImports, igStrMap) {
		t.Errorf("want %v imports graph; got %v", wantImports, igStrMap)
	}

	// Check that the source's modules are returned.
	wantMods := []*Module{
		{Path: "golang.org/amod", Version: "v1.1.3"},
		{Path: "golang.org/bmod", Version: "v0.5.0"},
		{Path: "golang.org/cmod", Version: "v0.3.0"},
		{Path: "golang.org/entry"},
		{Path: "golang.org/wmod", Version: "v0.0.0"},
		{Path: "golang.org/zmod", Version: "v0.0.0"},
		{Path: "stdlib", Version: "v1.18.0"},
	}
	gotMods := result.Modules
	sort.Slice(gotMods, func(i, j int) bool { return gotMods[i].Path < gotMods[j].Path })
	if diff := cmp.Diff(wantMods, gotMods, cmpopts.IgnoreFields(Module{}, "Dir")); diff != "" {
		t.Errorf("modules mismatch (-want, +got):\n%s", diff)
	}
}

// TestRequires checks for module requires graph correctness. The
// inlined test code has the following import/requires graphs:
//
//		entry/x		        entry
//		/     \                 /   \
//	 imod1/i    imod2/i         imod1   imod2
//	    |          |                \   /
//	  amod/a1 -> amod/a2            amod
//		       |                  |
//	            bmod/bvuln          bmod
//
// Packages ending in "vuln" have some known vulnerabilities.
func TestRequires(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import (
				_ "golang.org/imod1/i"
				_ "golang.org/imod2/i"
			)
			`},
		},
		{
			Name: "golang.org/imod1@v0.0.0",
			Files: map[string]interface{}{
				"i/i.go": `
			package i

			import _ "golang.org/amod/a1"
			`},
		},
		{
			Name: "golang.org/imod2@v0.0.0",
			Files: map[string]interface{}{
				"i/i.go": `
			package i

			import _ "golang.org/amod/a2"
			`},
		},
		{
			Name: "golang.org/amod@v0.0.1",
			Files: map[string]interface{}{"a1/a1.go": `
			package a1

			import _ "golang.org/amod/a2"

			`,
				"a2/a2.go": `
			package a2

			import _ "golang.org/bmod/bvuln"
		`}},
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
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &Config{
		Client:      testClient,
		ImportsOnly: true,
	}
	result, err := Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// There should be only one vulnerability bvuln.Vuln.
	if len(result.Vulns) != 1 {
		t.Errorf("want 1 Vuln, got %d", len(result.Vulns))
	}

	// Check that vulnerabilities are connected to the requires graph.
	if v := result.Vulns[0]; v.RequireSink == 0 {
		t.Errorf("want RequireSink !=0 for %v:%v; got %v", v.Symbol, v.PkgPath, v.RequireSink)
	}

	// Check that the module entry points are collected.
	if got := len(result.Requires.Entries); got != 1 {
		t.Errorf("want 1 module entry point; got %v", got)
	}

	// The requires slice should include requires chains:
	//   entry -> imod1 -> amod -> bmod
	//     |                |
	//     -----> imod2 ---->
	// That is, zmod module shoud not appear in the slice.
	wantRequires := map[string][]string{
		"golang.org/entry": {"golang.org/imod1", "golang.org/imod2"},
		"golang.org/imod1": {"golang.org/amod"},
		"golang.org/imod2": {"golang.org/amod"},
		"golang.org/amod":  {"golang.org/bmod"},
	}

	if rgStrMap := reqGraphToStrMap(result.Requires); !reflect.DeepEqual(wantRequires, rgStrMap) {
		t.Errorf("want %v requires graph; got %v", wantRequires, rgStrMap)
	}

	// Check that the source's modules are returned.
	wantMods := []*Module{
		{Path: "golang.org/amod", Version: "v0.0.1"},
		{Path: "golang.org/bmod", Version: "v0.5.0"},
		{Path: "golang.org/entry"},
		{Path: "golang.org/imod1", Version: "v0.0.0"},
		{Path: "golang.org/imod2", Version: "v0.0.0"},
		stdlibModule,
	}
	gotMods := result.Modules
	sort.Slice(gotMods, func(i, j int) bool { return gotMods[i].Path < gotMods[j].Path })
	if diff := cmp.Diff(wantMods, gotMods, cmpopts.IgnoreFields(Module{}, "Dir")); diff != "" {
		t.Errorf("modules mismatch (-want, +got):\n%s", diff)
	}
}

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
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"), path.Join(e.Temp(), "entry/y"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatal("failed to load x and y test packages")
	}

	cfg := &Config{
		Client: testClient,
	}
	result, err := Source(context.Background(), Convert(pkgs), cfg)
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
	if got := len(result.Calls.Entries); got != 2 {
		t.Errorf("want 2 call graph entry points; got %v", got)
	}

	// Check that vulnerabilities are connected to the call graph.
	// For the test example, all vulns should have a call sink.
	for _, v := range result.Vulns {
		if v.CallSink == 0 {
			t.Errorf("want CallSink !=0 for %v:%v; got 0", v.Symbol, v.PkgPath)
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

	if callStrMap := callGraphToStrMap(result.Calls); !reflect.DeepEqual(wantCalls, callStrMap) {
		t.Errorf("want %v call graph; got %v", wantCalls, callStrMap)
	}
}

func TestFiltering(t *testing.T) {
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import "golang.org/vmod/vuln"

			func X() {
				vuln.V()
			}`,
			},
		},
		{
			Name: "golang.org/vmod@v1.2.3",
			Files: map[string]interface{}{"vuln/vuln.go": `
			package vuln

			func V() {}
			`},
		},
	})
	defer e.Cleanup()

	client := &test.MockClient{
		Ret: map[string][]*osv.Entry{
			"golang.org/vmod": []*osv.Entry{
				{
					ID: "V",
					Affected: []osv.Affected{{
						Package: osv.Package{Name: "golang.org/vmod"},
						Ranges:  osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
						EcosystemSpecific: osv.EcosystemSpecific{
							Imports: []osv.EcosystemSpecificImport{{
								Path:    "golang.org/vmod/vuln",
								Symbols: []string{"V"},
								GOOS:    []string{"linux"},
								GOARCH:  []string{"amd64"},
							}},
						},
					}},
				},
			},
		},
	}

	// Load x as entry package.
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &Config{
		Client:      client,
		ImportsOnly: true,
	}

	os.Setenv("GOOS", "linux")
	os.Setenv("GOARCH", "amd64")

	result, err := Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	if g, w := len(result.Vulns), 1; g != w {
		t.Errorf("got %d Vulns, want %d", g, w)
	}

	os.Setenv("GOOS", "freebsd")
	os.Setenv("GOARCH", "arm64")

	result, err = Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	// GOOS and GOARCH no longer affect the vulns.
	if g, w := len(result.Vulns), 1; g != w {
		t.Errorf("got %d Vulns, want %d", g, w)
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

	client := &test.MockClient{
		Ret: map[string][]*osv.Entry{
			"golang.org/vmod": []*osv.Entry{
				{
					ID: "V",
					Affected: []osv.Affected{{
						Package: osv.Package{Name: "golang.org/vmod"},
						Ranges:  osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Introduced: "1.2.0"}}}},
						EcosystemSpecific: osv.EcosystemSpecific{
							Imports: []osv.EcosystemSpecificImport{{
								Path:    "golang.org/vmod/vuln",
								Symbols: []string{},
							}},
						},
					}},
				},
			},
		},
	}

	// Load x as entry package.
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &Config{
		Client: client,
	}
	result, err := Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Vulns) != 5 {
		t.Errorf("want 5 Vulns, got %d", len(result.Vulns))
	}

	for _, v := range result.Vulns {
		if v.Symbol == "V1" && v.CallSink == 0 {
			t.Errorf("expected a call sink for V1; got none")
		} else if v.Symbol != "V1" && v.CallSink != 0 {
			t.Errorf("expected no call sink for %v; got %v", v.Symbol, v.CallSink)
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
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &Config{
		Client: testClient,
	}
	result, err := Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Vulns) != 2 {
		t.Errorf("want 2 Vulns, got %d", len(result.Vulns))
	}

	var vuln *Vuln
	for _, v := range result.Vulns {
		if v.Symbol == "VulnData.Vuln1" && v.CallSink != 0 {
			vuln = v
		}
	}

	if vuln == nil {
		t.Fatal("VulnData.Vuln1 should be deemed a called vulnerability")
	}

	stacks := CallStacks(result)[vuln]
	if len(stacks) != 1 {
		t.Fatalf("want 1 stack for VulnData.Vuln1; got %v stacks", len(stacks))
	}

	stack := stacks[0]
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
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &Config{
		Client: testClient,
	}
	result, err := Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}

	if l := len(result.Calls.Functions); l != 3 {
		t.Errorf("want 3 functions (X, y, Vuln) in vulnerability graph; got %v", l)
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
	pkgs, err := test.LoadPackages(e, path.Join(e.Temp(), "entry/x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatal("failed to load x test package")
	}

	cfg := &Config{
		Client: testClient,
	}
	_, err = Source(context.Background(), Convert(pkgs), cfg)
	if err != nil {
		t.Fatal(err)
	}
}
