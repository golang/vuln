// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/packages/packagestest"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/test"
)

// stacksToString converts map *Vuln:stack to Vuln.Symbol:"f1->...->fN"
// string representation.
func stacksToString(stacks map[*Vuln]CallStack) map[string]string {
	m := make(map[string]string)
	for v, st := range stacks {
		var stStr []string
		for _, call := range st {
			stStr = append(stStr, call.Function.Name)
		}
		m[v.Symbol] = strings.Join(stStr, "->")
	}
	return m
}

func TestSourceCallstacks(t *testing.T) {
	// Call graph structure for the test program
	//    entry1      entry2
	//      |           |
	//    interm1       |
	//      |    \     /
	//      |   interm2(interface)
	//      |   /     |
	//     vuln1    vuln2
	o := &osv.Entry{ID: "o"}
	e1 := &FuncNode{Name: "entry1"}
	e2 := &FuncNode{Name: "entry2"}
	i1 := &FuncNode{Name: "interm1", CallSites: []*CallSite{{Parent: e1, Resolved: true}}}
	i2 := &FuncNode{Name: "interm2", CallSites: []*CallSite{{Parent: e2, Resolved: true}, {Parent: i1, Resolved: true}}}
	v1 := &FuncNode{Name: "vuln1", CallSites: []*CallSite{{Parent: i1, Resolved: true}, {Parent: i2, Resolved: false}}}
	v2 := &FuncNode{Name: "vuln2", CallSites: []*CallSite{{Parent: i2, Resolved: false}}}

	vp := &packages.Package{PkgPath: "v1", Module: &packages.Module{Path: "m1"}}
	vuln1 := &Vuln{CallSink: v1, Package: vp, OSV: o, Symbol: "vuln1"}
	vuln2 := &Vuln{CallSink: v2, Package: vp, OSV: o, Symbol: "vuln2"}
	res := &Result{
		EntryFunctions: []*FuncNode{e1, e2},
		Vulns:          []*Vuln{vuln1, vuln2},
	}

	want := map[string]string{
		"vuln1": "entry1->interm1->vuln1",
		"vuln2": "entry2->interm2->vuln2",
	}

	stacks := sourceCallstacks(res)
	if got := stacksToString(stacks); !reflect.DeepEqual(want, got) {
		t.Errorf("want %v; got %v", want, got)
	}
}

func TestSourceUniqueCallStack(t *testing.T) {
	// Call graph structure for the test program
	//    entry1      entry2
	//      |           |
	//    vuln1      interm1
	//      |           |
	//      |        interm2
	//      |     /
	//    vuln2
	o := &osv.Entry{ID: "o"}
	e1 := &FuncNode{Name: "entry1"}
	e2 := &FuncNode{Name: "entry2"}
	i1 := &FuncNode{Name: "interm1", CallSites: []*CallSite{{Parent: e2}}}
	i2 := &FuncNode{Name: "interm2", CallSites: []*CallSite{{Parent: i1}}}
	v1 := &FuncNode{Name: "vuln1", CallSites: []*CallSite{{Parent: e1}}}
	v2 := &FuncNode{Name: "vuln2", CallSites: []*CallSite{{Parent: v1}, {Parent: i2}}}

	vp := &packages.Package{PkgPath: "v1", Module: &packages.Module{Path: "m1"}}
	vuln1 := &Vuln{CallSink: v1, Package: vp, OSV: o, Symbol: "vuln1"}
	vuln2 := &Vuln{CallSink: v2, Package: vp, OSV: o, Symbol: "vuln2"}
	res := &Result{
		EntryFunctions: []*FuncNode{e1, e2},
		Vulns:          []*Vuln{vuln1, vuln2},
	}

	want := map[string]string{
		"vuln1": "entry1->vuln1",
		"vuln2": "entry2->interm1->interm2->vuln2",
	}

	stacks := sourceCallstacks(res)
	if got := stacksToString(stacks); !reflect.DeepEqual(want, got) {
		t.Errorf("want %v; got %v", want, got)
	}
}

// TestInits checks for correct positions of init functions
// and their respective calls (see #51575).
func TestInits(t *testing.T) {
	testClient, err := client.NewInMemoryClient(
		[]*osv.Entry{
			{
				ID: "A", Affected: []osv.Affected{{Module: osv.Module{Path: "golang.org/amod"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						Path: "golang.org/amod/avuln", Symbols: []string{"A"}},
					}},
				}},
			},
			{
				ID: "C", Affected: []osv.Affected{{Module: osv.Module{Path: "golang.org/cmod"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver}},
					EcosystemSpecific: osv.EcosystemSpecific{Packages: []osv.Package{{
						Path: "golang.org/cmod/cvuln", Symbols: []string{"C"}},
					}},
				}},
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	e := packagestest.Export(t, packagestest.Modules, []packagestest.Module{
		{
			Name: "golang.org/entry",
			Files: map[string]interface{}{
				"x/x.go": `
			package x

			import (
				_ "golang.org/amod/avuln"
				_ "golang.org/bmod/b"
			)
			`,
			},
		},
		{
			Name: "golang.org/amod@v0.5.0",
			Files: map[string]interface{}{"avuln/avuln.go": `
			package avuln

			func init() {
				A()
			}

			func A() {}
			`},
		},
		{
			Name: "golang.org/bmod@v0.5.0",
			Files: map[string]interface{}{"b/b.go": `
			package b

			import _ "golang.org/cmod/cvuln"
			`},
		},
		{
			Name: "golang.org/cmod@v0.5.0",
			Files: map[string]interface{}{"cvuln/cvuln.go": `
			package cvuln

			var x int = C()

			func C() int {
				return 0
			}
			`},
		},
	})
	defer e.Cleanup()

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
	result, err := source(context.Background(), test.NewMockHandler(), cfg, testClient, graph)
	if err != nil {
		t.Fatal(err)
	}

	cs := sourceCallstacks(result)
	want := map[string][]string{
		"A": {
			// Entry init's position is the package statement.
			// It calls avuln.init at avuln import statement.
			"N:golang.org/entry/x.init	F:x.go:2:4	C:x.go:5:5",
			// implicit avuln.init is calls explicit init at the avuln
			// package statement.
			"N:golang.org/amod/avuln.init	F:avuln.go:2:4	C:avuln.go:2:4",
			"N:golang.org/amod/avuln.init#1	F:avuln.go:4:9	C:avuln.go:5:6",
			"N:golang.org/amod/avuln.A	F:avuln.go:8:9	C:",
		},
		"C": {
			"N:golang.org/entry/x.init	F:x.go:2:4	C:x.go:6:5",
			"N:golang.org/bmod/b.init	F:b.go:2:4	C:b.go:4:11",
			"N:golang.org/cmod/cvuln.init	F:cvuln.go:2:4	C:cvuln.go:4:17",
			"N:golang.org/cmod/cvuln.C	F:cvuln.go:6:9	C:",
		},
	}
	if diff := cmp.Diff(want, fullStacksToString(cs)); diff != "" {
		t.Errorf("modules mismatch (-want, +got):\n%s", diff)
	}
}

// fullStacksToString is like stacksToString but the stack stringification
// is a slice of strings, each containing detailed information on each on
// the corresponding frame.
func fullStacksToString(callStacks map[*Vuln]CallStack) map[string][]string {
	m := make(map[string][]string)
	for v, cs := range callStacks {
		var scs []string
		for _, se := range cs {
			fPos := se.Function.Pos
			fp := fmt.Sprintf("%s:%d:%d", filepath.Base(fPos.Filename), fPos.Line, fPos.Column)

			var cp string
			if se.Call != nil && se.Call.Pos.IsValid() {
				cPos := se.Call.Pos
				cp = fmt.Sprintf("%s:%d:%d", filepath.Base(cPos.Filename), cPos.Line, cPos.Column)
			}

			sse := fmt.Sprintf("N:%s.%s\tF:%v\tC:%v", se.Function.Package.PkgPath, se.Function.Name, fp, cp)
			scs = append(scs, sse)
		}
		m[v.OSV.ID] = scs
	}
	return m
}

func TestIsExported(t *testing.T) {
	for _, tc := range []struct {
		symbol string
		want   bool
	}{
		{"foo", false},
		{"Foo", true},
		{"x.foo", false},
		{"X.foo", false},
		{"x.Foo", true},
		{"X.Foo", true},
	} {
		tc := tc
		t.Run(tc.symbol, func(t *testing.T) {
			if got := isExported(tc.symbol); tc.want != got {
				t.Errorf("want %t; got %t", tc.want, got)
			}
		})
	}
}
