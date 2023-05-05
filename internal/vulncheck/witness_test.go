// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"reflect"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// chainsToString converts map Vuln:chains to Vuln.PkgPath:["pkg1->...->pkgN", ...]
// string representation.
func chainsToString(chains map[*Vuln][]ImportChain) map[string][]string {
	m := make(map[string][]string)
	for v, chs := range chains {
		var chsStr []string
		for _, ch := range chs {
			var chStr []string
			for _, imp := range ch {
				chStr = append(chStr, imp.Package.PkgPath)
			}
			chsStr = append(chsStr, strings.Join(chStr, "->"))
		}
		m[v.ImportSink.Package.PkgPath] = chsStr
	}
	return m
}

// stacksToString converts map *Vuln:stacks to Vuln.Symbol:["f1->...->fN", ...]
// string representation.
func stacksToString(stacks map[*Vuln][]CallStack) map[string][]string {
	m := make(map[string][]string)
	for v, sts := range stacks {
		var stsStr []string
		for _, st := range sts {
			var stStr []string
			for _, call := range st {
				stStr = append(stStr, call.Function.Name)
			}
			stsStr = append(stsStr, strings.Join(stStr, "->"))
		}
		m[v.Symbol] = stsStr
	}
	return m
}

func TestImportChains(t *testing.T) {
	// Package import structure for the test program
	//    entry1  entry2
	//      |       |
	//    interm1   |
	//      |    \  |
	//      |   interm2
	//      |   /     |
	//     vuln1    vuln2
	e1 := &PkgNode{Package: &packages.Package{ID: "1", PkgPath: "entry1"}}
	e2 := &PkgNode{Package: &packages.Package{ID: "2", PkgPath: "entry2"}}
	i1 := &PkgNode{Package: &packages.Package{ID: "3", PkgPath: "interm1"}, ImportedBy: []*PkgNode{e1}}
	i2 := &PkgNode{Package: &packages.Package{ID: "4", PkgPath: "interm2"}, ImportedBy: []*PkgNode{e2, i1}}
	v1 := &PkgNode{Package: &packages.Package{ID: "5", PkgPath: "vuln1"}, ImportedBy: []*PkgNode{i1, i2}}
	v2 := &PkgNode{Package: &packages.Package{ID: "6", PkgPath: "vuln2"}, ImportedBy: []*PkgNode{i2}}
	vuln1 := &Vuln{ImportSink: v1}
	vuln2 := &Vuln{ImportSink: v2}
	res := &Result{
		Packages:      map[string]*PkgNode{"1": e1, "2": e2, "3": i1, "4": i2, "5": v1, "6": v2},
		EntryPackages: []*PkgNode{e1, e2},
		Vulns:         []*Vuln{vuln1, vuln2},
	}

	// The chain entry1->interm1->interm2->vuln1 is not reported
	// as there exist a shorter trace going from entry1 to vuln1
	// via interm1.
	want := map[string][]string{
		"vuln1": {"entry1->interm1->vuln1", "entry2->interm2->vuln1"},
		"vuln2": {"entry2->interm2->vuln2", "entry1->interm1->interm2->vuln2"},
	}

	chains := ImportChains(res)
	if got := chainsToString(chains); !reflect.DeepEqual(want, got) {
		t.Errorf("want %v; got %v", want, got)
	}
}

func TestCallStacks(t *testing.T) {
	// Call graph structure for the test program
	//    entry1      entry2
	//      |           |
	//    interm1(std)  |
	//      |    \     /
	//      |   interm2(interface)
	//      |   /     |
	//     vuln1    vuln2
	e1 := &FuncNode{Name: "entry1"}
	e2 := &FuncNode{Name: "entry2"}
	i1 := &FuncNode{Name: "interm1", PkgPath: "net/http", CallSites: []*CallSite{{Parent: e1, Resolved: true}}}
	i2 := &FuncNode{Name: "interm2", CallSites: []*CallSite{{Parent: e2, Resolved: true}, {Parent: i1, Resolved: true}}}
	v1 := &FuncNode{Name: "vuln1", CallSites: []*CallSite{{Parent: i1, Resolved: true}, {Parent: i2, Resolved: false}}}
	v2 := &FuncNode{Name: "vuln2", CallSites: []*CallSite{{Parent: i2, Resolved: false}}}
	vuln1 := &Vuln{CallSink: v1, Symbol: "vuln1"}
	vuln2 := &Vuln{CallSink: v2, Symbol: "vuln2"}
	res := &Result{
		EntryFunctions: []*FuncNode{e1, e2},
		Vulns:          []*Vuln{vuln1, vuln2},
	}

	want := map[string][]string{
		"vuln1": {"entry2->interm2->vuln1", "entry1->interm1->vuln1"},
		"vuln2": {"entry2->interm2->vuln2", "entry1->interm1->interm2->vuln2"},
	}

	stacks := CallStacks(res)
	if got := stacksToString(stacks); !reflect.DeepEqual(want, got) {
		t.Errorf("want %v; got %v", want, got)
	}
}
