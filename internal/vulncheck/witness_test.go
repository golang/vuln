// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/osv"
)

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

func TestCallStacks(t *testing.T) {
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
	vuln1 := &Vuln{CallSink: v1, ImportSink: vp, OSV: o, Symbol: "vuln1"}
	vuln2 := &Vuln{CallSink: v2, ImportSink: vp, OSV: o, Symbol: "vuln2"}
	res := &Result{
		EntryFunctions: []*FuncNode{e1, e2},
		Vulns:          []*Vuln{vuln1, vuln2},
	}

	want := map[string][]string{
		"vuln1": {"entry1->interm1->vuln1"},
		"vuln2": {"entry2->interm2->vuln2"},
	}

	stacks := CallStacks(res)
	if got := stacksToString(stacks); !reflect.DeepEqual(want, got) {
		t.Errorf("want %v; got %v", want, got)
	}
}

func TestUniqueCallStack(t *testing.T) {
	a := &FuncNode{Name: "A"}
	b := &FuncNode{Name: "B"}
	v1 := &FuncNode{Name: "V1"}
	v2 := &FuncNode{Name: "V2"}
	v3 := &FuncNode{Name: "V3"}

	vuln1 := &Vuln{Symbol: "V1", CallSink: v1}
	vuln2 := &Vuln{Symbol: "V2", CallSink: v2}
	vuln3 := &Vuln{Symbol: "V3", CallSink: v3}

	callStack := func(fs ...*FuncNode) CallStack {
		var cs CallStack
		for _, f := range fs {
			cs = append(cs, StackEntry{Function: f})
		}
		return cs
	}

	// V1, V2, and V3 are vulnerable symbols
	skip := []*Vuln{vuln1, vuln2, vuln3}
	for _, test := range []struct {
		vuln *Vuln
		css  []CallStack
		want CallStack
	}{
		// [A -> B -> V3 -> V1, A -> V1] ==> A -> V1 since the first stack goes through V3
		{vuln1, []CallStack{callStack(a, b, v3, v1), callStack(a, v1)}, callStack(a, v1)},
		// [A -> V1 -> V2] ==> nil since the only candidate call stack goes through V1
		{vuln2, []CallStack{callStack(a, v1, v2)}, nil},
		// [A -> V1 -> V3, A -> B -> v3] ==> A -> B -> V3 since the first stack goes through V1
		{vuln3, []CallStack{callStack(a, v1, v3), callStack(a, b, v3)}, callStack(a, b, v3)},
	} {
		t.Run(test.vuln.Symbol, func(t *testing.T) {
			got := uniqueCallStack(test.vuln, test.css, skip)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
