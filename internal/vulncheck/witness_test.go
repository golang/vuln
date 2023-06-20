// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"reflect"
	"strings"
	"testing"
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
	e1 := &FuncNode{Name: "entry1"}
	e2 := &FuncNode{Name: "entry2"}
	i1 := &FuncNode{Name: "interm1", CallSites: []*CallSite{{Parent: e1, Resolved: true}}}
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
		"vuln1": {"entry1->interm1->vuln1", "entry2->interm2->vuln1"},
		"vuln2": {"entry2->interm2->vuln2", "entry1->interm1->interm2->vuln2"},
	}

	stacks := CallStacks(res)
	if got := stacksToString(stacks); !reflect.DeepEqual(want, got) {
		t.Errorf("want %v; got %v", want, got)
	}
}
