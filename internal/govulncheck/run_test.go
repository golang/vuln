// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

func TestLatestFixed(t *testing.T) {
	for _, test := range []struct {
		name string
		in   []osv.Affected
		want string
	}{
		{"empty", nil, ""},
		{
			"no semver",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeGit,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
							},
						}},
				},
			},
			"",
		},
		{
			"one",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
							},
						}},
				},
			},
			"v1.2.3",
		},
		{
			"several",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.0.0", Fixed: "v1.2.3"},
								{Introduced: "v1.5.0", Fixed: "v1.5.6"},
							},
						}},
				},
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "v1.3.0", Fixed: "v1.4.1"},
							},
						}},
				},
			},
			"v1.5.6",
		},
		{
			"no v prefix",
			[]osv.Affected{
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Fixed: "1.17.2"},
							},
						}},
				},
				{
					Ranges: osv.Affects{
						{
							Type: osv.TypeSemver,
							Events: []osv.RangeEvent{
								{Introduced: "1.18.0", Fixed: "1.18.4"},
							},
						}},
				},
			},
			"1.18.4",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := LatestFixed(test.in)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestUniqueCallStack(t *testing.T) {
	a := &vulncheck.FuncNode{Name: "A"}
	b := &vulncheck.FuncNode{Name: "B"}
	v1 := &vulncheck.FuncNode{Name: "V1"}
	v2 := &vulncheck.FuncNode{Name: "V2"}
	v3 := &vulncheck.FuncNode{Name: "V3"}

	vuln1 := &vulncheck.Vuln{Symbol: "V1", CallSink: 1}
	vuln2 := &vulncheck.Vuln{Symbol: "V2", CallSink: 2}
	vuln3 := &vulncheck.Vuln{Symbol: "V3", CallSink: 3}

	vr := &vulncheck.Result{
		Calls: &vulncheck.CallGraph{
			Functions: map[int]*vulncheck.FuncNode{1: v1, 2: v2, 3: v3},
		},
		Vulns: []*vulncheck.Vuln{vuln1, vuln2, vuln3},
	}

	callStack := func(fs ...*vulncheck.FuncNode) vulncheck.CallStack {
		var cs vulncheck.CallStack
		for _, f := range fs {
			cs = append(cs, vulncheck.StackEntry{Function: f})
		}
		return cs
	}

	// V1, V2, and V3 are vulnerable symbols
	skip := []*vulncheck.Vuln{vuln1, vuln2, vuln3}
	for _, test := range []struct {
		vuln *vulncheck.Vuln
		css  []vulncheck.CallStack
		want vulncheck.CallStack
	}{
		// [A -> B -> V3 -> V1, A -> V1] ==> A -> V1 since the first stack goes through V3
		{vuln1, []vulncheck.CallStack{callStack(a, b, v3, v1), callStack(a, v1)}, callStack(a, v1)},
		// [A -> V1 -> V2] ==> nil since the only candidate call stack goes through V1
		{vuln2, []vulncheck.CallStack{callStack(a, v1, v2)}, nil},
		// [A -> V1 -> V3, A -> B -> v3] ==> A -> B -> V3 since the first stack goes through V1
		{vuln3, []vulncheck.CallStack{callStack(a, v1, v3), callStack(a, b, v3)}, callStack(a, b, v3)},
	} {
		t.Run(test.vuln.Symbol, func(t *testing.T) {
			got := uniqueCallStack(test.vuln, test.css, skip, vr)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
