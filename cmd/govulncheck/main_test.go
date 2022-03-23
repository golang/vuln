// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package main

import (
	"strings"
	"testing"

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
	} {
		t.Run(test.name, func(t *testing.T) {
			got := latestFixed(test.in)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestPkgPath(t *testing.T) {
	for _, test := range []struct {
		in   vulncheck.FuncNode
		want string
	}{
		{
			vulncheck.FuncNode{PkgPath: "math", Name: "Floor"},
			"math",
		},
		{
			vulncheck.FuncNode{RecvType: "a.com/b.T", Name: "M"},
			"a.com/b",
		},
		{
			vulncheck.FuncNode{RecvType: "*a.com/b.T", Name: "M"},
			"a.com/b",
		},
	} {
		got := pkgPath(&test.in)
		if got != test.want {
			t.Errorf("%+v: got %q, want %q", test.in, got, test.want)
		}
	}
}

func TestSummarizeCallStack(t *testing.T) {
	topPkgs := map[string]bool{"t1": true, "t2": true}
	vulnPkg := "v"

	for _, test := range []struct {
		in, want string
	}{
		{"a.F", ""},
		{"t1.F", ""},
		{"v.V", ""},
		{
			"t1.F v.V",
			"t1.F calls v.V",
		},
		{
			"t1.F t2.G v.V1 v.v2",
			"t2.G calls v.V1",
		},
		{
			"t1.F x.Y t2.G a.H b.I c.J v.V",
			"t2.G calls a.H, which eventually calls v.V",
		},
	} {
		in := stringToCallStack(test.in)
		got := summarizeCallStack(in, topPkgs, vulnPkg)
		if got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.in, got, test.want)
		}
	}
}

func stringToCallStack(s string) vulncheck.CallStack {
	var cs vulncheck.CallStack
	for _, e := range strings.Fields(s) {
		parts := strings.Split(e, ".")
		cs = append(cs, vulncheck.StackEntry{
			Function: &vulncheck.FuncNode{
				PkgPath: parts[0],
				Name:    parts[1],
			},
		})
	}
	return cs
}
