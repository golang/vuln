// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"testing"

	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

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
			got := latestFixed(test.in)
			if got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
