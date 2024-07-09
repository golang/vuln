// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

func TestSubcomponentSet(t *testing.T) {
	id1 := "GO-2021-0265"
	id2 := "GO-2022-1234"
	tests := []struct {
		name     string
		findings []*govulncheck.Finding
		want     int
	}{
		{
			name: "multiple findings at same level different mod",
			findings: []*govulncheck.Finding{
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod1",
							Package: "mod1/pkg",
						},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod2",
							Package: "mod2/pkg2",
						},
					},
				},
			},
			want: 2,
		},
		{
			name: "multiple Findings at same level same mod",
			findings: []*govulncheck.Finding{
				{
					OSV:          id1,
					FixedVersion: "v1.9.3",
					Trace: []*govulncheck.Frame{
						{
							Module:   "github.com/tidwall/gjson",
							Version:  "v1.6.5",
							Package:  "github.com/tidwall/gjson",
							Function: "Get",
						},
					},
				},
				{
					OSV:          id1,
					FixedVersion: "v1.9.3",
					Trace: []*govulncheck.Frame{
						{
							Module:   "github.com/tidwall/gjson",
							Version:  "v1.6.5",
							Package:  "github.com/tidwall/gjson",
							Function: "Get",
							Receiver: "Result",
						},
					},
				},
			},
			want: 1,
		},
		{
			name: "mix of findings for different osvs",
			findings: []*govulncheck.Finding{
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod1",
							Version: "v1.0.0",
						},
					},
				},
				{
					OSV: id2,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod2",
							Version: "v1.0.0",
							Package: "mod2/pkg2",
						},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod2",
							Version: "v1.2.1",
						},
					},
				},
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unique := subcomponentSet(tt.findings)
			if len(unique) != tt.want {
				t.Errorf("want %v findings, got %v instead", tt.want, unique)
			}
		})
	}
}

// Copied from internal/sarif
func TestMoreSpecific(t *testing.T) {
	frame := func(m, p, f string) *govulncheck.Frame {
		return &govulncheck.Frame{
			Module:   m,
			Package:  p,
			Function: f,
		}
	}

	for _, tc := range []struct {
		name   string
		want   int
		trace1 []*govulncheck.Frame
		trace2 []*govulncheck.Frame
	}{
		{"sym-vs-sym", 0,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1"), frame("m2", "p2", "f2")},
		},
		{"sym-vs-pkg", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m1", "p1", "f2")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
		},
		{"pkg-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v1"), frame("m2", "p2", "v2")},
		},
		{"pkg-vs-mod", -1,
			[]*govulncheck.Frame{
				frame("m1", "p1", "")},
			[]*govulncheck.Frame{
				frame("m1", "", "")},
		},
		{"mod-vs-sym", 1,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m1", "p1", "v2"), frame("m1", "p1", "f1")},
		},
		{"mod-vs-mod", 0,
			[]*govulncheck.Frame{
				frame("m1", "", "")},
			[]*govulncheck.Frame{
				frame("m2", "", "")},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f1 := &govulncheck.Finding{Trace: tc.trace1}
			f2 := &govulncheck.Finding{Trace: tc.trace2}
			if got := moreSpecific(f1, f2); got != tc.want {
				t.Errorf("want %d; got %d", tc.want, got)
			}
		})
	}
}
