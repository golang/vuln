// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"strings"
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

func TestSummarizeCallStack(t *testing.T) {
	for _, test := range []struct {
		in, want string
	}{
		{"ma.a.F", "a.F"},
		{"m1.p1.F", "p1.F"},
		{"mv.v.V", "v.V"},
		{
			"m1.p1.F mv.v.V",
			"p1.F calls v.V",
		},
		{
			"m1.p1.F m1.p2.G mv.v.V1 mv.v.v2",
			"p2.G calls v.V1, which calls v.v2",
		},
		{
			"m1.p1.F m1.p2.G mv.v.V$1 mv.v.V1",
			"p2.G calls v.V, which calls v.V1",
		},
		{
			"m1.p1.F m1.p2.G$1 mv.v.V1",
			"p2.G calls v.V1",
		},
		{
			"m1.p1.F m1.p2.G$1 mv.v.V$1 mv.v.V1",
			"p2.G calls v.V, which calls v.V1",
		},
		{
			"m1.p1.F w.x.Y m1.p2.G ma.a.H mb.b.I mc.c.J mv.v.V",
			"p2.G calls a.H, which eventually calls v.V",
		},
		{
			"m1.p1.F w.x.Y m1.p2.G ma.a.H mb.b.I mc.c.J mv.v.V$1 mv.v.V1",
			"p2.G calls a.H, which eventually calls v.V1",
		},
		{
			"m1.p1.F m1.p1.F$1 ma.a.H mb.b.I mv.v.V1",
			"p1.F calls a.H, which eventually calls v.V1",
		},
	} {
		in := stringToFinding(test.in)
		got := compactTrace(in)
		if got != test.want {
			t.Errorf("%s:\ngot  %s\nwant %s", test.in, got, test.want)
		}
	}
}

func stringToFinding(s string) *govulncheck.Finding {
	f := &govulncheck.Finding{}
	entries := strings.Fields(s)
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		firstDot := strings.Index(e, ".")
		lastDot := strings.LastIndex(e, ".")
		f.Trace = append(f.Trace, &govulncheck.Frame{
			Module:   e[:firstDot],
			Package:  e[:firstDot] + "/" + e[firstDot+1:lastDot],
			Function: e[lastDot+1:],
		})
	}
	return f
}
