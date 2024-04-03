// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
)

func TestCompactTrace(t *testing.T) {
	for _, tc := range []struct {
		trace []*govulncheck.Frame
		want  string
	}{
		{
			// binary mode
			[]*govulncheck.Frame{{Function: "Foo"}},
			"Foo",
		},
		{
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "user", Function: "W"},
				{Module: "user", Function: "U"},
			},
			"W calls V",
		},
		{
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "interim", Function: "I"},
				{Module: "user", Function: "U"},
				{Module: "user", Function: "W"},
			},
			"U calls I, which calls V",
		},
		{
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "x", Function: "X"},
				{Module: "interim", Function: "K"},
				{Module: "interim", Function: "J"},
				{Module: "interim", Function: "I"},
				{Module: "user", Function: "U"},
				{Module: "user", Function: "W"},
			},
			"U calls I, which eventually calls V",
		},
	} {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			f := &govulncheck.Finding{Trace: tc.trace}
			got := compactTrace(f)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("(-want got+) %s", diff)
			}
		})
	}
}
