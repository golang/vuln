// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package traces

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
)

func TestCompact(t *testing.T) {
	for _, tc := range []struct {
		trace []*govulncheck.Frame
		want  []*govulncheck.Frame
	}{
		{
			[]*govulncheck.Frame{},
			nil,
		},
		{
			// binary mode
			[]*govulncheck.Frame{{Function: "Foo"}},
			[]*govulncheck.Frame{{Function: "Foo"}},
		},
		{
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "user", Function: "U"},
			},
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "user", Function: "U"},
			},
		},
		{
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "user", Function: "W"},
				{Module: "user", Function: "U"},
			},
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "user", Function: "W"},
			},
		},
		{
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "interim", Function: "I"},
				{Module: "user", Function: "U"},
				{Module: "user", Function: "W"},
			},
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "interim", Function: "I"},
				{Module: "user", Function: "U"},
			},
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
			[]*govulncheck.Frame{
				{Module: "vuln", Function: "V"},
				{Module: "interim", Function: "J"},
				{Module: "interim", Function: "I"},
				{Module: "user", Function: "U"},
			},
		},
	} {
		f := &govulncheck.Finding{Trace: tc.trace}
		got := Compact(f)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("(-want; got+): %s", diff)
		}
	}
}
