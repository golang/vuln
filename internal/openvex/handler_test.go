// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

func TestFinding(t *testing.T) {
	const id1 = "ID1"
	tests := []struct {
		name     string
		id       string
		findings []*govulncheck.Finding
		want     findingLevel
	}{
		{
			name: "multiple",
			id:   id1,
			findings: []*govulncheck.Finding{
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:  "mod",
							Package: "mod/pkg",
						},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module:   "mod",
							Package:  "mod/pkg",
							Function: "func",
						},
					},
				},
				{
					OSV: id1,
					Trace: []*govulncheck.Frame{
						{
							Module: "mod",
						},
					},
				},
			},
			want: called,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHandler(nil)
			for _, f := range tt.findings {
				if err := h.Finding(f); err != nil {
					t.Errorf("handler.Finding() error = %v", err)
				}
			}
			got := h.levels[tt.id]
			if got != tt.want {
				t.Errorf("want %v; got %v", tt.want, got)
			}
		})
	}
}
