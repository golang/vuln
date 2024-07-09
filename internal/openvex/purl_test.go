// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"testing"

	"golang.org/x/vuln/internal/govulncheck"
)

func TestPurlFromFinding(t *testing.T) {
	for _, tt := range []struct {
		name     string
		finding  *govulncheck.Finding
		wantPurl string
	}{
		{
			name: "module no package",
			finding: &govulncheck.Finding{
				Trace: []*govulncheck.Frame{
					{
						Module:  "github.com/user/module",
						Version: "v0.5.7",
					},
				},
			},
			wantPurl: "pkg:golang/github.com%2Fuser%2Fmodule@v0.5.7",
		},
		{
			name: "module w/ package",
			finding: &govulncheck.Finding{
				Trace: []*govulncheck.Frame{
					{
						Module:  "github.com/user/module",
						Version: "v0.5.7",
						Package: "github.com/user/module/pkg",
					},
				},
			},
			wantPurl: "pkg:golang/github.com%2Fuser%2Fmodule@v0.5.7",
		},
		{
			name: "submodule",
			finding: &govulncheck.Finding{
				Trace: []*govulncheck.Frame{
					{
						Module:  "github.com/user/module/submodule",
						Version: "v0.5.7",
						Package: "github.com/user/module/submodule/pkg",
					},
				},
			},
			wantPurl: "pkg:golang/github.com%2Fuser%2Fmodule%2Fsubmodule@v0.5.7",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gotPurl := purlFromFinding(tt.finding)
			if gotPurl != tt.wantPurl {
				t.Errorf("want: %v, got: %v", tt.wantPurl, gotPurl)
			}
		})
	}
}
