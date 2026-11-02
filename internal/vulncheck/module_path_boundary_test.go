// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
)

func TestModuleVulnsPathComponentBoundary(t *testing.T) {
	root := &ModVulns{Module: &packages.Module{Path: "example.com/foo"}}
	nested := &ModVulns{Module: &packages.Module{Path: "example.com/foo/bar"}}
	affected := affectingVulns{root, nested}
	for _, tc := range []struct {
		name, module, importPath string
		want                     *ModVulns
	}{
		{"module itself", "", "example.com/foo", root},
		{"package within module", "", "example.com/foo/pkg", root},
		{"sibling prefix", "", "example.com/foobar/pkg", nil},
		{"hyphenated sibling", "", "example.com/foo-helpers/client", nil},
		{"nested module", "", "example.com/foo/bar/pkg", nested},
		{"nested sibling", "", "example.com/foo/barn/pkg", root},
		{"known module", "example.com/foo", "example.com/foo/pkg", root},
		{"known unaffected module", "example.com/foobar", "example.com/foobar/pkg", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, affected.moduleVulns(tc.module, tc.importPath)); diff != "" {
				t.Errorf("moduleVulns(%q, %q) mismatch (-want +got):\n%s", tc.module, tc.importPath, diff)
			}
		})
	}
}
