// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck_test

import (
	"context"
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/test"
	"golang.org/x/vuln/internal/vulncheck"
)

func TestFetchVulnerabilities(t *testing.T) {
	mc := &test.MockClient{
		Ret: map[string][]*osv.Entry{
			"example.mod/a": {{ID: "a", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "2.0.0"}}}}}}}},
			"example.mod/b": {{ID: "b", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "1.1.1"}}}}}}}},
			"example.mod/d": {{ID: "c", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/d"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "2.0.0"}}}}}}}},
			"example.mod/e": {{ID: "e", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/e"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "2.2.0"}}}}}}}},
		},
	}

	got, err := vulncheck.FetchVulnerabilities(context.Background(), mc, []*vulncheck.Module{
		{Path: "example.mod/a", Version: "v1.0.0"},
		{Path: "example.mod/b", Version: "v1.0.4"},
		{Path: "example.mod/c", Replace: &vulncheck.Module{Path: "example.mod/d", Version: "v1.0.0"}, Version: "v2.0.0"},
		{Path: "example.mod/e", Replace: &vulncheck.Module{Path: "../local/example.mod/d", Version: "v1.0.1"}, Version: "v2.1.0"},
	})
	if err != nil {
		t.Fatalf("FetchVulnerabilities failed: %s", err)
	}

	want := []*vulncheck.ModVulns{
		{
			Module: &vulncheck.Module{Path: "example.mod/a", Version: "v1.0.0"},
			Vulns: []*osv.Entry{
				{ID: "a", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/a"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "2.0.0"}}}}}}},
			},
		},
		{
			Module: &vulncheck.Module{Path: "example.mod/b", Version: "v1.0.4"},
			Vulns: []*osv.Entry{
				{ID: "b", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/b"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "1.1.1"}}}}}}},
			},
		},
		{
			Module: &vulncheck.Module{Path: "example.mod/c", Replace: &vulncheck.Module{Path: "example.mod/d", Version: "v1.0.0"}, Version: "v2.0.0"},
			Vulns: []*osv.Entry{
				{ID: "c", Affected: []osv.Affected{{Package: osv.Package{Name: "example.mod/d"}, Ranges: osv.Affects{{Type: osv.TypeSemver, Events: []osv.RangeEvent{{Fixed: "2.0.0"}}}}}}},
			},
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		log.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}
