// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/vulncheck"
)

func TestFetchVulnerabilities(t *testing.T) {
	a := &osv.Entry{ID: "a", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/a"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Fixed: "2.0.0"}}}}}}}
	b := &osv.Entry{ID: "b", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/b"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Fixed: "1.1.1"}}}}}}}
	c := &osv.Entry{ID: "c", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/d"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Fixed: "2.0.0"}}}}}}}
	d := &osv.Entry{ID: "e", Affected: []osv.Affected{{Module: osv.Module{Path: "example.mod/e"}, Ranges: []osv.Range{{Type: osv.RangeTypeSemver, Events: []osv.RangeEvent{{Fixed: "2.2.0"}}}}}}}

	mc, err := client.NewInMemoryClient([]*osv.Entry{a, b, c, d})
	if err != nil {
		t.Fatal(err)
	}

	got, err := vulncheck.FetchVulnerabilities(context.Background(), mc, []*packages.Module{
		{Path: "example.mod/a", Version: "v1.0.0"},
		{Path: "example.mod/b", Version: "v1.0.4"},
		{Path: "example.mod/c", Replace: &packages.Module{Path: "example.mod/d", Version: "v1.0.0"}, Version: "v2.0.0"},
		{Path: "example.mod/e", Replace: &packages.Module{Path: "../local/example.mod/d", Version: "v1.0.1"}, Version: "v2.1.0"},
	})
	if err != nil {
		t.Fatalf("FetchVulnerabilities failed: %s", err)
	}

	want := []*vulncheck.ModVulns{
		{
			Module: &packages.Module{Path: "example.mod/a", Version: "v1.0.0"},
			Vulns:  []*osv.Entry{a},
		},
		{
			Module: &packages.Module{Path: "example.mod/b", Version: "v1.0.4"},
			Vulns:  []*osv.Entry{b},
		},
		{
			Module: &packages.Module{Path: "example.mod/c", Replace: &packages.Module{Path: "example.mod/d", Version: "v1.0.0"}, Version: "v2.0.0"},
			Vulns:  []*osv.Entry{c},
		},
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("mismatch (-want, +got):\n%s", diff)
	}
}
