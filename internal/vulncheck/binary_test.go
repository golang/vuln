// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/buildinfo"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/test"
)

func TestBinary(t *testing.T) {
	bin := &Bin{
		Modules: []*packages.Module{
			{Path: "golang.org/entry"},
			{Path: "golang.org/cmod", Version: "v1.1.3"},
			{Path: "golang.org/amod", Version: "v1.1.3"},
			{Path: "golang.org/bmod", Version: "v0.5.0"},
		},
		GoVersion: "go1.20",
		GOOS:      "linux",
		GOARCH:    "amd64",
		PkgSymbols: []buildinfo.Symbol{
			{Pkg: "golang.org/entry", Name: "main"},
			{Pkg: "golang.org/cmod/c", Name: "C"},
			{Pkg: "golang.org/amod/avuln", Name: "VulnData.Vuln1"}, // assume linker skips VulnData.Vuln2
			{Pkg: "golang.org/bmod/bvuln", Name: "NoVuln"},         // assume linker skips NoVuln
			{Pkg: "archive/zip", Name: "OpenReader"},
		},
	}

	c, err := newTestClient()
	if err != nil {
		t.Fatal(err)
	}

	// Test imports only mode
	cfg := &govulncheck.Config{ScanLevel: "package"}
	res, err := binary(context.Background(), test.NewMockHandler(), bin, cfg, c)
	if err != nil {
		t.Fatal(err)
	}

	// With package scan level, all vulnerable packages should be detected.
	want := []*Vuln{
		{Package: &packages.Package{PkgPath: "golang.org/bmod/bvuln"}},
		{Package: &packages.Package{PkgPath: "golang.org/amod/avuln"}},
		{Package: &packages.Package{PkgPath: "archive/zip"}},
	}

	less := func(v1, v2 *Vuln) bool {
		return (v1.Package.PkgPath + "." + v1.Symbol) < (v2.Package.PkgPath + "." + v2.Symbol)
	}
	equal := func(v1, v2 *Vuln) bool {
		if v1.Symbol != v2.Symbol {
			return false
		}
		if v1.Package != nil && v2.Package != nil {
			return v1.Package.PkgPath == v2.Package.PkgPath
		}
		return true // we don't care about these cases here
	}

	if diff := cmp.Diff(want, res.Vulns, cmpopts.SortSlices(less), cmp.Comparer(equal)); diff != "" {
		t.Errorf("(-want, +got): %s", diff)
	}

	// Test the symbols.
	cfg.ScanLevel = "symbol"
	res, err = binary(context.Background(), test.NewMockHandler(), bin, cfg, c)
	if err != nil {
		t.Fatal(err)
	}

	want = []*Vuln{
		{Symbol: "OpenReader", Package: &packages.Package{PkgPath: "archive/zip"}},
		{Symbol: "VulnData.Vuln1", Package: &packages.Package{PkgPath: "golang.org/amod/avuln"}},
	}
	if diff := cmp.Diff(want, res.Vulns, cmpopts.SortSlices(less), cmp.Comparer(equal)); diff != "" {
		t.Errorf("(-want, +got): %s", diff)
	}
}
