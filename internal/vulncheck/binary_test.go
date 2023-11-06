// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package vulncheck

import (
	"context"
	"sort"
	"testing"

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

	// With package scan level, all test vulnerable symbols should be detected.
	wantVulns := []*testVuln{
		{Symbol: "Vuln", PkgPath: "golang.org/bmod/bvuln", ModPath: "golang.org/bmod"},
		{Symbol: "VulnData.Vuln1", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
		{Symbol: "VulnData.Vuln2", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
		{Symbol: "OpenReader", PkgPath: "archive/zip", ModPath: "stdlib"},
	}

	compareVulns(t, wantVulns, res)

	// Test the symbols.
	cfg.ScanLevel = "symbol"
	res, err = binary(context.Background(), test.NewMockHandler(), bin, cfg, c)
	if err != nil {
		t.Fatal(err)
	}

	wantVulns = []*testVuln{
		{Symbol: "VulnData.Vuln1", PkgPath: "golang.org/amod/avuln", ModPath: "golang.org/amod"},
		{Symbol: "OpenReader", PkgPath: "archive/zip", ModPath: "stdlib"},
	}

	compareVulns(t, wantVulns, res)
}

type testVuln struct {
	Symbol  string
	PkgPath string
	ModPath string
}

func compareVulns(t *testing.T, want []*testVuln, res *Result) {
	if len(want) != len(res.Vulns) {
		t.Error("want", len(want), "vulnerabilities, got", len(res.Vulns))
		return
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Symbol < want[j].Symbol })
	sort.Slice(res.Vulns, func(i, j int) bool { return res.Vulns[i].Symbol < res.Vulns[j].Symbol })
	for i, want := range want {
		got := res.Vulns[i]
		if want.Symbol != got.Symbol {
			t.Error("[", i, "] want", want.Symbol, ", got", got.Symbol)
		}
		if want.PkgPath != got.Package.PkgPath {
			t.Error("[", i, "] want", want.ModPath, ", got", got.Package.Module.Path)
		}
		if want.ModPath != got.Package.Module.Path {
			t.Error("[", i, "] want", want.ModPath, ", got", got.Package.Module.Path)
		}
	}
}
