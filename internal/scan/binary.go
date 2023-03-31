// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package scan

import (
	"context"
	"os"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/vulncheck"
)

// runBinary detects presence of vulnerable symbols in an executable.
func runBinary(ctx context.Context, output govulncheck.Handler, cfg *config) (*govulncheck.Result, error) {
	var exe *os.File
	exe, err := os.Open(cfg.patterns[0])
	if err != nil {
		return nil, err
	}
	defer exe.Close()

	p := &govulncheck.Progress{Message: binaryProgressMessage}
	if err := output.Progress(p); err != nil {
		return nil, err
	}
	vr, err := binary(ctx, exe, &cfg.Config)
	if err != nil {
		return nil, err
	}
	return createBinaryResult(vr), nil
}

func createBinaryResult(vr *vulncheck.Result) *govulncheck.Result {
	modVersions := moduleVersionMap(vr.Modules)
	// Create Result where each vulncheck.Vuln{OSV, ModPath, PkgPath} becomes
	// a separate Vuln{OSV, Modules{Packages{PkgPath}}} entry. We merge the
	// results later.
	r := &govulncheck.Result{}
	for _, vv := range vr.Vulns {
		p := &govulncheck.Package{Path: vv.PkgPath}
		// in binary mode, call stacks contain just the symbol data
		p.CallStacks = []govulncheck.CallStack{{Symbol: vv.Symbol}}
		m := &govulncheck.Module{
			Path:         vv.ModPath,
			FoundVersion: foundVersion(vv.ModPath, modVersions),
			FixedVersion: fixedVersion(vv.ModPath, vv.OSV.Affected),
			Packages:     []*govulncheck.Package{p},
		}
		v := &govulncheck.Vuln{OSV: vv.OSV, Modules: []*govulncheck.Module{m}}
		r.Vulns = append(r.Vulns, v)
	}

	r = merge(r)
	sortResult(r)
	return r
}
