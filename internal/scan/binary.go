// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unicode"

	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/vulncheck"
)

// runBinary detects presence of vulnerable symbols in an executable.
func runBinary(ctx context.Context, handler govulncheck.Handler, cfg *config, client *client.Client) error {
	var exe *os.File
	exe, err := os.Open(cfg.patterns[0])
	if err != nil {
		return err
	}
	defer exe.Close()

	p := &govulncheck.Progress{Message: binaryProgressMessage}
	if err := handler.Progress(p); err != nil {
		return err
	}
	vr, err := binary(ctx, exe, &cfg.Config, client)
	if err != nil {
		return fmt.Errorf("govulncheck: %v", err)
	}
	return emitBinaryResult(handler, vr)
}

func emitBinaryResult(handler govulncheck.Handler, vr *vulncheck.Result) error {
	osvs := map[string]*osv.Entry{}

	// Create Result where each vulncheck.Vuln{OSV, ModPath, PkgPath} becomes
	// a separate Vuln{OSV, Modules{Packages{PkgPath}}} entry. We merge the
	// results later.
	var findings []*govulncheck.Finding
	for _, vv := range uniqueVulns(vr.Vulns) {
		p := &govulncheck.Package{Path: vv.ImportSink.PkgPath}
		// in binary mode, there is 1 call stack containing the vulnerable
		// symbol.
		f := &govulncheck.StackFrame{
			Function: vv.Symbol,
			Package:  vv.ImportSink.PkgPath,
		}
		parts := strings.Split(vv.Symbol, ".")
		if len(parts) != 1 {
			f.Function = parts[0]
			f.Receiver = parts[1]
		}
		p.CallStacks = []govulncheck.CallStack{
			{Frames: []*govulncheck.StackFrame{f}},
		}
		m := &govulncheck.Module{
			Path:         vv.ImportSink.Module.Path,
			FoundVersion: foundVersion(vv),
			FixedVersion: fixedVersion(vv.ImportSink.Module.Path, vv.OSV.Affected),
			Packages:     []*govulncheck.Package{p},
		}

		v := &govulncheck.Finding{OSV: vv.OSV.ID, Modules: []*govulncheck.Module{m}}
		findings = append(findings, v)
		osvs[vv.OSV.ID] = vv.OSV
	}

	findings = merge(findings)
	sortResult(findings)
	// For each vulnerability, queue it to be written to the output.
	for _, f := range findings {
		if err := handler.OSV(osvs[f.OSV]); err != nil {
			return err
		}
		if err := handler.Finding(f); err != nil {
			return err
		}
	}
	return nil
}

// uniqueVulns does for binary mode what uniqueCallStack does for source mode.
// It tries not to report redundant symbols. Since there are no call stacks in
// binary mode, the following approximate approach is used. Do not report unexported
// symbols for a <vulnID, pkg, module> triple if there are some exported symbols.
// Otherwise, report all unexported symbols to avoid not reporting anything.
func uniqueVulns(vulns []*vulncheck.Vuln) []*vulncheck.Vuln {
	type key struct {
		id  string
		pkg string
		mod string
	}
	hasExported := make(map[key]bool)
	for _, v := range vulns {
		if isExported(v.Symbol) {
			k := key{id: v.OSV.ID, pkg: v.ImportSink.PkgPath, mod: v.ImportSink.Module.Path}
			hasExported[k] = true
		}
	}

	var uniques []*vulncheck.Vuln
	for _, v := range vulns {
		k := key{id: v.OSV.ID, pkg: v.ImportSink.PkgPath, mod: v.ImportSink.Module.Path}
		if isExported(v.Symbol) || !hasExported[k] {
			uniques = append(uniques, v)
		}
	}
	return uniques
}

// isExported checks if the symbol is exported. Assumes that the
// symbol is of the form "identifier" or "identifier1.identifier2".
func isExported(symbol string) bool {
	parts := strings.Split(symbol, ".")
	if len(parts) == 1 {
		return unicode.IsUpper(rune(symbol[0]))
	}
	return unicode.IsUpper(rune(parts[1][0]))
}
