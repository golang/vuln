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
	vr, err := vulncheck.Binary(ctx, exe, &cfg.Config, client)
	if err != nil {
		return fmt.Errorf("govulncheck: %v", err)
	}
	callstacks := binaryCallstacks(vr)
	return emitBinaryResult(handler, vr, callstacks)
}

func emitBinaryResult(handler govulncheck.Handler, vr *vulncheck.Result, callstacks map[*vulncheck.Vuln]vulncheck.CallStack) error {
	osvs := map[string]*osv.Entry{}
	// first deal with all the affected vulnerabilities
	emitted := map[string]bool{}
	seen := map[string]bool{}
	emitFinding := func(finding *govulncheck.Finding) error {
		if !seen[finding.OSV] {
			seen[finding.OSV] = true
			if err := handler.OSV(osvs[finding.OSV]); err != nil {
				return err
			}
		}
		return handler.Finding(finding)
	}

	for _, vv := range vr.Vulns {
		osvs[vv.OSV.ID] = vv.OSV
		fixed := vulncheck.FixedVersion(vulncheck.ModPath(vv.ImportSink.Module), vulncheck.ModVersion(vv.ImportSink.Module), vv.OSV.Affected)
		stack := callstacks[vv]
		if stack == nil {
			continue
		}
		emitted[vv.OSV.ID] = true
		emitFinding(&govulncheck.Finding{
			OSV:          vv.OSV.ID,
			FixedVersion: fixed,
			Trace:        tracefromEntries(stack),
		})
	}
	for _, vv := range vr.Vulns {
		if emitted[vv.OSV.ID] {
			continue
		}
		stacks := callstacks[vv]
		if len(stacks) != 0 {
			continue
		}
		emitted[vv.OSV.ID] = true
		emitFinding(&govulncheck.Finding{
			OSV:          vv.OSV.ID,
			FixedVersion: vulncheck.FixedVersion(vulncheck.ModPath(vv.ImportSink.Module), vulncheck.ModVersion(vv.ImportSink.Module), vv.OSV.Affected),
			Trace:        []*govulncheck.Frame{frameFromPackage(vv.ImportSink)},
		})
	}
	return nil
}

func binaryCallstacks(vr *vulncheck.Result) map[*vulncheck.Vuln]vulncheck.CallStack {
	callstacks := map[*vulncheck.Vuln]vulncheck.CallStack{}
	for _, vv := range uniqueVulns(vr.Vulns) {
		f := &vulncheck.FuncNode{Package: vv.ImportSink, Name: vv.Symbol}
		parts := strings.Split(vv.Symbol, ".")
		if len(parts) != 1 {
			f.RecvType = parts[0]
			f.Name = parts[1]
		}
		callstacks[vv] = vulncheck.CallStack{vulncheck.StackEntry{Function: f}}
	}
	return callstacks
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
