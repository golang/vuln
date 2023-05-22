// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package vulncheck

import (
	"context"
	"fmt"
	"io"
	"runtime/debug"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/vulncheck/internal/buildinfo"
)

// Binary detects presence of vulnerable symbols in exe.
// The Calls, Imports, and Requires fields on Result will be empty.
func Binary(ctx context.Context, exe io.ReaderAt, cfg *govulncheck.Config, client *client.Client) (_ *Result, err error) {
	mods, packageSymbols, bi, err := buildinfo.ExtractPackagesAndSymbols(exe)
	if err != nil {
		return nil, fmt.Errorf("could not parse provided binary: %v", err)
	}

	graph := NewPackageGraph(bi.GoVersion)
	graph.AddModules(mods...)
	mods = append(mods, graph.GetModule(internal.GoStdModulePath))

	mv, err := FetchVulnerabilities(ctx, client, mods)
	if err != nil {
		return nil, err
	}
	modVulns := moduleVulnerabilities(mv)

	goos := findSetting("GOOS", bi)
	goarch := findSetting("GOARCH", bi)
	if goos == "" || goarch == "" {
		fmt.Printf("warning: failed to extract build system specification GOOS: %s GOARCH: %s\n", goos, goarch)
	}

	modVulns = modVulns.filter(goos, goarch)
	result := &Result{}

	if packageSymbols == nil {
		// The binary exe is stripped. We currently cannot detect inlined
		// symbols for stripped binaries (see #57764), so we report
		// vulnerabilities at the go.mod-level precision.
		addRequiresOnlyVulns(result, graph, modVulns)
	} else {
		for pkg, symbols := range packageSymbols {
			if !cfg.ScanLevel.WantSymbols() {
				addImportsOnlyVulns(result, graph, pkg, symbols, modVulns)
			} else {
				addSymbolVulns(result, graph, pkg, symbols, modVulns)
			}
		}
	}
	return result, nil
}

// addImportsOnlyVulns adds Vuln entries to result in imports only mode, i.e., for each vulnerable symbol
// of pkg.
func addImportsOnlyVulns(result *Result, graph *PackageGraph, pkg string, symbols []string, modVulns moduleVulnerabilities) {
	for _, osv := range modVulns.vulnsForPackage(pkg) {
		for _, affected := range osv.Affected {
			for _, p := range affected.EcosystemSpecific.Packages {
				if p.Path != pkg {
					continue
				}
				syms := p.Symbols
				if len(syms) == 0 {
					// If every symbol of pkg is vulnerable, we would ideally
					// compute every symbol mentioned in the pkg and then add
					// Vuln entry for it, just as we do in Source. However,
					// we don't have code of pkg here so we have to do best
					// we can, which is the symbols of pkg actually appearing
					// in the binary.
					syms = symbols
				}

				for _, symbol := range syms {
					addVuln(result, graph, osv, symbol, pkg)
				}
			}
		}
	}
}

// addSymbolVulns adds Vuln entries to result for every symbol of pkg in the binary that is vulnerable.
func addSymbolVulns(result *Result, graph *PackageGraph, pkg string, symbols []string, modVulns moduleVulnerabilities) {
	for _, symbol := range symbols {
		for _, osv := range modVulns.vulnsForSymbol(pkg, symbol) {
			addVuln(result, graph, osv, symbol, pkg)
		}
	}
}

// findSetting returns value of setting from bi if present.
// Otherwise, returns "".
func findSetting(setting string, bi *debug.BuildInfo) string {
	for _, s := range bi.Settings {
		if s.Key == setting {
			return s.Value
		}
	}
	return ""
}

// addRequiresOnlyVulns adds to result all vulnerabilities in modVulns.
// Used when the binary under analysis is stripped.
func addRequiresOnlyVulns(result *Result, graph *PackageGraph, modVulns moduleVulnerabilities) {
	for _, mv := range modVulns {
		for _, osv := range mv.Vulns {
			for _, affected := range osv.Affected {
				for _, p := range affected.EcosystemSpecific.Packages {
					syms := p.Symbols
					if len(syms) == 0 {
						// If every symbol of pkg is vulnerable, we would ideally
						// compute every symbol mentioned in the pkg and then add
						// Vuln entry for it, just as we do in Source. However,
						// we don't have code of pkg here and we don't even have
						// pkg symbols used in stripped binary, so we add a placeholder
						// symbol.
						//
						// Note: this should not affect output of govulncheck since
						// in binary mode no symbol/call stack information is
						// communicated back to the user.
						syms = []string{fmt.Sprintf("%s/*", p.Path)}
					}

					for _, symbol := range syms {
						addVuln(result, graph, osv, symbol, p.Path)
					}
				}
			}
		}
	}
}

func addVuln(result *Result, graph *PackageGraph, osv *osv.Entry, symbol string, pkgPath string) {
	result.Vulns = append(result.Vulns, &Vuln{
		OSV:        osv,
		Symbol:     symbol,
		ImportSink: graph.GetPackage(pkgPath),
	})
}
