// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package vulncheck

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/buildinfo"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

// Bin is an abstraction of Go binary containing
// minimal information needed by govulncheck.
type Bin struct {
	Modules    []*packages.Module `json:"modules,omitempty"`
	PkgSymbols []buildinfo.Symbol `json:"pkgSymbols,omitempty"`
	GoVersion  string             `json:"goVersion,omitempty"`
	GOOS       string             `json:"goos,omitempty"`
	GOARCH     string             `json:"goarch,omitempty"`
}

// Binary detects presence of vulnerable symbols in bin and
// emits findings to handler.
func Binary(ctx context.Context, handler govulncheck.Handler, bin *Bin, cfg *govulncheck.Config, client *client.Client) error {
	vr, err := binary(ctx, handler, bin, cfg, client)
	if err != nil {
		return err
	}
	return emitBinaryResult(handler, vr, binaryCallstacks(vr))
}

// binary detects presence of vulnerable symbols in bin.
// It does not compute call graphs so the corresponding
// info in Result will be empty.
func binary(ctx context.Context, handler govulncheck.Handler, bin *Bin, cfg *govulncheck.Config, client *client.Client) (*Result, error) {
	graph := NewPackageGraph(bin.GoVersion)
	graph.AddModules(bin.Modules...)
	mods := append(bin.Modules, graph.GetModule(internal.GoStdModulePath))

	mv, err := FetchVulnerabilities(ctx, client, mods)
	if err != nil {
		return nil, err
	}

	// Emit OSV entries immediately in their raw unfiltered form.
	if err := emitOSVs(handler, mv); err != nil {
		return nil, err
	}

	if bin.GOOS == "" || bin.GOARCH == "" {
		fmt.Printf("warning: failed to extract build system specification GOOS: %s GOARCH: %s\n", bin.GOOS, bin.GOARCH)
	}
	affVulns := affectingVulnerabilities(mv, bin.GOOS, bin.GOARCH)

	result := &Result{}
	if len(bin.PkgSymbols) == 0 {
		// The binary exe is stripped. We currently cannot detect inlined
		// symbols for stripped binaries (see #57764), so we report
		// vulnerabilities at the go.mod-level precision.
		addRequiresOnlyVulns(result, graph, affVulns)
	} else {
		// Group symbols per package to avoid querying vulns all over again.
		pkgSymbols := make(map[string][]string)
		for _, sym := range bin.PkgSymbols {
			pkgSymbols[sym.Pkg] = append(pkgSymbols[sym.Pkg], sym.Name)
		}

		for pkg, symbols := range pkgSymbols {
			// sort symbols for deterministic results
			sort.SliceStable(symbols, func(i, j int) bool { return symbols[i] < symbols[j] })
			if !cfg.ScanLevel.WantSymbols() {
				addImportsOnlyVulns(result, graph, pkg, symbols, affVulns)
			} else {
				addSymbolVulns(result, graph, pkg, symbols, affVulns)
			}
		}
	}
	return result, nil
}

// addImportsOnlyVulns adds Vuln entries to result in imports only mode, i.e., for each vulnerable symbol
// of pkg.
func addImportsOnlyVulns(result *Result, graph *PackageGraph, pkg string, symbols []string, affVulns affectingVulns) {
	for _, osv := range affVulns.ForPackage(pkg) {
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
func addSymbolVulns(result *Result, graph *PackageGraph, pkg string, symbols []string, affVulns affectingVulns) {
	for _, symbol := range symbols {
		for _, osv := range affVulns.ForSymbol(pkg, symbol) {
			addVuln(result, graph, osv, symbol, pkg)
		}
	}
}

// addRequiresOnlyVulns adds to result all vulnerabilities in affVulns.
// Used when the binary under analysis is stripped.
func addRequiresOnlyVulns(result *Result, graph *PackageGraph, affVulns affectingVulns) {
	for _, mv := range affVulns {
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
		OSV:     osv,
		Symbol:  symbol,
		Package: graph.GetPackage(pkgPath),
	})
}
