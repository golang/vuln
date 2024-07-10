// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/buildinfo"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/semver"
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
	if cfg.ScanLevel.WantSymbols() {
		return emitCallFindings(handler, binaryCallstacks(vr))
	}
	return nil
}

// binary detects presence of vulnerable symbols in bin.
// It does not compute call graphs so the corresponding
// info in Result will be empty.
func binary(ctx context.Context, handler govulncheck.Handler, bin *Bin, cfg *govulncheck.Config, client *client.Client) (*Result, error) {
	graph := NewPackageGraph(bin.GoVersion)
	graph.AddModules(bin.Modules...)
	mods := append(bin.Modules, graph.GetModule(internal.GoStdModulePath))

	if err := handler.Progress(&govulncheck.Progress{Message: fetchingVulnsMessage}); err != nil {
		return nil, err
	}

	mv, err := FetchVulnerabilities(ctx, client, mods)
	if err != nil {
		return nil, err
	}

	// Emit OSV entries immediately in their raw unfiltered form.
	if err := emitOSVs(handler, mv); err != nil {
		return nil, err
	}

	if err := handler.Progress(&govulncheck.Progress{Message: checkingBinVulnsMessage}); err != nil {
		return nil, err
	}

	// Emit warning message for ancient Go binaries, defined as binaries
	// built with Go version without support for debug.BuildInfo (< go1.18).
	if semver.Less(bin.GoVersion, "go1.18") {
		p := &govulncheck.Progress{Message: fmt.Sprintf("warning: binary built with Go version %s, only standard library vulnerabilities will be checked", bin.GoVersion)}
		if err := handler.Progress(p); err != nil {
			return nil, err
		}
	}

	if bin.GOOS == "" || bin.GOARCH == "" {
		p := &govulncheck.Progress{Message: fmt.Sprintf("warning: failed to extract build system specification GOOS: %s GOARCH: %s\n", bin.GOOS, bin.GOARCH)}
		if err := handler.Progress(p); err != nil {
			return nil, err
		}
	}
	affVulns := affectingVulnerabilities(mv, bin.GOOS, bin.GOARCH)
	if err := emitModuleFindings(handler, affVulns); err != nil {
		return nil, err
	}

	if !cfg.ScanLevel.WantPackages() || len(affVulns) == 0 {
		return &Result{}, nil
	}

	// Group symbols per package to avoid querying affVulns all over again.
	var pkgSymbols map[string][]string
	if len(bin.PkgSymbols) == 0 {
		// The binary exe is stripped. We currently cannot detect inlined
		// symbols for stripped binaries (see #57764), so we report
		// vulnerabilities at the go.mod-level precision.
		pkgSymbols = allKnownVulnerableSymbols(affVulns)
	} else {
		pkgSymbols = make(map[string][]string)
		for _, sym := range bin.PkgSymbols {
			pkgSymbols[sym.Pkg] = append(pkgSymbols[sym.Pkg], sym.Name)
		}
	}

	impVulns := binImportedVulnPackages(graph, pkgSymbols, affVulns)
	// Emit information on imported vulnerable packages now to
	// mimic behavior of source.
	if err := emitPackageFindings(handler, impVulns); err != nil {
		return nil, err
	}

	// Return result immediately if not in symbol mode to mimic the
	// behavior of source.
	if !cfg.ScanLevel.WantSymbols() || len(impVulns) == 0 {
		return &Result{Vulns: impVulns}, nil
	}

	symVulns := binVulnSymbols(graph, pkgSymbols, affVulns)
	return &Result{Vulns: symVulns}, nil
}

func binImportedVulnPackages(graph *PackageGraph, pkgSymbols map[string][]string, affVulns affectingVulns) []*Vuln {
	var vulns []*Vuln
	for pkg := range pkgSymbols {
		for _, osv := range affVulns.ForPackage(internal.UnknownModulePath, pkg) {
			vuln := &Vuln{
				OSV:     osv,
				Package: graph.GetPackage(pkg),
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

func binVulnSymbols(graph *PackageGraph, pkgSymbols map[string][]string, affVulns affectingVulns) []*Vuln {
	var vulns []*Vuln
	for pkg, symbols := range pkgSymbols {
		for _, symbol := range symbols {
			for _, osv := range affVulns.ForSymbol(internal.UnknownModulePath, pkg, symbol) {
				vuln := &Vuln{
					OSV:     osv,
					Symbol:  symbol,
					Package: graph.GetPackage(pkg),
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns
}

// allKnownVulnerableSymbols returns all known vulnerable symbols for packages in graph.
// If all symbols of a package are vulnerable, that is modeled as a wild car symbol "<pkg-path>/*".
func allKnownVulnerableSymbols(affVulns affectingVulns) map[string][]string {
	pkgSymbols := make(map[string][]string)
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

					pkgSymbols[p.Path] = append(pkgSymbols[p.Path], syms...)
				}
			}
		}
	}
	return pkgSymbols
}
