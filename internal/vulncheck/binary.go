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
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/internal/vulncheck/internal/buildinfo"
)

// Binary detects presence of vulnerable symbols in exe.
// The Calls, Imports, and Requires fields on Result will be empty.
func Binary(ctx context.Context, exe io.ReaderAt, cfg *Config) (_ *Result, err error) {
	mods, packageSymbols, bi, err := buildinfo.ExtractPackagesAndSymbols(exe)
	if err != nil {
		return nil, fmt.Errorf("could not parse provided binary: %v", err)
	}

	cmods := convertModules(mods)
	// set the stdlib version for detection of vulns in the standard library
	// TODO(https://go.dev/issue/53740): what if Go version is not in semver
	// format?
	stdlibModule.Version = semver.GoTagToSemver(bi.GoVersion)
	// Add "stdlib" module.
	cmods = append(cmods, stdlibModule)

	mv, err := FetchVulnerabilities(ctx, cfg.Client, cmods)
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
		addRequiresOnlyVulns(result, modVulns)
	} else {
		for pkg, symbols := range packageSymbols {
			mod := findPackageModule(pkg, cmods)
			if cfg.ImportsOnly {
				addImportsOnlyVulns(pkg, mod, symbols, result, modVulns)
			} else {
				addSymbolVulns(pkg, mod, symbols, result, modVulns)
			}
		}
	}
	setModules(result, cmods)
	return result, nil
}

// addImportsOnlyVulns adds Vuln entries to result in imports only mode, i.e., for each vulnerable symbol
// of pkg.
func addImportsOnlyVulns(pkg, mod string, symbols []string, result *Result, modVulns moduleVulnerabilities) {
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
					vuln := &Vuln{
						OSV:     osv,
						Symbol:  symbol,
						PkgPath: pkg,
						ModPath: mod,
					}
					result.Vulns = append(result.Vulns, vuln)
				}
			}
		}
	}
}

// addSymbolVulns adds Vuln entries to result for every symbol of pkg in the binary that is vulnerable.
func addSymbolVulns(pkg, mod string, symbols []string, result *Result, modVulns moduleVulnerabilities) {
	for _, symbol := range symbols {
		for _, osv := range modVulns.vulnsForSymbol(pkg, symbol) {
			vuln := &Vuln{
				OSV:     osv,
				Symbol:  symbol,
				PkgPath: pkg,
				ModPath: mod,
			}
			result.Vulns = append(result.Vulns, vuln)
		}
	}
}

func convertModules(mods []*packages.Module) []*Module {
	vmods := make([]*Module, len(mods))
	convertMod := newModuleConverter()
	for i, mod := range mods {
		vmods[i] = convertMod(mod)
	}
	return vmods
}

// findPackageModule returns the path of a module that could contain the import
// path pkg. It uses paths only. It is possible but unlikely for a package path
// to match two or more different module paths. We just take the first one.
// If no module path matches, findPackageModule returns the empty string.
func findPackageModule(pkg string, mods []*Module) string {
	if isStdPackage(pkg) {
		return stdlibModule.Path
	}

	for _, m := range mods {
		if pkg == m.Path || strings.HasPrefix(pkg, m.Path+"/") {
			return m.Path
		}
	}
	return ""
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
func addRequiresOnlyVulns(result *Result, modVulns moduleVulnerabilities) {
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
						vuln := &Vuln{
							OSV:     osv,
							Symbol:  symbol,
							PkgPath: p.Path,
							ModPath: mv.Module.Path,
						}
						result.Vulns = append(result.Vulns, vuln)
					}
				}
			}
		}
	}
}
