// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"fmt"
	"go/token"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/semver"
)

// Result contains information on how known vulnerabilities are reachable
// in the call graph, package imports graph, and module requires graph of
// the user code.
type Result struct {
	// EntryFunctions are a subset of Functions representing vulncheck entry points.
	EntryFunctions []*FuncNode

	// EntryPackages are a subset of Packages representing packages of vulncheck entry points.
	EntryPackages []*packages.Package

	// Vulns contains information on detected vulnerabilities and their place in
	// the above graphs. Only vulnerabilities whose symbols are reachable in Calls,
	// or whose packages are imported in Imports, or whose modules are required in
	// Requires, have an entry in Vulns.
	Vulns []*Vuln
}

// Vuln provides information on how a vulnerability is affecting user code by
// connecting it to the Result.{Calls,Imports,Requires} graphs. Vulnerabilities
// detected in Go binaries do not appear in the Result graphs.
type Vuln struct {
	// OSV contains information on the detected vulnerability in the shared
	// vulnerability format.
	//
	// OSV, Symbol, PkgPath, and ModPath identify a vulnerability.
	//
	// Note that *osv.Entry may describe multiple symbols from multiple
	// packages.
	OSV *osv.Entry

	// Symbol is the name of the detected vulnerable function or method.
	Symbol string

	// CallSink is the FuncNode in Result.Calls corresponding to Symbol.
	//
	// When analyzing binaries, Symbol is not reachable, or cfg.ScanLevel
	// is symbol, CallSink will be unavailable and set to 0.
	CallSink *FuncNode

	// ImportSink is the PkgNode in Result.Imports corresponding to PkgPath.
	//
	// When analyzing binaries or PkgPath is not imported, ImportSink will be
	// unavailable and set to 0.
	ImportSink *packages.Package
}

// A FuncNode describes a function in the call graph.
type FuncNode struct {
	// Name is the name of the function.
	Name string

	// RecvType is the receiver object type of this function, if any.
	RecvType string

	// Package is the package the function is part of.
	Package *packages.Package

	// Position describes the position of the function in the file.
	Pos *token.Position

	// CallSites is a set of call sites where this function is called.
	CallSites []*CallSite
}

func (fn *FuncNode) String() string {
	if fn.RecvType == "" {
		return fmt.Sprintf("%s.%s", fn.Package.PkgPath, fn.Name)
	}
	return fmt.Sprintf("%s.%s", fn.RecvType, fn.Name)
}

// Receiver returns the FuncNode's receiver, with package path removed.
// Pointers are preserved if present.
func (fn *FuncNode) Receiver() string {
	return strings.Replace(fn.RecvType, fmt.Sprintf("%s.", fn.Package.PkgPath), "", 1)
}

// A CallSite describes a function call.
type CallSite struct {
	// Parent is the enclosing function where the call is made.
	Parent *FuncNode

	// Name stands for the name of the function (variable) being called.
	Name string

	// RecvType is the full path of the receiver object type, if any.
	RecvType string

	// Position describes the position of the function in the file.
	Pos *token.Position

	// Resolved indicates if the called function can be statically resolved.
	Resolved bool
}

// moduleVulnerabilities is an internal structure for
// holding and querying vulnerabilities provided by a
// vulnerability database client.
type moduleVulnerabilities []*ModVulns

// ModVulns groups vulnerabilities per module.
type ModVulns struct {
	Module *packages.Module
	Vulns  []*osv.Entry
}

func (mv moduleVulnerabilities) filter(os, arch string) moduleVulnerabilities {
	now := time.Now()
	var filteredMod moduleVulnerabilities
	for _, mod := range mv {
		module := mod.Module
		modVersion := module.Version
		if module.Replace != nil {
			modVersion = module.Replace.Version
		}
		// TODO(https://golang.org/issues/49264): if modVersion == "", try vcs?
		var filteredVulns []*osv.Entry
		for _, v := range mod.Vulns {
			// Ignore vulnerabilities that have been withdrawn
			if v.Withdrawn != nil && v.Withdrawn.Before(now) {
				continue
			}

			var filteredAffected []osv.Affected
			for _, a := range v.Affected {
				// Vulnerabilities from some databases might contain
				// information on related but different modules that
				// were, say, reported in the same CVE. We filter such
				// information out as it might lead to incorrect results:
				// Computing a latest fix could consider versions of these
				// different packages.
				if a.Module.Path != module.Path {
					continue
				}

				// A module version is affected if
				//  - it is included in one of the affected version ranges
				//  - and module version is not ""
				if modVersion == "" {
					// Module version of "" means the module version is not available,
					// and so we don't want to spam users with potential false alarms.
					continue
				}
				if !semver.Affects(a.Ranges, modVersion) {
					continue
				}
				var filteredImports []osv.Package
				for _, p := range a.EcosystemSpecific.Packages {
					if matchesPlatform(os, arch, p) {
						filteredImports = append(filteredImports, p)
					}
				}
				if len(a.EcosystemSpecific.Packages) != 0 && len(filteredImports) == 0 {
					continue
				}
				a.EcosystemSpecific.Packages = filteredImports
				filteredAffected = append(filteredAffected, a)
			}
			if len(filteredAffected) == 0 {
				continue
			}
			// save the non-empty vulnerability with only
			// affected symbols.
			newV := *v
			newV.Affected = filteredAffected
			filteredVulns = append(filteredVulns, &newV)
		}
		filteredMod = append(filteredMod, &ModVulns{
			Module: module,
			Vulns:  filteredVulns,
		})
	}
	return filteredMod
}

func matchesPlatform(os, arch string, e osv.Package) bool {
	return matchesPlatformComponent(os, e.GOOS) &&
		matchesPlatformComponent(arch, e.GOARCH)
}

// matchesPlatformComponent reports whether a GOOS (or GOARCH)
// matches a list of GOOS (or GOARCH) values from an osv.EcosystemSpecificImport.
func matchesPlatformComponent(s string, ps []string) bool {
	// An empty input or an empty GOOS or GOARCH list means "matches everything."
	if s == "" || len(ps) == 0 {
		return true
	}
	for _, p := range ps {
		if s == p {
			return true
		}
	}
	return false
}

// vulnsForPackage returns the vulnerabilities for the module which is the most
// specific prefix of importPath, or nil if there is no matching module with
// vulnerabilities.
func (mv moduleVulnerabilities) vulnsForPackage(importPath string) []*osv.Entry {
	isStd := isStdPackage(importPath)
	var mostSpecificMod *ModVulns
	for _, mod := range mv {
		md := mod
		if isStd && mod.Module.Path == internal.GoStdModulePath {
			// standard library packages do not have an associated module,
			// so we relate them to the artificial stdlib module.
			mostSpecificMod = md
		} else if strings.HasPrefix(importPath, md.Module.Path) {
			if mostSpecificMod == nil || len(mostSpecificMod.Module.Path) < len(md.Module.Path) {
				mostSpecificMod = md
			}
		}
	}
	if mostSpecificMod == nil {
		return nil
	}

	if mostSpecificMod.Module.Replace != nil {
		// standard libraries do not have a module nor replace module
		importPath = fmt.Sprintf("%s%s", mostSpecificMod.Module.Replace.Path, strings.TrimPrefix(importPath, mostSpecificMod.Module.Path))
	}
	vulns := mostSpecificMod.Vulns
	packageVulns := []*osv.Entry{}
Vuln:
	for _, v := range vulns {
		for _, a := range v.Affected {
			for _, p := range a.EcosystemSpecific.Packages {
				if p.Path == importPath {
					packageVulns = append(packageVulns, v)
					continue Vuln
				}
			}
		}
	}
	return packageVulns
}

// vulnsForSymbol returns vulnerabilities for `symbol` in `mv.VulnsForPackage(importPath)`.
func (mv moduleVulnerabilities) vulnsForSymbol(importPath, symbol string) []*osv.Entry {
	vulns := mv.vulnsForPackage(importPath)
	if vulns == nil {
		return nil
	}

	symbolVulns := []*osv.Entry{}
vulnLoop:
	for _, v := range vulns {
		for _, a := range v.Affected {
			for _, p := range a.EcosystemSpecific.Packages {
				if p.Path != importPath {
					continue
				}
				if len(p.Symbols) > 0 && !contains(p.Symbols, symbol) {
					continue
				}
				symbolVulns = append(symbolVulns, v)
				continue vulnLoop
			}
		}
	}
	return symbolVulns
}

func contains(symbols []string, target string) bool {
	for _, s := range symbols {
		if s == target {
			return true
		}
	}
	return false
}

func isStdPackage(pkg string) bool {
	if pkg == "" {
		return false
	}
	// std packages do not have a "." in their path. For instance, see
	// Contains in pkgsite/+/refs/heads/master/internal/stdlbib/stdlib.go.
	if i := strings.IndexByte(pkg, '/'); i != -1 {
		pkg = pkg[:i]
	}
	return !strings.Contains(pkg, ".")
}
