// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

// Config is used for configuring vulncheck algorithms.
type Config struct {
	// ImportsOnly instructs vulncheck to analyze import chains only.
	// Otherwise, call chains are analyzed too.
	ImportsOnly bool

	// Client is used for querying data from a vulnerability database.
	Client client.Client

	// SourceGoVersion is Go version used to build Source inputs passed
	// to vulncheck. If not provided, the current Go version at PATH
	// is used to detect vulnerabilities in Go standard library.
	SourceGoVersion string

	// Consider only vulnerabilities that apply to this OS and architecture.
	// An empty string means "all" (don't filter).
	// Applies only to Source.
	GOOS, GOARCH string
}

// Package is a Go package for vulncheck analysis. It is a version of
// packages.Package trimmed down to reduce memory consumption.
type Package struct {
	Name      string
	PkgPath   string
	Imports   []*Package
	Pkg       *types.Package
	Fset      *token.FileSet
	Syntax    []*ast.File
	TypesInfo *types.Info
	Module    *Module
}

// Module is a Go module for vulncheck analysis.
type Module struct {
	Path    string
	Version string
	Dir     string
	Replace *Module
}

// Convert transforms a slice of packages.Package to
// a slice of corresponding vulncheck.Package.
func Convert(pkgs []*packages.Package) []*Package {
	convertMod := newModuleConverter()
	ps := make(map[*packages.Package]*Package)
	var pkg func(*packages.Package) *Package
	pkg = func(p *packages.Package) *Package {
		if vp, ok := ps[p]; ok {
			return vp
		}

		vp := &Package{
			Name:      p.Name,
			PkgPath:   p.PkgPath,
			Pkg:       p.Types,
			Fset:      p.Fset,
			Syntax:    p.Syntax,
			TypesInfo: p.TypesInfo,
			Module:    convertMod(p.Module),
		}
		ps[p] = vp

		for _, i := range p.Imports {
			vp.Imports = append(vp.Imports, pkg(i))
		}
		return vp
	}

	var vpkgs []*Package
	for _, p := range pkgs {
		vpkgs = append(vpkgs, pkg(p))
	}
	return vpkgs
}

// Result contains information on how known vulnerabilities are reachable
// in the call graph, package imports graph, and module requires graph of
// the user code.
type Result struct {
	// Calls is a call graph whose roots are program entry functions and
	// methods, and sinks are known vulnerable symbols. It is empty when
	// Config.ImportsOnly is true or when no vulnerable symbols are reachable
	// via the program call graph.
	Calls *CallGraph

	// Imports is a package dependency graph whose roots are entry user packages
	// and sinks are packages with some known vulnerable symbols. It is empty
	// when no packages with vulnerabilities are imported in the program.
	Imports *ImportGraph

	// Requires is a module dependency graph whose roots are entry user modules
	// and sinks are modules with some vulnerable packages. It is empty when no
	// modules with vulnerabilities are required by the program. If used, the
	// standard library is modeled as an artificial "stdlib" module whose version
	// is the Go version used to build the code under analysis.
	Requires *RequireGraph

	// Vulns contains information on detected vulnerabilities and their place in
	// the above graphs. Only vulnerabilities whose symbols are reachable in Calls,
	// or whose packages are imported in Imports, or whose modules are required in
	// Requires, have an entry in Vulns.
	Vulns []*Vuln

	// Modules are the modules that comprise the user code.
	Modules []*Module
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

	// PkgPath is the package path of the detected Symbol.
	PkgPath string

	// ModPath is the module path corresponding to PkgPath.
	ModPath string

	// CallSink is the ID of the FuncNode in Result.Calls corresponding to
	// Symbol.
	//
	// When analyzing binaries, Symbol is not reachable, or Config.ImportsOnly
	// is true, CallSink will be unavailable and set to 0.
	CallSink int

	// ImportSink is the ID of the PkgNode in Result.Imports corresponding to
	// PkgPath.
	//
	// When analyzing binaries or PkgPath is not imported, ImportSink will be
	// unavailable and set to 0.
	ImportSink int

	// RequireSink is the ID of the ModNode in Result.Requires corresponding to
	// ModPath.
	//
	// When analyzing binaries, RequireSink will be unavailable and set to 0.
	RequireSink int
}

// CallGraph is a slice of a full program call graph whose sinks are vulnerable
// functions and sources are entry points of user packages.
//
// CallGraph is directed from vulnerable functions towards program entry
// functions (see FuncNode) for a more efficient traversal of the slice
// related to a particular vulnerability.
type CallGraph struct {
	// Functions contains all call graph nodes as a map: FuncNode.ID -> FuncNode.
	Functions map[int]*FuncNode

	// Entries are IDs of a subset of Functions representing vulncheck entry points.
	Entries []int
}

// A FuncNode describes a function in the call graph.
type FuncNode struct {
	// ID is the id used to identify the FuncNode in CallGraph.
	ID int

	// Name is the name of the function.
	Name string

	// RecvType is the receiver object type of this function, if any.
	RecvType string

	// PkgPath is the import path of the package containing the function.
	PkgPath string

	// Position describes the position of the function in the file.
	Pos *token.Position

	// CallSites is a set of call sites where this function is called.
	CallSites []*CallSite
}

func (fn *FuncNode) String() string {
	if fn.RecvType == "" {
		return fmt.Sprintf("%s.%s", fn.PkgPath, fn.Name)
	}
	return fmt.Sprintf("%s.%s", fn.RecvType, fn.Name)
}

// A CallSite describes a function call.
type CallSite struct {
	// Parent is ID of the enclosing function where the call is made.
	Parent int

	// Name stands for the name of the function (variable) being called.
	Name string

	// RecvType is the full path of the receiver object type, if any.
	RecvType string

	// Position describes the position of the function in the file.
	Pos *token.Position

	// Resolved indicates if the called function can be statically resolved.
	Resolved bool
}

// RequireGraph is a slice of a full program module requires graph whose sinks
// are modules with known vulnerabilities and sources are modules of user entry
// packages.
//
// RequireGraph is directed from a vulnerable module towards the program entry
// modules (see ModNode) for a more efficient traversal of the slice related
// to a particular vulnerability.
type RequireGraph struct {
	// Modules contains all module nodes as a map: module node id -> module node.
	Modules map[int]*ModNode

	// Entries are IDs of a subset of Modules representing modules of vulncheck entry points.
	Entries []int
}

// A ModNode describes a module in the requires graph.
type ModNode struct {
	// ID is the id used to identify the ModNode in CallGraph.
	ID int

	// Path is the module path.
	Path string

	// Version is the module version.
	Version string

	// Replace is the ID of the replacement module node.
	// A zero value means there is no replacement.
	Replace int

	// RequiredBy contains IDs of the modules requiring this module.
	RequiredBy []int
}

// ImportGraph is a slice of a full program package import graph whose sinks are
// packages with some known vulnerabilities and sources are user specified
// packages.
//
// ImportGraph is directed from a vulnerable package towards the program entry
// packages (see PkgNode) for a more efficient traversal of the slice related
// to a particular vulnerability.
type ImportGraph struct {
	// Packages contains all package nodes as a map: package node id -> package node.
	Packages map[int]*PkgNode

	// Entries are IDs of a subset of Packages representing packages of vulncheck entry points.
	Entries []int
}

// A PkgNode describes a package in the import graph.
type PkgNode struct {
	// ID is the id used to identify the PkgNode in ImportGraph.
	ID int

	// Name is the package identifier as it appears in the source code.
	Name string

	// Path is the package path.
	Path string

	// Module holds ID of the corresponding module (node) in the Requires graph.
	Module int

	// ImportedBy contains IDs of packages directly importing this package.
	ImportedBy []int

	// pkg is used for connecting package node to module and call graph nodes.
	pkg *Package
}

// moduleVulnerabilities is an internal structure for
// holding and querying vulnerabilities provided by a
// vulnerability database client.
type moduleVulnerabilities []modVulns

// modVulns groups vulnerabilities per module.
type modVulns struct {
	mod   *Module
	vulns []*osv.Entry
}

func (mv moduleVulnerabilities) filter(os, arch string) moduleVulnerabilities {
	var filteredMod moduleVulnerabilities
	for _, mod := range mv {
		module := mod.mod
		modVersion := module.Version
		if module.Replace != nil {
			modVersion = module.Replace.Version
		}
		// TODO(https://golang.org/issues/49264): if modVersion == "", try vcs?
		var filteredVulns []*osv.Entry
		for _, v := range mod.vulns {
			var filteredAffected []osv.Affected
			for _, a := range v.Affected {
				// Vulnerabilities from some databases might contain
				// information on related but different modules that
				// were, say, reported in the same CVE. We filter such
				// information out as it might lead to incorrect results:
				// Computing a latest fix could consider versions of these
				// different packages.
				if a.Package.Name != module.Path {
					continue
				}

				// A module version is affected if
				//  - it is included in one of the affected version ranges
				//  - and module version is not ""
				if modVersion == "" {
					// Module version of "" means the module version is not available,
					// and so we don't want to spam users with potential false alarms.
					// TODO: issue warning for "" cases above?
					continue
				}
				if !a.Ranges.AffectsSemver(modVersion) {
					continue
				}
				var filteredImports []osv.EcosystemSpecificImport
				for _, p := range a.EcosystemSpecific.Imports {
					if matchesPlatform(os, arch, p) {
						filteredImports = append(filteredImports, p)
					}
				}
				if len(a.EcosystemSpecific.Imports) != 0 && len(filteredImports) == 0 {
					continue
				}
				a.EcosystemSpecific.Imports = filteredImports
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
		filteredMod = append(filteredMod, modVulns{
			mod:   module,
			vulns: filteredVulns,
		})
	}
	return filteredMod
}

func matchesPlatform(os, arch string, e osv.EcosystemSpecificImport) bool {
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
	var mostSpecificMod *modVulns
	for _, mod := range mv {
		md := mod
		if isStd && mod.mod == stdlibModule {
			// standard library packages do not have an associated module,
			// so we relate them to the artificial stdlib module.
			mostSpecificMod = &md
		} else if strings.HasPrefix(importPath, md.mod.Path) {
			if mostSpecificMod == nil || len(mostSpecificMod.mod.Path) < len(md.mod.Path) {
				mostSpecificMod = &md
			}
		}
	}
	if mostSpecificMod == nil {
		return nil
	}

	if mostSpecificMod.mod.Replace != nil {
		// standard libraries do not have a module nor replace module
		importPath = fmt.Sprintf("%s%s", mostSpecificMod.mod.Replace.Path, strings.TrimPrefix(importPath, mostSpecificMod.mod.Path))
	}
	vulns := mostSpecificMod.vulns
	packageVulns := []*osv.Entry{}
Vuln:
	for _, v := range vulns {
		for _, a := range v.Affected {
			for _, p := range a.EcosystemSpecific.Imports {
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
			for _, p := range a.EcosystemSpecific.Imports {
				if p.Path != importPath {
					continue
				}
				if len(p.Symbols) > 0 && !slices.Contains(p.Symbols, symbol) {
					continue
				}
				symbolVulns = append(symbolVulns, v)
				continue vulnLoop
			}
		}
	}
	return symbolVulns
}

func newModuleConverter() func(m *packages.Module) *Module {
	pmap := map[*packages.Module]*Module{}
	var convert func(m *packages.Module) *Module
	convert = func(m *packages.Module) *Module {
		if m == nil {
			return nil
		}
		if vm, ok := pmap[m]; ok {
			return vm
		}
		vm := &Module{
			Path:    m.Path,
			Version: m.Version,
			Dir:     m.Dir,
			Replace: convert(m.Replace),
		}
		pmap[m] = vm
		return vm
	}
	return convert
}
