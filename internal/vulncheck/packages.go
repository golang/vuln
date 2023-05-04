// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/semver"
)

// PackageGraph holds a complete module and package graph.
// Its primary purpose is to allow fast access to the nodes by path.
type PackageGraph struct {
	modules  map[string]*packages.Module
	packages map[string]*packages.Package
}

func NewPackageGraph(goVersion string) *PackageGraph {
	graph := &PackageGraph{
		modules:  map[string]*packages.Module{},
		packages: map[string]*packages.Package{},
	}
	graph.AddModules(&packages.Module{
		Path:    internal.GoStdModulePath,
		Version: semver.GoTagToSemver(goVersion),
	})
	return graph
}

// AddModules adds the modules and any replace modules provided.
// It will ignore modules that have duplicate paths to ones the graph already holds.
func (g *PackageGraph) AddModules(mods ...*packages.Module) {
	for _, mod := range mods {
		if _, found := g.modules[mod.Path]; found {
			//TODO: check duplicates are okay?
			continue
		}
		g.modules[mod.Path] = mod
		if mod.Replace != nil {
			g.AddModules(mod.Replace)
		}
	}
}

// .
func (g *PackageGraph) GetModule(path string) *packages.Module {
	if mod, ok := g.modules[path]; ok {
		return mod
	}
	mod := &packages.Module{
		Path:    path,
		Version: "",
	}
	g.AddModules(mod)
	return mod
}

// AddPackages adds the packages and the full graph of imported packages.
// It will ignore packages that have duplicate paths to ones the graph already holds.
func (g *PackageGraph) AddPackages(pkgs ...*packages.Package) {
	for _, pkg := range pkgs {
		if _, found := g.packages[pkg.PkgPath]; found {
			//TODO: check duplicates are okay?
			continue
		}
		g.packages[pkg.PkgPath] = pkg
		g.fixupPackage(pkg)
		for _, child := range pkg.Imports {
			g.AddPackages(child)
		}
	}
}

func (g *PackageGraph) fixupPackage(pkg *packages.Package) {
	if pkg.Module != nil {
		g.AddModules(pkg.Module)
		return
	}
	pkg.Module = g.findModule(pkg.PkgPath)
}

// findModule finds a module for package.
// It does a longest prefix search amongst the existing modules, if that does
// not find anything, it returns the "unknown" module.
func (g *PackageGraph) findModule(pkgPath string) *packages.Module {
	//TODO: better stdlib test
	if !strings.Contains(pkgPath, ".") {
		return g.GetModule(internal.GoStdModulePath)
	}
	for _, m := range g.modules {
		//TODO: not first match, best match...
		if pkgPath == m.Path || strings.HasPrefix(pkgPath, m.Path+"/") {
			return m
		}
	}
	return g.GetModule(internal.UnknownModulePath)
}

// GetPackage returns the package matching the path.
// If the graph does not already know about the package, a new one is added.
func (g *PackageGraph) GetPackage(path string) *packages.Package {
	if pkg, ok := g.packages[path]; ok {
		return pkg
	}
	pkg := &packages.Package{
		PkgPath: path,
	}
	g.AddPackages(pkg)
	return pkg
}

// LoadPackages loads the packages specified by the patterns into the graph.
// See golang.org/x/tools/go/packages.Load for details of how it works.
func (g *PackageGraph) LoadPackages(cfg *packages.Config, tags []string, patterns []string) ([]*packages.Package, error) {
	if len(tags) > 0 {
		cfg.BuildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(tags, ","))}
	}
	cfg.Mode |=
		packages.NeedDeps |
			packages.NeedImports |
			packages.NeedModule |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedName

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &packageError{perrs}
	}
	g.AddPackages(pkgs...)
	return pkgs, err
}

// packageError contains errors from loading a set of packages.
type packageError struct {
	Errors []packages.Error
}

func (e *packageError) Error() string {
	var b strings.Builder
	fmt.Fprintln(&b, "\nThere are errors with the provided package patterns:")
	fmt.Fprintln(&b, "")
	for _, e := range e.Errors {
		fmt.Fprintln(&b, e)
	}
	fmt.Fprintln(&b, "\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.")
	return b.String()
}
