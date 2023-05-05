// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"
	"go/token"
	"sort"
	"sync"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

// Source detects vulnerabilities in packages. The result will contain:
//
// 1) An ImportGraph related to an import of a package with some known
// vulnerabilities.
//
// 2) A RequireGraph related to a require of a module with a package that has
// some known vulnerabilities.
//
// 3) A CallGraph leading to the use of a known vulnerable function or method.
func Source(ctx context.Context, pkgs []*packages.Package, cfg *govulncheck.Config, client *client.Client) (_ *Result, err error) {
	// buildSSA builds a whole program that assumes all packages use the same FileSet.
	// Check all packages in pkgs are using the same FileSet.
	// TODO(https://go.dev/issue/59729): take FileSet out of Package and
	// let Source take a single FileSet. That will make the enforcement
	// clearer from the API level.
	var fset *token.FileSet
	for _, p := range pkgs {
		if fset == nil {
			fset = p.Fset
		} else {
			if fset != p.Fset {
				return nil, fmt.Errorf("[]*Package must have created with the same FileSet")
			}
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// If we are building the callgraph, build ssa and the callgraph in parallel
	// with fetching vulnerabilities. If the vulns set is empty, return without
	// waiting for SSA construction or callgraph to finish.
	var (
		wg       sync.WaitGroup // guards entries, cg, and buildErr
		entries  []*ssa.Function
		cg       *callgraph.Graph
		buildErr error
	)
	if !cfg.ImportsOnly {
		wg.Add(1)
		go func() {
			defer wg.Done()
			prog, ssaPkgs := buildSSA(pkgs, fset)
			entries = entryPoints(ssaPkgs)
			cg, buildErr = callGraph(ctx, prog, entries)
		}()
	}

	mods := extractModules(pkgs)
	mv, err := FetchVulnerabilities(ctx, client, mods)
	if err != nil {
		return nil, err
	}
	modVulns := moduleVulnerabilities(mv)
	modVulns = modVulns.filter(cfg.GOOS, cfg.GOARCH)
	result := &Result{
		Packages:      make(map[string]*PkgNode),
		ModulesByPath: make(map[string]*ModNode),
	}

	vulnPkgModSlice(pkgs, modVulns, result)
	setModules(result, mods)
	// Return result immediately if in ImportsOnly mode or
	// if there are no vulnerable packages.
	if cfg.ImportsOnly || len(result.Packages) == 0 {
		return result, nil
	}

	wg.Wait() // wait for build to finish
	if buildErr != nil {
		return nil, err
	}

	vulnCallGraphSlice(entries, modVulns, cg, result)

	// Release residual memory.
	for _, p := range result.Packages {
		p.pkg = nil
	}

	return result, nil
}

// Set r.Modules to an adjusted list of modules.
func setModules(r *Result, mods []*packages.Module) {
	// Remove Dirs from modules; they aren't needed and complicate testing.
	for _, m := range mods {
		m.Dir = ""
		if m.Replace != nil {
			m.Replace.Dir = ""
		}
	}
	// Sort for determinism.
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	r.Modules = append(r.Modules, mods...)
}

// vulnPkgModSlice computes the slice of pkgs imports and requires graph
// leading to imports/requires of vulnerable packages/modules in modVulns
// and stores the computed slices to result.
func vulnPkgModSlice(pkgs []*packages.Package, modVulns moduleVulnerabilities, result *Result) {
	// analyzedPkgs contains information on packages analyzed thus far.
	// If a package is mapped to nil, this means it has been visited
	// but it does not lead to a vulnerable imports. Otherwise, a
	// visited package is mapped to Imports package node.
	analyzedPkgs := make(map[*packages.Package]*PkgNode)
	for _, pkg := range pkgs {
		// Top level packages that lead to vulnerable imports are
		// stored as result.EntryPackages graph entry points.
		if e := vulnImportSlice(pkg, modVulns, result, analyzedPkgs); e != nil {
			result.EntryPackages = append(result.EntryPackages, e)
		}
	}

	// Populate module requires slice as an overlay
	// of package imports slice.
	vulnModuleSlice(result)
}

// vulnImportSlice checks if pkg has some vulnerabilities or transitively imports
// a package with known vulnerabilities. If that is the case, populates result.Imports
// graph with this reachability information and returns the result.Imports package
// node for pkg. Otherwise, returns nil.
func vulnImportSlice(pkg *packages.Package, modVulns moduleVulnerabilities, result *Result, analyzed map[*packages.Package]*PkgNode) *PkgNode {
	if pn, ok := analyzed[pkg]; ok {
		return pn
	}
	analyzed[pkg] = nil
	// Recursively compute which direct dependencies lead to an import of
	// a vulnerable package and remember the nodes of such dependencies.
	var onSlice []*PkgNode
	for _, imp := range pkg.Imports {
		if impNode := vulnImportSlice(imp, modVulns, result, analyzed); impNode != nil {
			onSlice = append(onSlice, impNode)
		}
	}

	// Check if pkg has known vulnerabilities.
	vulns := modVulns.vulnsForPackage(pkg.PkgPath)

	// If pkg is not vulnerable nor it transitively leads
	// to vulnerabilities, jump out.
	if len(onSlice) == 0 && len(vulns) == 0 {
		return nil
	}

	// Module id gets populated later.
	pkgNode := &PkgNode{
		pkg: pkg,
	}
	analyzed[pkg] = pkgNode

	result.Packages[pkg.ID] = pkgNode

	// Save node predecessor information.
	for _, impSliceNode := range onSlice {
		impSliceNode.ImportedBy = append(impSliceNode.ImportedBy, pkgNode)
	}

	// Create Vuln entry for each symbol of known OSV entries for pkg.
	for _, osv := range vulns {
		for _, affected := range osv.Affected {
			for _, p := range affected.EcosystemSpecific.Packages {
				if p.Path != pkgNode.pkg.PkgPath {
					continue
				}

				symbols := p.Symbols
				if len(symbols) == 0 {
					symbols = allSymbols(pkg.Types)
				}

				for _, symbol := range symbols {
					vuln := &Vuln{
						OSV:        osv,
						Symbol:     symbol,
						PkgPath:    pkgNode.pkg.PkgPath,
						ImportSink: pkgNode,
					}
					result.Vulns = append(result.Vulns, vuln)
				}
			}
		}
	}
	return pkgNode
}

// vulnModuleSlice populates result.Requires as an overlay
// of result.Imports.
func vulnModuleSlice(result *Result) {
	// We first collect inverse requires by (predecessor)
	// relation on module node ids.
	modPredRelation := make(map[string]map[string]bool)
	for _, pkgNode := range result.Packages {
		// Create or get module node for pkgNode.
		pkgNode.Module = moduleNode(pkgNode, result)

		// Update the set of predecessors.
		if _, ok := modPredRelation[pkgNode.Module.Path]; !ok {
			modPredRelation[pkgNode.Module.Path] = make(map[string]bool)
		}
		predSet := modPredRelation[pkgNode.Module.Path]

		for _, predPkg := range pkgNode.ImportedBy {
			predMod := moduleNode(predPkg, result)
			// We don't add module edges for imports
			// of packages in the same module as that
			// will create self-loops in Requires graphs.
			if predMod.Path == pkgNode.Module.Path {
				continue
			}
			predSet[predMod.Path] = true
		}
	}

	// Add entry module IDs.
	seenEntries := make(map[string]bool)
	for _, ePkg := range result.EntryPackages {
		entryMod := moduleNode(ePkg, result)
		if seenEntries[entryMod.Path] {
			continue
		}
		seenEntries[entryMod.Path] = true
		result.EntryModules = append(result.EntryModules, entryMod)
	}

	// Store the predecessor requires relation to result.
	for modPath := range modPredRelation {
		var preds []*ModNode
		for predPath := range modPredRelation[modPath] {
			preds = append(preds, result.ModulesByPath[predPath])
		}
		modNode := result.ModulesByPath[modPath]
		modNode.RequiredBy = preds
	}

	// And finally update Vulns with module information.
	for _, vuln := range result.Vulns {
		vuln.RequireSink = vuln.ImportSink.Module
	}
}

// moduleNode creates a module node associated with pkgNode, if one does
// not exist already, and returns id of the module node. The actual module
// node is stored to result.
func moduleNode(pkgNode *PkgNode, result *Result) *ModNode {
	return getModuleNode(pkgNode.pkg.Module, result)
}

func getModuleNode(mod *packages.Module, result *Result) *ModNode {
	if mod == nil {
		return nil
	}
	if n, ok := result.ModulesByPath[mod.Path]; ok {
		return n
	}
	n := &ModNode{Module: mod}
	result.ModulesByPath[n.Path] = n
	// Create a replace module too when applicable.
	if mod.Replace != nil {
		n.Replace = getModuleNode(mod.Replace, result)
	}
	return n
}

// vulnCallGraphSlice checks if known vulnerabilities are transitively reachable from sources
// via call graph cg. If so, populates result.Calls graph with this reachability information.
func vulnCallGraphSlice(sources []*ssa.Function, modVulns moduleVulnerabilities, cg *callgraph.Graph, result *Result) {
	sinksWithVulns := vulnFuncs(cg, modVulns)

	// Compute call graph backwards reachable
	// from vulnerable functions and methods.
	var sinks []*callgraph.Node
	for n := range sinksWithVulns {
		sinks = append(sinks, n)
	}
	bcg := callGraphSlice(sinks, false)

	// Interesect backwards call graph with forward
	// reachable graph to remove redundant edges.
	var filteredSources []*callgraph.Node
	for _, e := range sources {
		if n, ok := bcg.Nodes[e]; ok {
			filteredSources = append(filteredSources, n)
		}
	}
	fcg := callGraphSlice(filteredSources, true)

	// Get the sinks that are in fact reachable from entry points.
	filteredSinks := make(map[*callgraph.Node][]*osv.Entry)
	for n, vs := range sinksWithVulns {
		if fn, ok := fcg.Nodes[n.Func]; ok {
			filteredSinks[fn] = vs
		}
	}

	// Transform the resulting call graph slice into
	// vulncheck representation and store it to result.
	vulnCallGraph(filteredSources, filteredSinks, result)
}

// callGraphSlice computes a slice of callgraph beginning at starts
// in the direction (forward/backward) controlled by forward flag.
func callGraphSlice(starts []*callgraph.Node, forward bool) *callgraph.Graph {
	g := &callgraph.Graph{Nodes: make(map[*ssa.Function]*callgraph.Node)}

	visited := make(map[*callgraph.Node]bool)
	var visit func(*callgraph.Node)
	visit = func(n *callgraph.Node) {
		if visited[n] {
			return
		}
		visited[n] = true

		var edges []*callgraph.Edge
		if forward {
			edges = n.Out
		} else {
			edges = n.In
		}

		for _, edge := range edges {
			nCallee := g.CreateNode(edge.Callee.Func)
			nCaller := g.CreateNode(edge.Caller.Func)
			callgraph.AddEdge(nCaller, edge.Site, nCallee)

			if forward {
				visit(edge.Callee)
			} else {
				visit(edge.Caller)
			}
		}
	}

	for _, s := range starts {
		visit(s)
	}
	return g
}

// vulnCallGraph creates vulnerability call graph from sources -> sinks reachability info.
func vulnCallGraph(sources []*callgraph.Node, sinks map[*callgraph.Node][]*osv.Entry, result *Result) {
	nodes := make(map[*ssa.Function]*FuncNode)
	createNode := func(f *ssa.Function) *FuncNode {
		if fn, ok := nodes[f]; ok {
			return fn
		}
		fn := funcNode(f)
		nodes[f] = fn
		return fn
	}

	// First create entries and sinks and store relevant information.
	for _, s := range sources {
		fn := createNode(s.Func)
		result.EntryFunctions = append(result.EntryFunctions, fn)
	}

	for s, vulns := range sinks {
		f := s.Func
		funNode := createNode(s.Func)

		// Populate CallSink field for each detected vuln symbol.
		for _, osv := range vulns {
			if vulnMatchesPackage(osv, funNode.PkgPath) {
				addCallSinkForVuln(funNode, osv, dbFuncName(f), funNode.PkgPath, result)
			}
		}
	}

	visited := make(map[*callgraph.Node]bool)
	var visit func(*callgraph.Node)
	visit = func(n *callgraph.Node) {
		if visited[n] {
			return
		}
		visited[n] = true

		for _, edge := range n.In {
			nCallee := createNode(edge.Callee.Func)
			nCaller := createNode(edge.Caller.Func)

			call := edge.Site
			cs := &CallSite{
				Parent:   nCaller,
				Name:     call.Common().Value.Name(),
				RecvType: callRecvType(call),
				Resolved: resolved(call),
				Pos:      instrPosition(call),
			}
			nCallee.CallSites = append(nCallee.CallSites, cs)

			visit(edge.Caller)
		}
	}

	for s := range sinks {
		visit(s)
	}
}

// vulnFuncs returns vulnerability information for vulnerable functions in cg.
func vulnFuncs(cg *callgraph.Graph, modVulns moduleVulnerabilities) map[*callgraph.Node][]*osv.Entry {
	m := make(map[*callgraph.Node][]*osv.Entry)
	for f, n := range cg.Nodes {
		vulns := modVulns.vulnsForSymbol(pkgPath(f), dbFuncName(f))
		if len(vulns) > 0 {
			m[n] = vulns
		}
	}
	return m
}

// pkgPath returns the path of the f's enclosing package, if any.
// Otherwise, returns "".
func pkgPath(f *ssa.Function) string {
	if f.Package() != nil && f.Package().Pkg != nil {
		return f.Package().Pkg.Path()
	}
	return ""
}

func funcNode(f *ssa.Function) *FuncNode {
	node := &FuncNode{
		Name:     f.Name(),
		PkgPath:  pkgPath(f),
		RecvType: funcRecvType(f),
		Pos:      funcPosition(f),
	}
	return node
}

// addCallSinkForVuln adds callID as call sink to vuln of result.Vulns
// identified with <osv, symbol, pkg>.
func addCallSinkForVuln(call *FuncNode, osv *osv.Entry, symbol, pkg string, result *Result) {
	for _, vuln := range result.Vulns {
		if vuln.OSV == osv && vuln.Symbol == symbol && vuln.PkgPath == pkg {
			vuln.CallSink = call
			return
		}
	}
}

// extractModules collects modules in `pkgs` up to uniqueness of
// module path and version.
func extractModules(pkgs []*packages.Package) []*packages.Module {
	modMap := map[string]*packages.Module{}
	seen := map[*packages.Package]bool{}
	var extract func(*packages.Package, map[string]*packages.Module)
	extract = func(pkg *packages.Package, modMap map[string]*packages.Module) {
		if pkg == nil || seen[pkg] {
			return
		}
		if pkg.Module != nil {
			if pkg.Module.Replace != nil {
				modMap[pkg.Module.Replace.Path] = pkg.Module
			} else {
				modMap[pkg.Module.Path] = pkg.Module
			}
		}
		seen[pkg] = true
		for _, imp := range pkg.Imports {
			extract(imp, modMap)
		}
	}
	for _, pkg := range pkgs {
		extract(pkg, modMap)
	}

	modules := []*packages.Module{}
	for _, mod := range modMap {
		modules = append(modules, mod)
	}
	return modules
}
