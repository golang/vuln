// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"
	"go/token"
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
func Source(ctx context.Context, pkgs []*packages.Package, cfg *govulncheck.Config, client *client.Client, graph *PackageGraph) (_ *Result, err error) {
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
	if cfg.ScanLevel.WantSymbols() {
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
	modVulns = modVulns.filter("", "")
	result := &Result{}

	vulnPkgModSlice(pkgs, modVulns, result)
	// Return result immediately if not in symbol mode or
	// if there are no vulnerable packages.
	if !cfg.ScanLevel.WantSymbols() || len(result.EntryPackages) == 0 {
		return result, nil
	}

	wg.Wait() // wait for build to finish
	if buildErr != nil {
		return nil, err
	}

	vulnCallGraphSlice(entries, modVulns, cg, result, graph)

	return result, nil
}

// vulnPkgModSlice computes the slice of pkgs imports and requires graph
// leading to imports/requires of vulnerable packages/modules in modVulns
// and stores the computed slices to result.
func vulnPkgModSlice(pkgs []*packages.Package, modVulns moduleVulnerabilities, result *Result) {
	// analyzedPkgs contains information on packages analyzed thus far.
	// If a package is mapped to false, this means it has been visited
	// but it does not lead to a vulnerable imports. Otherwise, a
	// visited package is mapped to true.
	analyzedPkgs := make(map[*packages.Package]bool)
	for _, pkg := range pkgs {
		// Top level packages that lead to vulnerable imports are
		// stored as result.EntryPackages graph entry points.
		if vulnerable := vulnImportSlice(pkg, modVulns, result, analyzedPkgs); vulnerable {
			result.EntryPackages = append(result.EntryPackages, pkg)
		}
	}
}

// vulnImportSlice checks if pkg has some vulnerabilities or transitively imports
// a package with known vulnerabilities. If that is the case, populates result.Imports
// graph with this reachability information and returns the result.Imports package
// node for pkg. Otherwise, returns nil.
func vulnImportSlice(pkg *packages.Package, modVulns moduleVulnerabilities, result *Result, analyzed map[*packages.Package]bool) bool {
	if vulnerable, ok := analyzed[pkg]; ok {
		return vulnerable
	}
	analyzed[pkg] = false
	// Recursively compute which direct dependencies lead to an import of
	// a vulnerable package and remember the nodes of such dependencies.
	transitiveVulnerable := false
	for _, imp := range pkg.Imports {
		if impVulnerable := vulnImportSlice(imp, modVulns, result, analyzed); impVulnerable {
			transitiveVulnerable = true
		}
	}

	// Check if pkg has known vulnerabilities.
	vulns := modVulns.vulnsForPackage(pkg.PkgPath)

	// If pkg is not vulnerable nor it transitively leads
	// to vulnerabilities, jump out.
	if !transitiveVulnerable && len(vulns) == 0 {
		return false
	}

	// Create Vuln entry for each symbol of known OSV entries for pkg.
	for _, osv := range vulns {
		for _, affected := range osv.Affected {
			for _, p := range affected.EcosystemSpecific.Packages {
				if p.Path != pkg.PkgPath {
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
						ImportSink: pkg,
					}
					result.Vulns = append(result.Vulns, vuln)
				}
			}
		}
	}
	analyzed[pkg] = true
	return true
}

// vulnCallGraphSlice checks if known vulnerabilities are transitively reachable from sources
// via call graph cg. If so, populates result.Calls graph with this reachability information.
func vulnCallGraphSlice(sources []*ssa.Function, modVulns moduleVulnerabilities, cg *callgraph.Graph, result *Result, graph *PackageGraph) {
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
	vulnCallGraph(filteredSources, filteredSinks, result, graph)
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
func vulnCallGraph(sources []*callgraph.Node, sinks map[*callgraph.Node][]*osv.Entry, result *Result, graph *PackageGraph) {
	nodes := make(map[*ssa.Function]*FuncNode)

	// First create entries and sinks and store relevant information.
	for _, s := range sources {
		fn := createNode(nodes, s.Func, graph)
		result.EntryFunctions = append(result.EntryFunctions, fn)
	}

	for s, vulns := range sinks {
		f := s.Func
		funNode := createNode(nodes, s.Func, graph)

		// Populate CallSink field for each detected vuln symbol.
		for _, osv := range vulns {
			if vulnMatchesPackage(osv, funNode.Package.PkgPath) {
				addCallSinkForVuln(funNode, osv, dbFuncName(f), funNode.Package.PkgPath, result)
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
			nCallee := createNode(nodes, edge.Callee.Func, graph)
			nCaller := createNode(nodes, edge.Caller.Func, graph)

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

func createNode(nodes map[*ssa.Function]*FuncNode, f *ssa.Function, graph *PackageGraph) *FuncNode {
	if fn, ok := nodes[f]; ok {
		return fn
	}
	fn := &FuncNode{
		Name:     f.Name(),
		Package:  graph.GetPackage(pkgPath(f)),
		RecvType: funcRecvType(f),
		Pos:      funcPosition(f),
	}
	nodes[f] = fn
	return fn
}

// addCallSinkForVuln adds callID as call sink to vuln of result.Vulns
// identified with <osv, symbol, pkg>.
func addCallSinkForVuln(call *FuncNode, osv *osv.Entry, symbol, pkg string, result *Result) {
	for _, vuln := range result.Vulns {
		if vuln.OSV == osv && vuln.Symbol == symbol && vuln.ImportSink.PkgPath == pkg {
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
