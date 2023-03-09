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
	"golang.org/x/tools/go/ssa"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/osv"
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
func Source(ctx context.Context, pkgs []*Package, cfg *Config) (_ *Result, err error) {
	defer derrors.Wrap(&err, "vulncheck.Source")

	// buildSSA builds a whole program that assumes all packages use the same FileSet.
	// Check all packages in pkgs are using the same FileSet.
	// TODO(hyangah): Alternative is to take FileSet out of Package and
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

	// set the stdlib version for detection of vulns in the standard library
	// TODO(#53740): what if Go version is not in semver format?
	if cfg.SourceGoVersion != "" {
		stdlibModule.Version = semver.GoTagToSemver(cfg.SourceGoVersion)
	} else {
		gover, err := internal.GoEnv("GOVERSION")
		if err != nil {
			return nil, err
		}
		stdlibModule.Version = semver.GoTagToSemver(gover)
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
	modVulns, err := fetchVulnerabilities(ctx, cfg.Client, mods)
	if err != nil {
		return nil, err
	}
	modVulns = modVulns.filter(cfg.GOOS, cfg.GOARCH)
	result := &Result{
		Imports:  &ImportGraph{Packages: make(map[int]*PkgNode)},
		Requires: &RequireGraph{Modules: make(map[int]*ModNode)},
		Calls:    &CallGraph{Functions: make(map[int]*FuncNode)},
	}

	vulnPkgModSlice(pkgs, modVulns, result)
	setModules(result, mods)
	// Return result immediately if in ImportsOnly mode or
	// if there are no vulnerable packages.
	if cfg.ImportsOnly || len(result.Imports.Packages) == 0 {
		return result, nil
	}

	wg.Wait() // wait for build to finish
	if buildErr != nil {
		return nil, err
	}

	vulnCallGraphSlice(entries, modVulns, cg, result)

	// Release residual memory.
	for _, p := range result.Imports.Packages {
		p.pkg = nil
	}

	return result, nil
}

// Set r.Modules to an adjusted list of modules.
func setModules(r *Result, mods []*Module) {
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

// pkgID is an id counter for nodes of Imports graph.
var pkgID int = 0

func nextPkgID() int {
	pkgID++
	return pkgID
}

// vulnPkgModSlice computes the slice of pkgs imports and requires graph
// leading to imports/requires of vulnerable packages/modules in modVulns
// and stores the computed slices to result.
func vulnPkgModSlice(pkgs []*Package, modVulns moduleVulnerabilities, result *Result) {
	// analyzedPkgs contains information on packages analyzed thus far.
	// If a package is mapped to nil, this means it has been visited
	// but it does not lead to a vulnerable imports. Otherwise, a
	// visited package is mapped to Imports package node.
	analyzedPkgs := make(map[*Package]*PkgNode)
	for _, pkg := range pkgs {
		// Top level packages that lead to vulnerable imports are
		// stored as result.Imports graph entry points.
		if e := vulnImportSlice(pkg, modVulns, result, analyzedPkgs); e != nil {
			result.Imports.Entries = append(result.Imports.Entries, e.ID)
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
func vulnImportSlice(pkg *Package, modVulns moduleVulnerabilities, result *Result, analyzed map[*Package]*PkgNode) *PkgNode {
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
	id := nextPkgID()
	pkgNode := &PkgNode{
		ID:   id,
		Name: pkg.Name,
		Path: pkg.PkgPath,
		pkg:  pkg,
	}
	analyzed[pkg] = pkgNode

	result.Imports.Packages[id] = pkgNode

	// Save node predecessor information.
	for _, impSliceNode := range onSlice {
		impSliceNode.ImportedBy = append(impSliceNode.ImportedBy, id)
	}

	// Create Vuln entry for each symbol of known OSV entries for pkg.
	for _, osv := range vulns {
		for _, affected := range osv.Affected {
			for _, p := range affected.EcosystemSpecific.Imports {
				if p.Path != pkgNode.Path {
					continue
				}

				symbols := p.Symbols
				if len(symbols) == 0 {
					symbols = allSymbols(pkg.Pkg)
				}

				for _, symbol := range symbols {
					vuln := &Vuln{
						OSV:        osv,
						Symbol:     symbol,
						PkgPath:    pkgNode.Path,
						ImportSink: id,
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
	// Map from module nodes, identified with their
	// path and version, to their unique ids.
	modNodeIDs := make(map[string]int)
	// We first collect inverse requires by (predecessor)
	// relation on module node ids.
	modPredRelation := make(map[int]map[int]bool)
	// Sort keys so modules are assigned IDs deterministically, for tests.
	var pkgIDs []int
	for id := range result.Imports.Packages {
		pkgIDs = append(pkgIDs, id)
	}
	sort.Ints(pkgIDs)
	for _, id := range pkgIDs {
		pkgNode := result.Imports.Packages[id]
		// Create or get module node for pkgNode.
		modID := moduleNodeID(pkgNode, result, modNodeIDs)
		pkgNode.Module = modID

		// Update the set of predecessors.
		if _, ok := modPredRelation[modID]; !ok {
			modPredRelation[modID] = make(map[int]bool)
		}
		predSet := modPredRelation[modID]

		for _, predPkgID := range pkgNode.ImportedBy {
			predModID := moduleNodeID(result.Imports.Packages[predPkgID], result, modNodeIDs)
			// We don't add module edges for imports
			// of packages in the same module as that
			// will create self-loops in Requires graphs.
			if predModID == modID {
				continue
			}
			predSet[predModID] = true
		}
	}

	// Add entry module IDs.
	seenEntries := make(map[int]bool)
	for _, epID := range result.Imports.Entries {
		entryModID := moduleNodeID(result.Imports.Packages[epID], result, modNodeIDs)
		if seenEntries[entryModID] {
			continue
		}
		seenEntries[entryModID] = true
		result.Requires.Entries = append(result.Requires.Entries, entryModID)
	}

	// Store the predecessor requires relation to result.
	for modID := range modPredRelation {
		if modID == 0 {
			continue
		}

		var predIDs []int
		for predID := range modPredRelation[modID] {
			predIDs = append(predIDs, predID)
		}
		modNode := result.Requires.Modules[modID]
		modNode.RequiredBy = predIDs
	}

	// And finally update Vulns with module information.
	for _, vuln := range result.Vulns {
		pkgNode := result.Imports.Packages[vuln.ImportSink]
		modNode := result.Requires.Modules[pkgNode.Module]

		vuln.RequireSink = pkgNode.Module
		vuln.ModPath = modNode.Path
	}
}

// modID is an id counter for nodes of Requires graph.
var modID int = 0

func nextModID() int {
	modID++
	return modID
}

// moduleNode creates a module node associated with pkgNode, if one does
// not exist already, and returns id of the module node. The actual module
// node is stored to result.
func moduleNodeID(pkgNode *PkgNode, result *Result, modNodeIDs map[string]int) int {
	mod := pkgNode.pkg.Module
	if isStdPackage(pkgNode.Path) {
		// standard library packages don't have a module.
		mod = stdlibModule
	}
	if mod == nil {
		return 0
	}

	mk := modKey(mod)
	if id, ok := modNodeIDs[mk]; ok {
		return id
	}

	id := nextModID()
	n := &ModNode{
		ID:      id,
		Path:    mod.Path,
		Version: mod.Version,
	}
	result.Requires.Modules[id] = n
	modNodeIDs[mk] = id

	// Create a replace module too when applicable.
	if mod.Replace != nil {
		rmk := modKey(mod.Replace)
		if rid, ok := modNodeIDs[rmk]; ok {
			n.Replace = rid
		} else {
			rid := nextModID()
			rn := &ModNode{
				Path:    mod.Replace.Path,
				Version: mod.Replace.Version,
			}
			result.Requires.Modules[rid] = rn
			modNodeIDs[rmk] = rid
			n.Replace = rid
		}
	}
	return id
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

// funID is an id counter for nodes of Calls graph.
var funID int = 0

func nextFunID() int {
	funID++
	return funID
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
		result.Calls.Functions[fn.ID] = fn
		return fn
	}

	// First create entries and sinks and store relevant information.
	for _, s := range sources {
		fn := createNode(s.Func)
		result.Calls.Entries = append(result.Calls.Entries, fn.ID)
	}

	for s, vulns := range sinks {
		f := s.Func
		funNode := createNode(s.Func)

		// Populate CallSink field for each detected vuln symbol.
		for _, osv := range vulns {
			if vulnMatchesPackage(osv, funNode.PkgPath) {
				addCallSinkForVuln(funNode.ID, osv, dbFuncName(f), funNode.PkgPath, result)
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
				Parent:   nCaller.ID,
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
	id := nextFunID()
	return &FuncNode{
		ID:       id,
		Name:     f.Name(),
		PkgPath:  pkgPath(f),
		RecvType: funcRecvType(f),
		Pos:      funcPosition(f),
	}
}

// addCallSinkForVuln adds callID as call sink to vuln of result.Vulns
// identified with <osv, symbol, pkg>.
func addCallSinkForVuln(callID int, osv *osv.Entry, symbol, pkg string, result *Result) {
	for _, vuln := range result.Vulns {
		if vuln.OSV == osv && vuln.Symbol == symbol && vuln.PkgPath == pkg {
			vuln.CallSink = callID
			return
		}
	}
}
