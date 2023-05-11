// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/vulncheck"
)

// runSource reports vulnerabilities that affect the analyzed packages.
//
// Vulnerabilities can be called (affecting the package, because a vulnerable
// symbol is actually exercised) or just imported by the package
// (likely having a non-affecting outcome).
func runSource(ctx context.Context, handler govulncheck.Handler, cfg *config, client *client.Client, dir string) error {
	var pkgs []*packages.Package
	graph := vulncheck.NewPackageGraph(cfg.GoVersion)
	pkgConfig := &packages.Config{Dir: dir, Tests: cfg.test}
	pkgs, err := graph.LoadPackages(pkgConfig, cfg.tags, cfg.patterns)
	if err != nil {
		// Try to provide a meaningful and actionable error message.
		if !fileExists(filepath.Join(dir, "go.mod")) {
			return fmt.Errorf("govulncheck: %v", errNoGoMod)
		}
		if isGoVersionMismatchError(err) {
			return fmt.Errorf("govulncheck: %v\n\n%v", errGoVersionMismatch, err)
		}
		return fmt.Errorf("govulncheck: loading packages: %w", err)
	}
	if err := handler.Progress(sourceProgressMessage(pkgs)); err != nil {
		return err
	}
	vr, err := vulncheck.Source(ctx, pkgs, &cfg.Config, client, graph)
	if err != nil {
		return err
	}
	callStacks := vulncheck.CallStacks(vr)
	filterCallStacks(callStacks)
	return emitResult(handler, vr, callStacks)
}

func filterCallStacks(callstacks map[*vulncheck.Vuln][]vulncheck.CallStack) {
	type key struct {
		id  string
		pkg string
		mod string
	}
	// Collect all called symbols for a package.
	// Needed for creating unique call stacks.
	vulnsPerPkg := make(map[key][]*vulncheck.Vuln)
	for vv := range callstacks {
		if vv.CallSink != nil {
			k := key{id: vv.OSV.ID, pkg: vv.ImportSink.PkgPath, mod: vv.ImportSink.Module.Path}
			vulnsPerPkg[k] = append(vulnsPerPkg[k], vv)
		}
	}
	for vv, stacks := range callstacks {
		var filtered []vulncheck.CallStack
		if vv.CallSink != nil {
			k := key{id: vv.OSV.ID, pkg: vv.ImportSink.PkgPath, mod: vv.ImportSink.Module.Path}
			vcs := uniqueCallStack(vv, stacks, vulnsPerPkg[k])
			if vcs != nil {
				filtered = []vulncheck.CallStack{vcs}
			}
		}
		callstacks[vv] = filtered
	}
}

func emitResult(handler govulncheck.Handler, vr *vulncheck.Result, callstacks map[*vulncheck.Vuln][]vulncheck.CallStack) error {
	osvs := map[string]*osv.Entry{}
	var findings []*govulncheck.Finding
	// first deal with all the affected vulnerabilities
	emitted := map[string]bool{}
	for _, vv := range vr.Vulns {
		osvs[vv.OSV.ID] = vv.OSV
		fixed := fixedVersion(vv.ImportSink.Module.Path, vv.OSV.Affected)
		stacks := callstacks[vv]
		for _, stack := range stacks {
			emitted[vv.OSV.ID] = true
			findings = append(findings, &govulncheck.Finding{
				OSV:          vv.OSV.ID,
				FixedVersion: fixed,
				Trace:        tracefromEntries(stack),
			})
		}
	}
	for _, vv := range vr.Vulns {
		if emitted[vv.OSV.ID] {
			continue
		}
		stacks := callstacks[vv]
		if len(stacks) != 0 {
			continue
		}
		emitted[vv.OSV.ID] = true
		// no callstacks, add an unafected finding
		findings = append(findings, &govulncheck.Finding{
			OSV:          vv.OSV.ID,
			FixedVersion: fixedVersion(vv.ImportSink.Module.Path, vv.OSV.Affected),
			Trace: []*govulncheck.Frame{{
				Module:  vv.ImportSink.Module.Path,
				Version: vv.ImportSink.Module.Version,
				Package: vv.ImportSink.PkgPath,
			}},
		})
	}
	// For each vulnerability, queue it to be written to the output.
	seen := map[string]bool{}
	sortResult(findings)
	for _, f := range findings {
		if !seen[f.OSV] {
			seen[f.OSV] = true
			if err := handler.OSV(osvs[f.OSV]); err != nil {
				return err
			}
		}
		if err := handler.Finding(f); err != nil {
			return err
		}
	}
	return nil
}

// tracefromEntries creates a sequence of
// frames from vcs. Position of a Frame is the
// call position of the corresponding stack entry.
func tracefromEntries(vcs vulncheck.CallStack) []*govulncheck.Frame {
	var frames []*govulncheck.Frame
	for _, e := range vcs {
		fr := &govulncheck.Frame{
			Function: e.Function.Name,
			Receiver: e.Function.Receiver(),
		}
		if e.Function.Package != nil {
			fr.Module = e.Function.Package.Module.Path
			fr.Version = e.Function.Package.Module.Version
			fr.Package = e.Function.Package.PkgPath
		}
		if e.Call == nil || e.Call.Pos == nil {
			fr.Position = nil
		} else {
			fr.Position = &govulncheck.Position{
				Filename: e.Call.Pos.Filename,
				Offset:   e.Call.Pos.Offset,
				Line:     e.Call.Pos.Line,
				Column:   e.Call.Pos.Column,
			}
		}
		frames = append(frames, fr)
	}
	return frames
}

// sourceProgressMessage returns a string of the form
//
//	"Scanning your code and P packages across M dependent modules for known vulnerabilities..."
//
// P is the number of strictly dependent packages of
// topPkgs and Y is the number of their modules.
func sourceProgressMessage(topPkgs []*packages.Package) *govulncheck.Progress {
	pkgs, mods := depPkgsAndMods(topPkgs)

	pkgsPhrase := fmt.Sprintf("%d package", pkgs)
	if pkgs != 1 {
		pkgsPhrase += "s"
	}

	modsPhrase := fmt.Sprintf("%d dependent module", mods)
	if mods != 1 {
		modsPhrase += "s"
	}

	msg := fmt.Sprintf("Scanning your code and %s across %s for known vulnerabilities...", pkgsPhrase, modsPhrase)
	return &govulncheck.Progress{Message: msg}
}

// depPkgsAndMods returns the number of packages that
// topPkgs depend on and the number of their modules.
func depPkgsAndMods(topPkgs []*packages.Package) (int, int) {
	tops := make(map[string]bool)
	depPkgs := make(map[string]bool)
	depMods := make(map[string]bool)

	for _, t := range topPkgs {
		tops[t.PkgPath] = true
	}

	var visit func(*packages.Package, bool)
	visit = func(p *packages.Package, top bool) {
		path := p.PkgPath
		if depPkgs[path] {
			return
		}
		if tops[path] && !top {
			// A top package that is a dependency
			// will not be in depPkgs, so we skip
			// reiterating on it here.
			return
		}

		// We don't count a top-level package as
		// a dependency even when they are used
		// as a dependent package.
		if !tops[path] {
			depPkgs[path] = true
			if p.Module != nil &&
				p.Module.Path != internal.GoStdModulePath && // no module for stdlib
				p.Module.Path != internal.UnknownModulePath { // no module for unknown
				depMods[p.Module.Path] = true
			}
		}

		for _, d := range p.Imports {
			visit(d, false)
		}
	}

	for _, t := range topPkgs {
		visit(t, true)
	}

	return len(depPkgs), len(depMods)
}

// summarizeTrace returns a short description of the call stack.
// It uses one of four forms, depending on what the lowest function F
// in the top module calls and what is the highest function V of vulnPkg:
//   - If F calls V directly and F as well as V are not anonymous functions:
//     "F calls V"
//   - The same case as above except F calls function G in some other package:
//     "F calls G, which eventually calls V"
//   - If F is an anonymous function, created by function G, and H is the
//     lowest non-anonymous function in topPkgs:
//     "H calls G, which eventually calls V"
//   - If V is an anonymous function, created by function W:
//     "F calls W, which eventually calls V"
//
// If it can't find any of these functions, summarizeTrace returns the empty string.
func summarizeTrace(finding *govulncheck.Finding) string {
	if len(finding.Trace) == 0 {
		return ""
	}
	iTop, iTopEnd := summarizeTop(finding.Trace)
	if iTop < 0 {
		return ""
	}

	vulnPkg := finding.Trace[len(finding.Trace)-1].Package
	iVulnStart, iVuln := summarizeVuln(finding.Trace, iTopEnd, vulnPkg)
	if iVulnStart < 0 {
		return ""
	}

	buf := &strings.Builder{}
	topPos := posToString(finding.Trace[iTop].Position)
	if topPos != "" {
		buf.WriteString(topPos)
		buf.WriteString(": ")
	}

	// The invariant is that the summary will always mention at most three functions
	// and never mention an anonymous function. It prioritizes summarizing top of the
	// stack as that is what the user has the most control of. For instance, if both
	// the top and vuln portions of the stack are each summarized with two functions,
	// then the final summary will mention the two functions of the top segment and
	// only one from the vuln segment.
	iMid := -1
	switch {
	case iTop != iTopEnd:
		// The last function of the top segment is anonymous.
		iMid = iTopEnd
	case iVulnStart != iTopEnd+1:
		// If there is something in between top and vuln segments of
		// the stack, then also summarize that intermediate segment.
		iMid = iTopEnd + 1
	case iVulnStart != iVuln:
		// The first function of the vuln segment is anonymous.
		iMid = iVulnStart
	}

	addSymbolName(buf, finding.Trace[iTop])
	buf.WriteString(" calls ")
	if iMid >= 0 {
		addSymbolName(buf, finding.Trace[iMid])
		buf.WriteString(", which eventually calls ")
	}
	addSymbolName(buf, finding.Trace[iVuln])
	return buf.String()
}

func addSymbolName(buf *strings.Builder, frame *govulncheck.Frame) {
	if frame.Package != "" {
		buf.WriteString(frame.Package)
		buf.WriteString(".")
	}
	if frame.Receiver != "" {
		if frame.Receiver[0] == '*' {
			buf.WriteString(frame.Receiver[1:])
		} else {
			buf.WriteString(frame.Receiver)
		}
		buf.WriteString(".")
	}
	funcname := strings.Split(frame.Function, "$")[0]
	buf.WriteString(funcname)
}

// summarizeTop returns summary information for the beginning segment
// of call stack frames that belong to topPkgs. It returns the latest,
// e.g., lowest function in this segment and its index in frames. If
// that function is anonymous, then summarizeTop also returns the
// lowest non-anonymous function and its index in frames. In that case,
// the anonymous function is replaced by the function that created it.
//
//	[p.V p.W q.Q ...]        -> (1, 1, p.W, p.W)
//	[p.V p.W p.Z$1 q.Q ...]  -> (1, 2, p.W, p.Z)
func summarizeTop(frames []*govulncheck.Frame) (iTop, iTopEnd int) {
	topModule := frames[0].Module
	iTopEnd = lowest(frames, func(e *govulncheck.Frame) bool {
		return e.Module == topModule
	})
	if iTopEnd < 0 {
		return -1, -1
	}

	if !isAnonymousFunction(frames[iTopEnd].Function) {
		iTop = iTopEnd
		return
	}

	iTop = lowest(frames, func(e *govulncheck.Frame) bool {
		return e.Module == topModule && !isAnonymousFunction(e.Function)
	})
	if iTop < 0 {
		iTop = iTopEnd
		return
	}
	return
}

// summarizeVuln returns summary information for the final segment
// of call stack frames that belong to vulnPkg. It returns the earliest,
// e.g., highest function in this segment and its index in frames. If
// that function is anonymous, then summarizeVuln also returns the
// highest non-anonymous function. In that case, the anonymous function
// is replaced by the function that created it.
//
//	[x x q.Q v.V v.W]   -> (3, v.V, v.V)
//	[x x q.Q v.V$1 v.W] -> (3, v.V, v.W)
func summarizeVuln(frames []*govulncheck.Frame, iTop int, vulnPkg string) (iVulnStart int, iVuln int) {
	iVulnStart = highest(frames[iTop+1:], func(e *govulncheck.Frame) bool {
		return e.Package == vulnPkg
	})
	if iVulnStart < 0 {
		return -1, -1
	}
	iVulnStart += iTop + 1 // adjust for slice in call to highest.
	if !isAnonymousFunction(frames[iVulnStart].Function) {
		iVuln = iVulnStart
		return
	}

	iVuln = highest(frames[iVulnStart:], func(e *govulncheck.Frame) bool {
		return e.Package == vulnPkg && !isAnonymousFunction(e.Function)
	})
	if iVuln < 0 {
		iVuln = iVulnStart
		return
	}
	iVuln += iVulnStart
	return
}

// updateInitPositions populates non-existing positions of init functions
// and their respective calls in callStacks (see #51575).
func updateInitPositions(callStacks map[*vulncheck.Vuln][]vulncheck.CallStack) {
	for _, css := range callStacks {
		for _, cs := range css {
			for i := range cs {
				updateInitPosition(&cs[i])
				if i != len(cs)-1 {
					updateInitCallPosition(&cs[i], cs[i+1])
				}
			}
		}
	}
}

// updateInitCallPosition updates the position of a call to init in a stack frame, if
// one already does not exist:
//
//	P1.init -> P2.init: position of call to P2.init is the position of "import P2"
//	statement in P1
//
//	P.init -> P.init#d: P.init is an implicit init. We say it calls the explicit
//	P.init#d at the place of "package P" statement.
func updateInitCallPosition(curr *vulncheck.StackEntry, next vulncheck.StackEntry) {
	call := curr.Call
	if !isInit(next.Function) || (call.Pos != nil && call.Pos.IsValid()) {
		// Skip non-init functions and inits whose call site position is available.
		return
	}

	var pos token.Position
	if curr.Function.Name == "init" && curr.Function.Package == next.Function.Package {
		// We have implicit P.init calling P.init#d. Set the call position to
		// be at "package P" statement position.
		pos = packageStatementPos(curr.Function.Package)
	} else {
		// Choose the beginning of the import statement as the position.
		pos = importStatementPos(curr.Function.Package, next.Function.Package.PkgPath)
	}

	call.Pos = &pos
}

func importStatementPos(pkg *packages.Package, importPath string) token.Position {
	var importSpec *ast.ImportSpec
spec:
	for _, f := range pkg.Syntax {
		for _, impSpec := range f.Imports {
			// Import spec paths have quotation marks.
			impSpecPath, err := strconv.Unquote(impSpec.Path.Value)
			if err != nil {
				panic(fmt.Sprintf("import specification: package path has no quotation marks: %v", err))
			}
			if impSpecPath == importPath {
				importSpec = impSpec
				break spec
			}
		}
	}

	if importSpec == nil {
		// for sanity, in case of a wild call graph imprecision
		return token.Position{}
	}

	// Choose the beginning of the import statement as the position.
	return pkg.Fset.Position(importSpec.Pos())
}

func packageStatementPos(pkg *packages.Package) token.Position {
	if len(pkg.Syntax) == 0 {
		return token.Position{}
	}
	// Choose beginning of the package statement as the position. Pick
	// the first file since it is as good as any.
	return pkg.Fset.Position(pkg.Syntax[0].Package)
}

// updateInitPosition updates the position of P.init function in a stack frame if one
// is not available. The new position is the position of the "package P" statement.
func updateInitPosition(se *vulncheck.StackEntry) {
	fun := se.Function
	if !isInit(fun) || (fun.Pos != nil && fun.Pos.IsValid()) {
		// Skip non-init functions and inits whose position is available.
		return
	}

	pos := packageStatementPos(fun.Package)
	fun.Pos = &pos
}

func isInit(f *vulncheck.FuncNode) bool {
	// A source init function, or anonymous functions used in inits, will
	// be named "init#x" by vulncheck (more precisely, ssa), where x is a
	// positive integer. Implicit inits are named simply "init".
	return f.Name == "init" || strings.HasPrefix(f.Name, "init#")
}

func isAnonymousFunction(funcName string) bool {
	// anonymous functions have $ sign in their name (naming done by ssa)
	return strings.ContainsRune(funcName, '$')
}

// uniqueCallStack returns the first unique call stack among css, if any.
// Unique means that the call stack does not go through symbols of vg.
func uniqueCallStack(v *vulncheck.Vuln, css []vulncheck.CallStack, vg []*vulncheck.Vuln) vulncheck.CallStack {
	vulnFuncs := make(map[*vulncheck.FuncNode]bool)
	for _, v := range vg {
		vulnFuncs[v.CallSink] = true
	}

callstack:
	for _, cs := range css {
		for _, e := range cs {
			if e.Function != v.CallSink && vulnFuncs[e.Function] {
				continue callstack
			}
		}
		return cs
	}
	return nil
}
