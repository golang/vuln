// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/vulncheck"
)

// updateInitPositions populates non-existing positions of init functions
// and their respective calls in callStacks (see #51575).
func updateInitPositions(callStacks map[*vulncheck.Vuln][]vulncheck.CallStack, pkgs []*vulncheck.Package) {
	pMap := pkgMap(pkgs)
	for _, css := range callStacks {
		for _, cs := range css {
			for i, _ := range cs {
				updateInitPosition(&cs[i], pMap)
				if i != len(cs)-1 {
					updateInitCallPosition(&cs[i], cs[i+1], pMap)
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
func updateInitCallPosition(curr *vulncheck.StackEntry, next vulncheck.StackEntry, pkgs map[string]*vulncheck.Package) {
	call := curr.Call
	if !isInit(next.Function) || (call.Pos != nil && call.Pos.IsValid()) {
		// Skip non-init functions and inits whose call site position is available.
		return
	}

	pkg := pkgs[curr.Function.PkgPath]
	var pos token.Position
	if curr.Function.Name == "init" && curr.Function.PkgPath == next.Function.PkgPath {
		// We have implicit P.init calling P.init#d. Set the call position to
		// be at "package P" statement position.
		pos = packageStatementPos(pkg)
	} else {
		// Choose the beginning of the import statement as the position.
		pos = importStatementPos(pkg, next.Function.PkgPath)
	}

	call.Pos = &pos
}

func importStatementPos(pkg *vulncheck.Package, importPath string) token.Position {
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

func packageStatementPos(pkg *vulncheck.Package) token.Position {
	if len(pkg.Syntax) == 0 {
		return token.Position{}
	}
	// Choose beginning of the package statement as the position. Pick
	// the first file since it is as good as any.
	return pkg.Fset.Position(pkg.Syntax[0].Package)
}

// updateInitPosition updates the position of P.init function in a stack frame if one
// is not available. The new position is the position of the "package P" statement.
func updateInitPosition(se *vulncheck.StackEntry, pkgs map[string]*vulncheck.Package) {
	fun := se.Function
	if !isInit(fun) || (fun.Pos != nil && fun.Pos.IsValid()) {
		// Skip non-init functions and inits whose position is available.
		return
	}

	pos := packageStatementPos(pkgs[fun.PkgPath])
	fun.Pos = &pos
}

func isInit(f *vulncheck.FuncNode) bool {
	// A source init function, or anonymous functions used in inits, will
	// be named "init#x" by vulncheck (more precisely, ssa), where x is a
	// positive integer. Implicit inits are named simply "init".
	return f.Name == "init" || strings.HasPrefix(f.Name, "init#")
}

// summarizeCallStack returns a short description of the call stack.
// It uses one of four forms, depending on what the lowest function F
// in topPkgs calls and what is the highest function V of vulnPkg:
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
// If it can't find any of these functions, summarizeCallStack returns the empty string.
func summarizeCallStack(cs CallStack, topPkgs map[string]bool, vulnPkg string) string {
	iTop, iTopEnd, topFunc, topEndFunc := summarizeTop(cs.Frames, topPkgs)
	if iTop < 0 {
		return ""
	}

	iVulnStart, vulnStartFunc, vulnFunc := summarizeVuln(cs.Frames, iTopEnd, vulnPkg)
	if iVulnStart < 0 {
		return ""
	}

	topPos := internal.AbsRelShorter(cs.Frames[iTop].Pos())
	if topPos != "" {
		topPos += ": "
	}

	// The invariant is that the summary will always mention at most three functions
	// and never mention an anonymous function. It prioritizes summarizing top of the
	// stack as that is what the user has the most control of. For instance, if both
	// the top and vuln portions of the stack are each summarized with two functions,
	// then the final summary will mention the two functions of the top segment and
	// only one from the vuln segment.
	if topFunc != topEndFunc {
		// The last function of the top segment is anonymous.
		return fmt.Sprintf("%s%s calls %s, which eventually calls %s", topPos, topFunc, topEndFunc, vulnFunc)
	}
	if iVulnStart != iTopEnd+1 {
		// If there is something in between top and vuln segments of
		// the stack, then also summarize that intermediate segment.
		return fmt.Sprintf("%s%s calls %s, which eventually calls %s", topPos, topFunc, cs.Frames[iTopEnd+1].Name(), vulnFunc)
	}
	if vulnStartFunc != vulnFunc {
		// The first function of the vuln segment is anonymous.
		return fmt.Sprintf("%s%s calls %s, which eventually calls %s", topPos, topFunc, vulnStartFunc, vulnFunc)
	}
	return fmt.Sprintf("%s%s calls %s", topPos, topFunc, vulnFunc)
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
func summarizeTop(frames []*StackFrame, topPkgs map[string]bool) (iTop, iTopEnd int, topFunc, topEndFunc string) {
	iTopEnd = lowest(frames, func(e *StackFrame) bool {
		return topPkgs[e.PkgPath]
	})
	if iTopEnd < 0 {
		return -1, -1, "", ""
	}

	topEndFunc = frames[iTopEnd].Name()
	if !isAnonymousFunction(topEndFunc) {
		iTop = iTopEnd
		topFunc = topEndFunc
		return
	}

	topEndFunc = creatorName(topEndFunc)

	iTop = lowest(frames, func(e *StackFrame) bool {
		return topPkgs[e.PkgPath] && !isAnonymousFunction(e.FuncName)
	})
	if iTop < 0 {
		iTop = iTopEnd
		topFunc = topEndFunc // for sanity
		return
	}

	topFunc = frames[iTop].Name()
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
func summarizeVuln(frames []*StackFrame, iTop int, vulnPkg string) (iVulnStart int, vulnStartFunc, vulnFunc string) {
	iVulnStart = highest(frames[iTop+1:], func(e *StackFrame) bool {
		return e.PkgPath == vulnPkg
	})
	if iVulnStart < 0 {
		return -1, "", ""
	}
	iVulnStart += iTop + 1 // adjust for slice in call to highest.

	vulnStartFunc = frames[iVulnStart].Name()
	if !isAnonymousFunction(vulnStartFunc) {
		vulnFunc = vulnStartFunc
		return
	}

	vulnStartFunc = creatorName(vulnStartFunc)

	iVuln := highest(frames[iVulnStart:], func(e *StackFrame) bool {
		return e.PkgPath == vulnPkg && !isAnonymousFunction(e.FuncName)
	})
	if iVuln < 0 {
		vulnFunc = vulnStartFunc // for sanity
		return
	}

	vulnFunc = frames[iVuln+iVulnStart].Name()
	return
}

// creatorName returns the name of the function that created
// the anonymous function anonFuncName. Assumes anonFuncName
// is of the form <name>$1...
func creatorName(anonFuncName string) string {
	vs := strings.Split(anonFuncName, "$")
	if len(vs) == 1 {
		return anonFuncName
	}
	return vs[0]
}

func isAnonymousFunction(funcName string) bool {
	// anonymous functions have $ sign in their name (naming done by ssa)
	return strings.ContainsRune(funcName, '$')
}

// uniqueCallStack returns the first unique call stack among css, if any.
// Unique means that the call stack does not go through symbols of vg.
func uniqueCallStack(v *vulncheck.Vuln, css []vulncheck.CallStack, vg []*vulncheck.Vuln, r *vulncheck.Result) vulncheck.CallStack {
	vulnFuncs := make(map[*vulncheck.FuncNode]bool)
	for _, v := range vg {
		vulnFuncs[r.Calls.Functions[v.CallSink]] = true
	}

	vulnFunc := r.Calls.Functions[v.CallSink]
callstack:
	for _, cs := range css {
		for _, e := range cs {
			if e.Function != vulnFunc && vulnFuncs[e.Function] {
				continue callstack
			}
		}
		return cs
	}
	return nil
}
