// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"container/list"
	"fmt"
	"go/token"
	"sort"
	"strings"
	"sync"
)

// ImportChain is a slice of packages where each
// subsequent package is imported by its immediate
// predecessor. The chain starts with a client package
// and ends in a package with some known vulnerabilities.
type ImportChain []*PkgNode

// ImportChains returns a slice of representative import chains for
// each vulnerability in res. The returned chains are ordered
// increasingly by their length.
//
// ImportChains performs a breadth-first search of res.RequireGraph starting
// at a vulnerable package and going up until reaching an entry package
// in res.ImportGraph.Entries. During this search, a package is visited
// only once to avoid analyzing every possible import chain. Hence, not
// all import chains are analyzed.
//
// Note that vulnerabilities from the same package will have the same
// slice of identified import chains.
func ImportChains(res *Result) map[*Vuln][]ImportChain {
	// Group vulns per package.
	vPerPkg := make(map[int][]*Vuln)
	for _, v := range res.Vulns {
		vPerPkg[v.ImportSink] = append(vPerPkg[v.ImportSink], v)
	}

	// Collect chains in parallel for every package path.
	var wg sync.WaitGroup
	var mu sync.Mutex
	chains := make(map[*Vuln][]ImportChain)
	for pkgID, vulns := range vPerPkg {
		pID := pkgID
		vs := vulns
		wg.Add(1)
		go func() {
			pChains := importChains(pID, res)
			mu.Lock()
			for _, v := range vs {
				chains[v] = pChains
			}
			mu.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()
	return chains
}

// importChains finds representative chains of package imports
// leading to vulnerable package identified with vulnSinkID.
func importChains(vulnSinkID int, res *Result) []ImportChain {
	if vulnSinkID == 0 {
		return nil
	}

	// Entry packages, needed for finalizing chains.
	entries := make(map[int]bool)
	for _, e := range res.Imports.Entries {
		entries[e] = true
	}

	var chains []ImportChain
	seen := make(map[int]bool)

	queue := list.New()
	queue.PushBack(&importChain{pkg: res.Imports.Packages[vulnSinkID]})
	for queue.Len() > 0 {
		front := queue.Front()
		c := front.Value.(*importChain)
		queue.Remove(front)

		pkg := c.pkg
		if seen[pkg.ID] {
			continue
		}
		seen[pkg.ID] = true

		for _, impBy := range pkg.ImportedBy {
			imp := res.Imports.Packages[impBy]
			newC := &importChain{pkg: imp, child: c}
			// If the next package is an entry, we have
			// a chain to report.
			if entries[imp.ID] {
				chains = append(chains, newC.ImportChain())
			}
			queue.PushBack(newC)
		}
	}
	return chains
}

// importChain models an chain of package imports.
type importChain struct {
	pkg   *PkgNode
	child *importChain
}

// ImportChain converts importChain to ImportChain type.
func (r *importChain) ImportChain() ImportChain {
	if r == nil {
		return nil
	}
	return append([]*PkgNode{r.pkg}, r.child.ImportChain()...)
}

// CallStack is a call stack starting with a client
// function or method and ending with a call to a
// vulnerable symbol.
type CallStack []StackEntry

// StackEntry is an element of a call stack.
type StackEntry struct {
	// Function whose frame is on the stack.
	Function *FuncNode

	// Call is the call site inducing the next stack frame.
	// nil when the frame represents the last frame in the stack.
	Call *CallSite
}

// CallStacks returns representative call stacks for each
// vulnerability in res. The returned call stacks are heuristically
// ordered by how seemingly easy is to understand them: shorter
// call stacks with less dynamic call sites appear earlier in the
// returned slices.
//
// CallStacks performs a breadth-first search of res.CallGraph starting
// at the vulnerable symbol and going up until reaching an entry
// function or method in res.CallGraph.Entries. During this search,
// each function is visited at most once to avoid potential
// exponential explosion. Hence, not all call stacks are analyzed.
func CallStacks(res *Result) map[*Vuln][]CallStack {
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	stacksPerVuln := make(map[*Vuln][]CallStack)
	for _, vuln := range res.Vulns {
		vuln := vuln
		wg.Add(1)
		go func() {
			cs := callStacks(vuln.CallSink, res)
			// sort call stacks by the estimated value to the user
			sort.SliceStable(cs, func(i int, j int) bool { return stackLess(cs[i], cs[j]) })
			mu.Lock()
			stacksPerVuln[vuln] = cs
			mu.Unlock()
			wg.Done()
		}()
	}

	wg.Wait()
	return stacksPerVuln
}

// callStacks finds representative call stacks
// for vulnerable symbol identified with vulnSinkID.
func callStacks(vulnSinkID int, res *Result) []CallStack {
	if vulnSinkID == 0 {
		return nil
	}

	entries := make(map[int]bool)
	for _, e := range res.Calls.Entries {
		entries[e] = true
	}

	var stacks []CallStack
	seen := make(map[int]bool)

	queue := list.New()
	queue.PushBack(&callChain{f: res.Calls.Functions[vulnSinkID]})

	for queue.Len() > 0 {
		front := queue.Front()
		c := front.Value.(*callChain)
		queue.Remove(front)

		f := c.f
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true

		// Pick a single call site for each function in determinstic order.
		// A single call site is sufficient as we visit a function only once.
		for _, cs := range callsites(f.CallSites, res, seen) {
			caller := res.Calls.Functions[cs.Parent]
			nStack := &callChain{f: caller, call: cs, child: c}
			if entries[caller.ID] {
				stacks = append(stacks, nStack.CallStack())
			}
			queue.PushBack(nStack)
		}
	}
	return stacks
}

// callsites picks a call site from sites for each non-visited function.
// For each such function, the smallest (posLess) call site is chosen. The
// returned slice is sorted by caller functions (funcLess). Assumes callee
// of each call site is the same.
func callsites(sites []*CallSite, result *Result, visited map[int]bool) []*CallSite {
	minCs := make(map[int]*CallSite)
	for _, cs := range sites {
		if visited[cs.Parent] {
			continue
		}
		if csLess(cs, minCs[cs.Parent]) {
			minCs[cs.Parent] = cs
		}
	}

	var fs []*FuncNode
	for id := range minCs {
		fs = append(fs, result.Calls.Functions[id])
	}
	sort.SliceStable(fs, func(i, j int) bool { return funcLess(fs[i], fs[j]) })

	var css []*CallSite
	for _, f := range fs {
		css = append(css, minCs[f.ID])
	}
	return css
}

// callChain models a chain of function calls.
type callChain struct {
	call  *CallSite // nil for entry points
	f     *FuncNode
	child *callChain
}

// CallStack converts callChain to CallStack type.
func (c *callChain) CallStack() CallStack {
	if c == nil {
		return nil
	}
	return append(CallStack{StackEntry{Function: c.f, Call: c.call}}, c.child.CallStack()...)
}

// weight computes an approximate measure of how easy is to understand the call
// stack when presented to the client as a witness. The smaller the value, the more
// understandable the stack is. Currently defined as the number of unresolved
// call sites in the stack.
func weight(stack CallStack) int {
	w := 0
	for _, e := range stack {
		if e.Call != nil && !e.Call.Resolved {
			w += 1
		}
	}
	return w
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

// confidence computes an approximate measure of whether the stack
// is realizeable in practice. Currently, it equals the number of call
// sites in stack that go through standard libraries. Such call stacks
// have been experimentally shown to often result in false positives.
func confidence(stack CallStack) int {
	c := 0
	for _, e := range stack {
		if isStdPackage(e.Function.PkgPath) {
			c += 1
		}
	}
	return c
}

// stackLess compares two call stacks in terms of their estimated
// value to the user. Shorter stacks generally come earlier in the ordering.
//
// Two stacks are lexicographically ordered by:
// 1) their estimated level of confidence in being a real call stack,
// 2) their length, and 3) the number of dynamic call sites in the stack.
func stackLess(s1, s2 CallStack) bool {
	if c1, c2 := confidence(s1), confidence(s2); c1 != c2 {
		return c1 < c2
	}

	if len(s1) != len(s2) {
		return len(s1) < len(s2)
	}

	if w1, w2 := weight(s1), weight(s2); w1 != w2 {
		return w1 < w2
	}

	// At this point, the stableness/determinism of
	// sorting is guaranteed by the determinism of
	// the underlying call graph and the call stack
	// search algorithm.
	return true
}

// csLess compares two call sites by their locations and, if needed,
// their string representation.
func csLess(cs1, cs2 *CallSite) bool {
	if cs2 == nil {
		return true
	}

	// fast code path
	if p1, p2 := cs1.Pos, cs2.Pos; p1 != nil && p2 != nil {
		if posLess(*p1, *p2) {
			return true
		}
		if posLess(*p2, *p1) {
			return false
		}
		// for sanity, should not occur in practice
		return fmt.Sprintf("%v.%v", cs1.RecvType, cs2.Name) < fmt.Sprintf("%v.%v", cs2.RecvType, cs2.Name)
	}

	// code path rarely exercised
	if cs2.Pos == nil {
		return true
	}
	if cs1.Pos == nil {
		return false
	}
	// should very rarely occur in practice
	return fmt.Sprintf("%v.%v", cs1.RecvType, cs2.Name) < fmt.Sprintf("%v.%v", cs2.RecvType, cs2.Name)
}

// posLess compares two positions by their line and column number,
// and filename if needed.
func posLess(p1, p2 token.Position) bool {
	if p1.Line < p2.Line {
		return true
	}
	if p2.Line < p1.Line {
		return false
	}

	if p1.Column < p2.Column {
		return true
	}
	if p2.Column < p1.Column {
		return false
	}

	return strings.Compare(p1.Filename, p2.Filename) == -1
}

// funcLess compares two function nodes by locations of
// corresponding functions and, if needed, their string representation.
func funcLess(f1, f2 *FuncNode) bool {
	if p1, p2 := f1.Pos, f2.Pos; p1 != nil && p2 != nil {
		if posLess(*p1, *p2) {
			return true
		}
		if posLess(*p2, *p1) {
			return false
		}
		// for sanity, should not occur in practice
		return f1.String() < f2.String()
	}

	if f2.Pos == nil {
		return true
	}
	if f1.Pos == nil {
		return false
	}
	// should happen only for inits
	return f1.String() < f2.String()
}
