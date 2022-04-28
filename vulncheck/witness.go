// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"container/list"
	"fmt"
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

	// Call is the call site inducing the stack frame.
	// nil when the frame represents the stack entry point.
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

		for _, cs := range f.CallSites {
			callee := res.Calls.Functions[cs.Parent]
			nStack := &callChain{f: callee, call: cs, child: c}
			if entries[callee.ID] {
				stacks = append(stacks, nStack.CallStack())
			}
			queue.PushBack(nStack)
		}
	}
	return stacks
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
	// At this point we just need to make sure the ordering is deterministic.
	// TODO(zpavlinovic): is there a more meaningful additional ordering?
	return stackStrLess(s1, s2)
}

// stackStrLess compares string representation of stacks.
func stackStrLess(s1, s2 CallStack) bool {
	// Creates a unique string representation of a call stack
	// for comparison purposes only.
	stackStr := func(stack CallStack) string {
		var stackStr []string
		for _, cs := range stack {
			s := cs.Function.String()
			if cs.Call != nil && cs.Call.Pos != nil {
				p := cs.Call.Pos
				s = fmt.Sprintf("%s[%s:%d:%d:%d]", s, p.Filename, p.Line, p.Column, p.Offset)
			}
			stackStr = append(stackStr, s)
		}
		return strings.Join(stackStr, "->")
	}
	return strings.Compare(stackStr(s1), stackStr(s2)) <= 0
}
