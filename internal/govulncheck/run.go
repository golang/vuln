// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"fmt"
	"go/token"
	"io"
	"sort"

	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

// Source reports vulnerabilities that affect the analyzed packages.
//
// Vulnerabilities can be called (affecting the package, because a vulnerable
// symbol is actually exercised) or just imported by the package
// (likely having a non-affecting outcome).
//
// This function is used for source code analysis by cmd/govulncheck and
// exp/govulncheck.
func Source(ctx context.Context, cfg *Config, pkgs []*vulncheck.Package) (*Result, error) {
	vcfg := &vulncheck.Config{
		Client:          cfg.Client,
		SourceGoVersion: cfg.GoVersion,
	}
	vr, err := vulncheck.Source(ctx, pkgs, vcfg)
	if err != nil {
		return nil, err
	}
	return createSourceResult(vr, pkgs), nil
}

// Binary detects presence of vulnerable symbols in exe.
//
// This function is used for binary analysis by cmd/govulncheck.
func Binary(ctx context.Context, cfg *Config, exe io.ReaderAt) (*Result, error) {
	vcfg := &vulncheck.Config{
		Client: cfg.Client,
	}
	vr, err := binary(ctx, exe, vcfg)
	if err != nil {
		return nil, err
	}
	return createBinaryResult(vr), nil
}

func createSourceResult(vr *vulncheck.Result, pkgs []*vulncheck.Package) *Result {
	topPkgs := map[string]bool{}
	for _, p := range pkgs {
		topPkgs[p.PkgPath] = true
	}
	modVersions := moduleVersionMap(vr.Modules)
	callStacks := vulncheck.CallStacks(vr)

	type key struct {
		id  string
		pkg string
		mod string
	}
	// Collect all called symbols for a package.
	// Needed for creating unique call stacks.
	vulnsPerPkg := make(map[key][]*vulncheck.Vuln)
	for _, vv := range vr.Vulns {
		if vv.CallSink != 0 {
			k := key{id: vv.OSV.ID, pkg: vv.PkgPath, mod: vv.ModPath}
			vulnsPerPkg[k] = append(vulnsPerPkg[k], vv)
		}
	}

	// Create Result where each vulncheck.Vuln{OSV, ModPath, PkgPath} becomes
	// a separate Vuln{OSV, Modules{Packages{PkgPath}}} entry. We merge the
	// results later.
	r := &Result{}
	for _, vv := range vr.Vulns {
		p := &Package{Path: vv.PkgPath}
		m := &Module{
			Path:         vv.ModPath,
			FoundVersion: foundVersion(vv.ModPath, modVersions),
			FixedVersion: fixedVersion(vv.ModPath, vv.OSV.Affected),
			Packages:     []*Package{p},
		}
		v := &Vuln{OSV: vv.OSV, Modules: []*Module{m}}

		if vv.CallSink != 0 {
			k := key{id: vv.OSV.ID, pkg: vv.PkgPath, mod: vv.ModPath}
			vcs := uniqueCallStack(vv, callStacks[vv], vulnsPerPkg[k], vr)
			if vcs != nil {
				cs := CallStack{
					Frames: stackFramesfromEntries(vcs),
					Symbol: vv.Symbol,
				}
				cs.Summary = summarizeCallStack(cs, topPkgs, p.Path)
				p.CallStacks = []CallStack{cs}
			}
		}
		r.Vulns = append(r.Vulns, v)
	}

	r = merge(r)
	sortResult(r)
	return r
}

func createBinaryResult(vr *vulncheck.Result) *Result {
	modVersions := moduleVersionMap(vr.Modules)
	// Create Result where each vulncheck.Vuln{OSV, ModPath, PkgPath} becomes
	// a separate Vuln{OSV, Modules{Packages{PkgPath}}} entry. We merge the
	// results later.
	r := &Result{}
	for _, vv := range vr.Vulns {
		p := &Package{Path: vv.PkgPath}
		// in binary mode, call stacks contain just the symbol data
		p.CallStacks = []CallStack{{Symbol: vv.Symbol}}
		m := &Module{
			Path:         vv.ModPath,
			FoundVersion: foundVersion(vv.ModPath, modVersions),
			FixedVersion: fixedVersion(vv.ModPath, vv.OSV.Affected),
			Packages:     []*Package{p},
		}
		v := &Vuln{OSV: vv.OSV, Modules: []*Module{m}}
		r.Vulns = append(r.Vulns, v)
	}

	r = merge(r)
	sortResult(r)
	return r
}

// merge takes r and creates a Result where duplicate
// vulns, modules, and packages are merged together.
// For instance, Vulns with the same OSV field are
// merged into a single one. The same applies for
// Modules of a Vuln, and Packages of a Module.
func merge(r *Result) *Result {
	nr := &Result{}
	// merge vulns by their ID. Note that there can
	// be several OSVs with the same ID but different
	// pointer values
	osvs := make(map[string]*osv.Entry)
	vs := make(map[string][]*Module)
	for _, v := range r.Vulns {
		osvs[v.OSV.ID] = v.OSV
		vs[v.OSV.ID] = append(vs[v.OSV.ID], v.Modules...)
	}

	for id, mods := range vs {
		v := &Vuln{OSV: osvs[id], Modules: mods}
		nr.Vulns = append(nr.Vulns, v)
	}

	// merge modules
	for _, v := range nr.Vulns {
		ms := make(map[string][]*Module)
		for _, m := range v.Modules {
			ms[m.Path] = append(ms[m.Path], m)
		}

		var nms []*Module
		for mpath, mods := range ms {
			// modules with the same path must have
			// same found and fixed versions
			validateModuleVersions(mods)
			nm := &Module{
				Path:         mpath,
				FixedVersion: mods[0].FixedVersion,
				FoundVersion: mods[0].FoundVersion,
			}
			for _, mod := range mods {
				nm.Packages = append(nm.Packages, mod.Packages...)
			}
			nms = append(nms, nm)
		}
		v.Modules = nms
	}

	// merge packages
	for _, v := range nr.Vulns {
		for _, m := range v.Modules {
			ps := make(map[string][]*Package)
			for _, p := range m.Packages {
				ps[p.Path] = append(ps[p.Path], p)
			}

			var nps []*Package
			for ppath, pkgs := range ps {
				np := &Package{Path: ppath}
				for _, p := range pkgs {
					np.CallStacks = append(np.CallStacks, p.CallStacks...)
				}
				nps = append(nps, np)
			}
			m.Packages = nps
		}
	}
	return nr
}

// validateModuleVersions checks that all modules have
// the same found and fixed version. If not, panics.
func validateModuleVersions(modules []*Module) {
	var found, fixed string
	for i, m := range modules {
		if i == 0 {
			found = m.FoundVersion
			fixed = m.FixedVersion
			continue
		}
		if m.FoundVersion != found || m.FixedVersion != fixed {
			panic(fmt.Sprintf("found or fixed version incompatible for module %s", m.Path))
		}
	}
}

// sortResults sorts Vulns, Modules, and Packages of r.
func sortResult(r *Result) {
	sort.Slice(r.Vulns, func(i, j int) bool {
		return r.Vulns[i].OSV.ID > r.Vulns[j].OSV.ID
	})
	for _, v := range r.Vulns {
		sort.Slice(v.Modules, func(i, j int) bool {
			return v.Modules[i].Path < v.Modules[j].Path
		})
		for _, m := range v.Modules {
			sort.Slice(m.Packages, func(i, j int) bool {
				return m.Packages[i].Path < m.Packages[j].Path
			})
		}
	}
}

// stackFramesFromEntries creates a sequence of stack
// frames from vcs. Position of a StackFrame is the
// call position of the corresponding stack entry.
func stackFramesfromEntries(vcs vulncheck.CallStack) []*StackFrame {
	var frames []*StackFrame
	for _, e := range vcs {
		fr := &StackFrame{
			FuncName: e.Function.Name,
			PkgPath:  e.Function.PkgPath,
			RecvType: e.Function.RecvType,
		}
		if e.Call == nil || e.Call.Pos == nil {
			fr.Position = token.Position{}
		} else {
			fr.Position = *e.Call.Pos
		}
		frames = append(frames, fr)
	}
	return frames
}
