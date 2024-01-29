// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"go/token"
	"sort"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

// emitOSVs emits all OSV vuln entries in modVulns to handler.
func emitOSVs(handler govulncheck.Handler, modVulns []*ModVulns) error {
	for _, mv := range modVulns {
		for _, v := range mv.Vulns {
			if err := handler.OSV(v); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitModuleFindings emits module-level findings for vulnerabilities in modVulns.
func emitModuleFindings(handler govulncheck.Handler, affVulns affectingVulns) error {
	for _, vuln := range affVulns {
		for _, osv := range vuln.Vulns {
			if err := handler.Finding(&govulncheck.Finding{
				OSV:          osv.ID,
				FixedVersion: FixedVersion(modPath(vuln.Module), modVersion(vuln.Module), osv.Affected),
				Trace:        []*govulncheck.Frame{frameFromModule(vuln.Module, osv.Affected)},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitPackageFinding emits package-level findings fod vulnerabilities in vulns.
func emitPackageFindings(handler govulncheck.Handler, vulns []*Vuln) error {
	for _, v := range vulns {
		if err := handler.Finding(&govulncheck.Finding{
			OSV:          v.OSV.ID,
			FixedVersion: FixedVersion(modPath(v.Package.Module), modVersion(v.Package.Module), v.OSV.Affected),
			Trace:        []*govulncheck.Frame{frameFromPackage(v.Package)},
		}); err != nil {
			return err
		}
	}
	return nil
}

// emitCallFindings emits call-level findings for vulnerabilities
// that have a call stack in callstacks.
func emitCallFindings(handler govulncheck.Handler, callstacks map[*Vuln]CallStack) error {
	var vulns []*Vuln
	for v := range callstacks {
		vulns = append(vulns, v)
	}

	sort.SliceStable(vulns, func(i, j int) bool {
		return vulns[i].Symbol < vulns[j].Symbol
	})

	for _, vuln := range vulns {
		stack := callstacks[vuln]
		if stack == nil {
			continue
		}
		fixed := FixedVersion(modPath(vuln.Package.Module), modVersion(vuln.Package.Module), vuln.OSV.Affected)
		if err := handler.Finding(&govulncheck.Finding{
			OSV:          vuln.OSV.ID,
			FixedVersion: fixed,
			Trace:        traceFromEntries(stack),
		}); err != nil {
			return err
		}
	}
	return nil
}

// traceFromEntries creates a sequence of
// frames from vcs. Position of a Frame is the
// call position of the corresponding stack entry.
func traceFromEntries(vcs CallStack) []*govulncheck.Frame {
	var frames []*govulncheck.Frame
	for i := len(vcs) - 1; i >= 0; i-- {
		e := vcs[i]
		fr := frameFromPackage(e.Function.Package)
		fr.Function = e.Function.Name
		fr.Receiver = e.Function.Receiver()
		isSink := i == (len(vcs) - 1)
		fr.Position = posFromStackEntry(e, isSink)
		frames = append(frames, fr)
	}
	return frames
}

func posFromStackEntry(e StackEntry, sink bool) *govulncheck.Position {
	var p *token.Position
	if sink && e.Function != nil && e.Function.Pos != nil {
		// For sinks, i.e., vulns we take the position
		// of the symbol.
		p = e.Function.Pos
	} else if e.Call != nil && e.Call.Pos != nil {
		// Otherwise, we take the position of
		// the call statement.
		p = e.Call.Pos
	}

	if p == nil {
		return nil
	}
	return &govulncheck.Position{
		Filename: p.Filename,
		Offset:   p.Offset,
		Line:     p.Line,
		Column:   p.Column,
	}
}

func frameFromPackage(pkg *packages.Package) *govulncheck.Frame {
	fr := &govulncheck.Frame{}
	if pkg != nil {
		fr.Module = pkg.Module.Path
		fr.Version = pkg.Module.Version
		fr.Package = pkg.PkgPath
	}
	if pkg.Module.Replace != nil {
		fr.Module = pkg.Module.Replace.Path
		fr.Version = pkg.Module.Replace.Version
	}
	return fr
}

func frameFromModule(mod *packages.Module, affected []osv.Affected) *govulncheck.Frame {
	fr := &govulncheck.Frame{
		Module:  mod.Path,
		Version: mod.Version,
	}

	if mod.Path == internal.GoStdModulePath {
		for _, a := range affected {
			if a.Module.Path != mod.Path {
				continue
			}
			fr.Package = a.EcosystemSpecific.Packages[0].Path
		}
	}

	if mod.Replace != nil {
		fr.Module = mod.Replace.Path
		fr.Version = mod.Replace.Version
	}

	return fr
}
