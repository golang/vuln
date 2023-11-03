// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
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
//
// It does not emit imported symbols. Only the package information is emitted.
func emitPackageFindings(handler govulncheck.Handler, vulns []*Vuln) error {
	emitted := make(map[Vuln]bool)
	for _, vuln := range vulns {
		v := Vuln{
			Package: vuln.Package,
			OSV:     vuln.OSV,
		}
		if emitted[v] {
			// do not emit the same finding all over again
			continue
		}
		emitted[v] = true

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
			Trace:        tracefromEntries(stack),
		}); err != nil {
			return err
		}
	}
	return nil
}

// tracefromEntries creates a sequence of
// frames from vcs. Position of a Frame is the
// call position of the corresponding stack entry.
func tracefromEntries(vcs CallStack) []*govulncheck.Frame {
	var frames []*govulncheck.Frame
	for i := len(vcs) - 1; i >= 0; i-- {
		e := vcs[i]
		fr := frameFromPackage(e.Function.Package)
		fr.Function = e.Function.Name
		fr.Receiver = e.Function.Receiver()
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

func emitBinaryResult(handler govulncheck.Handler, vr *Result, callstacks map[*Vuln]CallStack) error {
	// first deal with all the affected vulnerabilities
	emitted := map[string]bool{}
	for _, vv := range vr.Vulns {
		fixed := FixedVersion(modPath(vv.Package.Module), modVersion(vv.Package.Module), vv.OSV.Affected)
		stack := callstacks[vv]
		if stack == nil {
			continue
		}
		emitted[vv.OSV.ID] = true
		if err := handler.Finding(&govulncheck.Finding{
			OSV:          vv.OSV.ID,
			FixedVersion: fixed,
			Trace:        tracefromEntries(stack),
		}); err != nil {
			return err
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
		if err := handler.Finding(&govulncheck.Finding{
			OSV:          vv.OSV.ID,
			FixedVersion: FixedVersion(modPath(vv.Package.Module), modVersion(vv.Package.Module), vv.OSV.Affected),
			Trace:        []*govulncheck.Frame{frameFromPackage(vv.Package)},
		}); err != nil {
			return err
		}
	}
	return nil
}
