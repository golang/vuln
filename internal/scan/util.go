// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	isem "golang.org/x/vuln/internal/semver"
	"golang.org/x/vuln/internal/vulncheck"
)

// merge takes r and creates a Result where duplicate
// vulns, modules, and packages are merged together.
// For instance, Vulns with the same OSV field are
// merged into a single one. The same applies for
// Modules of a Vuln, and Packages of a Module.
func merge(findings []*govulncheck.Finding) []*govulncheck.Finding {
	var nr []*govulncheck.Finding
	// merge vulns by their ID. Note that there can
	// be several OSVs with the same ID but different
	// pointer values
	vs := make(map[string][]*govulncheck.Module)
	for _, v := range findings {
		vs[v.OSV] = append(vs[v.OSV], v.Modules...)
	}

	for id, mods := range vs {
		v := &govulncheck.Finding{OSV: id, Modules: mods}
		nr = append(nr, v)
	}

	// merge modules
	for _, v := range nr {
		ms := make(map[string][]*govulncheck.Module)
		for _, m := range v.Modules {
			ms[m.Path] = append(ms[m.Path], m)
		}

		var nms []*govulncheck.Module
		for mpath, mods := range ms {
			// modules with the same path must have
			// same found and fixed versions
			validateModuleVersions(mods)
			nm := &govulncheck.Module{
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
	for _, v := range nr {
		for _, m := range v.Modules {
			ps := make(map[string][]*govulncheck.Package)
			for _, p := range m.Packages {
				ps[p.Path] = append(ps[p.Path], p)
			}

			var nps []*govulncheck.Package
			for ppath, pkgs := range ps {
				np := &govulncheck.Package{Path: ppath}
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
func validateModuleVersions(modules []*govulncheck.Module) {
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
func sortResult(findings []*govulncheck.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].OSV > findings[j].OSV
	})
	for _, v := range findings {
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

// latestFixed returns the latest fixed version in the list of affected ranges,
// or the empty string if there are no fixed versions.
func latestFixed(modulePath string, as []osv.Affected) string {
	v := ""
	for _, a := range as {
		if modulePath != a.Module.Path {
			continue
		}
		fixed := isem.LatestFixedVersion(a.Ranges)
		// Special case: if there is any affected block for this module
		// with no fix, the module is considered unfixed.
		if fixed == "" {
			return ""
		}
		if isem.Less(v, fixed) {
			v = fixed
		}
	}
	return v
}

func foundVersion(vuln *vulncheck.Vuln) string {
	m := vuln.ImportSink.Module
	v := m.Version
	for m.Replace != nil {
		m = m.Replace
		v = m.Version
	}
	if v == "" {
		return ""
	}
	return versionString(m.Path, v[1:])
}

func fixedVersion(modulePath string, affected []osv.Affected) string {
	fixed := latestFixed(modulePath, affected)
	if fixed != "" {
		fixed = versionString(modulePath, fixed)
	}
	return fixed
}

// versionString prepends a version string prefix (`v` or `go`
// depending on the modulePath) to the given semver-style version string.
func versionString(modulePath, version string) string {
	if version == "" {
		return ""
	}
	v := "v" + version
	if modulePath == internal.GoStdModulePath || modulePath == internal.GoCmdModulePath {
		return semverToGoTag(v)
	}
	return v
}

// highest returns the highest (one with the smallest index) entry in the call
// stack for which f returns true.
func highest(cs []*govulncheck.StackFrame, f func(e *govulncheck.StackFrame) bool) int {
	for i := 0; i < len(cs); i++ {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

// lowest returns the lowest (one with the largest index) entry in the call
// stack for which f returns true.
func lowest(cs []*govulncheck.StackFrame, f func(e *govulncheck.StackFrame) bool) int {
	for i := len(cs) - 1; i >= 0; i-- {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

// pkgMap creates a map from package paths to packages for all pkgs
// and their transitive imports.
func pkgMap(pkgs []*packages.Package) map[string]*packages.Package {
	m := make(map[string]*packages.Package)
	var visit func(*packages.Package)
	visit = func(p *packages.Package) {
		if _, ok := m[p.PkgPath]; ok {
			return
		}
		m[p.PkgPath] = p

		for _, i := range p.Imports {
			visit(i)
		}
	}

	for _, p := range pkgs {
		visit(p)
	}
	return m
}

func moduleVersionString(modulePath, version string) string {
	if version == "" {
		return ""
	}
	return fmt.Sprintf("%s@%s", modulePath, version)
}

// indent returns the output of prefixing n spaces to s at every line break,
// except for empty lines. See TestIndent for examples.
func indent(s string, n int) string {
	b := []byte(s)
	var result []byte
	shouldAppend := true
	prefix := strings.Repeat(" ", n)
	for _, c := range b {
		if shouldAppend && c != '\n' {
			result = append(result, prefix...)
		}
		result = append(result, c)
		shouldAppend = c == '\n'
	}
	return string(result)
}
