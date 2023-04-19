// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

var (
	//go:embed template/config.tmpl
	introTemplate string

	//go:embed template/output.tmpl
	outputTemplate string
)

// tmplResult is a structure containing summarized govulncheck.Result, passed
// to outputTemplate.
type tmplResult struct {
	Affected        []tmplVulnInfo
	Unaffected      []tmplVulnInfo
	AffectedModules int
	StdlibAffected  bool
}

// createTmplResult transforms Result r into a
// template structure for printing.
func createTmplResult(vulns []*govulncheck.Vuln, verbose, source bool) tmplResult {
	// unaffected are (imported) OSVs, none of which vulnerabilities are called.
	var (
		r      tmplResult
		vInfos []tmplVulnInfo
	)
	topPkgs := topPackages(vulns)
	for _, v := range vulns {
		vInfos = append(vInfos, createTmplVulnInfo(v, verbose, source, topPkgs))
	}
	r.Affected, r.Unaffected = splitVulns(vInfos)
	r.AffectedModules = affectedModules(vInfos)
	r.StdlibAffected = stdlibAffected(vInfos)
	return r
}

func topPackages(vulns []*govulncheck.Vuln) map[string]bool {
	topPkgs := map[string]bool{}
	for _, v := range vulns {
		for _, m := range v.Modules {
			for _, p := range m.Packages {
				for _, c := range p.CallStacks {
					if len(c.Frames) > 0 {
						topPkgs[c.Frames[0].Package] = true
					}
				}
			}
		}
	}
	return topPkgs
}

func splitVulns(vulns []tmplVulnInfo) (affected, unaffected []tmplVulnInfo) {
	for _, a := range vulns {
		if a.Affected {
			affected = append(affected, a)
		} else {
			unaffected = append(unaffected, a)
		}
	}
	return affected, unaffected
}

// AffectedModules returns the number of unique modules
// whose vulnerabilties are detected.
func affectedModules(vulns []tmplVulnInfo) int {
	mods := make(map[string]bool)
	for _, a := range vulns {
		if !a.Affected {
			continue
		}
		for _, m := range a.Modules {
			if !m.IsStd {
				mods[m.Module] = true
			}
		}
	}
	return len(mods)
}

// stdlibAffected tells if some of the vulnerabilities
// detected come from standard library.
func stdlibAffected(vulns []tmplVulnInfo) bool {
	for _, a := range vulns {
		if !a.Affected {
			continue
		}
		for _, m := range a.Modules {
			if m.IsStd {
				return true
			}
		}
	}
	return false
}

// tmplVulnInfo is a vulnerability info
// structure used by the outputTemplate.
type tmplVulnInfo struct {
	ID       string
	Details  string
	Modules  []tmplModVulnInfo
	Affected bool
}

// createTmplVulnInfo creates a template vuln info for
// a vulnerability that is called by source code or
// present in the binary.
func createTmplVulnInfo(v *govulncheck.Vuln, verbose, source bool, topPkgs map[string]bool) tmplVulnInfo {
	vInfo := tmplVulnInfo{
		ID:       v.OSV.ID,
		Details:  v.OSV.Details,
		Affected: !source || IsCalled(v),
	}

	// stacks returns call stack info of p as a
	// string depending on verbose and source mode.
	stacks := func(p *govulncheck.Package) string {
		if !source {
			return ""
		}

		if verbose {
			return verboseCallStacks(p.CallStacks)
		}
		return defaultCallStacks(p.CallStacks, topPkgs)
	}

	for _, m := range v.Modules {
		if m.Path == internal.GoStdModulePath {
			// For stdlib vulnerabilities, we pretend each package
			// is effectively a module because showing "Module: stdlib"
			// to the user is confusing. In most cases, stdlib
			// vulnerabilities affect only one package anyhow.
			for _, p := range m.Packages {
				if source && len(p.CallStacks) == 0 {
					// package symbols not exercised, nothing to do here
					continue
				}
				tm := createTmplModule(m, p.Path, v.OSV)
				tm.Stacks = stacks(p) // for binary mode, this will be ""
				vInfo.Modules = append(vInfo.Modules, tm)
			}
			if len(vInfo.Modules) == 0 {
				p := m.Packages[0]
				tm := createTmplModule(m, p.Path, v.OSV)
				tm.Stacks = stacks(p) // for binary mode, this will be ""
				vInfo.Modules = append(vInfo.Modules, tm)
			}
			continue
		}

		// For third-party packages, we create a single output entry for
		// the whole module by merging call stack info of each exercised
		// package (in source mode).
		var moduleStacks []string
		if source {
			for _, p := range m.Packages {
				if len(p.CallStacks) == 0 {
					// package symbols not exercised, nothing to do here
					continue
				}
				moduleStacks = append(moduleStacks, stacks(p))
			}
		}
		tm := createTmplModule(m, m.Path, v.OSV)
		tm.Stacks = strings.Join(moduleStacks, "\n") // for binary mode, this will be ""
		vInfo.Modules = append(vInfo.Modules, tm)
	}
	return vInfo
}

// tmplModVulnInfo is a module vulnerability
// structure used by the outputTemplate.
type tmplModVulnInfo struct {
	IsStd     bool
	Module    string
	Found     string
	Fixed     string
	Platforms []string
	Stacks    string
}

func createTmplModule(m *govulncheck.Module, path string, osv *osv.Entry) tmplModVulnInfo {
	return tmplModVulnInfo{
		IsStd:     m.Path == internal.GoStdModulePath,
		Module:    path,
		Found:     moduleVersionString(path, m.FoundVersion),
		Fixed:     moduleVersionString(path, m.FixedVersion),
		Platforms: platforms(m.Path, osv),
	}
}

func defaultCallStacks(css []govulncheck.CallStack, topPkgs map[string]bool) string {
	var summaries []string
	for _, cs := range css {
		s := summarizeCallStack(cs, topPkgs)
		summaries = append(summaries, s)
	}

	// Sort call stack summaries and get rid of duplicates.
	// Note that different call stacks can yield same summaries.
	if len(summaries) > 0 {
		sort.Strings(summaries)
		summaries = compact(summaries)
	}
	var b strings.Builder
	for _, s := range summaries {
		b.WriteString(s)
		b.WriteString("\n")
	}
	return b.String()
}

func verboseCallStacks(css []govulncheck.CallStack) string {
	// Display one full call stack for each vuln.
	i := 1
	var b strings.Builder
	for _, cs := range css {
		vf := cs.Frames[len(cs.Frames)-1]
		symbol := vf.Function
		if vf.Receiver != "" {
			symbol = fmt.Sprintf("%s.%s", vf.Receiver, vf.Function)
		}
		b.WriteString(fmt.Sprintf("#%d: for function %s\n", i, symbol))
		for _, e := range cs.Frames {
			b.WriteString(fmt.Sprintf("  %s\n", FuncName(e)))
			if pos := AbsRelShorter(Pos(e)); pos != "" {
				b.WriteString(fmt.Sprintf("      %s\n", pos))
			}
		}
		i++
	}
	return b.String()
}

// platforms returns a string describing the GOOS, GOARCH,
// or GOOS/GOARCH pairs that the vuln affects for a particular
// module mod. If it affects all of them, it returns the empty
// string.
//
// When mod is an empty string, returns platform information for
// all modules of e.
func platforms(mod string, e *osv.Entry) []string {
	if e == nil {
		return nil
	}
	platforms := map[string]bool{}
	for _, a := range e.Affected {
		if mod != "" && a.Module.Path != mod {
			continue
		}
		for _, p := range a.EcosystemSpecific.Packages {
			for _, os := range p.GOOS {
				// In case there are no specific architectures,
				// just list the os entries.
				if len(p.GOARCH) == 0 {
					platforms[os] = true
					continue
				}
				// Otherwise, list all the os+arch combinations.
				for _, arch := range p.GOARCH {
					platforms[os+"/"+arch] = true
				}
			}
			// Cover the case where there are no specific
			// operating systems listed.
			if len(p.GOOS) == 0 {
				for _, arch := range p.GOARCH {
					platforms[arch] = true
				}
			}
		}
	}
	var keys []string
	for k := range platforms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// wrap wraps s to fit in maxWidth by breaking it into lines at whitespace. If a
// single word is longer than maxWidth, it is retained as its own line.
func wrap(s string, maxWidth int) string {
	var b strings.Builder
	w := 0

	for _, f := range strings.Fields(s) {
		if w > 0 && w+len(f)+1 > maxWidth {
			b.WriteByte('\n')
			w = 0
		}
		if w != 0 {
			b.WriteByte(' ')
			w++
		}
		b.WriteString(f)
		w += len(f)
	}
	return b.String()
}
