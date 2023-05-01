// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

type summaries struct {
	Affected        []vulnSummary `json:"affected,omitempty"`
	Unaffected      []vulnSummary `json:"unaffected,omitempty"`
	AffectedModules int           `json:"affected_modules,omitempty"`
	StdlibAffected  bool          `json:"stdlib_affected,omitempty"`
}

type vulnSummary struct {
	OSV      string
	Details  string
	Modules  []moduleSummary
	Affected bool
}

type moduleSummary struct {
	IsStd        bool
	Module       string
	FoundVersion string
	FixedVersion string
	Platforms    []string
	CallStacks   []callStackSummary
}

type callStackSummary struct {
	Symbol  string
	Compact string
	Frames  []stackFrameSummary
	// Suppressed is true for entries who's compact form would be a repetition
	Suppressed bool
}

type stackFrameSummary struct {
	Symbol   string
	Name     string
	Position string
}

func topPackages(vulns []*govulncheck.Finding) map[string]bool {
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

func createSummaries(osvs []*osv.Entry, vulns []*govulncheck.Finding) summaries {
	s := summaries{}
	findings := merge(vulns)
	sortResult(findings)
	topPkgs := topPackages(vulns)
	// unaffected are (imported) OSVs none of
	// which vulnerabilities are called.
	for _, v := range findings {
		entry := createVulnSummary(osvs, v, topPkgs)
		if entry.Affected {
			s.Affected = append(s.Affected, entry)
		} else {
			s.Unaffected = append(s.Unaffected, entry)
		}
	}

	mods := make(map[string]struct{})
	for _, a := range s.Affected {
		for _, m := range a.Modules {
			if m.IsStd {
				s.StdlibAffected = true
			} else {
				mods[m.Module] = struct{}{}
			}
		}
	}
	s.AffectedModules = len(mods)
	return s
}

func createVulnSummary(osvs []*osv.Entry, v *govulncheck.Finding, topPkgs map[string]bool) vulnSummary {
	vInfo := vulnSummary{
		Affected: IsCalled(v),
		OSV:      v.OSV,
	}
	osv := findOSV(osvs, v.OSV)
	if osv != nil {
		vInfo.Details = osv.Details
	}

	for _, m := range v.Modules {
		if m.Path == internal.GoStdModulePath {
			// For stdlib vulnerabilities, we pretend each package
			// is effectively a module because showing "Module: stdlib"
			// to the user is confusing. In most cases, stdlib
			// vulnerabilities affect only one package anyhow.
			for _, p := range m.Packages {
				if len(p.CallStacks) == 0 {
					// package symbols not exercised, nothing to do here
					continue
				}
				tm := createModuleSummary(m, p.Path, osv)
				addStacks(&tm, p, topPkgs)
				attachModule(&vInfo, tm)
			}
			if len(vInfo.Modules) == 0 && len(m.Packages) > 0 {
				p := m.Packages[0]
				tm := createModuleSummary(m, p.Path, osv)
				addStacks(&tm, p, topPkgs) // for binary mode, this will be ""
				attachModule(&vInfo, tm)
			}
			continue
		}

		// For third-party packages, we create a single output entry for
		// the whole module by merging call stack info of each exercised
		// package (in source mode).
		tm := createModuleSummary(m, m.Path, osv)
		for _, p := range m.Packages {
			addStacks(&tm, p, topPkgs)
		}
		attachModule(&vInfo, tm)
	}
	return vInfo
}

func findOSV(osvs []*osv.Entry, id string) *osv.Entry {
	for _, entry := range osvs {
		if entry.ID == id {
			return entry
		}
	}
	return nil
}

func createModuleSummary(m *govulncheck.Module, path string, oe *osv.Entry) moduleSummary {
	return moduleSummary{
		IsStd:        m.Path == internal.GoStdModulePath,
		Module:       path,
		FoundVersion: moduleVersionString(path, m.FoundVersion),
		FixedVersion: moduleVersionString(path, m.FixedVersion),
		Platforms:    platforms(m.Path, oe),
	}
}

func attachModule(s *vulnSummary, m moduleSummary) {
	// Suppress duplicate compact call stack summaries.
	// Note that different call stacks can yield same summaries.
	seen := map[string]struct{}{}
	for i, css := range m.CallStacks {
		if _, wasSeen := seen[css.Compact]; !wasSeen {
			seen[css.Compact] = struct{}{}
		} else {
			m.CallStacks[i].Suppressed = true
		}
	}
	s.Modules = append(s.Modules, m)
}

func addStacks(m *moduleSummary, p *govulncheck.Package, topPkgs map[string]bool) {
	for _, cs := range p.CallStacks {
		if len(cs.Frames) == 0 {
			continue
		}
		css := callStackSummary{
			Compact: summarizeCallStack(cs, topPkgs),
		}
		for _, e := range cs.Frames {
			symbol := e.Function
			if e.Receiver != "" {
				symbol = fmt.Sprint(e.Receiver, ".", symbol)
			}
			css.Frames = append(css.Frames, stackFrameSummary{
				Symbol:   symbol,
				Name:     FuncName(e),
				Position: posToString(e.Position),
			})
		}
		css.Symbol = css.Frames[len(css.Frames)-1].Symbol
		m.CallStacks = append(m.CallStacks, css)
	}
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

func posToString(p *govulncheck.Position) string {
	if p == nil || p.Line <= 0 {
		return ""
	}
	return token.Position{
		Filename: AbsRelShorter(p.Filename),
		Offset:   p.Offset,
		Line:     p.Line,
		Column:   p.Column,
	}.String()
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
