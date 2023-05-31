// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
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
	URL      string
	Modules  []*moduleSummary
	Affected bool
}

type moduleSummary struct {
	IsStd        bool
	Module       string
	FoundVersion string
	FixedVersion string
	Platforms    []string
	Traces       []traceSummary
}

type traceSummary struct {
	Symbol  string
	Compact string
	Trace   []frameSummary
}

type frameSummary struct {
	Symbol   string
	Position string
}

func createSummaries(osvs []*osv.Entry, findings []*govulncheck.Finding) summaries {
	s := summaries{}
	// group findings by osv
	grouped := map[string][]*govulncheck.Finding{}
	var osvids []string
	for _, f := range findings {
		list, found := grouped[f.OSV]
		if !found {
			osvids = append(osvids, f.OSV)
		}
		grouped[f.OSV] = append(list, f)
	}
	// unaffected are (imported) OSVs none of
	// which vulnerabilities are called.
	for _, osvid := range osvids {
		list := grouped[osvid]
		entry := createVulnSummary(osvs, osvid, list)
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

func createVulnSummary(osvs []*osv.Entry, osvid string, findings []*govulncheck.Finding) vulnSummary {
	seen := map[string]struct{}{}
	vInfo := vulnSummary{
		Affected: IsCalled(findings),
		OSV:      osvid,
	}
	osv := findOSV(osvs, osvid)
	if osv != nil {
		vInfo.Details = osv.Details
		if osv.DatabaseSpecific != nil {
			vInfo.URL = osv.DatabaseSpecific.URL
		}
	}
	for _, f := range findings {
		lastFrame := f.Trace[0]
		// find the right module summary, or create it if this is the first stack for that module
		var ms *moduleSummary
		for _, check := range vInfo.Modules {
			if check.Module == lastFrame.Module {
				ms = check
				break
			}
		}
		if ms == nil {
			ms = &moduleSummary{
				IsStd:        lastFrame.Module == internal.GoStdModulePath,
				Module:       lastFrame.Module,
				FoundVersion: moduleVersionString(lastFrame.Module, lastFrame.Package, lastFrame.Version),
				FixedVersion: moduleVersionString(lastFrame.Module, lastFrame.Package, f.FixedVersion),
				Platforms:    platforms(lastFrame.Module, osv),
			}
			vInfo.Modules = append(vInfo.Modules, ms)
		}
		css := newTraceSummary(f)
		if css.Compact == "" {
			continue
		}
		// Suppress duplicate compact call stack summaries.
		// Note that different call stacks can yield same summaries.
		if _, wasSeen := seen[css.Compact]; !wasSeen {
			seen[css.Compact] = struct{}{}
			ms.Traces = append(ms.Traces, css)
		}
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

func newTraceSummary(f *govulncheck.Finding) traceSummary {
	css := traceSummary{
		Compact: summarizeTrace(f),
	}
	if len(f.Trace) == 1 && f.Trace[0].Function == "" {
		return css
	}
	for i := len(f.Trace) - 1; i >= 0; i-- {
		frame := f.Trace[i]
		buf := &strings.Builder{}
		addSymbolName(buf, frame, false)
		css.Trace = append(css.Trace, frameSummary{
			Symbol:   buf.String(),
			Position: posToString(frame.Position),
		})
	}
	css.Symbol = css.Trace[len(css.Trace)-1].Symbol
	return css
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
func wrap(indent string, s string, maxWidth int) string {
	var b strings.Builder
	w := 0
	for _, f := range strings.Fields(s) {
		if w > 0 && w+len(f)+1 > maxWidth {
			// line would be too long with this word
			b.WriteByte('\n')
			w = 0
		}
		if w == 0 {
			// first field on line, indent
			b.WriteString(indent)
			w = len(indent)
		} else {
			// not first word, space separate
			b.WriteByte(' ')
			w++
		}
		// now write the word
		b.WriteString(f)
		w += len(f)
	}
	return b.String()
}
