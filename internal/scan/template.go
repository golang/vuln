// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"go/token"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

type findingSummary struct {
	*govulncheck.Finding
	Compact string
	OSV     *osv.Entry
}

type summaryCounters struct {
	VulnerabilitiesCalled int
	ModulesCalled         int
	StdlibCalled          bool
}

func fixupFindings(osvs []*osv.Entry, findings []*findingSummary) {
	for _, f := range findings {
		f.OSV = getOSV(osvs, f.Finding.OSV)
	}
}

func groupByVuln(findings []*findingSummary) [][]*findingSummary {
	return groupBy(findings, func(left, right *findingSummary) int {
		return -strings.Compare(left.OSV.ID, right.OSV.ID)
	})
}

func groupByModule(findings []*findingSummary) [][]*findingSummary {
	return groupBy(findings, func(left, right *findingSummary) int {
		return strings.Compare(left.Trace[0].Module, right.Trace[0].Module)
	})
}

func groupBy(findings []*findingSummary, compare func(left, right *findingSummary) int) [][]*findingSummary {
	switch len(findings) {
	case 0:
		return nil
	case 1:
		return [][]*findingSummary{findings}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return compare(findings[i], findings[j]) < 0
	})
	result := [][]*findingSummary{}
	first := 0
	for i, next := range findings {
		if i == first {
			continue
		}
		if compare(findings[first], next) != 0 {
			result = append(result, findings[first:i])
			first = i
		}
	}
	result = append(result, findings[first:])
	return result
}

func counters(findings []*findingSummary) summaryCounters {
	vulns := map[string]struct{}{}
	modules := map[string]struct{}{}
	for _, f := range findings {
		if f.Trace[0].Function == "" {
			continue
		}
		id := f.OSV.ID
		vulns[id] = struct{}{}
		mod := f.Trace[0].Module
		modules[mod] = struct{}{}
	}
	result := summaryCounters{
		VulnerabilitiesCalled: len(vulns),
		ModulesCalled:         len(modules),
	}
	if _, found := modules[internal.GoStdModulePath]; found {
		result.StdlibCalled = true
		result.ModulesCalled--
	}
	return result
}

func isCalled(findings []*findingSummary) bool {
	for _, f := range findings {
		if f.Trace[0].Function != "" {
			return true
		}
	}
	return false
}
func getOSV(osvs []*osv.Entry, id string) *osv.Entry {
	for _, entry := range osvs {
		if entry.ID == id {
			return entry
		}
	}
	return &osv.Entry{
		ID:               id,
		DatabaseSpecific: &osv.DatabaseSpecific{},
	}
}

func newFindingSummary(f *govulncheck.Finding) *findingSummary {
	return &findingSummary{
		Finding: f,
		Compact: compactTrace(f),
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

func symbol(frame *govulncheck.Frame, short bool) string {
	buf := &strings.Builder{}
	addSymbolName(buf, frame, short)
	return buf.String()
}

// compactTrace returns a short description of the call stack.
// It prefers to show you the edge from the top module to other code, along with
// the vulnerable symbol.
// Where the vulnerable symbol directly called by the users code, it will only
// show those two points.
// If the vulnerable symbol is in the users code, it will show the entry point
// and the vulnerable symbol.
func compactTrace(finding *govulncheck.Finding) string {
	if len(finding.Trace) < 1 {
		return ""
	}
	iTop := len(finding.Trace) - 1
	topModule := finding.Trace[iTop].Module
	// search for the exit point of the top module
	for i, frame := range finding.Trace {
		if frame.Module == topModule {
			iTop = i
			break
		}
	}

	if iTop == 0 {
		// all in one module, reset to the end
		iTop = len(finding.Trace) - 1
	}

	buf := &strings.Builder{}
	topPos := posToString(finding.Trace[iTop].Position)
	if topPos != "" {
		buf.WriteString(topPos)
		buf.WriteString(": ")
	}

	if iTop > 0 {
		addSymbolName(buf, finding.Trace[iTop], true)
		buf.WriteString(" calls ")
	}
	if iTop > 1 {
		addSymbolName(buf, finding.Trace[iTop-1], true)
		buf.WriteString(", which")
		if iTop > 2 {
			buf.WriteString(" eventually")
		}
		buf.WriteString(" calls ")
	}
	addSymbolName(buf, finding.Trace[0], true)
	return buf.String()
}

// notIdentifier reports whether ch is an invalid identifier character.
func notIdentifier(ch rune) bool {
	return !('a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' ||
		'0' <= ch && ch <= '9' ||
		ch == '_' ||
		ch >= utf8.RuneSelf && (unicode.IsLetter(ch) || unicode.IsDigit(ch)))
}

// importPathToAssumedName is taken from goimports, it works out the natural imported name
// for a package.
// This is used to get a shorter identifier in the compact stack trace
func importPathToAssumedName(importPath string) string {
	base := path.Base(importPath)
	if strings.HasPrefix(base, "v") {
		if _, err := strconv.Atoi(base[1:]); err == nil {
			dir := path.Dir(importPath)
			if dir != "." {
				base = path.Base(dir)
			}
		}
	}
	base = strings.TrimPrefix(base, "go-")
	if i := strings.IndexFunc(base, notIdentifier); i >= 0 {
		base = base[:i]
	}
	return base
}

func addSymbolName(w io.Writer, frame *govulncheck.Frame, short bool) {
	if frame.Function == "" {
		return
	}
	if frame.Package != "" {
		pkg := frame.Package
		if short {
			pkg = importPathToAssumedName(frame.Package)
		}
		io.WriteString(w, pkg)
		io.WriteString(w, ".")
	}
	if frame.Receiver != "" {
		if frame.Receiver[0] == '*' {
			io.WriteString(w, frame.Receiver[1:])
		} else {
			io.WriteString(w, frame.Receiver)
		}
		io.WriteString(w, ".")
	}
	funcname := strings.Split(frame.Function, "$")[0]
	io.WriteString(w, funcname)
}
