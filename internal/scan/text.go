// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/vulncheck"
)

type style int

const (
	defaultStyle = style(iota)
	osvCalledStyle
	osvImportedStyle
	detailsStyle
	sectionStyle
	keyStyle
	valueStyle
)

// NewtextHandler returns a handler that writes govulncheck output as text.
func NewTextHandler(w io.Writer) *TextHandler {
	return &TextHandler{w: w}
}

type TextHandler struct {
	w         io.Writer
	osvs      []*osv.Entry
	findings  []*findingSummary
	scanLevel govulncheck.ScanLevel

	err error

	showColor    bool
	showTraces   bool
	showVersion  bool
	showAllVulns bool
}

const (
	detailsMessage = `For details, see https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.`

	binaryProgressMessage = `Scanning your binary for known vulnerabilities...`

	noVulnsMessage = `No vulnerabilities found.`

	noOtherVulnsMessage = `No other vulnerabilities found.`

	verboseMessage = `'-show verbose' for more details`

	symbolMessage = `'-scan symbol' for more fine grained vulnerability detection`
)

func (h *TextHandler) Show(show []string) {
	for _, show := range show {
		switch show {
		case "traces":
			h.showTraces = true
		case "color":
			h.showColor = true
		case "version":
			h.showVersion = true
		case "verbose":
			h.showAllVulns = true
		}
	}
}

func Flush(h govulncheck.Handler) error {
	if th, ok := h.(interface{ Flush() error }); ok {
		return th.Flush()
	}
	return nil
}

func (h *TextHandler) Flush() error {
	if len(h.findings) == 0 {
		h.print(noVulnsMessage + "\n")
	} else {
		fixupFindings(h.osvs, h.findings)
		counters := h.allVulns(h.findings)
		h.summary(counters)
	}
	if h.err != nil {
		return h.err
	}
	// We found vulnerabilities when the findings' level matches the scan level.
	if (isCalled(h.findings) && h.scanLevel == govulncheck.ScanLevelSymbol) ||
		(isImported(h.findings) && h.scanLevel == govulncheck.ScanLevelPackage) ||
		(isRequired(h.findings) && h.scanLevel == govulncheck.ScanLevelModule) {
		return errVulnerabilitiesFound
	}

	return nil
}

// Config writes version information only if --version was set.
func (h *TextHandler) Config(config *govulncheck.Config) error {
	if config.ScanLevel != "" {
		h.scanLevel = config.ScanLevel
	}
	if !h.showVersion {
		return nil
	}
	if config.GoVersion != "" {
		h.style(keyStyle, "Go: ")
		h.print(config.GoVersion, "\n")
	}
	if config.ScannerName != "" {
		h.style(keyStyle, "Scanner: ")
		h.print(config.ScannerName)
		if config.ScannerVersion != "" {
			h.print(`@`, config.ScannerVersion)
		}
		h.print("\n")
	}
	if config.DB != "" {
		h.style(keyStyle, "DB: ")
		h.print(config.DB, "\n")
		if config.DBLastModified != nil {
			h.style(keyStyle, "DB updated: ")
			h.print(*config.DBLastModified, "\n")
		}
	}
	h.print("\n")
	return h.err
}

// Progress writes progress updates during govulncheck execution.
func (h *TextHandler) Progress(progress *govulncheck.Progress) error {
	h.print(progress.Message, "\n\n")
	return h.err
}

// OSV gathers osv entries to be written.
func (h *TextHandler) OSV(entry *osv.Entry) error {
	h.osvs = append(h.osvs, entry)
	return nil
}

// Finding gathers vulnerability findings to be written.
func (h *TextHandler) Finding(finding *govulncheck.Finding) error {
	if err := validateFindings(finding); err != nil {
		return err
	}
	h.findings = append(h.findings, newFindingSummary(finding))
	return nil
}

func (h *TextHandler) allVulns(findings []*findingSummary) summaryCounters {
	byVuln := groupByVuln(findings)
	var called, imported, required [][]*findingSummary
	mods := map[string]struct{}{}
	stdlibCalled := false
	for _, findings := range byVuln {
		switch {
		case isStdFindings(findings):
			if isCalled(findings) {
				called = append(called, findings)
				stdlibCalled = true
			} else {
				required = append(required, findings)
			}
		case isCalled(findings):
			called = append(called, findings)
			mods[findings[0].Trace[0].Module] = struct{}{}
		case isImported(findings):
			imported = append(imported, findings)
		default:
			required = append(required, findings)
		}
	}

	if h.scanLevel.WantSymbols() {
		h.style(sectionStyle, "=== Symbol Results ===\n\n")
		if len(called) == 0 {
			h.print(noVulnsMessage, "\n\n")
		}
		for index, findings := range called {
			h.vulnerability(index, findings)
		}
	}

	if h.scanLevel == govulncheck.ScanLevelPackage || (h.scanLevel.WantPackages() && h.showAllVulns) {
		h.style(sectionStyle, "=== Package Results ===\n\n")
		if len(imported) == 0 {
			h.print(choose(!h.scanLevel.WantSymbols(), noVulnsMessage, noOtherVulnsMessage), "\n\n")
		}
		for index, findings := range imported {
			h.vulnerability(index, findings)
		}
	}

	if h.showAllVulns || h.scanLevel == govulncheck.ScanLevelModule {
		h.style(sectionStyle, "=== Module Results ===\n\n")
		if len(required) == 0 {
			h.print(choose(!h.scanLevel.WantPackages(), noVulnsMessage, noOtherVulnsMessage), "\n\n")
		}
		for index, findings := range required {
			h.vulnerability(index, findings)
		}
	}

	return summaryCounters{
		VulnerabilitiesCalled:   len(called),
		VulnerabilitiesImported: len(imported),
		VulnerabilitiesRequired: len(required),
		ModulesCalled:           len(mods),
		StdlibCalled:            stdlibCalled,
	}
}

func (h *TextHandler) vulnerability(index int, findings []*findingSummary) {
	h.style(keyStyle, "Vulnerability")
	h.print(" #", index+1, ": ")
	if isCalled(findings) {
		h.style(osvCalledStyle, findings[0].OSV.ID)
	} else {
		h.style(osvImportedStyle, findings[0].OSV.ID)
	}
	h.print("\n")
	h.style(detailsStyle)
	description := findings[0].OSV.Summary
	if description == "" {
		description = findings[0].OSV.Details
	}
	h.wrap("    ", description, 80)
	h.style(defaultStyle)
	h.print("\n")
	h.style(keyStyle, "  More info:")
	h.print(" ", findings[0].OSV.DatabaseSpecific.URL, "\n")

	byModule := groupByModule(findings)
	first := true
	for _, module := range byModule {
		//TODO: this assumes all traces on a module are found and fixed at the same versions
		lastFrame := module[0].Trace[0]
		mod := lastFrame.Module
		path := lastFrame.Module
		if path == internal.GoStdModulePath {
			path = lastFrame.Package
		}
		foundVersion := moduleVersionString(lastFrame.Module, lastFrame.Version)
		fixedVersion := moduleVersionString(lastFrame.Module, module[0].FixedVersion)
		if !first {
			h.print("\n")
		}
		first = false
		h.print("  ")
		if mod == internal.GoStdModulePath {
			h.print("Standard library")
		} else {
			h.style(keyStyle, "Module: ")
			h.print(mod)
		}
		h.print("\n    ")
		h.style(keyStyle, "Found in: ")
		h.print(path, "@", foundVersion, "\n    ")
		h.style(keyStyle, "Fixed in: ")
		if fixedVersion != "" {
			h.print(path, "@", fixedVersion)
		} else {
			h.print("N/A")
		}
		h.print("\n")
		platforms := platforms(mod, module[0].OSV)
		if len(platforms) > 0 {
			h.style(keyStyle, "    Platforms: ")
			for ip, p := range platforms {
				if ip > 0 {
					h.print(", ")
				}
				h.print(p)
			}
			h.print("\n")
		}
		h.traces(module)
	}
	h.print("\n")
}

func (h *TextHandler) traces(traces []*findingSummary) {
	first := true
	count := 1
	for _, entry := range traces {
		if entry.Compact == "" {
			continue
		}
		if first {
			h.style(keyStyle, "    Example traces found:\n")
		}
		first = false

		h.print("      #", count, ": ")
		count++
		if !h.showTraces {
			h.print(entry.Compact, "\n")
		} else {
			h.print("for function ", symbol(entry.Trace[0], false), "\n")
			for i := len(entry.Trace) - 1; i >= 0; i-- {
				t := entry.Trace[i]
				h.print("        ")
				if t.Position != nil {
					h.print(posToString(t.Position), ": ")
				}
				h.print(symbol(t, false), "\n")
			}
		}
	}
}

func (h *TextHandler) summary(c summaryCounters) {
	// print short summary of findings identified at the desired level of scan precision
	var vulnCount int
	h.print("Your code ", choose(h.scanLevel.WantSymbols(), "is", "may be"), " affected by ")
	switch h.scanLevel {
	case govulncheck.ScanLevelSymbol:
		vulnCount = c.VulnerabilitiesCalled
	case govulncheck.ScanLevelPackage:
		vulnCount = c.VulnerabilitiesImported
	case govulncheck.ScanLevelModule:
		vulnCount = c.VulnerabilitiesRequired
	}
	h.style(valueStyle, vulnCount)
	h.print(choose(vulnCount == 1, ` vulnerability`, ` vulnerabilities`))
	if h.scanLevel.WantSymbols() {
		h.print(choose(c.ModulesCalled > 0 || c.StdlibCalled, ` from `, ``))
		if c.ModulesCalled > 0 {
			h.style(valueStyle, c.ModulesCalled)
			h.print(choose(c.ModulesCalled == 1, ` module`, ` modules`))
		}
		if c.StdlibCalled {
			if c.ModulesCalled != 0 {
				h.print(` and `)
			}
			h.print(`the Go standard library`)
		}
	}
	h.print(".\n")

	// print summary for vulnerabilities found at other levels of scan precision
	if other := h.summaryOtherVulns(c); other != "" {
		h.wrap("", other, 80)
		h.print("\n")
	}

	// print suggested flags for more/better info depending on scan level and if in verbose mode
	if sugg := h.summarySuggestion(); sugg != "" {
		h.wrap("", sugg, 80)
		h.print("\n")
	}
}

func (h *TextHandler) summaryOtherVulns(c summaryCounters) string {
	var summary strings.Builder
	if c.VulnerabilitiesRequired+c.VulnerabilitiesImported == 0 {
		summary.WriteString("This scan found no other vulnerabilities in ")
		if h.scanLevel.WantSymbols() {
			summary.WriteString("packages you import or ")
		}
		summary.WriteString("modules you require.")
	} else {
		summary.WriteString(choose(h.scanLevel.WantPackages(), "This scan also found ", ""))
		if h.scanLevel.WantSymbols() {
			summary.WriteString(fmt.Sprint(c.VulnerabilitiesImported))
			summary.WriteString(choose(c.VulnerabilitiesImported == 1, ` vulnerability `, ` vulnerabilities `))
			summary.WriteString("in packages you import and ")
		}
		if h.scanLevel.WantPackages() {
			summary.WriteString(fmt.Sprint(c.VulnerabilitiesRequired))
			summary.WriteString(choose(c.VulnerabilitiesRequired == 1, ` vulnerability `, ` vulnerabilities `))
			summary.WriteString("in modules you require")
			summary.WriteString(choose(h.scanLevel.WantSymbols(), ", but your code doesn't appear to call these vulnerabilities.", "."))
		}
	}
	return summary.String()
}

func (h *TextHandler) summarySuggestion() string {
	var sugg strings.Builder
	switch h.scanLevel {
	case govulncheck.ScanLevelSymbol:
		if !h.showAllVulns {
			sugg.WriteString("Use " + verboseMessage + ".")
		}
	case govulncheck.ScanLevelPackage:
		sugg.WriteString("Use " + symbolMessage)
		if !h.showAllVulns {
			sugg.WriteString(" and " + verboseMessage)
		}
		sugg.WriteString(".")
	case govulncheck.ScanLevelModule:
		sugg.WriteString("Use " + symbolMessage + ".")
	}
	return sugg.String()
}

func (h *TextHandler) style(style style, values ...any) {
	if h.showColor {
		switch style {
		default:
			h.print(colorReset)
		case osvCalledStyle:
			h.print(colorBold, fgRed)
		case osvImportedStyle:
			h.print(colorBold, fgGreen)
		case detailsStyle:
			h.print(colorFaint)
		case sectionStyle:
			h.print(fgBlue)
		case keyStyle:
			h.print(colorFaint, fgYellow)
		case valueStyle:
			h.print(colorBold, fgCyan)
		}
	}
	h.print(values...)
	if h.showColor && len(values) > 0 {
		h.print(colorReset)
	}
}

func (h *TextHandler) print(values ...any) int {
	total, w := 0, 0
	for _, v := range values {
		if h.err != nil {
			return total
		}
		// do we need to specialize for some types, like time?
		w, h.err = fmt.Fprint(h.w, v)
		total += w
	}
	return total
}

// wrap wraps s to fit in maxWidth by breaking it into lines at whitespace. If a
// single word is longer than maxWidth, it is retained as its own line.
func (h *TextHandler) wrap(indent string, s string, maxWidth int) {
	w := 0
	for _, f := range strings.Fields(s) {
		if w > 0 && w+len(f)+1 > maxWidth {
			// line would be too long with this word
			h.print("\n")
			w = 0
		}
		if w == 0 {
			// first field on line, indent
			w = h.print(indent)
		} else {
			// not first word, space separate
			w += h.print(" ")
		}
		// now write the word
		w += h.print(f)
	}
}

func choose[t any](b bool, yes, no t) t {
	if b {
		return yes
	}
	return no
}

func isStdFindings(findings []*findingSummary) bool {
	for _, f := range findings {
		if vulncheck.IsStdPackage(f.Trace[0].Package) || f.Trace[0].Module == internal.GoStdModulePath {
			return true
		}
	}
	return false
}
