// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

type style int

const (
	defaultStyle = style(iota)
	goStyle
	scannerStyle
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
	w        io.Writer
	osvs     []*osv.Entry
	findings []*govulncheck.Finding

	err error

	showColor  bool
	showTraces bool
}

const (
	detailsMessage = `For details, see https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.`

	binaryProgressMessage = `Scanning your binary for known vulnerabilities...`
)

func (h *TextHandler) Show(show []string) {
	for _, show := range show {
		switch show {
		case "traces":
			h.showTraces = true
		case "color":
			h.showColor = true
		}
	}
}

func Flush(h govulncheck.Handler) error {
	if th, ok := h.(*TextHandler); ok {
		return th.Flush()
	}
	return nil
}

func (h *TextHandler) Flush() error {
	sortResult(h.findings)
	summary := createSummaries(h.osvs, h.findings)
	h.findings = nil

	h.vulnerabilities(summary.Affected)
	if len(summary.Unaffected) > 0 {
		h.print("\n")
		h.style(sectionStyle, "=== Informational ===\n")
		h.print("\nFound ", len(summary.Unaffected))
		h.print(choose(len(summary.Unaffected) == 1, ` vulnerability`, ` vulnerabilities`))
		h.print(" in packages that you import, but there are no call\nstacks leading to the use of ")
		h.print(choose(len(summary.Unaffected) == 1, `this vulnerability`, `these vulnerabilities`))
		h.print(". You may not need to\ntake any action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck\nfor details.\n\n")
		h.vulnerabilities(summary.Unaffected)
	}
	h.summary(summary)

	if h.err != nil {
		return h.err
	}
	if len(summary.Affected) > 0 {
		return errVulnerabilitiesFound
	}
	return nil
}

// Config writes text output formatted according to govulncheck-intro.tmpl.
func (h *TextHandler) Config(config *govulncheck.Config) error {
	h.print("govulncheck is an experimental tool. Share feedback at https://go.dev/s/govulncheck-feedback.\n\nUsing ")
	if config.GoVersion != "" {
		h.style(goStyle, config.GoVersion)
		h.print(` and `)
	}
	if config.ScannerName != "" {
		h.style(scannerStyle, config.ScannerName)
		if config.ScannerVersion != "" {
			h.print(`@`, config.ScannerVersion)
		}
		h.print(` with `)
	}
	h.print(`vulnerability data from `, config.DB)
	if config.DBLastModified != nil {
		h.print(` (last modified `, *config.DBLastModified, `)`)
	}
	h.print(".\n\n")
	return h.err
}

// Progress writes progress updates during govulncheck execution..
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
	h.findings = append(h.findings, finding)
	return nil
}

func (h *TextHandler) vulnerabilities(vulns []vulnSummary) {
	for iv, v := range vulns {
		if iv > 0 {
			h.print("\n")
		}
		h.style(keyStyle, "Vulnerability")
		h.print(" #", iv+1, ": ")
		if v.Affected {
			h.style(osvCalledStyle, v.OSV)
		} else {
			h.style(osvImportedStyle, v.OSV)
		}
		h.print("\n")
		h.style(detailsStyle)
		h.wrap("    ", v.Details, 80)
		h.style(defaultStyle)
		h.print("\n")
		h.style(keyStyle, "  More info:")
		h.print(" ", v.URL, "\n")
		for im, m := range v.Modules {
			if im > 0 {
				h.print("\n")
			}
			h.print("  ")
			if m.IsStd {
				h.print("Standard library")
			} else {
				h.style(keyStyle, "Module: ")
				h.print(m.Module)
			}
			h.print("\n    ")
			h.style(keyStyle, "Found in: ")
			h.print(m.FoundVersion, "\n    ")
			h.style(keyStyle, "Fixed in: ")
			if m.FixedVersion != "" {
				h.print(m.FixedVersion)
			} else {
				h.print("N/A")
			}
			h.print("\n")
			if len(m.Platforms) > 0 {
				h.style(keyStyle, "    Platforms: ")
				for ip, p := range m.Platforms {
					if ip > 0 {
						h.print(", ")
					}
					h.print(p)
				}
				h.print("\n")
			}
			h.traces(m.Traces)
		}
	}
}

func (h *TextHandler) traces(traces []traceSummary) {
	if len(traces) == 0 {
		return
	}
	h.style(keyStyle, "    Example traces found:\n")
	for i, entry := range traces {
		h.print("      #", i+1, ": ")
		if !h.showTraces {
			h.print(entry.Compact, "\n")
		} else {
			h.print("for function ", entry.Symbol, "\n")
			for _, t := range entry.Trace {
				h.print("        ")
				if t.Position != "" {
					h.print(t.Position, ": ")
				}
				h.print(t.Symbol, "\n")
			}
		}
	}
}

func (h *TextHandler) summary(s summaries) {
	h.print("\n")
	if len(s.Affected) == 0 {
		h.print("No vulnerabilities found.\n")
		return
	}
	h.print(`Your code is affected by `)
	h.style(valueStyle, len(s.Affected))
	h.print(choose(len(s.Affected) == 1, ` vulnerability`, ` vulnerabilities`))
	h.print(` from`)
	if s.AffectedModules > 0 {
		h.print(` `)
		h.style(valueStyle, s.AffectedModules)
		h.print(choose(s.AffectedModules == 1, ` module`, ` modules`))
	}
	if s.StdlibAffected {
		if s.AffectedModules != 0 {
			h.print(` and`)
		}
		h.print(` the Go standard library`)
	}
	h.print(".\n")
}

func (h *TextHandler) style(style style, values ...any) {
	if h.showColor {
		switch style {
		default:
			h.print(colorReset)
		case goStyle:
			h.print(colorBold)
		case scannerStyle:
			h.print(colorBold)
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

func choose(b bool, yes, no any) any {
	if b {
		return yes
	}
	return no
}
