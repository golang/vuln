// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"embed"
	"fmt"
	"io"
	"text/template"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

//go:embed template
var templateFS embed.FS

// NewtextHandler returns a handler that writes govulncheck output as text.
func NewTextHandler(w io.Writer, source bool) *TextHandler {
	return &TextHandler{
		w:      w,
		source: source,
	}
}

type TextHandler struct {
	Show []string

	w        io.Writer
	osvs     []*osv.Entry
	findings []*govulncheck.Finding
	source   bool
}

const (
	labelWidth = 16
	lineLength = 55

	detailsMessage = `For details, see https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.`

	binaryProgressMessage = `Scanning your binary for known vulnerabilities...`
)

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
	if err := h.runTemplate("govulncheck-summary", summary); err != nil {
		return err
	}
	if len(summary.Affected) > 0 {
		return errVulnerabilitiesFound
	}
	return nil
}

// Config writes text output formatted according to govulncheck-intro.tmpl.
func (h *TextHandler) Config(config *govulncheck.Config) error {
	// Print config to the user.
	return h.runTemplate("govulncheck-intro", config)
}

// Progress writes progress updates during govulncheck execution..
func (h *TextHandler) Progress(progress *govulncheck.Progress) error {
	fmt.Fprintln(h.w)
	fmt.Fprintln(h.w, progress.Message)
	return nil
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

func (h *TextHandler) runTemplate(name string, value any) error {
	lineWidth := 80 - labelWidth
	funcs := template.FuncMap{
		// used in template for counting vulnerabilities
		"inc": func(i int) int { return i + 1 },
		// indent reversed to support template pipelining
		"indent": func(n int, s string) string { return indent(s, n) },
		"wrap":   func(s string) string { return wrap(s, lineWidth) },
	}
	installColorFunctions(funcs)
	tmpl := template.New("all").Funcs(funcs)
	_, err := tmpl.ParseFS(templateFS, "template/core*.tmpl")
	if err != nil {
		return err
	}
	for _, name := range h.Show {
		if _, err := tmpl.ParseFS(templateFS, "template/"+name+".tmpl"); err != nil {
			return err
		}
	}

	return tmpl.ExecuteTemplate(h.w, name, value)
}
