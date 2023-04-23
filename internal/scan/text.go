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
)

//go:embed template
var templateFS embed.FS

// NewtextHandler returns a handler that writes govulncheck output as text.
func NewTextHandler(w io.Writer, source, verbose bool) govulncheck.Handler {
	h := &textHandler{
		w:       w,
		source:  source,
		verbose: verbose,
		color:   false,
	}
	return h
}

type textHandler struct {
	w       io.Writer
	vulns   []*govulncheck.Vuln
	source  bool
	verbose bool
	color   bool
}

const (
	labelWidth = 16
	lineLength = 55

	detailsMessage = `For details, see https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.`

	binaryProgressMessage = `Scanning your binary for known vulnerabilities...`
)

func Flush(h govulncheck.Handler) error {
	if th, ok := h.(*textHandler); ok {
		return th.Flush()
	}
	return nil
}

func (h *textHandler) Flush() error {
	summary := createSummaries(h.vulns)
	h.vulns = nil
	return h.runTemplate("govulncheck-summary", summary)
}

// Config writes text output formatted according to govulncheck-intro.tmpl.
func (h *textHandler) Config(config *govulncheck.Config) error {
	// Print config to the user.
	return h.runTemplate("govulncheck-intro", config)
}

// Progress writes progress updates during govulncheck execution..
func (h *textHandler) Progress(progress *govulncheck.Progress) error {
	fmt.Fprintln(h.w)
	fmt.Fprintln(h.w, progress.Message)
	return nil
}

// Vulnerability gathers vulnerabilities to be written.
func (h *textHandler) Vulnerability(vuln *govulncheck.Vuln) error {
	h.vulns = append(h.vulns, vuln)
	return nil
}

func (h *textHandler) runTemplate(name string, value any) error {
	lineWidth := 80 - labelWidth
	funcs := template.FuncMap{
		// used in template for counting vulnerabilities
		"inc": func(i int) int { return i + 1 },
		// indent reversed to support template pipelining
		"indent": func(n int, s string) string { return indent(s, n) },
		"wrap":   func(s string) string { return wrap(s, lineWidth) },
	}
	if h.color {
		// we only add the color functions if we are in color mode as a safety measure
		// it means any use of those functions by a non color template will cause an error
		installColorFunctions(funcs)
	}
	tmpl := template.New("all").Funcs(funcs)
	_, err := tmpl.ParseFS(templateFS, "template/core*.tmpl")
	if err != nil {
		return err
	}
	if h.verbose {
		if _, err := tmpl.ParseFS(templateFS, "template/stacks.tmpl"); err != nil {
			return err
		}
	}
	if h.color {
		if _, err := tmpl.ParseFS(templateFS, "template/color.tmpl"); err != nil {
			return err
		}
	}

	return tmpl.ExecuteTemplate(h.w, name, value)
}
