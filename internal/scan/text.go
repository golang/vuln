// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"io"
	"strings"
	"text/template"

	"golang.org/x/vuln/internal/govulncheck"
)

// NewtextHandler returns a handler that writes govulncheck output as text.
func NewTextHandler(w io.Writer, source, verbose bool) govulncheck.Handler {
	h := &textHandler{
		w:       w,
		source:  source,
		verbose: verbose,
	}
	return h
}

type textHandler struct {
	w       io.Writer
	vulns   []*govulncheck.Vuln
	source  bool
	verbose bool
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
	lineWidth := 80 - labelWidth
	funcMap := template.FuncMap{
		"commaseparate": func(s []string) string {
			return strings.Join(s, ", ")
		},
		// used in template for counting vulnerabilities
		"inc": func(i int) int {
			return i + 1
		},
		// indent reversed to support template pipelining
		"indent": func(n int, s string) string {
			return indent(s, n)
		},
		"pluralize": pluralize,
		"wrap": func(s string) string {
			return wrap(s, lineWidth)
		},
	}

	tmplRes := createTmplResult(h.vulns, h.verbose, h.source)
	h.vulns = nil
	tmpl, err := template.New("govulncheck").Funcs(funcMap).Parse(outputTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(h.w, tmplRes)
}

// Config writes text output formatted according to govulncheck-intro.tmpl.
func (h *textHandler) Config(config *govulncheck.Config) error {
	// Print config to the user.
	tmpl, err := template.New("govulncheck-intro").Parse(introTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(h.w, config)
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

func pluralize(i int, s string) string {
	if i == 1 {
		return s
	}
	if string(s[len(s)-1]) == "y" {
		return s[0:len(s)-1] + "ies"
	}
	return s + "s"
}
