// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"io"
	"text/template"

	"golang.org/x/vuln/internal/govulncheck"
)

// NewTextHandler returns a handler that writes govulncheck output as text.
func NewTextHandler(w io.Writer) govulncheck.Handler {
	o := &textHandler{w: w}
	return o
}

type textHandler struct {
	w        io.Writer
	vulns    []*govulncheck.Vuln
	preamble *govulncheck.Preamble
}

const (
	labelWidth = 16
	lineLength = 55

	detailsMessage = `For details, see https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.`

	binaryProgressMessage = `Scanning your binary for known vulnerabilities...`
)

func (o *textHandler) Flush() error {
	lineWidth := 80 - labelWidth
	funcMap := template.FuncMap{
		// used in template for counting vulnerabilities
		"inc": func(i int) int {
			return i + 1
		},
		// indent reversed to support template pipelining
		"indent": func(n int, s string) string {
			return indent(s, n)
		},
		"wrap": func(s string) string {
			return wrap(s, lineWidth)
		},
	}

	source := o.preamble.Analysis == govulncheck.AnalysisSource
	verbose := o.preamble.Mode == govulncheck.ModeVerbose
	tmplRes := createTmplResult(o.vulns, verbose, source)
	o.vulns = nil
	tmpl, err := template.New("govulncheck").Funcs(funcMap).Parse(outputTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(o.w, tmplRes)
}

// Vulnerability gathers vulnerabilities to be written.
func (o *textHandler) Vulnerability(vuln *govulncheck.Vuln) error {
	o.vulns = append(o.vulns, vuln)
	return nil
}

// Preamble writes text output formatted according to govulncheck-intro.tmpl.
func (o *textHandler) Preamble(preamble *govulncheck.Preamble) error {
	p := *preamble
	o.preamble = &p
	// Print preamble to the user.
	tmpl, err := template.New("govulncheck-intro").Parse(introTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(o.w, preamble)
}

// Progress writes progress updates during govulncheck execution..
func (o *textHandler) Progress(msg string) error {
	fmt.Fprintln(o.w)
	fmt.Fprintln(o.w, msg)
	return nil
}
