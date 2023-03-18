// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"encoding/json"
	"fmt"

	"io"

	"golang.org/x/vuln/internal/result"
)

type jsonHandler struct {
	w     io.Writer
	vulns []*result.Vuln
}

// NewJSONHandler returns a handler that writes govulncheck output as json.
func NewJSONHandler(to io.Writer) Handler {
	return &jsonHandler{w: to}
}

// Flush writes all vulnerabilities in JSON format.
func (o *jsonHandler) Flush() error {
	b, err := json.MarshalIndent(o.vulns, "", " ")
	o.vulns = nil
	if err != nil {
		return err
	}
	_, err = o.w.Write(b)
	fmt.Fprintln(o.w)
	return err
}

// Vulnerability gathers vulnerabilities to be written.
func (o *jsonHandler) Vulnerability(vuln *result.Vuln) error {
	o.vulns = append(o.vulns, vuln)
	return nil
}

// Preamble does not do anything in JSON mode.
func (o *jsonHandler) Preamble(preamble *result.Preamble) error {
	return nil
}

// Progress does not do anything in JSON mode.
func (o *jsonHandler) Progress(msg string) error {
	return nil
}
