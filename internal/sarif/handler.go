// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"io"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

// handler for sarif output.
type handler struct {
	w    io.Writer
	cfg  *govulncheck.Config
	osvs map[string]*osv.Entry
	// findings contains same-level findings for an
	// OSV at the most precise level of granularity
	// available. This means, for instance, that if
	// an osv is indeed called, then all findings for
	// the osv will have call stack info.
	findings map[string][]*govulncheck.Finding
}

func NewHandler(w io.Writer) *handler {
	return &handler{
		w:        w,
		osvs:     make(map[string]*osv.Entry),
		findings: make(map[string][]*govulncheck.Finding),
	}
}
func (h *handler) Config(c *govulncheck.Config) error {
	h.cfg = c
	return nil
}

func (h *handler) Progress(p *govulncheck.Progress) error {
	return nil // not needed by sarif
}

func (h *handler) OSV(e *osv.Entry) error {
	h.osvs[e.ID] = e
	return nil
}

// moreSpecific favors a call finding over a non-call
// finding and a package finding over a module finding.
func moreSpecific(f1, f2 *govulncheck.Finding) int {
	if len(f1.Trace) > 1 && len(f2.Trace) > 1 {
		// Both are call stack findings.
		return 0
	}
	if len(f1.Trace) > 1 {
		return -1
	}
	if len(f2.Trace) > 1 {
		return 1
	}

	fr1, fr2 := f1.Trace[0], f2.Trace[0]
	if fr1.Function != "" && fr2.Function == "" {
		return -1
	}
	if fr1.Function == "" && fr2.Function != "" {
		return 1
	}
	if fr1.Package != "" && fr2.Package == "" {
		return -1
	}
	if fr1.Package == "" && fr2.Package != "" {
		return -1
	}
	return 0 // findings always have module info
}

func (h *handler) Finding(f *govulncheck.Finding) error {
	fs := h.findings[f.OSV]
	if len(fs) == 0 {
		fs = []*govulncheck.Finding{f}
	} else {
		if ms := moreSpecific(f, fs[0]); ms == -1 {
			// The new finding is more specific, so we need
			// to erase existing findings and add the new one.
			fs = []*govulncheck.Finding{f}
		} else if ms == 0 {
			// The new finding is equal to an existing one and
			// because of the invariant on h.findings, it is
			// also equal to all existing ones.
			fs = append(fs, f)
		}
		// Otherwise, the new finding is at a less precise level.
	}
	h.findings[f.OSV] = fs
	return nil
}

// Flush is used to print out to w the sarif json output.
// This is needed as sarif is not streamed.
func (h *handler) Flush() error {
	return nil
}