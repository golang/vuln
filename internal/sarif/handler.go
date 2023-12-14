// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

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
	sLog := toSarif(h)
	s, err := json.MarshalIndent(sLog, "", "  ")
	if err != nil {
		return err
	}
	h.w.Write(s)
	return nil
}

func toSarif(h *handler) Log {
	cfg := h.cfg
	r := Run{
		Tool: Tool{
			Driver: Driver{
				Name:           cfg.ScannerName,
				Version:        cfg.ScannerVersion,
				InformationURI: "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
				Properties:     *cfg,
				Rules:          rules(h),
			},
		},
		Results: results(h),
	}

	return Log{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []Run{r},
	}
}

func rules(h *handler) []Rule {
	var rs []Rule
	for id := range h.findings {
		osv := h.osvs[id]
		// s is either summary if it exists, or details
		// otherwise. Govulncheck text does the same.
		s := osv.Summary
		if s == "" {
			s = osv.Details
		}
		rs = append(rs, Rule{
			ID:               osv.ID,
			ShortDescription: Description{Text: fmt.Sprintf("[%s] %s", osv.ID, s)},
			FullDescription:  Description{Text: s},
			HelpURI:          fmt.Sprintf("https://pkg.go.dev/vuln/%s", osv.ID),
			Help:             Description{Text: osv.Details},
			Properties:       RuleTags{Tags: osv.Aliases},
		})
	}
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs
}

func results(h *handler) []Result {
	var results []Result
	for _, fs := range h.findings {
		res := Result{
			RuleID: fs[0].OSV,
			Level:  level(fs[0], h.cfg),
			// TODO: add location, message, code flows, and stacks
		}
		results = append(results, res)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].RuleID < results[j].RuleID }) // for deterministic output
	return results
}

const (
	errorLevel         = "error"
	warningLevel       = "warning"
	informationalLevel = "note"
)

func level(f *govulncheck.Finding, cfg *govulncheck.Config) string {
	fr := f.Trace[0]
	switch {
	case cfg.ScanLevel.WantSymbols():
		if fr.Function != "" {
			return errorLevel
		}
		if fr.Package != "" {
			return warningLevel
		}
		return informationalLevel
	case cfg.ScanLevel.WantPackages():
		if fr.Package != "" {
			return errorLevel
		}
		return warningLevel
	default:
		return errorLevel
	}
}
