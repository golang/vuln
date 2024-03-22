// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

type findingLevel int

const (
	invalid findingLevel = iota
	required
	imported
	called
)

type handler struct {
	w      io.Writer
	cfg    *govulncheck.Config
	osvs   map[string]*osv.Entry
	levels map[string]findingLevel
}

func NewHandler(w io.Writer) *handler {
	return &handler{
		w:      w,
		osvs:   make(map[string]*osv.Entry),
		levels: make(map[string]findingLevel),
	}
}

func (h *handler) Config(cfg *govulncheck.Config) error {
	h.cfg = cfg
	return nil
}

func (h *handler) Progress(progress *govulncheck.Progress) error {
	return nil
}

func (h *handler) OSV(e *osv.Entry) error {
	h.osvs[e.ID] = e
	return nil
}

// foundAtLevel returns the level at which a specific finding is present in the
// scanned product.
func foundAtLevel(f *govulncheck.Finding) findingLevel {
	frame := f.Trace[0]
	if frame.Function != "" {
		return called
	}
	if frame.Package != "" {
		return imported
	}
	return required
}

func (h *handler) Finding(f *govulncheck.Finding) error {
	fLevel := foundAtLevel(f)
	if fLevel > h.levels[f.OSV] {
		h.levels[f.OSV] = fLevel
	}
	return nil
}

// Flush is used to print the vex json to w.
// This is needed as vex is not streamed.
func (h *handler) Flush() error {
	doc := toVex(h)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = h.w.Write(out)
	return err
}

func toVex(h *handler) Document {
	doc := Document{
		Context:    ContextURI,
		Author:     DefaultAuthor,
		Timestamp:  time.Now().UTC(),
		Version:    1,
		Tooling:    Tooling,
		Statements: statements(h),
	}

	id := hashVex(doc)
	doc.ID = "govulncheck/vex:" + id
	return doc
}

// statements combines all OSVs found by govulncheck and generates the list of
// vex statements with the proper affected level and justification to match the
// openVex specification.
func statements(h *handler) []Statement {
	var scanLevel findingLevel
	switch h.cfg.ScanLevel {
	case govulncheck.ScanLevelModule:
		scanLevel = required
	case govulncheck.ScanLevelPackage:
		scanLevel = imported
	case govulncheck.ScanLevelSymbol:
		scanLevel = called
	}

	var statements []Statement
	for id, osv := range h.osvs {
		description := osv.Summary
		if description == "" {
			description = osv.Details
		}
		s := Statement{
			Vulnerability: Vulnerability{
				ID:          fmt.Sprintf("https://pkg.go.dev/vuln/%s", id),
				Name:        id,
				Description: description,
				Aliases:     osv.Aliases,
			},
			Products: []Product{
				{
					ID: DefaultPID,
				},
			},
		}

		if h.levels[id] >= scanLevel {
			s.Status = StatusAffected
		} else {
			s.Status = StatusNotAffected
			s.ImpactStatement = Impact
			s.Justification = JustificationNotPresent
			// We only reach this case if running in symbol mode
			if h.levels[id] == imported {
				s.Justification = JustificationNotExecuted
			}
		}
		statements = append(statements, s)
	}

	slices.SortFunc(statements, func(a, b Statement) int {
		if a.Vulnerability.ID > b.Vulnerability.ID {
			return 1
		}
		if a.Vulnerability.ID < b.Vulnerability.ID {
			return -1
		}
		// this should never happen in practice, since statements are being
		// populated from a map with the vulnerability IDs as keys
		return 0
	})
	return statements
}

func hashVex(doc Document) string {
	// json.Marshal should never error here (because of the structure of Document).
	// If an error does occur, it won't be a jsonerror, but instead a panic
	d := Document{
		Context:    doc.Context,
		ID:         doc.ID,
		Author:     doc.Author,
		Version:    doc.Version,
		Tooling:    doc.Tooling,
		Statements: doc.Statements,
	}
	out, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(out))
}
