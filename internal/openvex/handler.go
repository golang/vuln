// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openvex

import (
	"encoding/json"
	"io"
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
	doc := toVex()
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_, err = h.w.Write(out)
	return err
}

func toVex() Document {
	doc := Document{
		ID:        "govulncheckVEX", // TODO: create hash from document for ID
		Context:   ContextURI,
		Author:    DefaultAuthor,
		Timestamp: time.Now().UTC(),
		Version:   1,
		Tooling:   Tooling,
		//TODO: Add statements
	}
	return doc
}
