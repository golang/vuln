// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"sort"

	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

// MockHandler implements govulncheck.Handler but (currently)
// does nothing.
//
// For use in tests.
type MockHandler struct {
	ConfigMessages   []*govulncheck.Config
	ProgressMessages []*govulncheck.Progress
	OSVMessages      []*osv.Entry
	FindingMessages  []*govulncheck.Finding
}

func NewMockHandler() *MockHandler {
	return &MockHandler{}
}

func (h *MockHandler) Config(config *govulncheck.Config) error {
	h.ConfigMessages = append(h.ConfigMessages, config)
	return nil
}

func (h *MockHandler) Progress(progress *govulncheck.Progress) error {
	h.ProgressMessages = append(h.ProgressMessages, progress)
	return nil
}

func (h *MockHandler) OSV(entry *osv.Entry) error {
	h.OSVMessages = append(h.OSVMessages, entry)
	return nil
}

func (h *MockHandler) Finding(finding *govulncheck.Finding) error {
	h.FindingMessages = append(h.FindingMessages, finding)
	return nil
}

func (h *MockHandler) Sort() {
	sort.Slice(h.FindingMessages, func(i, j int) bool {
		if h.FindingMessages[i].OSV > h.FindingMessages[j].OSV {
			return true
		}
		if h.FindingMessages[i].OSV < h.FindingMessages[j].OSV {
			return false
		}

		iframe := h.FindingMessages[i].Trace[0]
		jframe := h.FindingMessages[j].Trace[0]
		if iframe.Module < jframe.Module {
			return true
		}
		if iframe.Module > jframe.Module {
			return false
		}
		if iframe.Package < jframe.Package {
			return true
		}
		if iframe.Package > jframe.Package {
			return false
		}
		if iframe.Receiver < jframe.Receiver {
			return true
		}
		if iframe.Receiver > jframe.Receiver {
			return false
		}
		return iframe.Function < jframe.Function
	})
}

func (h *MockHandler) Write(to govulncheck.Handler) error {
	h.Sort()
	for _, config := range h.ConfigMessages {
		if err := to.Config(config); err != nil {
			return err
		}
	}
	for _, progress := range h.ProgressMessages {
		if err := to.Progress(progress); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, finding := range h.FindingMessages {
		if !seen[finding.OSV] {
			seen[finding.OSV] = true
			// first time seeing this osv, so find and write the osv message
			for _, osv := range h.OSVMessages {
				if osv.ID == finding.OSV {
					if err := to.OSV(osv); err != nil {
						return err
					}
				}
			}
		}
		if err := to.Finding(finding); err != nil {
			return err
		}
	}
	for _, osv := range h.OSVMessages {
		if !seen[osv.ID] {
			if err := to.OSV(osv); err != nil {
				return err
			}
		}
	}
	return nil
}
