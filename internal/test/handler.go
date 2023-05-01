// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
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
