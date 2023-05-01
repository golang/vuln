// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import "golang.org/x/vuln/internal/govulncheck"

// MockHandler implements govulncheck.Handler but (currently)
// does nothing.
//
// For use in tests.
type MockHandler struct {
	ConfigMessages   []*govulncheck.Config
	ProgressMessages []*govulncheck.Progress
	VulnMessages     []*govulncheck.Vuln
}

func NewMockHandler() *MockHandler {
	return &MockHandler{}
}

func (h *MockHandler) Progress(progress *govulncheck.Progress) error {
	h.ProgressMessages = append(h.ProgressMessages, progress)
	return nil
}

func (h *MockHandler) Vulnerability(vuln *govulncheck.Vuln) error {
	h.VulnMessages = append(h.VulnMessages, vuln)
	return nil
}

func (h *MockHandler) Config(config *govulncheck.Config) error {
	h.ConfigMessages = append(h.ConfigMessages, config)
	return nil
}
