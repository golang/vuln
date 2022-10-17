// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/vuln/vulncheck"
)

var (
	// ErrContainsVulnerabilties is used to indicate that vulerabilities were
	// found in the output of Run.
	ErrContainsVulnerabilties = errors.New("module contains vulnerabilities")

	// ErrInvalidAnalysisType indicates that an unsupported AnalysisType was passed to Config.
	ErrInvalidAnalysisType = errors.New("invalid analysis type")

	// ErrInvalidOutputType indicates that an unsupported OutputType was passed to Config.
	ErrInvalidOutputType = errors.New("invalid output type")

	// ErrErrGoVersionMismatch is used to indicate that there is a mismatch between
	// the Go version used to build govulncheck and the one currently on PATH.
	ErrGoVersionMismatch = errors.New(`Loading packages failed, possibly due to a mismatch between the Go version
used to build govulncheck and the Go version on PATH. Consider rebuilding
govulncheck with the current Go version.`)

	// ErrNoGoSum indicates that a go.mod file was not found in this module.
	ErrNoGoMod = errors.New(`no go.mod file

govulncheck only works Go with modules. Try navigating to your module directory.
Otherwise, run go mod init to make your project a module.

See https://go.dev/doc/modules/managing-dependencies for more information.`)

	// ErrNoGoSum indicates that a go.sum file was not found in this module.
	ErrNoGoSum = errors.New(`no go.sum file

Your module is missing a go.sum file. Try running go mod tidy.

See https://go.dev/doc/modules/managing-dependencies for more information.`)

	// ErrNoModVersion indicates that govulncheck cannot access module version information.
	ErrNoModVersion = errors.New(`no module version information

This can happen when running govulncheck in GOPATH mode. govulncheck needs module
versions to correctly identify vulnerabilities.

See https://go.dev/doc/modules/managing-dependencies for more information.`)
)

// fileExists checks if file path exists. Returns true
// if the file exists or it cannot prove that it does
// not exist. Otherwise, returns false.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	}
	// Conservatively return true if os.Stat fails
	// for some other reason.
	return true
}

// isGoVersionMismatchError checks if err is due to mismatch between
// the Go version used to build govulncheck and the one currently
// on PATH.
func isGoVersionMismatchError(err error) bool {
	msg := err.Error()
	// See golang.org/x/tools/go/packages/packages.go.
	return strings.Contains(msg, "This application uses version go") &&
		strings.Contains(msg, "It may fail to process source files")
}

// inGoPathMode checks if govulncheck is running in GOPATH mode by checking
// if module information is available.
func inGoPathMode(pkgs []*vulncheck.Package) bool {
	packageModule := func(p *vulncheck.Package) *vulncheck.Module {
		m := p.Module
		if m == nil {
			return nil
		}
		if r := m.Replace; r != nil {
			return r
		}
		return m
	}

	hasModuleInfo := false
	var visit func(p *vulncheck.Package)
	visit = func(p *vulncheck.Package) {
		if packageModule(p) != nil {
			hasModuleInfo = true
			return
		}
		for _, i := range p.Imports {
			visit(i)
		}
	}
	for _, p := range pkgs {
		visit(p)
	}
	return !hasModuleInfo
}
