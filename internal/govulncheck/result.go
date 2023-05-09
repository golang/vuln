// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package result contains the JSON output structs for govulncheck.
package govulncheck

import (
	"time"

	"golang.org/x/vuln/internal/osv"
)

// Message is an entry in the output stream. It will always have exactly one
// field filled in.
type Message struct {
	Config   *Config    `json:"config,omitempty"`
	Progress *Progress  `json:"progress,omitempty"`
	OSV      *osv.Entry `json:"osv,omitempty"`
	Finding  *Finding   `json:"finding,omitempty"`
}

type Config struct {
	// Name is the name of the tool, for example, govulncheck.
	Name string `json:"name,omitempty"`

	// Version is the version of the tool.
	Version string `json:"version,omitempty"`

	// DataSource is the data source used by the tool, for example,
	// vuln.go.dev.
	DataSource string `json:"data_source,omitempty"`

	// LastModified is the last modified time of the data source.
	LastModified *time.Time `json:"last_modified,omitempty"`

	// GoVersion is the version of Go used for analyzing standard library
	// vulnerabilities.
	GoVersion string `json:"go_version,omitempty"`

	// Consider only vulnerabilities that apply to this OS.
	GOOS string `json:"goos,omitempty"`

	// Consider only vulnerabilities that apply to this architecture.
	GOARCH string `json:"goarch,omitempty"`

	// ImportsOnly instructs vulncheck to analyze import chains only.
	// Otherwise, call chains are analyzed too.
	ImportsOnly bool `json:"imports_only,omitempty"`
}

type Progress struct {
	// Message is the progress message.
	Message string `json:"message,omitempty"`
}

// Vuln represents a single OSV entry.
type Finding struct {
	// OSV contains all data from the OSV entry for this vulnerability.
	OSV string `json:"osv,omitempty"`

	// FixedVersion is the leaf module version where the vulnerability was
	// fixed. If there are multiple fixed versions in the OSV report, this will
	// be the latest fixed version.
	//
	// This is empty if a fix is not available.
	FixedVersion string `json:"fixed_version,omitempty"`

	// Frames contains an entry for each stack in the finding stack.
	//
	// The last frame will be the vulnerable symbol.
	// This must always have at least one entry.
	Frames []*StackFrame `json:"frames,omitempty"`
}

// StackFrame represents an entry in a path to a finding.
type StackFrame struct {
	// Module is the Module path.
	Module string `json:"module,omitempty"`

	// Version is the module version.
	Version string `json:"version,omitempty"`

	// Package is the import path.
	Package string `json:"package,omitempty"`

	// Function is the function name.
	//
	// For non-affecting vulnerabilities reported from the source mode
	// analysis, this will be empty.
	Function string `json:"function,omitempty"`

	// Receiver is the fully qualified receiver type,
	// if the called symbol is a method.
	//
	// The client can create the final symbol name by
	// prepending Receiver to FuncName.
	Receiver string `json:"receiver,omitempty"`

	// Position describes an arbitrary source position
	// including the file, line, and column location.
	// A Position is valid if the line number is > 0.
	Position *Position `json:"position,omitempty"`
}

// Position is a copy of token.Position used to marshal/unmarshal
// JSON correctly.
type Position struct {
	Filename string `json:"filename,omitempty"` // filename, if any
	Offset   int    `json:"offset"`             // offset, starting at 0
	Line     int    `json:"line"`               // line number, starting at 1
	Column   int    `json:"column"`             // column number, starting at 1 (byte count)
}
