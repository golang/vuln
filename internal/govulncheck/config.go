// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import "golang.org/x/tools/go/packages"

const (
	analysisBinary = "binary"
	analysisSource = "source"

	formatJSON    = "json"
	formatSummary = "summary"
	formatText    = "text"
	formatVerbose = "verbose"

	envGOVULNDB = "GOVULNDB"

	vulndbHost = "https://vuln.go.dev"
)

// Config is the configuration for Main.
type Config struct {
	// Analysis specifies the vulncheck analysis type. Valid types are "source" and "binary"
	Analysis string
	// OutputFormat specifies the result type. Valid types are:
	//  "text": print human readable compact text output to STDOUT.
	//  "verbose": print human readable verbose text output to STDOUT.
	//  "json": print JSON-encoded vulncheck.Result.
	//  "summary": print JSON-encoded Summary.
	OutputFormat string

	// Patterns are either the binary path for "binary" analysis mode, or
	// go package patterns for "source" analysis mode.
	Patterns []string

	// SourceLoadConfig specifies the package loading configuration.
	SourceLoadConfig packages.Config
}
