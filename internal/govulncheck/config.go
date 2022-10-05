// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import "golang.org/x/tools/go/packages"

const (
	// AnalysisTypeBinary is used for binary analysis with vulncheck.Binary.
	AnalysisTypeBinary = "binary"

	// AnalysisTypeSource is used for source code analysis with vulncheck.Source.
	AnalysisTypeSource = "source"
)

const (
	// OutputTypeText is the default output type for `govulncheck`.
	OutputTypeText = "text"

	//  OutputTypeVerbose is the output type for `govulncheck -v`.
	OutputTypeVerbose = "verbose"

	// OutputTypeJSON is the output type for `govulncheck -json`, which will print
	// the JSON-encoded vulncheck.Result.
	OutputTypeJSON = "json"

	// OutputTypeSummary is the output type for `govulncheck -summary-json`, which
	// will print the JSON-encoded govulncheck.Summary.
	//
	// This is only meant by use for experimental with gopls.
	OutputTypeSummary = "summary"
)

const (
	// envGOVULNDB is the GOVULNDB environment variable, which accepts a list
	// of a comma-separated list of vulnerability database URLs, with http://,
	// https://, or file:// protocols.
	//
	// If this is empty, govulncheck will default to the Go vulnerability
	// database at vuln.go.dev.
	envGOVULNDB = "GOVULNDB"

	// envGOVULNDB represents the GOVERSION environment variable.
	envGOVERSION = "GOVERSION"

	vulndbHost = "https://vuln.go.dev"
)

// Config is the configuration for Main.
type Config struct {
	// AnalysisType specifies the vulncheck analysis type.
	AnalysisType string

	// OutputType specifies the output format type.
	OutputType string

	// Patterns are either the binary path for "binary" analysis mode, or
	// go package patterns for "source" analysis mode.
	Patterns []string

	// SourceLoadConfig specifies the package loading configuration.
	SourceLoadConfig *packages.Config
}
