// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sarif defines Static Analysis Results Interchange Format
// (SARIF) types supported by govulncheck.
//
// See https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif
// for more information on the SARIF format.
package sarif

import "golang.org/x/vuln/internal/govulncheck"

// Log is the top-level SARIF object encoded in UTF-8.
type Log struct {
	// Version should always be "2.1.0"
	Version string `json:"version,omitempty"`

	// Schema should always be "https://json.schemastore.org/sarif-2.1.0.json"
	Schema string `json:"$schema,omitempty"`

	// Runs describes executions of static analysis tools. For govulncheck,
	// there will be only one run object.
	Runs []Run `json:"runs,omitempty"`
}

// Run summarizes results of a single invocation of a static analysis tool,
// in this case govulncheck.
type Run struct {
	Tool Tool `json:"tool,omitempty"`
	// Results contain govulncheck findings. There should be exactly one
	// Result per a detected OSV.
	Results []Result `json:"results,omitempty"`

	// URIBaseIDs encodes the SARIF originalUriBaseIds property
	URIBaseIDs map[string]ArtifactLocation `json:"originalUriBaseIds,omitempty"`
}

// Tool captures information about govulncheck analysis that was run.
type Tool struct {
	Driver Driver `json:"driver,omitempty"`
}

// Driver provides details about the govulncheck binary being executed.
type Driver struct {
	// Name should be "govulncheck"
	Name string `json:"name,omitempty"`
	// Version should be the govulncheck version
	Version string `json:"semanticVersion,omitempty"`
	// InformationURI should point to the description of govulncheck tool
	InformationURI string `json:"informationUri,omitempty"`
	// Properties are govulncheck run metadata, such as vuln db, Go version, etc.
	Properties govulncheck.Config `json:"properties,omitempty"`

	Rules []Rule `json:"rules,omitempty"`
}

// Rule corresponds to the static analysis rule/analyzer that
// produces findings. For govulncheck, rules are OSVs.
type Rule struct {
	// ID is OSV.ID
	ID               string      `json:"id,omitempty"`
	ShortDescription Description `json:"shortDescription,omitempty"`
	FullDescription  Description `json:"fullDescription,omitempty"`
	Help             Description `json:"help,omitempty"`
	HelpURI          string      `json:"helpUri,omitempty"`
	// Properties should contain OSV.Aliases (CVEs and GHSAs) as tags.
	// Consumers of govulncheck SARIF can use these tags to filter
	// results based on, say, CVEs.
	Properties RuleTags `json:"properties,omitempty"`
}

// RuleTags defines properties.tags.
type RuleTags struct {
	Tags []string `json:"tags,omitempty"`
}

// Description is a text in its raw or markdown form.
type Description struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

// Result is a set of govulncheck findings for an OSV. For call stack
// mode, it will contain call stacks for the OSV. There is exactly
// one Result per detected OSV. Only findings at the lowest possible
// level appear in the Result. For instance, if there are findings
// with call stacks for an OSV, those findings will be in the Result,
// but not the “imports” and “requires” findings for the same OSV.
type Result struct {
	// RuleID is the Rule.ID/OSV producing the finding.
	RuleID string `json:"ruleId,omitempty"`
	// Level is one of "error", "warning", "note", and "none".
	Level string `json:"level,omitempty"`
	// Message explains the overall findings.
	Message Description `json:"message,omitempty"`
	// Locations to which the findings are associated.
	Locations []Location `json:"locations,omitempty"`
	// CodeFlows can encode call stacks produced by govulncheck.
	CodeFlows []CodeFlow `json:"codeFlows,omitempty"`
	// Stacks can encode call stacks produced by govulncheck.
	Stacks []Stack `json:"stacks,omitempty"`
	// TODO: support Fixes when integration points to the same
}

// CodeFlow describes a detected offending flow of information in terms of
// code locations. More precisely, it can contain several related information
// flows, keeping them together. In govulncheck, those can be all call stacks
// for, say, a particular symbol or package.
type CodeFlow struct {
	// ThreadFlows is effectively a set of related information flows.
	ThreadFlows []ThreadFlow `json:"threadFlows,omitempty"`
}

// ThreadFlow encodes an information flow as a sequence of locations.
// For govulncheck, it can encode a call stack.
type ThreadFlow struct {
	Locations []ThreadFlowLocation `json:"locations,omitempty"`
}

type ThreadFlowLocation struct {
	Module string `json:"module,omitempty"`
	// Location also contains a Message field.
	Location Location `json:"location,omitempty"`
	// Can also contain Stack field that encodes a call stack
	// leading to this thread flow location.
}

// Stack is a sequence of frames and can encode a govulncheck call stack.
type Stack struct {
	Message Description `json:"message,omitempty"`
	Frames  []Frame     `json:"frames,omitempty"`
}

// Frame is effectively a module location. It can also contain thread and
// parameter info, but those are not needed for govulncheck.
type Frame struct {
	Module   string   `json:"module,omitempty"`
	Location Location `json:"location,omitempty"`
}

// Location is currently a physical location annotated with a message.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation,omitempty"`
	Message          Description      `json:"message,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           Region           `json:"region,omitempty"`
}

// ArtifactLocation is a path to an offending file.
type ArtifactLocation struct {
	// URI is a path to the artifact. If URIBaseID is empty, then
	// URI is absolute and it needs to start with, say, "file://."
	URI string `json:"uri,omitempty"`
	// URIBaseID is offset for URI. An example is %SRCROOT%, used by
	// Github Code Scanning to point to the root of the target repo.
	// Its value must be defined in URIBaseIDs of a Run.
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region is a target region within a file.
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
