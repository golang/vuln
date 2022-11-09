// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/osv"
)

func printJSON(r *govulncheck.Result) error {
	b, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	fmt.Println()
	return nil
}

const (
	labelWidth = 16
	lineLength = 55
)

func printText(r *govulncheck.Result, verbose, source bool) {
	// unaffected are (imported) OSVs none of
	// which vulnerabilities are called.
	var unaffected []*govulncheck.Vuln
	uniqueVulns := 0
	for _, v := range r.Vulns {
		if !source || v.IsCalled() {
			uniqueVulns++
		} else {
			// save arbitrary Vuln for informational message
			unaffected = append(unaffected, v)
		}
	}
	switch uniqueVulns {
	case 0:
		fmt.Println("No vulnerabilities found.")
	case 1:
		fmt.Println("Found 1 known vulnerability.")
	default:
		fmt.Printf("Found %d known vulnerabilities.\n", uniqueVulns)
	}

	lineWidth := 80 - labelWidth
	idx := 0
	for _, v := range r.Vulns {
		for _, m := range v.Modules {
			for _, p := range m.Packages {
				// In Binary mode there are no call stacks.
				if source && len(p.CallStacks) == 0 {
					continue
				}
				fmt.Println()

				id := v.OSV.ID
				details := wrap(v.OSV.Details, lineWidth)
				found := packageVersionString(p.Path, m.FoundVersion)
				fixed := packageVersionString(p.Path, m.FixedVersion)

				var stacksBuilder strings.Builder
				if source { // there are no call stacks in binary mode
					var stacks string
					if !verbose {
						stacks = defaultCallStacks(p.CallStacks)
					} else {
						stacks = verboseCallStacks(p.CallStacks)
					}
					if len(stacks) > 0 {
						stacksBuilder.WriteString(indent("\n\nCall stacks in your code:\n", 2))
						stacksBuilder.WriteString(indent(stacks, 6))
					}
				}
				printVulnerability(idx+1, id, details, stacksBuilder.String(), found, fixed, platforms(v.OSV))
				idx++
			}
		}
	}
	if len(unaffected) > 0 {
		fmt.Println()
		fmt.Println(informationalMessage)
		idx = 0
		for idx, un := range unaffected {
			// We pick random module and package info for
			// unaffected OSVs.
			m := un.Modules[0]
			p := m.Packages[0]
			found := packageVersionString(p.Path, m.FoundVersion)
			fixed := packageVersionString(p.Path, m.FixedVersion)
			fmt.Println()
			details := wrap(un.OSV.Details, lineWidth)
			printVulnerability(idx+1, un.OSV.ID, details, "", found, fixed, platforms(un.OSV))
		}
	}
}

func printVulnerability(idx int, id, details, callstack, found, fixed, platforms string) {
	if fixed == "" {
		fixed = "N/A"
	}
	if platforms != "" {
		platforms = "  Platforms: " + platforms + "\n"
	}
	fmt.Printf(`Vulnerability #%d: %s
%s%s
  Found in: %s
  Fixed in: %s
%s  More info: https://pkg.go.dev/vuln/%s
`, idx, id, indent(details, 2), callstack, found, fixed, platforms, id)
}

func defaultCallStacks(css []govulncheck.CallStack) string {
	var summaries []string
	for _, cs := range css {
		summaries = append(summaries, cs.Summary)
	}

	// Sort call stack summaries and get rid of duplicates.
	// Note that different call stacks can yield same summaries.
	if len(summaries) > 0 {
		sort.Strings(summaries)
		summaries = compact(summaries)
	}
	var b strings.Builder
	for _, s := range summaries {
		b.WriteString(s)
		b.WriteString("\n")
	}
	return b.String()
}

func verboseCallStacks(css []govulncheck.CallStack) string {
	// Display one full call stack for each vuln.
	i := 1
	var b strings.Builder
	for _, cs := range css {
		b.WriteString(fmt.Sprintf("#%d: for function %s\n", i, cs.Symbol))
		for _, e := range cs.Frames {
			b.WriteString(fmt.Sprintf("  %s\n", e.Name()))
			if pos := internal.AbsRelShorter(e.Pos()); pos != "" {
				b.WriteString(fmt.Sprintf("      %s\n", pos))
			}
		}
		i++
	}
	return b.String()
}

// platforms returns a string describing the GOOS/GOARCH pairs that the vuln affects.
// If it affects all of them, it returns the empty string.
func platforms(e *osv.Entry) string {
	platforms := map[string]bool{}
	for _, a := range e.Affected {
		for _, p := range a.EcosystemSpecific.Imports {
			for _, os := range p.GOOS {
				for _, arch := range p.GOARCH {
					platforms[os+"/"+arch] = true
				}
			}
		}
	}
	keys := maps.Keys(platforms)
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// compact replaces consecutive runs of equal elements with a single copy.
// This is like the uniq command found on Unix.
// compact modifies the contents of the slice s; it does not create a new slice.
//
// Modified (generics removed) from exp/slices/slices.go.
func compact(s []string) []string {
	if len(s) == 0 {
		return s
	}
	i := 1
	last := s[0]
	for _, v := range s[1:] {
		if v != last {
			s[i] = v
			i++
			last = v
		}
	}
	return s[:i]
}

func packageVersionString(packagePath, version string) string {
	if version == "" {
		return ""
	}
	return fmt.Sprintf("%s@%s", packagePath, version)
}

// indent returns the output of prefixing n spaces to s at every line break,
// except for empty lines. See TestIndent for examples.
func indent(s string, n int) string {
	b := []byte(s)
	var result []byte
	shouldAppend := true
	prefix := strings.Repeat(" ", n)
	for _, c := range b {
		if shouldAppend && c != '\n' {
			result = append(result, prefix...)
		}
		result = append(result, c)
		shouldAppend = c == '\n'
	}
	return string(result)
}
