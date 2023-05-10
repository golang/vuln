// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	isem "golang.org/x/vuln/internal/semver"
)

// validateFindings checks that the supplied findings all obey the protocol
// rules.
func validateFindings(findings ...*govulncheck.Finding) error {
	for _, f := range findings {
		if f.OSV == "" {
			return fmt.Errorf("invalid finding: all findings must have an associated OSV")
		}
		if len(f.Trace) < 1 {
			return fmt.Errorf("invalid finding: all callstacks must have at least one frame")
		}
		for _, frame := range f.Trace {
			if frame.Version != "" && frame.Module == "" {
				return fmt.Errorf("invalid finding: if Frame.Version is set, Frame.Module must also be")
			}
			if frame.Package != "" && frame.Module == "" {
				return fmt.Errorf("invalid finding: if Frame.Package is set, Frame.Module must also be")
			}
			if frame.Function != "" && frame.Package == "" {
				return fmt.Errorf("invalid finding: if Frame.Function is set, Frame.Package must also be")
			}
		}
	}
	return nil
}

// sortResults sorts Vulns, Modules, and Packages of r.
func sortResult(findings []*govulncheck.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].OSV > findings[j].OSV {
			return true
		}
		if findings[i].OSV < findings[j].OSV {
			return false
		}

		iframes := findings[i].Trace
		jframes := findings[j].Trace
		iframe := iframes[len(iframes)-1]
		jframe := jframes[len(jframes)-1]
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
		return iframe.Function < jframe.Function
	})
}

// latestFixed returns the latest fixed version in the list of affected ranges,
// or the empty string if there are no fixed versions.
func latestFixed(modulePath string, as []osv.Affected) string {
	v := ""
	for _, a := range as {
		if modulePath != a.Module.Path {
			continue
		}
		fixed := isem.LatestFixedVersion(a.Ranges)
		// Special case: if there is any affected block for this module
		// with no fix, the module is considered unfixed.
		if fixed == "" {
			return ""
		}
		if isem.Less(v, fixed) {
			v = fixed
		}
	}
	return v
}

func fixedVersion(modulePath string, affected []osv.Affected) string {
	fixed := latestFixed(modulePath, affected)
	if fixed != "" {
		fixed = "v" + fixed
	}
	return fixed
}

// highest returns the highest (one with the smallest index) entry in the call
// stack for which f returns true.
func highest(cs []*govulncheck.Frame, f func(e *govulncheck.Frame) bool) int {
	for i := 0; i < len(cs); i++ {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

// lowest returns the lowest (one with the largest index) entry in the call
// stack for which f returns true.
func lowest(cs []*govulncheck.Frame, f func(e *govulncheck.Frame) bool) int {
	for i := len(cs) - 1; i >= 0; i-- {
		if f(cs[i]) {
			return i
		}
	}
	return -1
}

func moduleVersionString(modulePath, pkgPath, version string) string {
	if version == "" {
		return ""
	}
	path := modulePath
	if modulePath == internal.GoStdModulePath || modulePath == internal.GoCmdModulePath {
		version = semverToGoTag(version)
		path = pkgPath
	}
	return fmt.Sprintf("%s@%s", path, version)
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
