// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"

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

func moduleVersionString(modulePath, version string) string {
	if version == "" {
		return ""
	}
	if modulePath == internal.GoStdModulePath || modulePath == internal.GoCmdModulePath {
		version = semverToGoTag(version)
	}
	return version
}
