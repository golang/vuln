// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
	"golang.org/x/vuln/internal/semver"
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

func fixedVersion(modulePath, version string, affected []osv.Affected) string {
	fixed := earliestValidFix(modulePath, version, affected)
	// Add "v" prefix if one does not exist. moduleVersionString
	// will later on replace it with "go" if needed.
	if fixed != "" && !strings.HasPrefix(fixed, "v") {
		fixed = "v" + fixed
	}
	return fixed
}

// earliestValidFix returns the earliest fix for version of modulePath that
// itself is not vulnerable in affected.
//
// Suppose we have a version "v1.0.0" and we use {...} to denote different
// affected regions. Assume for simplicity that all affected apply to the
// same input modulePath.
//
//	{[v0.1.0, v0.1.9), [v1.0.0, v2.0.0)} -> v2.0.0
//	{[v1.0.0, v1.5.0), [v2.0.0, v2.1.0}, {[v1.4.0, v1.6.0)} -> v2.1.0
func earliestValidFix(modulePath, version string, affected []osv.Affected) string {
	var moduleAffected []osv.Affected
	for _, a := range affected {
		if a.Module.Path == modulePath {
			moduleAffected = append(moduleAffected, a)
		}
	}

	vFixes := validFixes(version, moduleAffected)
	for _, fix := range vFixes {
		if !fixNegated(fix, moduleAffected) {
			return fix
		}
	}
	return ""

}

// validFixes computes all fixes for version in affected and
// returns them sorted increasingly. Assumes that all affected
// apply to the same module.
func validFixes(version string, affected []osv.Affected) []string {
	var fixes []string
	for _, a := range affected {
		for _, r := range a.Ranges {
			if r.Type != osv.RangeTypeSemver {
				continue
			}
			for _, e := range r.Events {
				fix := e.Fixed
				if fix != "" && semver.Less(version, fix) {
					fixes = append(fixes, fix)
				}
			}
		}
	}
	sort.SliceStable(fixes, func(i, j int) bool { return semver.Less(fixes[i], fixes[j]) })
	return fixes
}

// fixNegated checks if fix is negated to by a re-introduction
// of a vulnerability in affected. Assumes that all affected apply
// to the same module.
func fixNegated(fix string, affected []osv.Affected) bool {
	for _, a := range affected {
		for _, r := range a.Ranges {
			if semver.ContainsSemver(r, fix) {
				return true
			}
		}
	}
	return false
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

func modPath(mod *packages.Module) string {
	if mod.Replace != nil {
		return mod.Replace.Path
	}
	return mod.Path
}

func modVersion(mod *packages.Module) string {
	if mod.Replace != nil {
		return mod.Replace.Version
	}
	return mod.Version
}
