// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"fmt"

	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
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

func moduleVersionString(modulePath, version string) string {
	if version == "" {
		return ""
	}
	if modulePath == internal.GoStdModulePath || modulePath == internal.GoCmdModulePath {
		version = semverToGoTag(version)
	}
	return version
}
