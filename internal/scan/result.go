// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package govulncheck provides functionality to support the govulncheck command.
package scan

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/govulncheck"
)

// LoadMode is the level of information needed for each package
// for running golang.org/x/tools/go/packages.Load.
var LoadMode = packages.NeedName | packages.NeedImports | packages.NeedTypes |
	packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
	packages.NeedModule

// IsCalled reports whether the vulnerability is called, therefore
// affecting the target source code or binary.
func IsCalled(findings []*govulncheck.Finding) bool {
	for _, f := range findings {
		if f.Trace[len(f.Trace)-1].Function != "" {
			return true
		}
	}
	return false
}
