// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"fmt"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/packages/packagestest"
)

// LoadPackages loads packages for patterns. Returns error if the loading failed
// or some of the specified packages have issues. In the latter case, the error
// message will contain information only for the first observed package with issues.
func LoadPackages(e *packagestest.Exported, patterns ...string) ([]*packages.Package, error) {
	e.Config.Mode |= packages.NeedModule | packages.NeedName | packages.NeedFiles |
		packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedTypes |
		packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps
	pkgs, err := packages.Load(e.Config, patterns...)
	if err != nil {
		return pkgs, err
	}

	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			return pkgs, fmt.Errorf("%v", p.Errors)
		}
	}

	return pkgs, nil
}
