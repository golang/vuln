// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package test

import (
	"fmt"
	"strings"
	"testing"

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

func VerifyImports(t *testing.T, allowed ...string) {
	cfg := &packages.Config{Mode: packages.NeedImports | packages.NeedDeps}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatal(err)
	}
	check := map[string]struct{}{}
	for _, imp := range allowed {
		check[imp] = struct{}{}
	}
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			// this is an approximate stdlib check that is good enough for these tests
			if !strings.ContainsRune(imp.ID, '.') {
				continue
			}
			if _, ok := check[imp.ID]; !ok {
				t.Errorf("include of %s is not allowed", imp.ID)
			}
		}
	}
}
