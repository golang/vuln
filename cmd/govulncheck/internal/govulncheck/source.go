// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/vulncheck"
)

// A PackageError contains errors from loading a set of packages.
type PackageError struct {
	Errors []packages.Error
}

func (e *PackageError) Error() string {
	var b strings.Builder
	fmt.Fprintln(&b, "Packages contain errors:")
	for _, e := range e.Errors {
		fmt.Println(&b, e)
	}
	return b.String()
}

// LoadPackages loads the packages matching patterns using cfg, after setting
// the cfg mode flags that vulncheck needs for analysis.
// If the packages contain errors, a PackageError is returned containing a list of the errors,
// along with the packages themselves.
func LoadPackages(cfg *packages.Config, patterns ...string) ([]*vulncheck.Package, error) {
	cfg.Mode |= packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule

	pkgs, err := packages.Load(cfg, patterns...)
	vpkgs := vulncheck.Convert(pkgs)
	if err != nil {
		return nil, err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &PackageError{perrs}
	}
	return vpkgs, err
}

// Source calls vulncheck.Source on the Go source in pkgs. It returns the result
// with Vulns trimmed to those that are actually called.
func Source(ctx context.Context, pkgs []*vulncheck.Package, c client.Client) (*vulncheck.Result, error) {
	r, err := vulncheck.Source(ctx, pkgs, &vulncheck.Config{Client: c})
	if err != nil {
		return nil, err
	}
	// Keep only the vulns that are called.
	var vulns []*vulncheck.Vuln
	for _, v := range r.Vulns {
		if v.CallSink != 0 {
			vulns = append(vulns, v)
		}
	}
	r.Vulns = vulns
	return r, nil
}
