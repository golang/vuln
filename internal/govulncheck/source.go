// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
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
		fmt.Fprintln(&b, e)
	}
	return b.String()
}

// loadPackages loads the packages matching patterns using cfg, after setting
// the cfg mode flags that vulncheck needs for analysis.
// If the packages contain errors, a PackageError is returned containing a list of the errors,
// along with the packages themselves.
func loadPackages(cfg Config) ([]*vulncheck.Package, error) {
	patterns := cfg.Patterns
	cfg.SourceLoadConfig.Mode |= packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule

	pkgs, err := packages.Load(cfg.SourceLoadConfig, patterns...)
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

// callInfo is information about calls to vulnerable functions.
type callInfo struct {
	// callStacks contains all call stacks to vulnerable functions.
	callStacks map[*vulncheck.Vuln][]vulncheck.CallStack

	// vulnGroups contains vulnerabilities grouped by ID and package.
	vulnGroups [][]*vulncheck.Vuln

	// moduleVersions is a map of module paths to versions.
	moduleVersions map[string]string

	// topPackages contains the top-level packages in the call info.
	topPackages map[string]bool
}

// getCallInfo computes call stacks and related information from a vulncheck.Result.
// It also makes a set of top-level packages from pkgs.
func getCallInfo(r *vulncheck.Result, pkgs []*vulncheck.Package) *callInfo {
	pset := map[string]bool{}
	for _, p := range pkgs {
		pset[p.PkgPath] = true
	}
	return &callInfo{
		callStacks:     vulncheck.CallStacks(r),
		vulnGroups:     groupByIDAndPackage(r.Vulns),
		moduleVersions: moduleVersionMap(r.Modules),
		topPackages:    pset,
	}
}

func groupByIDAndPackage(vs []*vulncheck.Vuln) [][]*vulncheck.Vuln {
	groups := map[[2]string][]*vulncheck.Vuln{}
	for _, v := range vs {
		key := [2]string{v.OSV.ID, v.PkgPath}
		groups[key] = append(groups[key], v)
	}

	var res [][]*vulncheck.Vuln
	for _, g := range groups {
		res = append(res, g)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i][0].PkgPath < res[j][0].PkgPath
	})
	return res
}

// moduleVersionMap builds a map from module paths to versions.
func moduleVersionMap(mods []*vulncheck.Module) map[string]string {
	moduleVersions := map[string]string{}
	for _, m := range mods {
		v := m.Version
		if m.Replace != nil {
			v = m.Replace.Version
		}
		moduleVersions[m.Path] = v
	}
	return moduleVersions
}
