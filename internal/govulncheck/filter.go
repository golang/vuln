// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"sort"

	"golang.org/x/vuln/vulncheck"
)

// filterCalled returns vulnerabilities where the symbols are actually called.
func filterCalled(r *vulncheck.Result) []*vulncheck.Vuln {
	var vulns []*vulncheck.Vuln
	for _, v := range r.Vulns {
		if v.CallSink != 0 {
			vulns = append(vulns, v)
		}
	}
	sortVulns(vulns)
	return vulns
}

// filterUnaffected returns vulnerabilities where no symbols are called,
// grouped by module.
func filterUnaffected(r *vulncheck.Result) []*vulncheck.Vuln {
	// It is possible that the same vuln.OSV.ID has vuln.CallSink != 0
	// for one symbol, but vuln.CallSink == 0 for a different one, so
	// we need to filter out ones that have been called.
	called := filterCalled(r)
	calledIDs := map[string]bool{}
	for _, vuln := range called {
		calledIDs[vuln.OSV.ID] = true
	}

	idToVuln := map[string]*vulncheck.Vuln{}
	for _, vuln := range r.Vulns {
		if !calledIDs[vuln.OSV.ID] {
			idToVuln[vuln.OSV.ID] = vuln
		}
	}
	var output []*vulncheck.Vuln
	for _, vuln := range idToVuln {
		output = append(output, vuln)
	}
	sortVulns(output)
	return output
}

func sortVulns(vulns []*vulncheck.Vuln) {
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].OSV.ID > vulns[j].OSV.ID
	})
}

func sortPackages(pkgs []*vulncheck.Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].PkgPath < pkgs[j].PkgPath
	})
	for _, pkg := range pkgs {
		sort.Slice(pkg.Imports, func(i, j int) bool {
			return pkg.Imports[i].PkgPath < pkg.Imports[j].PkgPath
		})
	}
}
