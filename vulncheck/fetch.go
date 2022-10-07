// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"

	"golang.org/x/vuln/client"
	"golang.org/x/vuln/internal"
)

var stdlibModule = &Module{
	Path: internal.GoStdModulePath,
	// Version is populated by Source and Binary based on user input
}

// modKey creates a unique string identifier for mod.
func modKey(mod *Module) string {
	if mod == nil {
		return ""
	}
	return fmt.Sprintf("%s@%s", mod.Path, mod.Version)
}

// extractModules collects modules in `pkgs` up to uniqueness of
// module path and version.
func extractModules(pkgs []*Package) []*Module {
	modMap := map[string]*Module{}

	// Add "stdlib" module. Even if stdlib is not used, which
	// is unlikely, it won't appear in vulncheck.Modules nor
	// other results.
	modMap[stdlibModule.Path] = stdlibModule

	seen := map[*Package]bool{}
	var extract func(*Package, map[string]*Module)
	extract = func(pkg *Package, modMap map[string]*Module) {
		if pkg == nil || seen[pkg] {
			return
		}
		if pkg.Module != nil {
			if pkg.Module.Replace != nil {
				modMap[modKey(pkg.Module.Replace)] = pkg.Module
			} else {
				modMap[modKey(pkg.Module)] = pkg.Module
			}
		}
		seen[pkg] = true
		for _, imp := range pkg.Imports {
			extract(imp, modMap)
		}
	}
	for _, pkg := range pkgs {
		extract(pkg, modMap)
	}

	modules := []*Module{}
	for _, mod := range modMap {
		modules = append(modules, mod)
	}
	return modules
}

// fetchVulnerabilities fetches vulnerabilities that affect the supplied modules.
func fetchVulnerabilities(ctx context.Context, client client.Client, modules []*Module) (moduleVulnerabilities, error) {
	mv := moduleVulnerabilities{}
	for _, mod := range modules {
		modPath := mod.Path
		if mod.Replace != nil {
			modPath = mod.Replace.Path
		}

		vulns, err := client.GetByModule(ctx, modPath)
		if err != nil {
			return nil, err
		}
		if len(vulns) == 0 {
			continue
		}
		mv = append(mv, modVulns{
			mod:   mod,
			vulns: vulns,
		})
	}
	return mv, nil
}
