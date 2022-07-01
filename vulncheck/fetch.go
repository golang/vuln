// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/vuln/client"
)

var stdlibModule = &Module{
	Path: "stdlib",
	// Version is populated by Source and Binary based on user input
}

var (
	// Regexp for matching go tags. The groups are:
	// 1  the major.minor version
	// 2  the patch version, or empty if none
	// 3  the entire prerelease, if present
	// 4  the prerelease type ("beta" or "rc")
	// 5  the prerelease number
	tagRegexp = regexp.MustCompile(`^go(\d+\.\d+)(\.\d+|)((beta|rc|-pre)(\d+))?$`)
)

// This is a modified copy of pkgsite/internal/stdlib:VersionForTag.
func goTagToSemver(tag string) string {
	if tag == "" {
		return ""
	}

	tag = strings.Fields(tag)[0]
	// Special cases for go1.
	if tag == "go1" {
		return "v1.0.0"
	}
	if tag == "go1.0" {
		return ""
	}
	m := tagRegexp.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	version := "v" + m[1]
	if m[2] != "" {
		version += m[2]
	} else {
		version += ".0"
	}
	if m[3] != "" {
		if !strings.HasPrefix(m[4], "-") {
			version += "-"
		}
		version += m[4] + "." + m[5]
	}
	return version
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
