// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vulncheck

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/osv"
)

func frameFromPackage(pkg *packages.Package) *govulncheck.Frame {
	fr := &govulncheck.Frame{
		Module:  pkg.Module.Path,
		Version: pkg.Module.Version,
		Package: pkg.PkgPath,
	}

	if pkg.Module.Replace != nil {
		fr.Module = pkg.Module.Replace.Path
		fr.Version = pkg.Module.Replace.Version
	}
	return fr
}

func frameFromModule(mod *packages.Module, affected []osv.Affected) *govulncheck.Frame {
	fr := &govulncheck.Frame{
		Module:  mod.Path,
		Version: mod.Version,
	}

	if mod.Path == internal.GoStdModulePath {
		for _, a := range affected {
			if a.Module.Path != mod.Path {
				continue
			}
			fr.Package = a.EcosystemSpecific.Packages[0].Path
		}
	}

	if mod.Replace != nil {
		fr.Module = mod.Replace.Path
		fr.Version = mod.Replace.Version
	}

	return fr
}

func emitModuleFindings(modVulns moduleVulnerabilities, handler govulncheck.Handler) map[string]*osv.Entry {
	osvs := make(map[string]*osv.Entry)
	for _, vuln := range modVulns {
		for _, osv := range vuln.Vulns {
			if _, found := osvs[osv.ID]; !found {
				handler.OSV(osv)
			}
			handler.Finding(&govulncheck.Finding{
				OSV:          osv.ID,
				FixedVersion: FixedVersion(ModPath(vuln.Module), ModVersion(vuln.Module), osv.Affected),
				Trace:        []*govulncheck.Frame{frameFromModule(vuln.Module, osv.Affected)},
			})
		}
	}
	return osvs
}

func emitPackageFinding(vuln *Vuln, handler govulncheck.Handler) error {
	return handler.Finding(&govulncheck.Finding{
		OSV:          vuln.OSV.ID,
		FixedVersion: FixedVersion(ModPath(vuln.ImportSink.Module), ModVersion(vuln.ImportSink.Module), vuln.OSV.Affected),
		Trace:        []*govulncheck.Frame{frameFromPackage(vuln.ImportSink)},
	})
}
