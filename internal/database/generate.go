// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package database generates the vulnerability database.
package database

import (
	"strings"

	"golang.org/x/mod/semver"
	"golang.org/x/vuln/internal/report"
	"golang.org/x/vuln/osv"
)

func Generate(id string, url string, r report.Report) (osv.Entry, []string) {
	importPath := r.Module
	if r.Package != "" {
		importPath = r.Package
	}
	moduleMap := make(map[string]bool)
	if r.Stdlib {
		moduleMap["stdlib"] = true
	} else {
		moduleMap[r.Module] = true
	}
	lastModified := r.Published
	if r.LastModified != nil {
		lastModified = *r.LastModified
	}
	entry := osv.Entry{
		ID:        id,
		Published: r.Published,
		Modified:  lastModified,
		Withdrawn: r.Withdrawn,
		Details:   r.Description,
		Affected:  []osv.Affected{generateAffected(importPath, r.Versions, r.OS, r.Arch, r.Symbols, url)},
	}

	for _, additional := range r.AdditionalPackages {
		additionalPath := additional.Module
		if additional.Package != "" {
			additionalPath = additional.Package
		}
		if !r.Stdlib {
			moduleMap[additional.Module] = true
		}
		entry.Affected = append(entry.Affected, generateAffected(additionalPath, additional.Versions, r.OS, r.Arch, additional.Symbols, url))
	}

	if r.Links.PR != "" {
		entry.References = append(entry.References, osv.Reference{Type: "FIX", URL: r.Links.PR})
	}
	if r.Links.Commit != "" {
		entry.References = append(entry.References, osv.Reference{Type: "FIX", URL: r.Links.Commit})
	}
	for _, link := range r.Links.Context {
		entry.References = append(entry.References, osv.Reference{Type: "WEB", URL: link})
	}

	if r.CVE != "" {
		entry.Aliases = []string{r.CVE}
	} else {
		entry.Aliases = r.CVEs
	}

	var modules []string
	for module := range moduleMap {
		modules = append(modules, module)
	}

	return entry, modules
}

func generateAffectedRanges(versions []report.VersionRange) osv.Affects {
	a := osv.AffectsRange{Type: osv.TypeSemver}
	if len(versions) == 0 || versions[0].Introduced == "" {
		a.Events = append(a.Events, osv.RangeEvent{Introduced: "0"})
	}
	for _, v := range versions {
		if v.Introduced != "" {
			v.Introduced = canonicalizeSemverPrefix(v.Introduced)
			a.Events = append(a.Events, osv.RangeEvent{Introduced: removeSemverPrefix(semver.Canonical(v.Introduced))})
		}
		if v.Fixed != "" {
			v.Fixed = canonicalizeSemverPrefix(v.Fixed)
			a.Events = append(a.Events, osv.RangeEvent{Fixed: removeSemverPrefix(semver.Canonical(v.Fixed))})
		}
	}
	return osv.Affects{a}
}

func generateAffected(importPath string, versions []report.VersionRange, goos, goarch, symbols []string, url string) osv.Affected {
	return osv.Affected{
		Package: osv.Package{
			Name:      importPath,
			Ecosystem: osv.GoEcosystem,
		},
		Ranges:           generateAffectedRanges(versions),
		DatabaseSpecific: osv.DatabaseSpecific{URL: url},
		EcosystemSpecific: osv.EcosystemSpecific{
			GOOS:    goos,
			GOARCH:  goarch,
			Symbols: symbols,
		},
	}
}

// removeSemverPrefix removes the 'v' or 'go' prefixes from go-style
// SEMVER strings, for usage in the public vulnerability format.
func removeSemverPrefix(s string) string {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "go")
	return s
}

// canonicalizeSemverPrefix turns a SEMVER string into the canonical
// representation using the 'v' prefix, as used by the OSV format.
// Input may be a bare SEMVER ("1.2.3"), Go prefixed SEMVER ("go1.2.3"),
// or already canonical SEMVER ("v1.2.3").
func canonicalizeSemverPrefix(s string) string {
	return addSemverPrefix(removeSemverPrefix(s))
}

// addSemverPrefix adds a 'v' prefix to s if it isn't already prefixed
// with 'v' or 'go'. This allows us to easily test go-style SEMVER
// strings against normal SEMVER strings.
func addSemverPrefix(s string) string {
	if !strings.HasPrefix(s, "v") && !strings.HasPrefix(s, "go") {
		return "v" + s
	}
	return s
}
