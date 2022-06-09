// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"embed"
	"fmt"
	"html/template"
	"io"

	"golang.org/x/vuln/cmd/govulncheck/internal/govulncheck"
	"golang.org/x/vuln/vulncheck"
)

//go:embed static/*
var staticContent embed.FS

func html(w io.Writer, ci *govulncheck.CallInfo) error {
	tmpl, err := template.New("govulncheck.tmpl").Funcs(template.FuncMap{
		"funcName": govulncheck.FuncName,
	}).ParseFS(staticContent, "static/govulncheck.tmpl")
	if err != nil {
		return err
	}

	type callstack struct {
		Summary string
		Stack   vulncheck.CallStack
	}

	type vuln struct {
		ID             string
		PkgPath        string
		CurrentVersion string
		FixedVersion   string
		Reference      string
		Details        string
		Stacks         []callstack
	}

	var vulns []*vuln
	for _, vg := range ci.VulnGroups {
		v0 := vg[0]
		vn := &vuln{
			ID:             v0.OSV.ID,
			PkgPath:        v0.PkgPath,
			CurrentVersion: ci.ModuleVersions[v0.ModPath],
			FixedVersion:   "v" + govulncheck.LatestFixed(v0.OSV.Affected),
			Reference:      fmt.Sprintf("https://pkg.go.dev/vuln/%s", v0.OSV.ID),
			Details:        v0.OSV.Details,
		}
		// Keep first call stack for each vuln.
		for _, v := range vg {
			if css := ci.CallStacks[v]; len(css) > 0 {
				vn.Stacks = append(vn.Stacks, callstack{
					Summary: govulncheck.SummarizeCallStack(css[0], ci.TopPackages, v.PkgPath),
					Stack:   css[0],
				})
			}
		}
		vulns = append(vulns, vn)
	}
	return tmpl.Execute(w, vulns)
}
