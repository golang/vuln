// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package main

import (
	"fmt"
	"html/template"
	"io"

	"golang.org/x/vuln/vulncheck"
)

func html(w io.Writer, r *vulncheck.Result, callStacks map[*vulncheck.Vuln][]vulncheck.CallStack, moduleVersions map[string]string, topPackages map[string]bool, vulnGroups [][]*vulncheck.Vuln) error {
	tmpl, err := template.New("govulncheck").Funcs(template.FuncMap{
		"funcName": funcName,
	}).Parse(templateSource)
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
	for _, vg := range vulnGroups {
		v0 := vg[0]
		vn := &vuln{
			ID:             v0.OSV.ID,
			PkgPath:        v0.PkgPath,
			CurrentVersion: moduleVersions[v0.ModPath],
			FixedVersion:   "v" + latestFixed(v0.OSV.Affected),
			Reference:      fmt.Sprintf("https://pkg.go.dev/vuln/%s", v0.OSV.ID),
			Details:        v0.OSV.Details,
		}
		// Keep first call stack for each vuln.
		for _, v := range vg {
			if css := callStacks[v]; len(css) > 0 {
				vn.Stacks = append(vn.Stacks, callstack{
					Summary: summarizeCallStack(css[0], topPackages, v.PkgPath),
					Stack:   css[0],
				})
			}
		}
		vulns = append(vulns, vn)
	}
	return tmpl.Execute(w, vulns)
}

var templateSource = `
<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<title>govulncheck Results</title>
<style>
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu,
    'Helvetica Neue', Arial, sans-serif;
}
list-style-type: none;
</style>


<body>
  {{range .}}
    <h2>{{.ID}}</h2>
    <table>
      <tr><td>Package</td><td>{{.PkgPath}}</td></tr>
      <tr><td>Your version</td><td>{{.CurrentVersion}}</td></tr>
      <tr><td>Fixed version</td><td>{{.FixedVersion}}</td></tr>
      <tr><td>Reference</td><td>{{.Reference}}</td></tr>
      <tr><td>Description</td><td>{{.Details}}</td></tr>
    </table>

    {{range .Stacks}}
      <details>
        <summary>{{.Summary}}</summary>
        <ul>
          {{range .Stack}}
            <li>{{.Function | funcName}}</li>
          {{end}}
        </ul>
      </details>
    {{end}}
  {{else}}
    No vulnerabilities found.
  {{end}}
</body>
</html>
`
