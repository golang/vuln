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
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"funcName": funcName,
	}).Parse(templateSource)
	if err != nil {
		return err
	}

	type vuln struct {
		PkgPath        string
		CurrentVersion string
		FixedVersion   string
		Reference      string
		Details        string
	}

	type callstack struct {
		Summary string
		Stack   vulncheck.CallStack
	}

	type callstacks struct {
		ID     string // osv.Entry ID
		Stacks []callstack
	}

	data := struct {
		Vulns      []vuln
		CallStacks []callstacks
	}{}

	for _, vg := range vulnGroups {
		v0 := vg[0]
		data.Vulns = append(data.Vulns, vuln{
			PkgPath:        v0.PkgPath,
			CurrentVersion: moduleVersions[v0.ModPath],
			FixedVersion:   "v" + latestFixed(v0.OSV.Affected),
			Reference:      fmt.Sprintf("https://pkg.go.dev/vuln/%s", v0.OSV.ID),
			Details:        v0.OSV.Details,
		})
		// Keep first call stack for each vuln.
		stacks := callstacks{ID: v0.OSV.ID}
		for _, v := range vg {
			if css := callStacks[v]; len(css) > 0 {
				stacks.Stacks = append(stacks.Stacks, callstack{
					Summary: summarizeCallStack(css[0], topPackages, v.PkgPath),
					Stack:   css[0],
				})
			}
		}
		data.CallStacks = append(data.CallStacks, stacks)
	}
	return tmpl.Execute(w, data)
}

var templateSource = `
<!DOCTYPE html>
<html lang="en">
<meta charset="utf-8">
<title>govulncheck Results</title>

<body>
  {{with .Vulns}}
	<h2>Vulnerabilities</h2>
	<table>
	  <tr><th>Package</th><th>Your Version</th><th>Fixed Version</th><th>Reference</th><th>Details</th><tr>
	  {{range .Vulns}}
		<tr>
		  <td>{[.PkgPath}}</td>
		  <td>{{.CurrentVersion}}</td>
		  <td>{{.FixedVersion}}</td>
		  <td>{{.Reference}}</td>
		  <td>{{.Details}}</td>
		</tr>
	  {{end}}
	</table>

	 <h2>Call Stacks</h2>
	 {{range .CallStacks}}
	   <h3>.ID</h3>
	   {{range .Stacks}}
		 <details>
		   <summary>{{.Summary}}</summary>
		   {{range .Stack}}
			 <p>{{.Function | funcName}}</p>
		   {{end}}
		 </details>
	   {{end}}
	 {{end}}
  {{else}}
    No vulnerabilities found.
  {{end}}
</body>
</html>
`
