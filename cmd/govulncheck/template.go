// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// introTemplate is a text template used to communicate to the
// user the environment used for vulnerability analysis, namely
// the Go version, govulncheck version, vuln dbs with their last
// modified timestamp.
const introTemplate = `govulncheck is an experimental tool. Share feedback at https://go.dev/s/govulncheck-feedback.

Using {{.GoPhrase}}govulncheck{{.GovulncheckVersion}} with
vulnerability data from {{.DBsPhrase}}{{.DBLastModifiedPhrase}}.
`

// outputTemplate is a text template used to print out
// govulncheck output. It consists of three sections showing
// 1) the number of vulnerabilities detected, 2) callstacks
// detected for each pair of module and vulnerability, and
// 3) vulnerabilities that are only imported but not called.
const outputTemplate = `
{{- define "CountPhrase" -}}{{if eq (len .Affected) 1}}vulnerability{{else}}vulnerabilities{{end}}{{- end -}}
{{- define "ModulePhrase" -}}{{if eq .AffectedModules 1}}1 module{{else}}{{.AffectedModules}} modules{{end}}{{- end -}}
{{- define "StdlibPhrase" -}}{{if .AffectedModules}} and {{end}}the Go standard library{{- end -}}
{{- define "VulnCount" -}}
{{if eq (len .Affected) 0}}No vulnerabilities found.
{{else}}Your code is affected by {{len .Affected}} {{template "CountPhrase" .}} from {{if .AffectedModules}}{{template "ModulePhrase" .}}{{end}}{{if .StdlibAffected}}{{template "StdlibPhrase" .}}{{end}}.
{{end}}
{{- end -}}

{{- define "Affected" -}}
{{if len .Affected}}{{range $idx, $vulnInfo := .Affected}}
Vulnerability #{{inc $idx}}: {{$vulnInfo.ID}}
{{wrap $vulnInfo.Details | indent 2}}

  More info: https://pkg.go.dev/vuln/{{$vulnInfo.ID}}
{{range $modInfo := $vulnInfo.Modules}}
  {{if $modInfo.IsStd}}Standard library{{else}}Module: {{$modInfo.Module}}{{end}}
    Found in: {{$modInfo.Found}}
    Fixed in: {{if $modInfo.Fixed}}{{$modInfo.Fixed}}{{else}}N/A{{end}}
    {{- if $modInfo.Platforms}}
    Platforms: {{$modInfo.Platforms}}{{end}}
{{if $modInfo.Stacks}}
    Call stacks in your code:
{{indent 6 $modInfo.Stacks}}{{end}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "Informational" -}}
{{if len .Unaffected}}
=== Informational ===

Found {{len .Unaffected}} {{if eq (len .Unaffected) 1}}vulnerability{{else}}vulnerabilities{{end}} in packages that you import, but there are no call
stacks leading to the use of {{if eq (len .Unaffected) 1}}this vulnerability{{else}}these vulnerabilities{{end}}. You may not need to
take any action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
for details.
{{range $idx, $vulnInfo := .Unaffected}}
Vulnerability #{{inc $idx}}: {{$vulnInfo.ID}}{{$modInfo:= index $vulnInfo.Modules 0}}
{{wrap $vulnInfo.Details | indent 2}}
  More info: https://pkg.go.dev/vuln/{{$vulnInfo.ID}}
  Found in: {{$modInfo.Found}}
  Fixed in: {{if $modInfo.Fixed}}{{$modInfo.Fixed}}{{else}}N/A{{end}}
  {{- if $modInfo.Platforms}}
  Platforms: {{$modInfo.Platforms}}{{end}}
{{end}}
{{- end -}}
{{- end -}}

{{template "VulnCount" .}}{{template "Affected" .}}{{template "Informational" . -}}
`

// tmplResult is a structure containing summarized
// govulncheck.Result, passed to outputTemplate.
type tmplResult struct {
	Unaffected []tmplVulnInfo
	Affected   []tmplVulnInfo
}

// AffectedModules returns the number of unique modules
// whose vulnerabilties are detected.
func (r tmplResult) AffectedModules() int {
	mods := make(map[string]bool)
	for _, a := range r.Affected {
		for _, m := range a.Modules {
			if !m.IsStd {
				mods[m.Module] = true
			}
		}
	}
	return len(mods)
}

// StdlibAffected tells if some of the vulnerabilities
// detected come from standard library.
func (r tmplResult) StdlibAffected() bool {
	for _, a := range r.Affected {
		for _, m := range a.Modules {
			if m.IsStd {
				return true
			}
		}
	}
	return false
}

// tmplVulnInfo is a vulnerability info
// structure used by the outputTemplate.
type tmplVulnInfo struct {
	ID      string
	Details string
	Modules []tmplModVulnInfo
}

// tmplModVulnInfo is a module vulnerability
// structure used by the outputTemplate.
type tmplModVulnInfo struct {
	IsStd     bool
	Module    string
	Found     string
	Fixed     string
	Platforms string
	Stacks    string
}
