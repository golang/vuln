// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// outputTemplate is a text template used to print out
// govulncheck output. It consists of three sections showing
// 1) the number of vulnerabilities detected, 2) callstacks
// detected for each pair of module and vulnerability, and
// 3) vulnerabilities that are only imported but not called.
const outputTemplate = `
{{- define "VulnCount" -}}
{{if eq .UniqueVulns 0}}No vulnerabilities found.
{{else if eq .UniqueVulns 1}}Found 1 known vulnerability.
{{else}}Found {{ .UniqueVulns }} known vulnerabilities.
{{end}}
{{- end -}}

{{- define "Affected" -}}
{{if len .Affected}}{{range $idx, $vulnInfo := .Affected}}
Vulnerability #{{inc $idx}}: {{$vulnInfo.ID}}
{{wrap $vulnInfo.Details | indent 2}}
{{if $vulnInfo.Stacks}}
  Call stacks in your code:
{{indent 6 $vulnInfo.Stacks}}
{{end}}  Found in: {{$vulnInfo.Found}}
  Fixed in: {{if $vulnInfo.Fixed}}{{$vulnInfo.Fixed}}{{else}}N/A{{end}}
  {{if $vulnInfo.Platforms}}Platforms: {{$vulnInfo.Platforms}}
  {{end -}}
  More info: https://pkg.go.dev/vuln/{{$vulnInfo.ID}}
{{end}}
{{- end -}}
{{- end -}}

{{- define "Informational" -}}
{{if len .Unaffected}}
=== Informational ===

The vulnerabilities below are in packages that you import, but your code
doesn't appear to call any vulnerable functions. You may not need to take any
action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
for details.
{{range $idx, $vulnInfo := .Unaffected}}
Vulnerability #{{inc $idx}}: {{$vulnInfo.ID}}
{{wrap $vulnInfo.Details | indent 2}}
  Found in: {{$vulnInfo.Found}}
  Fixed in: {{if $vulnInfo.Fixed}}{{$vulnInfo.Fixed}}{{else}}N/A{{end}}
  {{if $vulnInfo.Platforms}}Platforms: {{$vulnInfo.Platforms}}
  {{end -}}
  More info: https://pkg.go.dev/vuln/{{$vulnInfo.ID}}
{{end}}
{{- end -}}
{{- end -}}

{{template "VulnCount" .}}{{template "Affected" .}}{{template "Informational" . -}}
`

// tmplResult is a structure containing summarized
// govulncheck.Result, passed to outputTemplate.
type tmplResult struct {
	UniqueVulns int
	Unaffected  []tmplVulnInfo
	Affected    []tmplVulnInfo
}

// tmplVulnInfo is a vulnerability info
// structure used by the outputTemplate.
type tmplVulnInfo struct {
	ID        string
	Details   string
	Found     string
	Fixed     string
	Platforms string
	Stacks    string
}
