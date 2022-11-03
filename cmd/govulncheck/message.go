// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

const (
	introMessage = `govulncheck is an experimental tool. Share feedback at https://go.dev/s/govulncheck-feedback.

Scanning for dependencies with known vulnerabilities...`

	informationalMessage = `=== Informational ===

The vulnerabilities below are in packages that you import, but your code
doesn't appear to call any vulnerable functions. You may not need to take any
action. See https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
for details.`
)
