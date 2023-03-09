// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package govulncheck provides functionality to support the govulncheck command.
package govulncheck

import (
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/internal/result"
)

// LoadMode is the level of information needed for each package
// for running golang.org/x/tools/go/packages.Load.
var LoadMode = packages.NeedName | packages.NeedImports | packages.NeedTypes |
	packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
	packages.NeedModule

// Config is used for configuring the output of govulncheck.
type Config struct {
	// Client is the client used to make requests to a vulnerability
	// database(s). If nil, a default client is constructed that makes requests
	// to vuln.go.dev.
	Client client.Client

	// GoVersion specifies the Go version used when analyzing source code.
	//
	// By default, GoVersion is the go command version found from the PATH.
	GoVersion string
}

// IsCalled reports whether the vulnerability is called, therefore
// affecting the target source code or binary.
func IsCalled(v *result.Vuln) bool {
	for _, m := range v.Modules {
		for _, p := range m.Packages {
			if len(p.CallStacks) > 0 {
				return true
			}
		}
	}
	return false
}

// FuncName returns the full qualified function name from sf,
// adjusted to remove pointer annotations.
func FuncName(sf *result.StackFrame) string {
	var n string
	if sf.RecvType == "" {
		n = fmt.Sprintf("%s.%s", sf.PkgPath, sf.FuncName)
	} else {
		n = fmt.Sprintf("%s.%s", sf.RecvType, sf.FuncName)
	}
	return strings.TrimPrefix(n, "*")
}

// Pos returns the position of the call in sf as string.
// If position is not available, return "".
func Pos(sf *result.StackFrame) string {
	if sf.Position.IsValid() {
		return sf.Position.String()
	}
	return ""
}
