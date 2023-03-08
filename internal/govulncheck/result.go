// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package govulncheck provides functionality to support the govulncheck command.
package govulncheck

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
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
