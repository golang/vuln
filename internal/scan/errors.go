// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/tools/go/packages"
)

var (
	// ErrVulnerabilitiesFound indicates that vulnerabilities were detected
	// when running govulncheck. This returns exit status 3 when running
	// without the -json flag.
	ErrVulnerabilitiesFound = errors.New("vulnerabilities found")

	// ErrNoPatterns indicates that no patterns were passed in when running
	// govulncheck.
	//
	// In this case, we assume that the user does not know how to run
	// govulncheck, and print the usage message with exit status 1.
	ErrNoPatterns = errors.New("no patterns provided")
)

//lint:file-ignore ST1005 Ignore staticcheck message about error formatting
var (
	// errGoVersionMismatch is used to indicate that there is a mismatch between
	// the Go version used to build govulncheck and the one currently on PATH.
	errGoVersionMismatch = errors.New(`Loading packages failed, possibly due to a mismatch between the Go version
used to build govulncheck and the Go version on PATH. Consider rebuilding
govulncheck with the current Go version.`)

	// errNoGoMod indicates that a go.mod file was not found in this module.
	errNoGoMod = errors.New(`no go.mod file

govulncheck only works with Go modules. Try navigating to your module directory.
Otherwise, run go mod init to make your project a module.

See https://go.dev/doc/modules/managing-dependencies for more information.`)

	// errNoBinaryFlag indicates that govulncheck was run on a file, without
	// the -mode=binary flag.
	errNoBinaryFlag = errors.New(`By default, govulncheck runs source analysis on Go modules.

Did you mean to run govulncheck with -mode=binary?

For details, run govulncheck -h.`)
)

// packageError contains errors from loading a set of packages.
type packageError struct {
	Errors []packages.Error
}

func (e *packageError) Error() string {
	var b strings.Builder
	fmt.Fprintln(&b, "\nThere are errors with the provided package patterns:")
	fmt.Fprintln(&b, "")
	for _, e := range e.Errors {
		fmt.Fprintln(&b, e)
	}
	fmt.Fprintln(&b, "\nFor details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.")
	return b.String()
}

// isGoVersionMismatchError checks if err is due to mismatch between
// the Go version used to build govulncheck and the one currently
// on PATH.
func isGoVersionMismatchError(err error) bool {
	msg := err.Error()
	// See golang.org/x/tools/go/packages/packages.go.
	return strings.Contains(msg, "This application uses version go") &&
		strings.Contains(msg, "It may fail to process source files")
}
