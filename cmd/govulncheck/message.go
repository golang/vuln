// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"golang.org/x/vuln/internal/govulncheck"
)

const (
	noGoModErrorMessage = `govulncheck only works Go with modules. To make your project a module, run go mod init.

See https://go.dev/doc/modules/managing-dependencies for more information.`

	noGoSumErrorMessage = `Your module is missing a go.sum file. Try running go mod tidy.

See https://go.dev/doc/modules/managing-dependencies for more information.`

	goVersionMismatchErrorMessage = `Loading packages failed, possibly due to a mismatch between the Go version
used to build govulncheck and the Go version on PATH. Consider rebuilding
govulncheck with the current Go version.`
)

var errToMessage = map[error]string{
	govulncheck.ErrNoGoMod:             noGoModErrorMessage,
	govulncheck.ErrNoGoSum:             noGoSumErrorMessage,
	govulncheck.ErrGoVersionMismatch:   goVersionMismatchErrorMessage,
	govulncheck.ErrInvalidAnalysisType: "",
	govulncheck.ErrInvalidOutputType:   "",
}

func messageForError(err error) (out string) {
	msg, ok := errToMessage[err]
	if !ok {
		return ""
	}
	return fmt.Sprintf("govulncheck: %v\n\n%s", err, msg)
}
