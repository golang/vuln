// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"os"
)

const noGoModErrorMessage = `govulncheck: no go.mod file

govulncheck only works Go with modules. To make your project a module, run go mod init.

See https://go.dev/doc/modules/managing-dependencies for more information.`

const noGoSumErrorMessage = `govulncheck: no go.sum file

Your module is missing a go.sum file. Try running go mod tidy.

See https://go.dev/doc/modules/managing-dependencies for more information.`

// fileExists checks if file path exists. Returns true
// if the file exists or it cannot prove that it does
// not exist. Otherwise, returns false.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	}
	// Conservatively return true if os.Stat fails
	// for some other reason.
	return true
}
