// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govulncheck

import (
	"context"
	"errors"
	"io"

	"golang.org/x/vuln/vulncheck"
)

// Source reports vulnerabilities that affect the analyzed packages.
//
// Vulnerabilities can be called (affecting the package, because a vulnerable
// symbol is actually exercised) or just imported by the package
// (likely having a non-affecting outcome).
//
// This function is used for source code analysis by cmd/govulncheck and
// exp/govulncheck.
//
// TODO(https://go.dev/issue/56042): implement
func Source(ctx context.Context, cfg *Config, pkgs []*vulncheck.Package) (*Result, error) {
	return nil, errors.New("not implemented")
}

// Binary detects presence of vulnerable symbols in exe.
//
// This function is used for binary analysis by cmd/govulncheck.
//
// TODO(https://go.dev/issue/56042): implement
func Binary(ctx context.Context, cfg *Config, exe io.ReaderAt) (*Result, error) {
	return nil, errors.New("not implemented")
}
