// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.18
// +build !go1.18

package govulncheck

import (
	"context"
	"errors"
	"io"

	"golang.org/x/vuln/vulncheck"
)

func binary(ctx context.Context, exe io.ReaderAt, cfg *vulncheck.Config) (_ *vulncheck.Result, err error) {
	return nil, errors.New("compile with Go 1.18 or higher to analyze binary files")
}
