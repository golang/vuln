// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package scan

import (
	"context"
	"os"

	"golang.org/x/vuln/internal/client"
	"golang.org/x/vuln/internal/derrors"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/internal/vulncheck"
)

// runBinary detects presence of vulnerable symbols in an executable.
func runBinary(ctx context.Context, handler govulncheck.Handler, cfg *config, client *client.Client) (err error) {
	defer derrors.Wrap(&err, "govulncheck")

	exe, err := os.Open(cfg.patterns[0])
	if err != nil {
		return err
	}
	defer exe.Close()

	p := &govulncheck.Progress{Message: binaryProgressMessage}
	if err := handler.Progress(p); err != nil {
		return err
	}
	return vulncheck.Binary(ctx, handler, exe, &cfg.Config, client)
}
