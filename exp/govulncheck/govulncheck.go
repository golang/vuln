// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package govulncheck has experimental govulncheck API.
package govulncheck

import (
	"context"

	"golang.org/x/vuln/internal/govulncheck"
)

// Config is the configuration for Main.
type Config = govulncheck.Config

// Main is the main function for the govulncheck command line tool.
func Main(cfg Config) error {
	ctx := context.Background()
	_, err := govulncheck.Run(ctx, cfg)
	return err
}
