// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package govulncheck has experimental govulncheck API.
package govulncheck

import "golang.org/x/vuln/internal/govulncheck"

// Config is the configuration for Main.
type Config = govulncheck.Config

// Run is the main function for the govulncheck command line tool.
func Run(cfg Config) {
	govulncheck.Run(cfg)
}
