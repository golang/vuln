// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/vuln/internal/govulncheck"
)

func main() {
	ctx := context.Background()
	err := govulncheck.Command(ctx, os.Args[0], os.Args[1:]...).Run()
	if err != nil {
		switch err {
		case flag.ErrHelp:
			os.Exit(0)
		case govulncheck.ErrMissingArgPatterns:
			os.Exit(1)
		case govulncheck.ErrVulnerabilitiesFound:
			os.Exit(3)
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
