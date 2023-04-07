// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"golang.org/x/vuln/internal/scan"
)

func main() {
	ctx := context.Background()
	err := scan.Command(ctx, os.Args[1:]...).Run()
	if err != nil {
		switch err {
		case flag.ErrHelp:
			os.Exit(0)
		case scan.ErrVulnerabilitiesFound:
			os.Exit(3)
		case scan.ErrNoPatterns:
			// flag.Usage is printed in the case of this error, so do not print
			// the actual error message.
			os.Exit(1)
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
