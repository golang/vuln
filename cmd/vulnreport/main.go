// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command vulnreport provides a tool for creating a YAML vulnerability report for
// x/vulndb.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/vuln/internal/derrors"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: vulnreport [cmd] [filename]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  create [filename]: creates a new vulnerability YAML report\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  lint [filename]: lints a vulnerability YAML report\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	filename := flag.Arg(1)
	switch cmd {
	case "create":
		if err := create(filename); err != nil {
			log.Fatal(err)
		}
	case "lint":
		log.Fatalf("not implemented")
	default:
		flag.Usage()
		log.Fatalf("unsupported command: %q", cmd)
	}
}

func create(filename string) (err error) {
	defer derrors.Wrap(&err, "create(%q)", filename)
	return os.WriteFile(filename,
		[]byte(`module:
package:
versions:
  - introduced:
  - fixed:
description: |

cve:
credit:
symbols:
  -
published:
links:
  commit:
  pr:
  context:
    -
`), 0644)
}
