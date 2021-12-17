// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command report2cve provides a tool for converting YAML reports into JSON
// CVEs.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/vuln/srv/internal/report"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprint(os.Stderr, "usage: report2cve report.yaml")
		os.Exit(1)
	}
	cve, err := report.ToCVE(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// We need to use an encoder so that it doesn't escape angle
	// brackets.
	e := json.NewEncoder(os.Stdout)
	e.SetEscapeHTML(false)
	e.SetIndent("", "\t")
	if err = e.Encode(cve); err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal CVE: %s\n", err)
		os.Exit(1)
	}
}
