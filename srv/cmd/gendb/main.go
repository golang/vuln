// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command gendb provides a tool for converting YAML reports into JSON
// database.
package main

import (
	"flag"
	"log"

	"golang.org/x/vuln/srv/internal/database"
)

// TODO(rolandshoemaker): once we have the HTML representation ready this should
// be the prefix for that.
const dbURL = "https://go.googlesource.com/vuln/+/refs/heads/master/reports/"

var (
	yamlDir = flag.String("reports", "reports", "Directory containing yaml reports")
	jsonDir = flag.String("out", "out", "Directory to write JSON database to")
)

func main() {
	flag.Parse()
	if err := database.Generate(*yamlDir, *jsonDir, dbURL); err != nil {
		log.Fatal(err)
	}
}
