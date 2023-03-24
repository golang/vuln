// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
)

const usage = `test helper for examining the output of running govulncheck on
stackrox-io/scanner binary (https://quay.io/repository/stackrox-io/scanner).

Example usage: ./stackrox-scanner [path to output file]
`

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Incorrect number of expected command line arguments", usage)
	}
	out := os.Args[1]

	outJson, err := os.ReadFile(out)
	if err != nil {
		log.Fatal("Failed to read:", out)
	}

	var r govulncheck.Result
	if err := json.Unmarshal(outJson, &r); err != nil {
		log.Fatal("Failed to load json into internal/govulncheck.Result:", err)
	}

	symbolVulnPkgs := make(map[string]bool)
	for _, v := range r.Vulns {
		for _, m := range v.Modules {
			for _, p := range m.Packages {
				if len(p.CallStacks) > 0 {
					symbolVulnPkgs[p.Path] = true
				}
			}
		}
	}

	want := map[string]bool{
		"net/http":                     true,
		"path/filepath":                true,
		"regexp/syntax":                true,
		"archive/tar":                  true,
		"compress/gzip":                true,
		"crypto/elliptic":              true,
		"crypto/tls":                   true,
		"encoding/pem":                 true,
		"encoding/xml":                 true,
		"mime/multipart":               true,
		"golang.org/x/net/http2":       true,
		"golang.org/x/net/http2/hpack": true,
	}

	if diff := cmp.Diff(want, symbolVulnPkgs); diff != "" {
		log.Fatalf("present vulnerable symbol packages mismatch (-want, +got):\n%s", diff)
	}
}
