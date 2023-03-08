// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/result"
)

const usage = `test helper for examining the output of running govulncheck on k8s@v1.15.11.

Example usage: ./k8s [path to output file]
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

	var r result.Result
	if err := json.Unmarshal(outJson, &r); err != nil {
		log.Fatal("Failed to load json into internal/govulncheck.Result:", err)
	}

	calledVulnPkgs := make(map[string]bool)
	for _, v := range r.Vulns {
		for _, m := range v.Modules {
			for _, p := range m.Packages {
				if len(p.CallStacks) > 0 {
					calledVulnPkgs[p.Path] = true
				}
			}
		}
	}

	want := map[string]bool{
		"crypto/tls":     true,
		"net/http":       true,
		"path/filepath":  true,
		"mime/multipart": true,
		"github.com/containernetworking/cni/pkg/invoke":           true,
		"github.com/evanphx/json-patch":                           true,
		"github.com/opencontainers/selinux/go-selinux":            true,
		"github.com/prometheus/client_golang/prometheus/promhttp": true,
		"golang.org/x/crypto/cryptobyte":                          true,
		"golang.org/x/crypto/salsa20/salsa":                       true,
		"golang.org/x/crypto/ssh":                                 true,
		"golang.org/x/net/http/httpguts":                          true,
		"golang.org/x/net/http2":                                  true,
		"golang.org/x/net/http2/hpack":                            true,
		"golang.org/x/text/encoding/unicode":                      true,
	}

	if diff := cmp.Diff(want, calledVulnPkgs); diff != "" {
		log.Fatalf("reachable vulnerable packages mismatch (-want, +got):\n%s", diff)
	}
}
