// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"log"
	"os"

	"golang.org/x/vuln/cmd/govulncheck/integration/internal/integration"
)

const usage = `test helper for examining the output of running govulncheck on k8s@v1.15.11.

Example usage: ./k8s [path to output file]
`

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Incorrect number of expected command line arguments", usage)
	}
	out := os.Args[1]

	want := map[string]bool{
		"github.com/containernetworking/cni/pkg/invoke":           true,
		"github.com/evanphx/json-patch":                           true,
		"github.com/heketi/heketi/client/api/go-client":           true,
		"github.com/heketi/heketi/pkg/glusterfs/api":              true,
		"github.com/heketi/heketi/pkg/utils":                      true,
		"github.com/opencontainers/selinux/go-selinux":            true,
		"github.com/prometheus/client_golang/prometheus/promhttp": true,
		"golang.org/x/crypto/cryptobyte":                          true,
		"golang.org/x/crypto/salsa20/salsa":                       true,
		"golang.org/x/crypto/ssh":                                 true,
		"golang.org/x/net/http/httpguts":                          true,
		"golang.org/x/net/http2":                                  true,
		"golang.org/x/net/http2/hpack":                            true,
		"golang.org/x/text/encoding/unicode":                      true,
		"google.golang.org/grpc":                                  true,
	}
	if err := integration.CompareVulns(out, want); err != nil {
		log.Fatal(err)
	}
}
