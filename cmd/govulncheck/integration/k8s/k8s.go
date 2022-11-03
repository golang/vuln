// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/exp/govulncheck"
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

	var r govulncheck.Result
	if err := json.Unmarshal(outJson, &r); err != nil {
		log.Fatal("Failed to load json into exp/govulncheck.Result:", err)
	}

	type vuln struct {
		pkg    string
		symbol string
	}
	calledVulns := make(map[vuln]bool)
	for _, v := range r.Vulns {
		for _, m := range v.Modules {
			for _, p := range m.Packages {
				for _, c := range p.CallStacks {
					calledVulns[vuln{p.Path, c.Symbol}] = true
				}
			}
		}
	}

	want := map[vuln]bool{
		{"github.com/containernetworking/cni/pkg/invoke", "FindInPath"}:       true,
		{"github.com/evanphx/json-patch", "partialArray.add"}:                 true,
		{"github.com/opencontainers/selinux/go-selinux", "FileLabel"}:         true,
		{"github.com/opencontainers/selinux/go-selinux", "GetEnabled"}:        true,
		{"github.com/opencontainers/selinux/go-selinux", "SetFileLabel"}:      true,
		{"golang.org/x/crypto/cryptobyte", "Builder.AddBytes"}:                true,
		{"golang.org/x/crypto/cryptobyte", "Builder.AddUint16LengthPrefixed"}: true,
		{"golang.org/x/crypto/cryptobyte", "Builder.Bytes"}:                   true,
		{"golang.org/x/crypto/cryptobyte", "NewBuilder"}:                      true,
		{"golang.org/x/crypto/cryptobyte", "String.Empty"}:                    true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadASN1"}:                 true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadOptionalASN1"}:         true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadUint16LengthPrefixed"}: true,
		{"golang.org/x/crypto/salsa20/salsa", "XORKeyStream"}:                 true,
		{"golang.org/x/crypto/ssh", "NewClientConn"}:                          true,
		{"golang.org/x/crypto/ssh", "NewPublicKey"}:                           true,
		{"golang.org/x/crypto/ssh", "ed25519PublicKey.Verify"}:                true,
		{"golang.org/x/crypto/ssh", "parseED25519"}:                           true,
		{"golang.org/x/net/http/httpguts", "HeaderValuesContainsToken"}:       true,
		{"golang.org/x/net/http2", "Server.ServeConn"}:                        true,
		{"golang.org/x/text/encoding/unicode", "bomOverride.Transform"}:       true,
	}

	if diff := cmp.Diff(want, calledVulns); diff != "" {
		log.Fatalf("reachable vulnerable symbols mismatch (-want, +got):\n%s", diff)
	}
}
