// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/vulncheck"
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

	var r vulncheck.Result
	if err := json.Unmarshal(outJson, &r); err != nil {
		log.Fatal("Failed to load json into vulncheck.Result:", err)
	}

	if len(r.Vulns) != 47 {
		log.Fatalf("want 47 vulns; got %d", len(r.Vulns))
	}

	type vuln struct {
		pkg    string
		symbol string
	}
	calledVulns := make(map[vuln]bool)
	for _, v := range r.Vulns {
		calledVulns[vuln{v.PkgPath, v.Symbol}] = true
	}

	want := map[vuln]bool{
		{"github.com/containernetworking/cni/pkg/invoke", "FindInPath"}:               true,
		{"github.com/evanphx/json-patch", "partialArray.add"}:                         true,
		{"github.com/opencontainers/selinux/go-selinux", "CurrentLabel"}:              true,
		{"github.com/opencontainers/selinux/go-selinux", "FileLabel"}:                 true,
		{"github.com/opencontainers/selinux/go-selinux", "GetEnabled"}:                true,
		{"github.com/opencontainers/selinux/go-selinux", "SetFileLabel"}:              true,
		{"github.com/opencontainers/selinux/go-selinux", "getSelinuxMountPoint"}:      true,
		{"github.com/opencontainers/selinux/go-selinux", "lgetxattr"}:                 true,
		{"github.com/opencontainers/selinux/go-selinux", "lsetxattr"}:                 true,
		{"github.com/opencontainers/selinux/go-selinux", "readCon"}:                   true,
		{"github.com/opencontainers/selinux/go-selinux", "selinuxState.getEnabled"}:   true,
		{"github.com/opencontainers/selinux/go-selinux", "selinuxState.getSELinuxfs"}: true,
		{"github.com/opencontainers/selinux/go-selinux", "selinuxState.setEnable"}:    true,
		{"github.com/opencontainers/selinux/go-selinux", "selinuxState.setSELinuxfs"}: true,
		{"golang.org/x/crypto/cryptobyte", "Builder.AddBytes"}:                        true,
		{"golang.org/x/crypto/cryptobyte", "Builder.AddUint16LengthPrefixed"}:         true,
		{"golang.org/x/crypto/cryptobyte", "Builder.Bytes"}:                           true,
		{"golang.org/x/crypto/cryptobyte", "Builder.add"}:                             true,
		{"golang.org/x/crypto/cryptobyte", "Builder.addLengthPrefixed"}:               true,
		{"golang.org/x/crypto/cryptobyte", "Builder.callContinuation"}:                true,
		{"golang.org/x/crypto/cryptobyte", "Builder.flushChild"}:                      true,
		{"golang.org/x/crypto/cryptobyte", "NewBuilder"}:                              true,
		{"golang.org/x/crypto/cryptobyte", "String.Empty"}:                            true,
		{"golang.org/x/crypto/cryptobyte", "String.PeekASN1Tag"}:                      true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadASN1"}:                         true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadAnyASN1"}:                      true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadBytes"}:                        true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadOptionalASN1"}:                 true,
		{"golang.org/x/crypto/cryptobyte", "String.ReadUint16LengthPrefixed"}:         true,
		{"golang.org/x/crypto/cryptobyte", "String.Skip"}:                             true,
		{"golang.org/x/crypto/cryptobyte", "String.read"}:                             true,
		{"golang.org/x/crypto/cryptobyte", "String.readASN1"}:                         true,
		{"golang.org/x/crypto/cryptobyte", "String.readLengthPrefixed"}:               true,
		{"golang.org/x/crypto/cryptobyte", "String.readUnsigned"}:                     true,
		{"golang.org/x/crypto/salsa20/salsa", "XORKeyStream"}:                         true,
		{"golang.org/x/crypto/ssh", "NewClientConn"}:                                  true,
		{"golang.org/x/crypto/ssh", "NewPublicKey"}:                                   true,
		{"golang.org/x/crypto/ssh", "ed25519PublicKey.Verify"}:                        true,
		{"golang.org/x/crypto/ssh", "parseED25519"}:                                   true,
		{"golang.org/x/net/http/httpguts", "HeaderValuesContainsToken"}:               true,
		{"golang.org/x/net/http/httpguts", "headerValueContainsToken"}:                true,
		{"golang.org/x/net/http2", "Server.ServeConn"}:                                true,
		{"golang.org/x/net/http2", "serverConn.canonicalHeader"}:                      true,
		{"golang.org/x/net/http2", "serverConn.goAway"}:                               true,
		{"golang.org/x/text/encoding/unicode", "bomOverride.Transform"}:               true,
		{"golang.org/x/text/encoding/unicode", "utf16Decoder.Transform"}:              true,
	}

	if diff := cmp.Diff(want, calledVulns); diff != "" {
		log.Fatalf("reachable vulnerable symbols mismatch (-want, +got):\n%s", diff)
	}
}
