// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io/ioutil"
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

	outJson, err := ioutil.ReadFile(out)
	if err != nil {
		log.Fatal("Failed to read:", out)
	}

	var r vulncheck.Result
	if err := json.Unmarshal(outJson, &r); err != nil {
		log.Fatal("Failed to load json into vulncheck.Result:", err)
	}

	if len(r.Vulns) != 326 {
		log.Fatal("want 326 vulns; got", len(r.Vulns))
	}

	type vuln struct {
		pkg    string
		symbol string
	}
	calledVulns := make(map[vuln]bool)
	for _, v := range r.Vulns {
		if v.CallSink != 0 {
			calledVulns[vuln{v.PkgPath, v.Symbol}] = true
		}
	}

	want := map[vuln]bool{
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
		{"github.com/satori/go.uuid", "init"}:                                         true,
		{"golang.org/x/crypto/ssh", "NewPublicKey"}:                                   true,
		{"golang.org/x/crypto/ssh", "ed25519PublicKey.Verify"}:                        true,
		{"golang.org/x/crypto/ssh", "parseED25519"}:                                   true,
		{"golang.org/x/text/encoding/unicode", "bomOverride.Transform"}:               true,
		{"golang.org/x/text/encoding/unicode", "utf16Decoder.Transform"}:              true,
	}

	if !cmp.Equal(calledVulns, want) {
		log.Fatalf("want %v called symbols;\ngot%v\n", want, calledVulns)
	}
}
