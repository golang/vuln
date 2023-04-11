// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
)

func CompareVulns(out string, want map[string]bool) error {
	outJson, err := os.ReadFile(out)
	if err != nil {
		return fmt.Errorf("Failed to read %v:", out)
	}
	calledVulnPkgs := make(map[string]bool)
	dec := json.NewDecoder(bytes.NewReader(outJson))
	for dec.More() {
		msg := govulncheck.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			log.Fatalf("Failed to load json: %v", err)
		}
		if msg.Vulnerability != nil {
			for _, m := range msg.Vulnerability.Modules {
				for _, p := range m.Packages {
					if len(p.CallStacks) > 0 {
						calledVulnPkgs[p.Path] = true
					}
				}
			}
		}
	}
	if diff := cmp.Diff(want, calledVulnPkgs); diff != "" {
		return fmt.Errorf("reachable vulnerable packages mismatch (-want, +got):\n%s", diff)
	}
	return nil
}
