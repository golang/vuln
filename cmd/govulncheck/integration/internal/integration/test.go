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
	"strings"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/vuln/internal/govulncheck"
)

// CompareNonStdVulns compares vulnerable packages in out and want.
// For out, it only considers vulnerabilities outside of the standard
// library. Assumes the same for want.
func CompareNonStdVulns(out string, want map[string]bool) error {
	outJson, err := os.ReadFile(out)
	if err != nil {
		return fmt.Errorf("failed to read: %v", out)
	}
	calledVulnPkgs := make(map[string]bool)
	dec := json.NewDecoder(bytes.NewReader(outJson))
	for dec.More() {
		msg := govulncheck.Message{}
		// decode the next message in the stream
		if err := dec.Decode(&msg); err != nil {
			log.Fatalf("failed to load json: %v", err)
		}
		if msg.Finding != nil {
			if msg.Finding.Trace[0].Function == "" {
				// No symbol means the vulnerability is
				// imported but not called.
				continue
			}
			// collect only called non-std packages
			pkgPath := msg.Finding.Trace[0].Package
			if !isStd(pkgPath) {
				calledVulnPkgs[pkgPath] = true
			}
		}
	}
	if diff := cmp.Diff(want, calledVulnPkgs); diff != "" {
		return fmt.Errorf("reachable vulnerable packages mismatch (-want, +got):\n%s", diff)
	}
	return nil
}

// isStd returns true iff pkg is a standard library package.
func isStd(pkg string) bool {
	return !strings.Contains(pkg, ".")
}
