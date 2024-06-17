// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"golang.org/x/vuln/internal/govulncheck"
)

// CompareVulns checks if packages of called vulnerable symbols
// out are a superset of want.
func CompareVulns(out string, want map[string]bool) error {
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
			calledVulnPkgs[pkgPath] = true
		}
	}

	for pkg := range want {
		if _, ok := calledVulnPkgs[pkg]; !ok {
			e := fmt.Errorf("vulnerable symbols of expected package %s not detected", pkg)
			err = errors.Join(err, e)
		}

	}
	return err
}
