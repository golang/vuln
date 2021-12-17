// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vlint contains functionality for linting reports in x/vulndb.
package vlint

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/vuln/srv/internal/derrors"
	"golang.org/x/vuln/srv/internal/report"
	"gopkg.in/yaml.v2"
)

// LintReport is used to lint the x/vulndb/reports/ directory. It is run by
// TestLintReports (in the vulndb repo) to ensure that there are no errors in
// the YAML reports.
func LintReport(filename string) (_ []string, err error) {
	defer derrors.Wrap(&err, "Lint(%q)", filename)
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("ioutil.ReadDir(%q): %v", filename, err)
	}
	var r report.Report
	if err := yaml.UnmarshalStrict(b, &r); err != nil {
		return nil, fmt.Errorf("yaml.UnmarshalStrict(b, &r): %v (%q)", err, filename)
	}
	return r.Lint(), nil
}
