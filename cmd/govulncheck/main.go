// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/internal/govulncheck"
)

var (
	jsonFlag    = flag.Bool("json", false, "output JSON")
	verboseFlag = flag.Bool("v", false, "print a full call stack for each vulnerability")
	testFlag    = flag.Bool("test", false, "analyze test files. Only valid for source code.")
	tagsFlag    buildutil.TagsFlag

	// testmode flags. See main_testmode.go.
	dirFlag         string
	summaryJSONFlag bool
)

func init() {
	flag.Var(&tagsFlag, "tags", "comma-separated `list` of build tags")
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `usage:
	govulncheck [flags] package...
	govulncheck [flags] binary

`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
For details, see https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck.
`)
	}
	flag.Parse()

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	patterns := flag.Args()

	mode := govulncheck.AnalysisTypeSource
	if len(patterns) == 1 && isFile(patterns[0]) {
		mode = govulncheck.AnalysisTypeBinary
	}
	validateFlags(mode)

	outputType := govulncheck.OutputTypeText
	if *jsonFlag {
		outputType = govulncheck.OutputTypeJSON
	} else if summaryJSONFlag { // accessible only in testmode.
		outputType = govulncheck.OutputTypeSummary
	}
	if outputType == govulncheck.OutputTypeText && *verboseFlag {
		outputType = govulncheck.OutputTypeVerbose
	}

	var buildFlags []string
	if tagsFlag != nil {
		buildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(tagsFlag, ","))}
	}

	ctx := context.Background()
	_, err := govulncheck.Run(ctx, govulncheck.Config{
		AnalysisType: mode,
		OutputType:   outputType,
		Patterns:     patterns,
		SourceLoadConfig: &packages.Config{
			Dir:        filepath.FromSlash(dirFlag),
			Tests:      *testFlag,
			BuildFlags: buildFlags,
		},
	})
	if outputType == govulncheck.OutputTypeJSON {
		// The current behavior is to not print any errors.
		return
	}
	if errors.Is(err, govulncheck.ErrContainsVulnerabilties) {
		// This follows the style from
		// golang.org/x/tools/go/analysis/singlechecker,
		// which fails with 3 if there are findings (in this case, vulns).
		os.Exit(3)
	}
	if err != nil {
		die(fmt.Sprintf("govulncheck: %v", err))
	}
}

func validateFlags(mode string) {
	switch mode {
	case govulncheck.AnalysisTypeBinary:
		if *testFlag {
			die("govulncheck: the -test flag is invalid for binaries")
		}
		if tagsFlag != nil {
			die("govulncheck: the -tags flag is invalid for binaries")
		}
	}
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
