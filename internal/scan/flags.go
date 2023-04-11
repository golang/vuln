// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/vuln/internal/vulncheck"
)

type config struct {
	vulncheck.Config
	patterns []string
	mode     string
	db       string
	json     bool
	dir      string
	verbose  bool
	tags     []string
	test     bool
}

const (
	modeSource = "source"
	modeBinary = "binary"
)

var supportedModes = map[string]bool{
	modeSource: true,
	modeBinary: true,
}

func parseFlags(args []string) (*config, error) {
	cfg := &config{}
	var (
		tagsFlag buildutil.TagsFlag
		mode     string
	)
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.BoolVar(&cfg.json, "json", false, "output JSON")
	flags.BoolVar(&cfg.verbose, "v", false, "print a full call stack for each vulnerability")
	flags.BoolVar(&cfg.test, "test", false, "analyze test files (only valid for source mode)")
	flags.StringVar(&cfg.dir, "C", "", "change to dir before running govulncheck")
	flags.StringVar(&cfg.db, "db", "https://vuln.go.dev", "vulnerability database URL")
	flags.StringVar(&mode, "mode", modeSource, "supports source or binary")
	flags.Var(&tagsFlag, "tags", "comma-separated `list` of build tags")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), `Govulncheck is a tool for finding known vulnerabilities.

Usage:

	govulncheck [flags] [patterns]
	govulncheck -mode=binary [flags] [binary]

`)
		flags.PrintDefaults()
		fmt.Fprintf(flags.Output(), "\n%s\n", detailsMessage)
	}
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	cfg.patterns = flags.Args()
	if len(cfg.patterns) == 0 {
		flags.Usage()
		return nil, ErrMissingArgPatterns
	}
	if _, ok := supportedModes[mode]; !ok {
		return nil, ErrInvalidArg
	}
	cfg.mode = mode

	if cfg.mode == modeBinary {
		if len(cfg.patterns) != 1 {
			return nil, ErrInvalidArg
		}
		if !isFile(cfg.patterns[0]) {
			return nil, fmt.Errorf("%q is not a file", cfg.patterns[0])
		}
	}
	cfg.tags = tagsFlag
	return cfg, nil
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}
