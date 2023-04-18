// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"errors"
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

func parseFlags(args []string) (*config, error) {
	cfg := &config{}
	var tagsFlag buildutil.TagsFlag
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.BoolVar(&cfg.json, "json", false, "output JSON")
	flags.BoolVar(&cfg.verbose, "v", false, "print additional information")
	flags.BoolVar(&cfg.test, "test", false, "analyze test files (only valid for source mode)")
	flags.StringVar(&cfg.dir, "C", "", "change to dir before running govulncheck")
	flags.StringVar(&cfg.db, "db", "https://vuln.go.dev", "vulnerability database URL")
	flags.StringVar(&cfg.mode, "mode", modeSource, "supports source or binary")
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
		return nil, ErrNoPatterns
	}
	cfg.tags = tagsFlag
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("govulncheck: %w", err)
	}
	return cfg, nil
}

var supportedModes = map[string]bool{
	modeSource: true,
	modeBinary: true,
}

func validateConfig(cfg *config) error {
	if _, ok := supportedModes[cfg.mode]; !ok {
		return fmt.Errorf("%q is not a valid mode", cfg.mode)
	}
	switch cfg.mode {
	case modeSource:
		if len(cfg.patterns) == 1 && isFile(cfg.patterns[0]) {
			return fmt.Errorf("%q is a file.\n\n%v", cfg.patterns[0], errNoBinaryFlag)
		}
	case modeBinary:
		if cfg.test {
			return fmt.Errorf("the -test flag is not supported in binary mode")
		}
		if len(cfg.tags) > 0 {
			return fmt.Errorf("the -tags flag is not supported in binary mode")
		}
		if cfg.verbose {
			return fmt.Errorf("the -v flag is not supported in binary mode")
		}
		if len(cfg.patterns) != 1 {
			return fmt.Errorf("only 1 binary can be analyzed at a time")
		}
		if !isFile(cfg.patterns[0]) {
			return fmt.Errorf("%q is not a file", cfg.patterns[0])
		}
	}
	if cfg.json && cfg.verbose {
		return fmt.Errorf("the -v flag is not supported for JSON output")
	}
	return nil
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

// fileExists checks if file path exists. Returns true
// if the file exists or it cannot prove that it does
// not exist. Otherwise, returns false.
func fileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else if errors.Is(err, os.ErrNotExist) {
		return false
	}
	// Conservatively return true if os.Stat fails
	// for some other reason.
	return true
}
