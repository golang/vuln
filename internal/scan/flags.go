// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scan

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/vuln/internal/govulncheck"
)

type config struct {
	govulncheck.Config
	patterns []string
	mode     modeFlag
	db       string
	dir      string
	tags     buildutil.TagsFlag
	test     bool
	show     showFlag
	format   formatFlag
	env      []string
}

func parseFlags(cfg *config, stderr io.Writer, args []string) error {
	var version bool
	var json bool
	var scanFlag scanFlag
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.BoolVar(&json, "json", false, "output JSON (Go compatible legacy flag, see format flag)")
	flags.BoolVar(&cfg.test, "test", false, "analyze test files (only valid for source mode, default false)")
	flags.StringVar(&cfg.dir, "C", "", "change to `dir` before running govulncheck")
	flags.StringVar(&cfg.db, "db", "https://vuln.go.dev", "vulnerability database `url`")
	flags.Var(&cfg.mode, "mode", "supports 'source', 'binary', and 'extract'")
	flags.Var(&cfg.tags, "tags", "comma-separated `list` of build tags")
	flags.Var(&cfg.show, "show", "enable display of additional information specified by the comma separated `list`\nThe supported values are 'traces','color', 'version', and 'verbose'")
	flags.Var(&cfg.format, "format", "specify format output\nThe supported values are 'text' and 'json' (default 'text')")
	flags.BoolVar(&version, "version", false, "print the version information")
	flags.Var(&scanFlag, "scan", "set the scanning level desired, one of 'module', 'package', or 'symbol'")

	// We don't want to print the whole usage message on each flags
	// error, so we set to a no-op and do the printing ourselves.
	flags.Usage = func() {}
	usage := func() {
		fmt.Fprint(flags.Output(), `Govulncheck reports known vulnerabilities in dependencies.

Usage:

	govulncheck [flags] [patterns]
	govulncheck -mode=binary [flags] [binary]

`)
		flags.PrintDefaults()
		fmt.Fprintf(flags.Output(), "\n%s\n", detailsMessage)
	}

	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage() // print usage only on help
			return errHelp
		}
		return errUsage
	}
	cfg.patterns = flags.Args()
	if version {
		cfg.show = append(cfg.show, "version")
	}
	cfg.ScanLevel = govulncheck.ScanLevel(scanFlag)
	if err := validateConfig(cfg, json); err != nil {
		fmt.Fprintln(flags.Output(), err)
		return errUsage
	}
	return nil
}

func validateConfig(cfg *config, json bool) error {
	// take care of default values
	if cfg.mode == "" {
		cfg.mode = modeSource
	}
	if cfg.ScanLevel == "" {
		cfg.ScanLevel = govulncheck.ScanLevelSymbol
	}
	if json {
		if len(cfg.show) > 0 {
			return fmt.Errorf("the -show flag is not supported for JSON output")
		}
		if cfg.format != formatUnset {
			return fmt.Errorf("the -json flag cannot be used with -format flag")
		}
		cfg.format = formatJSON
	} else {
		if cfg.format == formatUnset {
			cfg.format = formatText
		}
	}

	switch cfg.mode {
	case modeSource:
		if len(cfg.patterns) == 1 && isFile(cfg.patterns[0]) {
			return fmt.Errorf("%q is a file.\n\n%v", cfg.patterns[0], errNoBinaryFlag)
		}
		if cfg.ScanLevel == govulncheck.ScanLevelModule && len(cfg.patterns) != 0 {
			return fmt.Errorf("patterns are not accepted for module only scanning")
		}
	case modeBinary:
		if cfg.test {
			return fmt.Errorf("the -test flag is not supported in binary mode")
		}
		if len(cfg.tags) > 0 {
			return fmt.Errorf("the -tags flag is not supported in binary mode")
		}
		if len(cfg.patterns) != 1 {
			return fmt.Errorf("only 1 binary can be analyzed at a time")
		}
		if !isFile(cfg.patterns[0]) {
			return fmt.Errorf("%q is not a file", cfg.patterns[0])
		}
	case modeExtract:
		if cfg.test {
			return fmt.Errorf("the -test flag is not supported in extract mode")
		}
		if len(cfg.tags) > 0 {
			return fmt.Errorf("the -tags flag is not supported in extract mode")
		}
		if len(cfg.patterns) != 1 {
			return fmt.Errorf("only 1 binary can be extracted at a time")
		}
		if cfg.format == formatJSON {
			return fmt.Errorf("the json format must be off in extract mode")
		}
		if !isFile(cfg.patterns[0]) {
			return fmt.Errorf("%q is not a file (source extraction is not supported)", cfg.patterns[0])
		}
	case modeConvert:
		if len(cfg.patterns) != 0 {
			return fmt.Errorf("patterns are not accepted in convert mode")
		}
		if cfg.dir != "" {
			return fmt.Errorf("the -C flag is not supported in convert mode")
		}
		if cfg.test {
			return fmt.Errorf("the -test flag is not supported in convert mode")
		}
		if len(cfg.tags) > 0 {
			return fmt.Errorf("the -tags flag is not supported in convert mode")
		}
	case modeQuery:
		if cfg.test {
			return fmt.Errorf("the -test flag is not supported in query mode")
		}
		if len(cfg.tags) > 0 {
			return fmt.Errorf("the -tags flag is not supported in query mode")
		}
		if cfg.format != formatJSON {
			return fmt.Errorf("the json format must be set in query mode")
		}
		for _, pattern := range cfg.patterns {
			// Parse the input here so that we can catch errors before
			// outputting the Config.
			if _, _, err := parseModuleQuery(pattern); err != nil {
				return err
			}
		}
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

var flagParseError = errors.New("see -help for details")

// showFlag is used for parsing and validation of
// govulncheck -show flag.
type showFlag []string

var supportedShows = map[string]bool{
	"traces":  true,
	"color":   true,
	"verbose": true,
	"version": true,
}

func (v *showFlag) Set(s string) error {
	if s == "" {
		return nil
	}
	for _, show := range strings.Split(s, ",") {
		sh := strings.TrimSpace(show)
		if _, ok := supportedShows[sh]; !ok {
			return flagParseError
		}
		*v = append(*v, sh)
	}
	return nil
}

func (f *showFlag) Get() interface{} { return *f }
func (f *showFlag) String() string   { return "" }

// formatFlag is used for parsing and validation of
// govulncheck -format flag.
type formatFlag string

const (
	formatUnset = ""
	formatJSON  = "json"
	formatText  = "text"
)

var supportedFormats = map[string]bool{
	formatJSON: true,
	formatText: true,
}

func (f *formatFlag) Get() interface{} { return *f }
func (f *formatFlag) Set(s string) error {
	if _, ok := supportedFormats[s]; !ok {
		return flagParseError
	}
	*f = formatFlag(s)
	return nil
}
func (f *formatFlag) String() string { return "" }

// modeFlag is used for parsing and validation of
// govulncheck -mode flag.
type modeFlag string

const (
	modeBinary  = "binary"
	modeSource  = "source"
	modeConvert = "convert" // only intended for use by gopls
	modeQuery   = "query"   // only intended for use by gopls
	modeExtract = "extract" // currently, only binary extraction is supported
)

var supportedModes = map[string]bool{
	modeSource:  true,
	modeBinary:  true,
	modeConvert: true,
	modeQuery:   true,
	modeExtract: true,
}

func (f *modeFlag) Get() interface{} { return *f }
func (f *modeFlag) Set(s string) error {
	if _, ok := supportedModes[s]; !ok {
		return flagParseError
	}
	*f = modeFlag(s)
	return nil
}
func (f *modeFlag) String() string { return "" }

// scanFlag is used for parsing and validation of
// govulncheck -scan flag.
type scanFlag string

var supportedLevels = map[string]bool{
	govulncheck.ScanLevelModule:  true,
	govulncheck.ScanLevelPackage: true,
	govulncheck.ScanLevelSymbol:  true,
}

func (f *scanFlag) Get() interface{} { return *f }
func (f *scanFlag) Set(s string) error {
	if _, ok := supportedLevels[s]; !ok {
		return flagParseError
	}
	*f = scanFlag(s)
	return nil
}
func (f *scanFlag) String() string { return "" }
