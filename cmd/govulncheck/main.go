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
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/vulncheck"
)

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		switch err {
		case flag.ErrHelp:
			os.Exit(0)
		case errMissingArgPatterns:
			os.Exit(1)
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if !cfg.sourceAnalysis {
		if cfg.test {
			fmt.Fprintln(os.Stderr, err)
			die(cfg, "govulncheck: the -test flag is invalid for binaries")
		}
		if cfg.tags != nil {
			die(cfg, "govulncheck: the -tags flag is invalid for binaries")
		}
	}
	if err := doGovulncheck(cfg); err != nil {
		die(cfg, fmt.Sprintf("govulncheck: %v", err))
	}
}

type config struct {
	patterns       []string
	sourceAnalysis bool
	db             string
	json           bool
	dir            string
	verbose        bool
	tags           []string
	test           bool
}

const (
	envGOVULNDB = "GOVULNDB"
	vulndbHost  = "https://vuln.go.dev"
)

var errMissingArgPatterns = errors.New("missing any pattern args")

func parseFlags(args []string) (*config, error) {
	cfg := &config{}
	var tagsFlag buildutil.TagsFlag
	flags := flag.NewFlagSet("", flag.ContinueOnError)
	flags.BoolVar(&cfg.json, "json", false, "output JSON")
	flags.BoolVar(&cfg.verbose, "v", false, "print a full call stack for each vulnerability")
	flags.BoolVar(&cfg.test, "test", false, "analyze test files. Only valid for source code.")
	flags.Var(&tagsFlag, "tags", "comma-separated `list` of build tags")
	flags.Usage = func() {
		fmt.Fprint(os.Stderr, `usage:
	govulncheck [flags] package...
	govulncheck [flags] binary

`)
		flags.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n%s\n", detailsMessage)
	}
	flags = addTestFlags(flags, cfg)
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	cfg.patterns = flags.Args()
	if len(cfg.patterns) == 0 {
		flags.Usage()
		return nil, errMissingArgPatterns
	}
	cfg.sourceAnalysis = true
	if len(cfg.patterns) == 1 && isFile(cfg.patterns[0]) {
		cfg.sourceAnalysis = false
	}
	cfg.tags = tagsFlag
	return cfg, nil
}

// doGovulncheck performs main govulncheck functionality and exits the
// program upon success with an appropriate exit status. Otherwise,
// returns an error.
func doGovulncheck(c *config) error {
	ctx := context.Background()
	dir := filepath.FromSlash(c.dir)

	dbs := []string{vulndbHost}
	if db := os.Getenv(envGOVULNDB); db != "" {
		dbs = strings.Split(db, ",")
	}

	cache, err := govulncheck.DefaultCache()
	if err != nil {
		return err
	}

	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: cache,
	})
	if err != nil {
		return err
	}

	if !c.json {
		// Print intro message when in text or verbose mode
		printIntro(ctx, dbClient, dbs, c.sourceAnalysis)
	}

	// config GoVersion is "", which means use current
	// Go version at path.
	cfg := &govulncheck.Config{Client: dbClient}
	var res *govulncheck.Result
	if c.sourceAnalysis {
		var pkgs []*vulncheck.Package
		pkgs, err = loadPackages(c, dir)
		if err != nil {
			// Try to provide a meaningful and actionable error message.
			if !fileExists(filepath.Join(dir, "go.mod")) {
				return errNoGoMod
			}
			if isGoVersionMismatchError(err) {
				return fmt.Errorf("%v\n\n%v", errGoVersionMismatch, err)
			}
			return err
		}

		if !c.json {
			fmt.Println()
			fmt.Println(sourceProgressMessage(pkgs))
		}
		res, err = govulncheck.Source(ctx, cfg, pkgs)
	} else {
		var f *os.File
		f, err = os.Open(c.patterns[0])
		if err != nil {
			return err
		}
		defer f.Close()

		if !c.json {
			fmt.Println()
			fmt.Println(binaryProgressMessage)
		}
		res, err = govulncheck.Binary(ctx, cfg, f)
	}
	if err != nil {
		return err
	}

	if c.json {
		// Following golang.org/x/tools/go/analysis/singlechecker,
		// return 0 exit code in -json mode.
		if err := printJSON(res); err != nil {
			return err
		}
		os.Exit(0)
	}

	if err := printText(res, c.verbose, c.sourceAnalysis); err != nil {
		return err
	}
	// Return exit status -3 if some vulnerabilities are actually
	// called in source mode or just present in binary mode.
	//
	// This follows the style from
	// golang.org/x/tools/go/analysis/singlechecker,
	// which fails with 3 if there are some findings.
	if c.sourceAnalysis {
		for _, v := range res.Vulns {
			if v.IsCalled() {
				os.Exit(3)
			}
		}
	} else if len(res.Vulns) > 0 {
		os.Exit(3)
	}
	os.Exit(0)
	return nil
}

// jsonFail prints an error to stdout in the format {Error: errorString}
func jsonFail(err error) {
	fmt.Printf("{\"Error\": %q}\n", err)
}

func isFile(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !s.IsDir()
}

func die(cfg *config, format string, args ...interface{}) {
	if !cfg.json {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		os.Exit(1)
	} else {
		jsonFail(errors.New(format))
		os.Exit(0)
	}
}

// loadPackages loads the packages matching patterns at dir using build tags
// provided by tagsFlag. Uses load mode needed for vulncheck analysis. If the
// packages contain errors, a packageError is returned containing a list of
// the errors, along with the packages themselves.
func loadPackages(c *config, dir string) ([]*vulncheck.Package, error) {
	var buildFlags []string
	if c.tags != nil {
		buildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(c.tags, ","))}
	}

	cfg := &packages.Config{Dir: dir, Tests: c.test}
	cfg.Mode |= packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = buildFlags

	pkgs, err := packages.Load(cfg, c.patterns...)
	vpkgs := vulncheck.Convert(pkgs)
	if err != nil {
		return nil, err
	}
	var perrs []packages.Error
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		perrs = append(perrs, p.Errors...)
	})
	if len(perrs) > 0 {
		err = &packageError{perrs}
	}
	return vpkgs, err
}
