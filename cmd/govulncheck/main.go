// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/buildutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/exp/govulncheck"
	gvc "golang.org/x/vuln/internal/govulncheck"
	"golang.org/x/vuln/vulncheck"
)

var (
	jsonFlag    = flag.Bool("json", false, "output JSON")
	verboseFlag = flag.Bool("v", false, "print a full call stack for each vulnerability")
	testFlag    = flag.Bool("test", false, "analyze test files. Only valid for source code.")
	tagsFlag    buildutil.TagsFlag

	// testmode flags. See main_testmode.go.
	dirFlag string
)

func init() {
	flag.Var(&tagsFlag, "tags", "comma-separated `list` of build tags")
}

const (
	envGOVULNDB = "GOVULNDB"
	vulndbHost  = "https://vuln.go.dev"
)

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

	sourceAnalysis := true
	if len(patterns) == 1 && isFile(patterns[0]) {
		sourceAnalysis = false
	}
	validateFlags(sourceAnalysis)

	if err := doGovulncheck(patterns, sourceAnalysis); err != nil {
		die(fmt.Sprintf("govulncheck: %v", err))
	}
}

// doGovulncheck performs main govulncheck functionality and exits the
// program upon success with an appropriate exit status. Otherwise,
// returns an error.
func doGovulncheck(patterns []string, sourceAnalysis bool) error {
	ctx := context.Background()
	dir := filepath.FromSlash(dirFlag)

	dbs := []string{vulndbHost}
	if db := os.Getenv(envGOVULNDB); db != "" {
		dbs = strings.Split(db, ",")
	}
	dbClient, err := client.NewClient(dbs, client.Options{
		HTTPCache: govulncheck.DefaultCache(),
	})
	if err != nil {
		return err
	}

	if !*jsonFlag {
		// Print intro message when in text or verbose mode
		fmt.Println(introMessage)
	}

	// config GoVersion is "", which means use current
	// Go version at path.
	cfg := &govulncheck.Config{Client: dbClient}
	var res *govulncheck.Result
	if sourceAnalysis {
		pkgs, err := loadPackages(patterns, dir)
		if err != nil {
			// Try to provide a meaningful and actionable error message.
			if !fileExists(filepath.Join(dir, "go.mod")) {
				return errNoGoMod
			}
			if !fileExists(filepath.Join(dir, "go.sum")) {
				return errNoGoSum
			}
			if isGoVersionMismatchError(err) {
				return fmt.Errorf("%v\n\n%v", errGoVersionMismatch, err)
			}
			return err
		}
		res, err = govulncheck.Source(ctx, cfg, pkgs)
	} else {
		f, err := os.Open(patterns[0])
		if err != nil {
			return err
		}
		defer f.Close()
		res, err = gvc.Binary(ctx, cfg, f)
	}
	if err != nil {
		return err
	}

	if *jsonFlag {
		// Following golang.org/x/tools/go/analysis/singlechecker,
		// return 0 exit code in -json mode.
		if err := printJSON(res); err != nil {
			return err
		}
		os.Exit(0)
	}

	printText(res, *verboseFlag, sourceAnalysis)
	// Return exit status -3 if some vulnerabilities are actually
	// called in source mode or just present in binary mode.
	//
	// This follows the style from
	// golang.org/x/tools/go/analysis/singlechecker,
	// which fails with 3 if there are some findings.
	if sourceAnalysis {
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

func validateFlags(source bool) {
	if !source {
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

// loadPackages loads the packages matching patterns at dir using build tags
// provided by tagsFlag. Uses load mode needed for vulncheck analysis. If the
// packages contain errors, a packageError is returned containing a list of
// the errors, along with the packages themselves.
func loadPackages(patterns []string, dir string) ([]*vulncheck.Package, error) {
	var buildFlags []string
	if tagsFlag != nil {
		buildFlags = []string{fmt.Sprintf("-tags=%s", strings.Join(tagsFlag, ","))}
	}

	cfg := &packages.Config{Dir: dir, Tests: *testFlag}
	cfg.Mode |= packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg.BuildFlags = buildFlags

	pkgs, err := packages.Load(cfg, patterns...)
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
