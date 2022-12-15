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
	"runtime/pprof"

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
	cpuprofile  = flag.String("cpuprofile", "", "write CPU profile to file")

	tagsFlag buildutil.TagsFlag

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

	// Profiling support.
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(f)
	}

	patterns := flag.Args()

	sourceAnalysis := true
	if len(patterns) == 1 && isFile(patterns[0]) {
		sourceAnalysis = false
	}
	validateFlags(sourceAnalysis)

	err := doGovulncheck(patterns, sourceAnalysis)
	pprof.StopCPUProfile()
	if err != nil {
		if code, ok := err.(exitCode); ok {
			os.Exit(int(code))
		}
		die("govulncheck: %v", err)
	}
}

// doGovulncheck performs the main govulncheck functionality and
// returns an error, possibly an exitCode.
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
		var pkgs []*vulncheck.Package
		pkgs, err = loadPackages(patterns, dir)
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
		res, err = govulncheck.Source(ctx, cfg, pkgs)
	} else {
		var f *os.File
		f, err = os.Open(patterns[0])
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
		// -json mode is always a success.
		if err := printJSON(res); err != nil {
			return err
		}
		return nil // success
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
				return exitCode(3)
			}
		}
	} else if len(res.Vulns) > 0 {
		return exitCode(3)
	}
	return nil
}

// exitCode is an error returned by doGovulncheck to indicate
// that the the program should silently exit with the specified code.
type exitCode int

func (code exitCode) Error() string { return fmt.Sprintf("exit code %d", code) }

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
